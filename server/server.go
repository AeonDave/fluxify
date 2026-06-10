//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"

	quic "github.com/quic-go/quic-go"

	"fluxify/common"
)

const (
	serverIPv4CIDR   = "10.8.0.1/24"
	serverIPv6CIDR   = "fd00:8:0::1/64"
	clientIPv6Prefix = "fd00:8:0::"

	// serverStatsInterval is how often per-path rate/RTT estimates are
	// refreshed for the downlink striping scheduler.
	serverStatsInterval = 100 * time.Millisecond
)

type Server struct {
	port      int
	ctrlPort  int
	ifaceName string
	pki       common.PKIPaths
	verbose   bool

	sessions       map[uint32]*serverSession
	ipToSession    map[string]*serverSession // "10.8.0.x" or "fd00::x" -> session
	clientSessions map[string]*serverSession // client name -> session
	sessMu         sync.RWMutex

	nextIPOctet atomic.Uint32

	tun      *water.Interface
	listener *quic.Listener

	tunWriteCh chan []byte

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool

	reorderSize  int
	reorderFlush time.Duration

	mssClamp mssClampConfig
}

func NewServer(port, ctrlPort int, iface string, pki common.PKIPaths, verbose bool, rsize int, rflush time.Duration) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		port:           port,
		ctrlPort:       ctrlPort,
		ifaceName:      iface,
		pki:            pki,
		verbose:        verbose,
		sessions:       make(map[uint32]*serverSession),
		ipToSession:    make(map[string]*serverSession),
		clientSessions: make(map[string]*serverSession),
		tunWriteCh:     make(chan []byte, 4096),
		ctx:            ctx,
		cancel:         cancel,
		reorderSize:    rsize,
		reorderFlush:   rflush,
	}
}

func (s *Server) logDebug(format string, v ...interface{}) {
	if s.verbose {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (s *Server) metricsLoop(every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for s.running.Load() {
		<-t.C
		s.logMetricsOnce()
	}
}

func (s *Server) logMetricsOnce() {
	s.sessMu.RLock()
	sessions := make([]*serverSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.sessMu.RUnlock()

	for _, sess := range sessions {
		m := sess.snapshotMetrics()
		log.Printf("[METRICS] %s", formatServerSessionMetrics(m))
	}
}

func (s *Server) Start() error {
	s.running.Store(true)
	s.logDebug("Starting server (port=%d, ctrl=%d)", s.port, s.ctrlPort)

	// Setup TUN
	conf := water.Config{DeviceType: water.TUN}
	if s.ifaceName != "" {
		conf.Name = s.ifaceName
		s.logDebug("TUN: using custom interface name: %s", s.ifaceName)
	}
	s.logDebug("TUN: creating device...")
	tun, err := water.New(conf)
	if err != nil {
		return fmt.Errorf("create tun: %v", err)
	}
	s.tun = tun
	log.Printf("TUN initialized: %s", tun.Name())

	s.logDebug("TUN: configuring IP addresses (v4=%s, v6=%s, MTU=%d)", serverIPv4CIDR, serverIPv6CIDR, common.MTU)
	if err := common.ConfigureTUN(common.TUNConfig{IfaceName: tun.Name(), CIDR: serverIPv4CIDR, IPv6CIDR: serverIPv6CIDR, MTU: common.MTU}); err != nil {
		return fmt.Errorf("configure tun: %v", err)
	}
	// Best-effort networking rules; these require root.
	s.logDebug("iptables: configuring forwarding and NAT rules...")
	if err := enableForwarding(execRunner{}); err != nil {
		log.Printf("enable forwarding: %v", err)
	}
	if err := ensureNatRule(execRunner{}); err != nil {
		log.Printf("ensure nat v4: %v", err)
	}
	if err := ensureNatRule6(execRunner{}); err != nil {
		log.Printf("ensure nat v6: %v", err)
	}
	if err := ensureForwardRules(execRunner{}, tun.Name()); err != nil {
		log.Printf("ensure forward v4: %v", err)
	}
	if err := ensureForwardRules6(execRunner{}, tun.Name()); err != nil {
		log.Printf("ensure forward v6: %v", err)
	}
	if err := ensureMSSClampRules(execRunner{}, tun.Name(), s.mssClamp); err != nil {
		log.Printf("mss clamp: %v", err)
	}

	// QUIC data plane.
	s.logDebug("QUIC: loading TLS config from PKI (dir=%s)", s.pki.Dir)
	tlsCfg, err := common.ServerTLSConfig(s.pki)
	if err != nil {
		return fmt.Errorf("quic tls config: %v", err)
	}
	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"fluxify-quic"}

	// InitialPacketSize stays at the safe default (1280); RFC 8899 path MTU
	// discovery raises the packet (and thus max datagram) size within the
	// first seconds of each connection.
	qc := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	s.logDebug("QUIC: binding to port %d...", s.port)
	ln, err := quic.ListenAddr(fmt.Sprintf(":%d", s.port), tlsCfg, qc)
	if err != nil {
		return fmt.Errorf("listen quic: %v", err)
	}
	s.listener = ln
	log.Printf("QUIC listening on :%d", s.port)

	go s.controlServer()

	s.wg.Add(4)
	go s.tunWriteLoop()
	go s.tunReadLoop()
	go s.acceptLoop()
	go s.statsLoop()

	s.wg.Add(1)
	go s.cleanupLoop()

	s.logDebug("Server startup complete")
	return nil
}

// ============================================================================
// QUIC data plane: one read loop per client connection (= per path)
// ============================================================================

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for s.running.Load() {
		conn, err := s.listener.Accept(s.ctx)
		if err != nil {
			if s.running.Load() && s.ctx.Err() == nil {
				log.Printf("quic accept error: %v", err)
			}
			return
		}
		s.logDebug("acceptLoop: new QUIC connection from %s", conn.RemoteAddr())
		s.wg.Add(1)
		go s.connLoop(conn)
	}
}

// connLoop pumps inbound datagrams from one client connection. The first
// datagram (normally the client's handshake announcement) binds the
// connection to its session, making the path available for downlink striping.
func (s *Server) connLoop(conn *quic.Conn) {
	defer s.wg.Done()
	var sess *serverSession
	defer func() {
		if sess != nil {
			sess.removeConn(conn)
		}
		_ = conn.CloseWithError(0, "closed")
		s.logDebug("connLoop: connection from %s closed", conn.RemoteAddr())
	}()
	for {
		dat, err := conn.ReceiveDatagram(s.ctx)
		if err != nil {
			return
		}
		h, payload, err := common.ParseDataPlaneDatagram(dat)
		if err != nil {
			s.logDebug("connLoop: failed to parse datagram: %v", err)
			continue
		}
		if sess == nil || sess.id != h.SessionID {
			if sess != nil {
				sess.removeConn(conn)
			}
			sess = s.getSession(h.SessionID)
			if sess == nil {
				s.logDebug("connLoop: unknown session ID: %d", h.SessionID)
				continue
			}
			sc := sess.connFor(conn)
			s.logDebug("connLoop: %s joined session %d (paths=%d)", sc.addr, sess.id, len(sess.conns))
		}
		s.handleDatagram(sess, sess.connFor(conn), h, payload)
	}
}

func (s *Server) handleDatagram(sess *serverSession, sc *serverConn, h common.DataPlaneHeader, payload []byte) {
	sess.touch()
	sc.touch()
	sc.bytesRecv.Add(uint64(len(payload)))

	switch h.Type {
	case common.DPTypeHandshake:
		// Path announcement: ack it so the client sees the path as live.
		s.enqueueControl(sess, sc, common.DPTypeHandshake, nil)
	case common.DPTypeHeartbeat:
		sc.hbRecv.Add(1)
		// Echo so the client can measure round-trip time on this path.
		s.enqueueControl(sess, sc, common.DPTypeHeartbeat, payload)
	case common.DPTypeIP:
		if !common.IsIPPacket(payload) {
			return
		}
		buf := common.GetBuffer()
		n := copy(buf, payload)
		for _, pkt := range sess.reorderBuf.Insert(h.SeqNum, buf[:n]) {
			select {
			case s.tunWriteCh <- pkt:
			default:
				common.PutBuffer(pkt)
			}
		}
	}
}

// enqueueControl sends a control datagram (heartbeat echo / handshake ack)
// back on the specific path it arrived on.
func (s *Server) enqueueControl(sess *serverSession, sc *serverConn, ptype uint8, payload []byte) {
	buf := common.GetBuffer()
	head := common.DataPlaneHeader{Version: common.DataPlaneVersion, Type: ptype, SessionID: sess.id}
	dg, err := common.BuildDataPlaneDatagram(buf, head, payload)
	if err != nil {
		common.PutBuffer(buf)
		return
	}
	sc.enqueue(dg)
}

// ============================================================================
// TUN I/O
// ============================================================================

func (s *Server) tunWriteLoop() {
	defer s.wg.Done()
	for data := range s.tunWriteCh {
		if _, err := s.tun.Write(data); err != nil {
			log.Printf("tun write error: %v", err)
		}
		common.PutBuffer(data)
	}
}

// tunReadLoop reads downlink packets and stripes each one across the owning
// session's paths. It reads at an offset so the session can stamp the
// dataplane header in place (no extra copy).
func (s *Server) tunReadLoop() {
	defer s.wg.Done()
	defer close(s.tunWriteCh)

	for s.running.Load() {
		buf := common.GetBuffer()
		n, err := s.tun.Read(buf[common.DataPlaneHdrSize:])
		if err != nil {
			if s.running.Load() {
				log.Printf("tun read error: %v", err)
			}
			common.PutBuffer(buf)
			continue
		}

		pkt := buf[common.DataPlaneHdrSize : common.DataPlaneHdrSize+n]
		dstIP := extractDstIP(pkt)
		if len(dstIP) == 0 {
			common.PutBuffer(buf)
			continue
		}

		sess := s.lookupSessionByIP(dstIP)
		if sess == nil {
			common.PutBuffer(buf)
			continue
		}
		sess.dispatch(buf[:common.DataPlaneHdrSize+n])
	}
}

// statsLoop refreshes per-path rate/RTT estimates for every session.
func (s *Server) statsLoop() {
	defer s.wg.Done()
	t := time.NewTicker(serverStatsInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.sessMu.RLock()
			sessions := make([]*serverSession, 0, len(s.sessions))
			for _, sess := range s.sessions {
				sessions = append(sessions, sess)
			}
			s.sessMu.RUnlock()
			for _, sess := range sessions {
				sess.updateStats(now)
			}
		}
	}
}

// ============================================================================
// Session registry
// ============================================================================

func (s *Server) getSession(id uint32) *serverSession {
	s.sessMu.RLock()
	defer s.sessMu.RUnlock()
	return s.sessions[id]
}

func (s *Server) lookupSessionByIP(ip net.IP) *serverSession {
	if ip == nil {
		return nil
	}
	s.sessMu.RLock()
	defer s.sessMu.RUnlock()
	return s.ipToSession[ip.String()]
}

func (s *Server) registerSession(sess *serverSession) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.sessions[sess.id] = sess
	if sess.name != "" {
		s.clientSessions[sess.name] = sess
	}
	if sess.clientIP != nil {
		s.ipToSession[sess.clientIP.String()] = sess
	}
	if sess.clientIPv6 != nil {
		s.ipToSession[sess.clientIPv6.String()] = sess
	}
	s.logDebug("registerSession: registered session %d for client '%s' (IPv4=%s, IPv6=%s)", sess.id, sess.name, sess.clientIP, sess.clientIPv6)
}

func extractDstIP(pkt []byte) net.IP {
	if len(pkt) == 0 {
		return nil
	}
	ver := pkt[0] >> 4
	if ver == 4 {
		if len(pkt) < 20 {
			return nil
		}
		return net.IP(pkt[16:20])
	} else if ver == 6 {
		if len(pkt) < 40 {
			return nil
		}
		return net.IP(pkt[24:40])
	}
	return nil
}

// ============================================================================
// Control plane
// ============================================================================

func (s *Server) controlServer() {
	s.logDebug("controlServer: loading TLS config...")
	tlsCfg, err := common.ServerTLSConfig(s.pki)
	if err != nil {
		log.Printf("control tls config err: %v", err)
		return
	}
	s.logDebug("controlServer: binding to port %d...", s.ctrlPort)
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.ctrlPort), tlsCfg)
	if err != nil {
		log.Printf("control listen err: %v", err)
		return
	}
	log.Printf("control TLS listening on :%d", s.ctrlPort)

	for s.running.Load() {
		conn, err := ln.Accept()
		if err != nil {
			if s.running.Load() {
				log.Printf("control accept err: %v", err)
			}
			continue
		}
		s.logDebug("controlServer: accepted connection from %s", conn.RemoteAddr())
		go s.handleControl(conn)
	}
}

func (s *Server) handleControl(conn net.Conn) {
	defer conn.Close()
	s.logDebug("handleControl: starting TLS handshake with %s", conn.RemoteAddr())
	peer := conn.(*tls.Conn)
	if err := peer.Handshake(); err != nil {
		s.logDebug("handleControl: TLS handshake failed: %v", err)
		return
	}
	state := peer.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		s.logDebug("handleControl: no peer certificates provided")
		return
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	s.logDebug("handleControl: TLS handshake successful, client CN=%s", cn)

	reqData, err := io.ReadAll(peer)
	if err != nil {
		s.logDebug("handleControl: failed to read request: %v", err)
		return
	}
	if len(bytes.TrimSpace(reqData)) == 0 {
		// A client may connect and complete the TLS handshake as a
		// connectivity probe, then close without sending a request.
		return
	}
	var req common.ControlRequest
	if err := req.Unmarshal(reqData); err != nil {
		s.logDebug("handleControl: failed to unmarshal request: %v", err)
		return
	}
	if req.ClientName == "" {
		req.ClientName = cn
	}
	s.logDebug("handleControl: received session request from client '%s'", req.ClientName)

	sessID := uint32(time.Now().UnixNano())
	var clientIP, clientIPv6 net.IP

	var replaced *serverSession
	s.sessMu.Lock()
	if old, ok := s.clientSessions[req.ClientName]; ok {
		clientIP = old.clientIP
		clientIPv6 = old.clientIPv6
		s.logDebug("handleControl: replacing existing session (old_id=%d, reusing_ips=%s/%s)", old.id, clientIP, clientIPv6)
		delete(s.sessions, old.id)
		delete(s.clientSessions, req.ClientName)
		if old.clientIP != nil {
			delete(s.ipToSession, old.clientIP.String())
		}
		if old.clientIPv6 != nil {
			delete(s.ipToSession, old.clientIPv6.String())
		}
		replaced = old
		log.Printf("Replaced session for %s (old_id=%d) reusing IP=%s", req.ClientName, old.id, clientIP)
	} else {
		clientIP, clientIPv6 = s.assignClientIPs()
		s.logDebug("handleControl: assigned new IPs for client (v4=%s, v6=%s)", clientIP, clientIPv6)
	}
	s.sessMu.Unlock()
	if replaced != nil {
		replaced.Close()
	}

	sess := newServerSession(sessID, req.ClientName, clientIP, clientIPv6, s.reorderSize, s.reorderFlush)
	s.registerSession(sess)

	go s.reorderFlushHandler(sess)

	resp := common.ControlResponse{
		SessionID:  sessID,
		DataPort:   s.port,
		ClientIP:   clientIP.String(),
		ClientIPv6: clientIPv6.String(),
	}
	b, _ := resp.Marshal()
	_, _ = peer.Write(b)
	log.Printf("New session: %s (id=%d) ip=%s", req.ClientName, sessID, clientIP)
}

func (s *Server) assignClientIPs() (net.IP, net.IP) {
	n := s.nextIPOctet.Add(1)
	if n < 2 || n > 250 {
		s.nextIPOctet.Store(2)
		n = 2
	}
	v4 := net.IPv4(10, 8, 0, byte(n))
	v6 := net.ParseIP(fmt.Sprintf("%s%d", clientIPv6Prefix, byte(n)))
	return v4, v6
}

// ============================================================================
// Housekeeping
// ============================================================================

func (s *Server) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for s.running.Load() {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.pruneSessions()
		}
	}
}

func (s *Server) pruneSessions() {
	s.sessMu.Lock()
	var closing []*serverSession
	for id, sess := range s.sessions {
		if !sess.isIdle() {
			sess.pruneStaleConns()
			continue
		}
		log.Printf("Session idle/expired: %s (id=%d) IP=%s", sess.name, id, sess.clientIP)
		closing = append(closing, sess)
		delete(s.sessions, id)
		if sess.name != "" {
			delete(s.clientSessions, sess.name)
		}
		if sess.clientIP != nil {
			delete(s.ipToSession, sess.clientIP.String())
		}
		if sess.clientIPv6 != nil {
			delete(s.ipToSession, sess.clientIPv6.String())
		}
	}
	s.sessMu.Unlock()
	for _, sess := range closing {
		sess.Close()
	}
}

func (s *Server) reorderFlushHandler(sess *serverSession) {
	for {
		select {
		case <-sess.stopReorder:
			return
		case <-sess.reorderBuf.FlushCh():
			for _, pkt := range sess.reorderBuf.FlushTimeout() {
				select {
				case s.tunWriteCh <- pkt:
				default:
					common.PutBuffer(pkt)
				}
			}
		}
	}
}
