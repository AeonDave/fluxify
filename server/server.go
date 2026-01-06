//go:build linux
// +build linux

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"

	quic "github.com/AeonDave/mp-quic-go"

	"fluxify/common"
)

const (
	serverIPv4CIDR   = "10.8.0.1/24"
	serverIPv6CIDR   = "fd00:8:0::1/64"
	clientIPv6Prefix = "fd00:8:0::"
)

type Server struct {
	port      int
	ctrlPort  int
	ifaceName string
	pki       common.PKIPaths
	verbose   bool

	sessions       map[uint32]*serverSession
	ipToSession    map[string]*serverSession // Map "10.8.0.x" or "fd00::x" -> Session
	clientSessions map[string]*serverSession // Map "clientName" -> Session
	sessMu         sync.RWMutex

	nextIPOctet atomic.Uint32

	tun      *water.Interface
	listener *quic.Listener

	tunWriteCh chan []byte
	outboundCh chan *outboundJob // packets from TUN to be sent to clients

	wg      sync.WaitGroup
	running atomic.Bool

	reorderSize  int
	reorderFlush time.Duration

	mssClamp mssClampConfig
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

type outboundJob struct {
	sess *serverSession
	data []byte
}

func NewServer(port, ctrlPort int, iface string, pki common.PKIPaths, verbose bool, rsize int, rflush time.Duration) *Server {
	return &Server{
		port:           port,
		ctrlPort:       ctrlPort,
		ifaceName:      iface,
		pki:            pki,
		verbose:        verbose,
		sessions:       make(map[uint32]*serverSession),
		ipToSession:    make(map[string]*serverSession),
		clientSessions: make(map[string]*serverSession),
		tunWriteCh:     make(chan []byte, 512),
		outboundCh:     make(chan *outboundJob, 512),
		reorderSize:    rsize,
		reorderFlush:   rflush,
	}
}

func (s *Server) logDebug(format string, v ...interface{}) {
	if s.verbose {
		log.Printf("[DEBUG] "+format, v...)
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
	s.logDebug("TUN: device %s created successfully", tun.Name())

	s.logDebug("TUN: configuring IP addresses (v4=%s, v6=%s, MTU=%d)", serverIPv4CIDR, serverIPv6CIDR, common.MTU)
	if err := common.ConfigureTUN(common.TUNConfig{IfaceName: tun.Name(), CIDR: serverIPv4CIDR, IPv6CIDR: serverIPv6CIDR, MTU: common.MTU}); err != nil {
		return fmt.Errorf("configure tun: %v", err)
	}
	// Best-effort: networking rules. These operations require root.
	s.logDebug("iptables: configuring forwarding and NAT rules...")
	if err := enableForwarding(execRunner{}); err != nil {
		log.Printf("enable forwarding: %v", err)
	} else {
		s.logDebug("iptables: IP forwarding enabled")
	}
	if err := ensureNatRule(execRunner{}); err != nil {
		log.Printf("ensure nat v4: %v", err)
	} else {
		s.logDebug("iptables: IPv4 NAT rule configured")
	}
	if err := ensureNatRule6(execRunner{}); err != nil {
		log.Printf("ensure nat v6: %v", err)
	} else {
		s.logDebug("iptables: IPv6 NAT rule configured")
	}
	if err := ensureForwardRules(execRunner{}, tun.Name()); err != nil {
		log.Printf("ensure forward v4: %v", err)
	} else {
		s.logDebug("iptables: IPv4 forward rules configured for %s", tun.Name())
	}
	if err := ensureForwardRules6(execRunner{}, tun.Name()); err != nil {
		log.Printf("ensure forward v6: %v", err)
	} else {
		s.logDebug("iptables: IPv6 forward rules configured for %s", tun.Name())
	}
	if err := ensureMSSClampRules(execRunner{}, tun.Name(), s.mssClamp); err != nil {
		log.Printf("mss clamp: %v", err)
	} else {
		s.logDebug("iptables: MSS clamp rules configured")
	}

	// Setup QUIC (multipath-capable)
	s.logDebug("QUIC: loading TLS config from PKI (dir=%s)", s.pki.Dir)
	tlsCfg, err := common.ServerTLSConfig(s.pki)
	if err != nil {
		return fmt.Errorf("quic tls config: %v", err)
	}
	s.logDebug("QUIC: TLS config loaded (NextProtos=[fluxify-quic])")
	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"fluxify-quic"}

	s.logDebug("QUIC: creating multipath config (MaxPaths=5, AutoPaths=true, Scheduler=LowLatency)")
	qc := &quic.Config{
		EnableDatagrams: true,
		MaxPaths:        5,
		MultipathController: quic.NewDefaultMultipathController(
			quic.NewLowLatencyScheduler(),
		),
		MultipathAutoPaths:     true,
		MultipathAutoAdvertise: true,
	}

	s.logDebug("QUIC: binding to port %d...", s.port)
	ln, err := quic.ListenAddr(fmt.Sprintf(":%d", s.port), tlsCfg, qc)
	if err != nil {
		return fmt.Errorf("listen quic: %v", err)
	}
	s.listener = ln
	log.Printf("QUIC listening on :%d", s.port)
	s.logDebug("QUIC: listener initialized successfully")

	s.logDebug("Starting control server goroutine...")
	go s.controlServer()

	s.logDebug("Starting TUN write loop...")
	s.wg.Add(1)
	go s.tunWriteLoop()

	s.logDebug("Starting TUN read loop...")
	s.wg.Add(1)
	go s.tunReadLoop()

	numReaders := runtime.NumCPU()
	s.logDebug("Starting QUIC accept loop with %d reader workers...", numReaders)
	s.wg.Add(1)
	go s.acceptLoop(numReaders)

	s.logDebug("Starting %d outbound workers...", numReaders)
	for i := 0; i < numReaders; i++ {
		s.wg.Add(1)
		go s.outboundWorker()
	}

	s.logDebug("Starting session cleanup loop...")
	s.wg.Add(1)
	go s.cleanupLoop()

	s.logDebug("Server startup complete")
	return nil
}

func (s *Server) acceptLoop(numReaders int) {
	defer s.wg.Done()
	s.logDebug("acceptLoop: started")
	for s.running.Load() {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			if s.running.Load() {
				log.Printf("quic accept error: %v", err)
			}
			return
		}
		s.logDebug("acceptLoop: new QUIC connection from %s, starting %d readers", conn.RemoteAddr(), numReaders)
		for i := 0; i < numReaders; i++ {
			s.wg.Add(1)
			go s.quicReadLoop(conn)
		}
	}
	s.logDebug("acceptLoop: stopped")
}

func (s *Server) quicReadLoop(conn *quic.Conn) {
	defer s.wg.Done()
	for s.running.Load() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		dat, err := conn.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			continue
		}
		h, payload, err := common.ParseDataPlaneDatagram(dat)
		if err != nil {
			s.logDebug("quicReadLoop: failed to parse datagram: %v", err)
			continue
		}
		sess := s.getSession(h.SessionID)
		if sess == nil {
			s.logDebug("quicReadLoop: unknown session ID: %d", h.SessionID)
			continue
		}
		s.logDebug("quicReadLoop: received %s datagram (session=%d, seq=%d, len=%d)", h.Type, h.SessionID, h.SeqNum, len(payload))
		s.handleDatagram(conn, sess, h, payload)
	}
}

func (s *Server) handleDatagram(conn *quic.Conn, sess *serverSession, h common.DataPlaneHeader, payload []byte) {
	sess.touch()

	sc := sess.updateOrAddConn(conn)
	sc.bytesRecv.Add(uint64(len(payload)))

	switch h.Type {
	case common.DPTypeHandshake:
		// keep-alive
	case common.DPTypeHeartbeat:
		var hb common.HeartbeatPayload
		if err := hb.Unmarshal(payload); err == nil {
			rtt := common.CalcRTT(hb.SendTime)
			updateServerConnRTT(sc, rtt)
			s.logDebug("handleDatagram: heartbeat from session %d, RTT=%v", sess.id, rtt)
		}
		// echo back
		head := common.DataPlaneHeader{Version: common.DataPlaneVersion, Type: common.DPTypeHeartbeat, SessionID: sess.id, SeqNum: 0, Flags: 0}
		dg, _ := common.BuildDataPlaneDatagram(nil, head, payload)
		_ = conn.SendDatagram(dg)
	case common.DPTypeIP:
		data := payload
		if (h.Flags & common.DPFlagCompression) != 0 {
			s.logDebug("handleDatagram: decompressing packet (compressed_size=%d)", len(payload))
			outBuf := common.GetBuffer()
			dec, err := common.DecompressPayloadInto(outBuf, payload, common.MaxPacketSize)
			if err != nil {
				common.PutBuffer(outBuf)
				return
			}
			data = dec
			// Copy into pooled buffer for reorder buffer storage
			storageBuf := common.GetBuffer()
			copy(storageBuf, data)
			common.PutBuffer(outBuf)
			ordered := sess.reorderBuf.Insert(h.SeqNum, storageBuf[:len(data)])
			for _, pkt := range ordered {
				select {
				case s.tunWriteCh <- pkt:
				default:
					common.PutBuffer(pkt)
				}
			}
			return
		}
		if !common.IsIPPacket(data) {
			return
		}
		storageBuf := common.GetBuffer()
		copy(storageBuf, data)
		ordered := sess.reorderBuf.Insert(h.SeqNum, storageBuf[:len(data)])
		for _, pkt := range ordered {
			select {
			case s.tunWriteCh <- pkt:
			default:
				common.PutBuffer(pkt)
			}
		}
	}
}

func (s *Server) tunWriteLoop() {
	defer s.wg.Done()
	for data := range s.tunWriteCh {
		s.logDebug("TUN write: %d bytes", len(data))
		if _, err := s.tun.Write(data); err != nil {
			log.Printf("tun write error: %v", err)
		}
		common.PutBuffer(data)
	}
}

func (s *Server) tunReadLoop() {
	defer s.wg.Done()
	defer close(s.outboundCh)

	for s.running.Load() {
		buf := common.GetBuffer()
		n, err := s.tun.Read(buf)
		if err != nil {
			if s.running.Load() {
				log.Printf("tun read error: %v", err)
			}
			common.PutBuffer(buf)
			continue
		}

		pkt := buf[:n]
		dstIP := extractDstIP(pkt)
		s.logDebug("TUN read: %d bytes dest=%s", n, dstIP)
		if len(dstIP) == 0 {
			common.PutBuffer(buf)
			continue
		}

		sess := s.lookupSessionByIP(dstIP)
		if sess != nil {
			select {
			case s.outboundCh <- &outboundJob{sess: sess, data: buf[:n]}:
			default:
				common.PutBuffer(buf)
			}
		} else {
			common.PutBuffer(buf)
		}
	}
}

func (s *Server) outboundWorker() {
	defer s.wg.Done()
	for job := range s.outboundCh {
		chosen := job.sess.pickBestConn()
		if chosen != nil {
			s.logDebug("QUIC send: %d bytes", len(job.data))
			job.sess.touch()
			_ = job.sess.sendDatagram(chosen, common.DPTypeIP, job.data, true)
		}
		common.PutBuffer(job.data)
	}
}

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
	s.logDebug("controlServer: ready to accept connections")

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
	s.logDebug("controlServer: stopped")
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
		log.Printf("Replaced session for %s (old_id=%d) reusing IP=%s", req.ClientName, old.id, clientIP)
	} else {
		clientIP, clientIPv6 = s.assignClientIPs()
		s.logDebug("handleControl: assigned new IPs for client (v4=%s, v6=%s)", clientIP, clientIPv6)
	}
	s.sessMu.Unlock()

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

func (s *Server) cleanupLoop() {
	defer s.wg.Done()
	s.logDebug("cleanupLoop: started (interval=10s)")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for s.running.Load() {
		select {
		case <-ticker.C:
			s.pruneSessions()
		}
	}
	s.logDebug("cleanupLoop: stopped")
}

func (s *Server) pruneSessions() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	var pruned, active int
	for id, sess := range s.sessions {
		if sess.isIdle() {
			pruned++
			log.Printf("Session idle/expired: %s (id=%d) IP=%s", sess.name, id, sess.clientIP)
			s.logDebug("pruneSessions: removing idle session %d (client=%s)", id, sess.name)
			sess.Close()
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
		} else {
			active++
			sess.pruneStaleConns()
		}
	}
	if pruned > 0 || active > 0 {
		s.logDebug("pruneSessions: checked %d sessions (active=%d, pruned=%d)", len(s.sessions)+pruned, active, pruned)
	}
}

func (s *Server) reorderFlushHandler(sess *serverSession) {
	for {
		select {
		case <-sess.stopReorder:
			return
		case <-sess.reorderBuf.FlushCh():
			pkts := sess.reorderBuf.FlushTimeout()
			for _, pkt := range pkts {
				select {
				case s.tunWriteCh <- pkt:
				default:
					common.PutBuffer(pkt)
					sess.reorderStats.packetsDropped.Add(1)
				}
			}
		}
	}
}
