//go:build linux
// +build linux

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"

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

	tun     *water.Interface
	udpConn *net.UDPConn

	tunWriteCh chan []byte
	outboundCh chan *outboundJob // packets from TUN to be sent to clients

	wg      sync.WaitGroup
	running atomic.Bool
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
	// Snapshot sessions under read lock.
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

func NewServer(port, ctrlPort int, iface string, pki common.PKIPaths, verbose bool) *Server {
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
	}
}

func (s *Server) logDebug(format string, v ...interface{}) {
	if s.verbose {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (s *Server) Start() error {
	s.running.Store(true)

	// Setup TUN
	conf := water.Config{DeviceType: water.TUN}
	if s.ifaceName != "" {
		conf.Name = s.ifaceName
	}
	tun, err := water.New(conf)
	if err != nil {
		return fmt.Errorf("create tun: %v", err)
	}
	s.tun = tun
	log.Printf("TUN initialized: %s", tun.Name())

	if err := common.ConfigureTUN(common.TUNConfig{IfaceName: tun.Name(), CIDR: serverIPv4CIDR, IPv6CIDR: serverIPv6CIDR, MTU: common.MTU}); err != nil {
		return fmt.Errorf("configure tun: %v", err)
	}
	_ = ensureNatRule()
	_ = ensureNatRule6()
	_ = ensureForwardRules(tun.Name())
	_ = ensureForwardRules6(tun.Name())
	enableForwarding()

	// Setup UDP
	udpAddr := &net.UDPAddr{Port: s.port}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %v", err)
	}
	s.udpConn = udpConn
	log.Printf("UDP listening on :%d", s.port)

	// Start Control Plane
	go s.controlServer()

	// Start Workers
	// 1. TUN Writer (Single Consumer to ensure thread safety on TUN write)
	s.wg.Add(1)
	go s.tunWriteLoop()

	// 2. TUN Reader (Single Producer)
	s.wg.Add(1)
	go s.tunReadLoop()

	// 3. UDP Readers (Multiple Consumers)
	numReaders := runtime.NumCPU()
	for i := 0; i < numReaders; i++ {
		s.wg.Add(1)
		go s.udpReadLoop(i)
	}

	// 4. Outbound Processors (TUN -> UDP encryption/compression workers)
	for i := 0; i < numReaders; i++ {
		s.wg.Add(1)
		go s.outboundWorker()
	}

	// 5. Cleanup Loop
	s.wg.Add(1)
	go s.cleanupLoop()

	return nil
}

func (s *Server) tunWriteLoop() {
	defer s.wg.Done()
	for data := range s.tunWriteCh {
		s.logDebug("TUN write: %d bytes", len(data))
		if _, err := s.tun.Write(data); err != nil {
			log.Printf("tun write error: %v", err)
		}
		// Data buffer came from common.Pool via udpReadLoop -> handlePacket
		common.PutBuffer(data)
	}
}

func (s *Server) tunReadLoop() {
	defer s.wg.Done()
	defer close(s.outboundCh)

	// Need a separate buffer allocation strategy for TUN reads.
	// Since we pass these to outboundCh, we can use the pool.
	for s.running.Load() {
		buf := common.GetBuffer()
		// We read standard MTU size.
		// Note: buf is MaxPacketSize + HeaderSize (~1522). TUN MTU is 1400. Safe.
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
			case s.outboundCh <- &outboundJob{sess: sess, data: buf[:n]}: // Pass slice but backed by pool array
				// ok
			default:
				// Drop if channel full
				common.PutBuffer(buf)
			}
		} else {
			// Unknown destination, drop
			common.PutBuffer(buf)
		}
	}
}

func (s *Server) outboundWorker() {
	defer s.wg.Done()
	for job := range s.outboundCh {
		// Phase 2: flow-based scheduling for server->client.
		// Keep packets of the same flow on the same conn to avoid TCP collapse due to reordering.
		chosen := job.sess.pickConnForIPPacket(job.data)
		if chosen != nil {
			s.logDebug("UDP send: %d bytes to %s", len(job.data), chosen.addr)
			job.sess.touch()
			_ = job.sess.encryptAndSend(chosen, common.PacketIP, job.data, true)
		}
		// Return the READ buffer to pool
		// (Note: job.data is a slice of the buffer from GetBuffer)
		common.PutBuffer(job.data)
	}
}

func (s *Server) udpReadLoop(id int) {
	defer s.wg.Done()
	for s.running.Load() {
		buf := common.GetBuffer()
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if s.running.Load() {
				log.Printf("udp read error: %v", err)
			}
			common.PutBuffer(buf) // return on error
			continue
		}

		packet := buf[:n]
		var hdr common.PacketHeader
		if err := hdr.Unmarshal(packet); err != nil {
			// Malformed
			common.PutBuffer(buf)
			continue
		}

		sess := s.getSession(hdr.SessionID)
		if sess == nil {
			common.PutBuffer(buf)
			continue
		}

		// Use a separate buffer for plaintext to avoid allocation
		payloadBuf := common.GetBuffer()
		h, payload, err := common.DecryptPacketInto(payloadBuf, sess.key, packet)
		if err != nil {
			log.Printf("decrypt error from %s: %v", addr, err)
			common.PutBuffer(payloadBuf)
			common.PutBuffer(buf)
			continue
		}

		s.handlePacket(sess, addr, h, payload, payloadBuf)

		// Input buffer is processed, return it
		common.PutBuffer(buf)
	}
}

// handlePacket processes the decrypted payload.
// It takes ownership of payloadBuf (which backs payload).
func (s *Server) handlePacket(sess *serverSession, addr *net.UDPAddr, h common.PacketHeader, payload []byte, payloadBuf []byte) {
	// Ensure we return the buffer if we don't pass it to tunWriteCh
	// We use a flag to track ownership transfer
	defer common.PutBuffer(payloadBuf)

	sess.touch()

	// Update connection state
	// Optimization: Only lock if we need to update?
	// updateOrAddConn locks internally.
	conn := sess.updateOrAddConn(s.udpConn, addr)

	conn.bytesRecv.Add(uint64(len(payload)))

	switch h.Type {
	case common.PacketHandshake:
		// Keep-alive
	case common.PacketHeartbeat:
		var hb common.HeartbeatPayload
		if err := hb.Unmarshal(payload); err == nil {
			rtt := common.CalcRTT(hb.SendTime)
			updateServerConnRTT(conn, rtt)
			s.logDebug("Heartbeat from %s (rtt=%v jitter=%v)", addr, rtt, time.Duration(conn.jitterNano.Load()))
		}
		// Echo back immediately (using session write)
		// Payload is small, we can just send it back.
		// We use sess.encryptAndSend which allocates new packet.
		if err := sess.encryptAndSend(conn, common.PacketHeartbeat, payload, false); err != nil {
			log.Printf("Debug: failed to echo heartbeat to %s: %v", addr, err)
		}
	case common.PacketIP:
		s.logDebug("IP packet from %s len=%d seq=%d", addr, len(payload), h.SeqNum)

		// Handle decompression.
		// NOTE: common.DecompressPayload currently allocates; we immediately copy into a pool buffer below.
		data := payload
		if len(h.Reserved) > 0 && h.Reserved[0] == common.CompressionGzip {
			outBuf := common.GetBuffer()
			dec, err := common.DecompressPayloadInto(outBuf, payload, common.MaxPacketSize)
			if err != nil {
				common.PutBuffer(outBuf)
				log.Printf("decompress error: %v", err)
				return
			}
			data = dec
			// outBuf now backs dec; we'll copy it into reorderBuf pool buffer below and then return outBuf.
			defer common.PutBuffer(outBuf)
		}
		if !isIPPacket(data) {
			s.logDebug("drop non-ip packet len=%d", len(data))
			return
		}

		// Prepare pool buffer for reorder buffer (avoid heap alloc)
		buf := common.GetBuffer()
		if len(data) > cap(buf) {
			common.PutBuffer(buf)
			sess.reorderStats.packetsDropped.Add(1)
			return
		}
		copy(buf, data)
		bufferData := buf[:len(data)]
		// Note: if data was heap-allocated by DecompressPayload, it becomes eligible for GC after this point.

		// Insert into reorder buffer. Ownership of bufferData transfers to reorderBuf
		// unless Insert returns it immediately.
		orderedPackets := sess.reorderBuf.Insert(h.SeqNum, bufferData)

		// Track reordering stats
		bufDepth := uint32(len(sess.reorderBuf.packets))
		if bufDepth > 0 {
			sess.reorderStats.packetsReordered.Add(1)
			if current := sess.reorderStats.maxBufferDepth.Load(); bufDepth > current {
				sess.reorderStats.maxBufferDepth.Store(bufDepth)
			}
		}

		// Send ordered packets to TUN (packets are pool-backed)
		for _, pkt := range orderedPackets {
			select {
			case s.tunWriteCh <- pkt:
				// tunWriteCh owns pkt and will PutBuffer
			default:
				common.PutBuffer(pkt)
				sess.reorderStats.packetsDropped.Add(1)
			}
		}
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

func isIPPacket(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	ver := pkt[0] >> 4
	switch ver {
	case 4:
		return len(pkt) >= 20
	case 6:
		return len(pkt) >= 40
	default:
		return false
	}
}

// Control server logic
func (s *Server) controlServer() {
	tlsCfg, err := common.ServerTLSConfig(s.pki)
	if err != nil {
		log.Printf("control tls config err: %v", err)
		return
	}
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
		go s.handleControl(conn)
	}
}

func (s *Server) handleControl(conn net.Conn) {
	defer conn.Close()
	peer := conn.(*tls.Conn)
	if err := peer.Handshake(); err != nil {
		return
	}
	state := peer.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}
	cn := state.PeerCertificates[0].Subject.CommonName

	reqData, err := io.ReadAll(peer)
	if err != nil {
		return
	}
	var req common.ControlRequest
	if err := req.Unmarshal(reqData); err != nil {
		return
	}
	if req.ClientName == "" {
		req.ClientName = cn
	}

	sessID := uint32(time.Now().UnixNano())
	key, err := common.GenerateSessionKey()
	if err != nil {
		return
	}

	var clientIP, clientIPv6 net.IP

	s.sessMu.Lock()
	if old, ok := s.clientSessions[req.ClientName]; ok {
		clientIP = old.clientIP
		clientIPv6 = old.clientIPv6
		// Delete old session to prevent ghosts
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
	}
	s.sessMu.Unlock()

	sess := newServerSession(sessID, req.ClientName, key, clientIP, clientIPv6)
	s.registerSession(sess)

	// Start reorder buffer flush handler for this session
	go s.reorderFlushHandler(sess)

	resp := common.ControlResponse{
		SessionID:  sessID,
		SessionKey: common.EncodeKeyBase64(key),
		UDPPort:    s.port,
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
		// Wrap to the first usable host (.2) and reset counter.
		s.nextIPOctet.Store(2)
		n = 2
	}
	v4 := net.IPv4(10, 8, 0, byte(n))
	v6 := net.ParseIP(fmt.Sprintf("%s%d", clientIPv6Prefix, byte(n)))
	return v4, v6
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for s.running.Load() {
		select {
		case <-ticker.C:
			s.pruneSessions()
		}
	}
}

func (s *Server) pruneSessions() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	for id, sess := range s.sessions {
		if sess.isIdle() {
			log.Printf("Session idle/expired: %s (id=%d) IP=%s", sess.name, id, sess.clientIP)
			sess.Close() // Cleanup reorder buffer
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
			sess.pruneStaleConns()
		}
	}
}

// reorderFlushHandler handles timeout-based flushing for reorder buffer
func (s *Server) reorderFlushHandler(sess *serverSession) {
	for {
		select {
		case <-sess.stopReorder:
			return
		case <-sess.reorderBuf.flushCh:
			// Timeout occurred, flush buffered packets
			flushedPackets := sess.reorderBuf.FlushTimeout()
			for _, pkt := range flushedPackets {
				select {
				case s.tunWriteCh <- pkt:
					// tunWriteCh owns pkt and will PutBuffer
				default:
					common.PutBuffer(pkt)
					sess.reorderStats.packetsDropped.Add(1)
				}
			}
		}
	}
}

// Helper functions (moved from main.go)

func ensureNatRule() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return err
	}
	if exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE").Run() == nil {
		return nil
	}
	return exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE").Run()
}

func ensureNatRule6() error {
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return err
	}
	if exec.Command("ip6tables", "-t", "nat", "-C", "POSTROUTING", "-s", "fd00:8:0::/64", "-j", "MASQUERADE").Run() == nil {
		return nil
	}
	return exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", "fd00:8:0::/64", "-j", "MASQUERADE").Run()
}

func ensureForwardRules(iface string) error {
	if iface == "" {
		return nil
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return err
	}
	rules := [][]string{
		{"FORWARD", "-i", iface, "-j", "ACCEPT"},
		{"FORWARD", "-o", iface, "-j", "ACCEPT"},
	}
	for _, rule := range rules {
		_ = exec.Command("iptables", append([]string{"-D"}, rule...)...).Run()
		add := append([]string{"-I", "FORWARD", "1"}, rule[1:]...)
		if err := exec.Command("iptables", add...).Run(); err != nil {
			return err
		}
	}
	return nil
}

func ensureForwardRules6(iface string) error {
	if iface == "" {
		return nil
	}
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return err
	}
	rules := [][]string{
		{"FORWARD", "-i", iface, "-j", "ACCEPT"},
		{"FORWARD", "-o", iface, "-j", "ACCEPT"},
	}
	for _, rule := range rules {
		_ = exec.Command("ip6tables", append([]string{"-D"}, rule...)...).Run()
		add := append([]string{"-I", "FORWARD", "1"}, rule[1:]...)
		if err := exec.Command("ip6tables", add...).Run(); err != nil {
			return err
		}
	}
	return nil
}

func enableForwarding() {
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()
}
