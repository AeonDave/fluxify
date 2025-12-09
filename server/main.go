package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"

	"fluxify/common"
)

type serverConn struct {
	udp       *net.UDPConn
	addr      *net.UDPAddr
	alive     atomic.Bool
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	lastRTT   atomic.Int64 // nanos
}

type serverSession struct {
	id          uint32
	conns       []*serverConn
	connMu      sync.RWMutex
	clientIP    net.IP // 10.8.0.X assigned
	key         []byte
	nextSeqSend atomic.Uint32
}

type serverState struct {
	sessions    map[uint32]*serverSession
	sessMu      sync.RWMutex
	nextIPOctet atomic.Uint32
	tun         *water.Interface
	udpPort     int
	pki         common.PKIPaths
}

func (s *serverState) getSession(id uint32) *serverSession {
	s.sessMu.RLock()
	sess := s.sessions[id]
	s.sessMu.RUnlock()
	return sess
}

func (s *serverState) assignClientIP() net.IP {
	// start at 10.8.0.2 and increment last octet
	n := s.nextIPOctet.Add(1)
	if n < 2 {
		n = 2
	}
	if n > 250 {
		n = 2
	}
	return net.IPv4(10, 8, 0, byte(n))
}

func main() {
	port := flag.Int("port", 8000, "UDP data port")
	ctrlPort := flag.Int("ctrl", 8443, "TLS control port")
	ifaceName := flag.String("iface", "", "TUN interface name (optional)")
	pkiDir := flag.String("pki", "./pki", "PKI directory")
	tuiMode := flag.Bool("tui", false, "run server with TUI for cert management")
	regen := flag.Bool("regen", false, "regenerate CA/server certs on start")
	hosts := flag.String("hosts", "127.0.0.1,localhost", "comma-separated SANs for server cert")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Println("Run as root for TUN/NAT setup")
	}

	pki := common.DefaultPKI(*pkiDir)
	hostList := splitCSV(*hosts)
	if len(hostList) == 0 {
		hostList = []string{"127.0.0.1", "localhost"}
	}
	if err := common.EnsureBasePKI(pki, hostList, *regen); err != nil {
		log.Fatalf("pki init error: %v", err)
	}

	if *tuiMode {
		runServerTUI(pki, hostList, *port, *ctrlPort, *ifaceName)
		return
	}

	if err := runServer(*port, *ctrlPort, *ifaceName, pki); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func runServer(port int, ctrlPort int, ifaceName string, pki common.PKIPaths) error {
	state := &serverState{sessions: make(map[uint32]*serverSession), udpPort: port, pki: pki}

	conf := water.Config{DeviceType: water.TUN}
	if ifaceName != "" {
		conf.Name = ifaceName
	}
	tun, err := water.New(conf)
	if err != nil {
		return err
	}
	state.tun = tun
	log.Printf("TUN up: %s", tun.Name())

	if err := common.ConfigureTUN(common.TUNConfig{IfaceName: tun.Name(), CIDR: "10.8.0.1/24", MTU: common.MTU}); err != nil {
		return err
	}
	_ = ensureNatRule()

	udpAddr := &net.UDPAddr{Port: port}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer func(udpConn *net.UDPConn) {
		_ = udpConn.Close()
	}(udpConn)
	log.Printf("UDP listening on :%d", port)

	go state.tunToClients()
	go state.controlServer(ctrlPort)

	buf := make([]byte, common.HeaderSize+common.MaxPacketSize)
	for {
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("udp read err: %v", err)
			continue
		}
		packet := buf[:n]
		var hdr common.PacketHeader
		if err := hdr.Unmarshal(packet[:common.HeaderSize]); err != nil {
			log.Printf("hdr parse err: %v", err)
			continue
		}
		sess := state.getSession(hdr.SessionID)
		if sess == nil {
			log.Printf("unknown session %d", hdr.SessionID)
			continue
		}
		h, payload, err := common.DecryptPacket(sess.key, packet)
		if err != nil {
			log.Printf("decrypt err: %v", err)
			continue
		}
		state.handlePacket(sess, udpConn, addr, h, payload)
	}
}

func (s *serverState) handlePacket(sess *serverSession, udp *net.UDPConn, addr *net.UDPAddr, h common.PacketHeader, payload []byte) {
	sess.connMu.Lock()
	var sc *serverConn
	for _, c := range sess.conns {
		if c.addr.String() == addr.String() {
			sc = c
			break
		}
	}
	if sc == nil {
		sc = &serverConn{udp: udp, addr: addr}
		sc.alive.Store(true)
		sess.conns = append(sess.conns, sc)
	}
	sess.connMu.Unlock()

	// Debug: log incoming packet metadata
	log.Printf("udp recv from %s type=%d session=%d len=%d", addr.String(), h.Type, h.SessionID, len(payload))

	sc.bytesRecv.Add(uint64(len(payload)))

	switch h.Type {
	case common.PacketHandshake:
		// nothing else, keep-alive
	case common.PacketHeartbeat:
		var hb common.HeartbeatPayload
		if err := hb.Unmarshal(payload); err == nil {
			sc.lastRTT.Store(int64(common.CalcRTT(hb.SendTime)))
		}
		// echo back
		s.sendPacket(sess, sc, common.PacketHeartbeat, h.SessionID, h.SeqNum, payload)
	case common.PacketIP:
		pay := payload
		if h.Reserved[0] == common.CompressionGzip {
			if dec, err := common.DecompressPayload(payload, common.MaxPacketSize); err == nil {
				pay = dec
			} else {
				log.Printf("decompress err: %v", err)
				return
			}
		}
		// write to TUN
		_, _ = s.tun.Write(pay)
		// optional reorder could be added here
	}
}

func (s *serverState) sendPacket(sess *serverSession, sc *serverConn, ptype uint8, sessionID uint32, seq uint32, payload []byte) {
	head := common.PacketHeader{
		Version:   common.ProtoVersion,
		Type:      ptype,
		SessionID: sessionID,
		SeqNum:    seq,
		Length:    uint16(len(payload)),
	}
	pkt, err := common.EncryptPacket(sess.key, head, payload)
	if err != nil {
		return
	}
	// Debug: log outgoing packet
	log.Printf("sendPacket to %s type=%d session=%d len=%d", sc.addr.String(), ptype, sessionID, len(payload))
	_, _ = sc.udp.WriteToUDP(pkt, sc.addr)
	sc.bytesSent.Add(uint64(len(payload)))
}

func (s *serverState) tunToClients() {
	buf := make([]byte, common.MTU+100)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			log.Printf("tun read err: %v", err)
			continue
		}
		pkt := buf[:n]
		dstIP := net.IP(pkt[16:20])
		// map to session by IP
		s.sessMu.RLock()
		for _, sess := range s.sessions {
			if sess.clientIP.Equal(dstIP) {
				s.sendToSession(sess, pkt)
			}
		}
		s.sessMu.RUnlock()
	}
}

func (s *serverState) sendToSession(sess *serverSession, data []byte) {
	sess.connMu.RLock()
	defer sess.connMu.RUnlock()
	if len(sess.conns) == 0 {
		return
	}
	// pick best alive (lowest RTT, fallback round-robin)
	var best *serverConn
	bestRTT := time.Duration(1<<63 - 1)
	for _, c := range sess.conns {
		if !c.alive.Load() {
			continue
		}
		rtt := time.Duration(c.lastRTT.Load())
		if rtt == 0 {
			rtt = 500 * time.Millisecond
		}
		if rtt < bestRTT {
			bestRTT = rtt
			best = c
		}
	}
	if best == nil {
		// fallback first
		best = sess.conns[0]
	}
	seq := sess.nextSeqSend.Add(1)
	compressed := data
	compressFlag := common.CompressionNone
	if comp, err := common.CompressPayload(data); err == nil {
		if len(comp) < len(data) {
			compressed = comp
			compressFlag = common.CompressionGzip
		}
	}
	head := common.PacketHeader{
		Version:   common.ProtoVersion,
		Type:      common.PacketIP,
		SessionID: sess.id,
		SeqNum:    seq,
		Length:    uint16(len(compressed)),
	}
	head.Reserved[0] = byte(compressFlag)
	pkt, err := common.EncryptPacket(sess.key, head, compressed)
	if err != nil {
		return
	}
	_, _ = best.udp.WriteToUDP(pkt, best.addr)
	best.bytesSent.Add(uint64(len(data)))
}

// controlServer handles TLS control plane to issue session key/ID.
func (s *serverState) controlServer(port int) {
	tlsCfg, err := common.ServerTLSConfig(s.pki)
	if err != nil {
		log.Printf("control tls config err: %v", err)
		return
	}
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsCfg)
	if err != nil {
		log.Printf("control listen err: %v", err)
		return
	}
	defer func(ln net.Listener) {
		_ = ln.Close()
	}(ln)
	log.Printf("control TLS listening on :%d", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("control accept err: %v", err)
			continue
		}
		go s.handleControl(conn)
	}
}

func (s *serverState) handleControl(conn net.Conn) {
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)
	peer := conn.(*tls.Conn)
	if err := peer.Handshake(); err != nil {
		log.Printf("control handshake err: %v", err)
		return
	}
	state := peer.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("no client cert")
		return
	}
	cn := state.PeerCertificates[0].Subject.CommonName

	reqData, err := io.ReadAll(peer)
	if err != nil {
		log.Printf("read control err: %v", err)
		return
	}
	var req common.ControlRequest
	if err := req.Unmarshal(reqData); err != nil {
		log.Printf("unmarshal control err: %v", err)
		return
	}
	if req.ClientName == "" {
		req.ClientName = cn
	}

	sessID := uint32(time.Now().UnixNano())
	key, err := common.GenerateSessionKey()
	if err != nil {
		log.Printf("gen key err: %v", err)
		return
	}
	clientIP := s.assignClientIP()
	sess := &serverSession{id: sessID, conns: []*serverConn{}, clientIP: clientIP, key: key}
	s.sessMu.Lock()
	s.sessions[sessID] = sess
	s.sessMu.Unlock()

	resp := common.ControlResponse{
		SessionID:  sessID,
		SessionKey: common.EncodeKeyBase64(key),
		UDPPort:    s.udpPort,
		ClientIP:   clientIP.String(),
	}
	b, _ := resp.Marshal()
	_, _ = peer.Write(b)
	log.Printf("issued session to %s id=%d", req.ClientName, sessID)
}

// ensureNatRule installs MASQUERADE if missing (best-effort, Linux only).
func ensureNatRule() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return err
	}
	check := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE")
	if err := check.Run(); err == nil {
		return nil
	}
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE")
	return cmd.Run()
}

// splitCSV splits a comma-separated string into trimmed, non-empty parts.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
