package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/songgao/water"

	"fluxify/common"
)

func startBondingClientCore(cfg clientConfig) (*clientState, func(), error) {
	if cfg.Client == "" {
		return nil, nil, fmt.Errorf("client name required")
	}
	cfg.Ifaces = sanitizeIfaces(cfg.Ifaces)
	if len(cfg.Ifaces) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 usable interfaces for bonding")
	}
	// Bonding requires TUN device which needs root
	if common.NeedsElevation() {
		log.Printf("bonding: TUN requires root, requesting elevation...")
		pkiPath := expandPath(cfg.PKI)
		extraArgs := []string{
			"-b", // force bonding mode
			"-server", cfg.Server,
			"-ifaces", strings.Join(cfg.Ifaces, ","),
			"-client", cfg.Client,
			"-pki", pkiPath,
		}
		if err := common.RelaunchWithPkexec(extraArgs...); err != nil {
			return nil, nil, fmt.Errorf("elevation required for TUN: %w", err)
		}
		return nil, nil, fmt.Errorf("elevation failed")
	}
	log.Printf("bonding: starting with client=%s server=%s pki=%s", cfg.Client, cfg.Server, cfg.PKI)
	ctrlHost, ctrlPort, err := parseServerAddr(cfg.Server, cfg.Ctrl)
	if err != nil {
		return nil, nil, err
	}
	ctrlAddr := net.JoinHostPort(ctrlHost, fmt.Sprintf("%d", ctrlPort))

	log.Printf("bonding: fetching session from %s", ctrlAddr)
	key, sessID, udpPort, clientIP, clientIPv6, err := fetchSession(ctrlAddr, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("control: %w", err)
	}
	log.Printf("bonding: session id=%d udp=%d ip4=%s ip6=%s", sessID, udpPort, clientIP, clientIPv6)

	serverUDP, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ctrlHost, fmt.Sprintf("%d", udpPort)))
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &clientState{
		serverUDP:  serverUDP,
		sessionID:  sessID,
		sessionKey: key,
		mode:       cfg.Mode,
		ctx:        ctx,
		cancel:     cancel,
	}

	log.Printf("bonding: creating TUN device")
	conf := water.Config{DeviceType: water.TUN}
	tun, err := water.New(conf)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("tun: %w", err)
	}
	state.tun = tun
	log.Printf("TUN up: %s", tun.Name())
	log.Printf("bonding: configuring TUN with %s/24 (IPv4) and %s (IPv6)", clientIP, addIPv6CIDR(clientIPv6))
	if err := common.ConfigureTUN(common.TUNConfig{IfaceName: tun.Name(), CIDR: clientIP + "/24", IPv6CIDR: addIPv6CIDR(clientIPv6), MTU: common.MTU}); err != nil {
		_ = state.tun.Close()
		cancel()
		return nil, nil, err
	}

	isLoopback := serverUDP.IP != nil && serverUDP.IP.IsLoopback()
	if !isLoopback {
		log.Printf("bonding: setting up routing")
		oldRoute, via, dev, err := common.GetDefaultRoute()
		if err != nil {
			_ = state.tun.Close()
			cancel()
			return nil, nil, fmt.Errorf("get default route: %w", err)
		}
		oldRoute6, via6, dev6, err := common.GetDefaultRoute6()
		if err != nil {
			_ = state.tun.Close()
			cancel()
			return nil, nil, fmt.Errorf("get default route v6: %w", err)
		}
		serverHost, _, _ := net.SplitHostPort(cfg.Server)
		serverIP := serverUDP.IP.String()
		if serverHost == "" {
			serverHost = serverIP
		}
		if serverUDP.IP.To4() != nil {
			_ = common.EnsureHostRoute(serverHost, via, dev)
		} else {
			_ = common.EnsureHostRoute6(serverHost, via6, dev6)
		}
		if err := common.SetDefaultRouteDev(tun.Name()); err != nil {
			if serverUDP.IP.To4() != nil {
				_ = common.DeleteHostRoute(serverHost)
			} else {
				_ = common.DeleteHostRoute6(serverHost)
			}
			_ = state.tun.Close()
			cancel()
			return nil, nil, fmt.Errorf("set default route: %w", err)
		}
		if err := common.SetDefaultRouteDev6(tun.Name()); err != nil {
			log.Printf("bonding: warning: failed to set IPv6 default via TUN: %v", err)
		}
		state.revertRoute = func() {
			_ = common.ReplaceDefaultRoute(oldRoute)
			if oldRoute6 != "" {
				_ = common.ReplaceDefaultRoute6(oldRoute6)
			}
			if serverUDP.IP.To4() != nil {
				_ = common.DeleteHostRoute(serverHost)
			} else {
				_ = common.DeleteHostRoute6(serverHost)
			}
		}
	} else {
		log.Printf("bonding: loopback server detected (%s); skipping route changes and iface binding for testing", serverUDP.String())
	}

	for i := 0; i < cfg.Conns; i++ {
		iface := pickIndex(cfg.Ifaces, i)
		ip := pickIndex(cfg.IPs, i)
		if isLoopback {
			iface = ""
			ip = ""
		}
		cc, err := dialConn(serverUDP, iface, ip)
		if err != nil {
			log.Printf("conn %d dial err: %v", i, err)
			continue
		}
		state.connMu.Lock()
		state.conns = append(state.conns, cc)
		state.connMu.Unlock()
		state.wg.Add(1)
		go state.readLoop(cc)
		state.sendHandshake(cc)
	}

	// Worker pool for TUN -> UDP
	numWorkers := runtime.NumCPU()
	workCh := make(chan []byte, numWorkers*10)

	state.wg.Add(1)
	go state.tunReader(workCh)

	for i := 0; i < numWorkers; i++ {
		state.wg.Add(1)
		go state.workerLoop(workCh)
	}

	state.wg.Add(1)
	go state.heartbeat()

	stop := func() {
		cancel()
		state.connMu.Lock()
		for _, c := range state.conns {
			_ = c.udp.Close()
		}
		state.connMu.Unlock()
		if state.tun != nil {
			_ = state.tun.Close()
		}
		state.wg.Wait()
		if state.revertRoute != nil {
			state.revertRoute()
		}
	}
	return state, stop, nil
}

func (c *clientState) readLoop(cc *clientConn) {
	defer c.wg.Done()
	// Reuse buffer for reading UDP packets.
	buf := common.GetBuffer()
	defer common.PutBuffer(buf)

	for {
		_ = cc.udp.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := cc.udp.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				select {
				case <-c.ctx.Done():
					return
				default:
					continue
				}
			}
			cc.alive.Store(false)
			return
		}

		// Decrypt into a separate buffer to avoid invalid overlap (panic).
		plainBuf := common.GetBuffer()
		h, payload, err := common.DecryptPacketInto(plainBuf, c.sessionKey, buf[:n])
		if err != nil {
			common.PutBuffer(plainBuf)
			continue
		}
		cc.bytesRecv.Add(uint64(len(payload)))

		switch h.Type {
		case common.PacketHeartbeat:
			var hb common.HeartbeatPayload
			if err := hb.Unmarshal(payload); err == nil {
				cc.rttNano.Store(int64(common.CalcRTT(hb.SendTime)))
			}
			common.PutBuffer(plainBuf)
		case common.PacketIP:
			pay := payload
			// Handle compression
			if h.Reserved[0] == common.CompressionGzip {
				// Decompress into yet another buffer
				outBuf := common.GetBuffer()
				dec, err := common.DecompressPayloadInto(outBuf, payload, common.MaxPacketSize)
				if err == nil {
					_, _ = c.tun.Write(dec)
					common.PutBuffer(outBuf)
				} else {
					log.Printf("decompress err: %v", err)
					common.PutBuffer(outBuf)
				}
				common.PutBuffer(plainBuf) // Release compressed payload buffer
			} else {
				_, _ = c.tun.Write(pay)
				common.PutBuffer(plainBuf) // Release payload buffer
			}
		default:
			common.PutBuffer(plainBuf)
		}
	}
}

func (c *clientState) tunReader(workCh chan<- []byte) {
	defer c.wg.Done()
	defer close(workCh)
	for {
		// Allocate buffer for new packet
		buf := common.GetBuffer()
		n, err := c.tun.Read(buf)
		if err != nil {
			common.PutBuffer(buf)
			select {
			case <-c.ctx.Done():
				return
			default:
				log.Printf("tun read err: %v", err)
				continue
			}
		}
		// Send valid slice to worker
		select {
		case workCh <- buf[:n]:
		case <-c.ctx.Done():
			common.PutBuffer(buf)
			return
		}
	}
}

func (c *clientState) workerLoop(workCh <-chan []byte) {
	defer c.wg.Done()
	for payload := range workCh {
		c.processAndSend(payload)
		// Return buffer to pool after processing
		// payload is a slice of the buffer from GetBuffer (resliced in tunReader)
		// We need to recover the original capacity-sized slice to Put properly?
		// common.PutBuffer handles checking capacity.
		// But payload is `buf[:n]`. `cap(payload)` should be `PoolBufSize`.
		// So passing payload to PutBuffer is fine.
		common.PutBuffer(payload)
	}
}

func (c *clientState) processAndSend(data []byte) {
	// Compression
	compressed := data
	compressFlag := common.CompressionNone

	// Try compression into a new buffer
	compBuf := common.GetBuffer()
	if comp, err := common.CompressPayloadInto(compBuf, data); err == nil {
		if len(comp) < len(data) {
			compressed = comp
			compressFlag = common.CompressionGzip
		}
	}
	// If we didn't use compBuf (compression failed or larger), return it.
	// If we used it, we must return it later.
	usedComp := (compressFlag == common.CompressionGzip)
	if !usedComp {
		common.PutBuffer(compBuf)
	} else {
		defer common.PutBuffer(compBuf) // Return compressed buffer at end
	}

	seq := c.nextSeqSend.Add(1)
	cc := c.pickBestConn()
	if cc == nil {
		return
	}

	head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketIP, SessionID: c.sessionID, SeqNum: seq, Length: uint16(len(compressed))}
	head.Reserved[0] = byte(compressFlag)

	// Encrypt into new packet buffer
	pktBuf := common.GetBuffer()
	defer common.PutBuffer(pktBuf)

	pkt, err := common.EncryptPacketInto(pktBuf, c.sessionKey, head, compressed)
	if err != nil {
		return
	}

	cc.mu.Lock()
	_, _ = cc.udp.Write(pkt)
	cc.mu.Unlock()
	cc.bytesSent.Add(uint64(len(data)))
}

func (c *clientState) pickBestConn() *clientConn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	if len(c.conns) == 0 {
		return nil
	}
	if c.mode == modeBonding {
		start := int(c.nextConnRR.Add(1)-1) % len(c.conns)
		for i := 0; i < len(c.conns); i++ {
			cand := c.conns[(start+i)%len(c.conns)]
			if cand.alive.Load() {
				return cand
			}
		}
		return nil
	}
	// load-balance: pick lowest RTT alive
	var best *clientConn
	bestRTT := time.Duration(1<<63 - 1)
	for _, cand := range c.conns {
		if !cand.alive.Load() {
			continue
		}
		rtt := time.Duration(cand.rttNano.Load())
		if rtt == 0 {
			rtt = 500 * time.Millisecond
		}
		if rtt < bestRTT {
			bestRTT = rtt
			best = cand
		}
	}
	if best != nil {
		return best
	}
	return c.conns[0]
}

func (c *clientState) sendHandshake(cc *clientConn) {
	head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketHandshake, SessionID: c.sessionID, SeqNum: 0, Length: 0}
	pkt, err := common.EncryptPacket(c.sessionKey, head, nil)
	if err != nil {
		return
	}
	cc.mu.Lock()
	_, _ = cc.udp.Write(pkt)
	cc.mu.Unlock()
}

func (c *clientState) heartbeat() {
	defer c.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		hb := common.HeartbeatPayload{SendTime: common.NowMonoNano()}
		payload := hb.Marshal()
		c.connMu.RLock()
		for _, cc := range c.conns {
			if !cc.alive.Load() {
				// try one ping to see if it comes back
				// or maybe we rely on generic traffic?
				// The original code sent heartbeat to all.
			}
			head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketHeartbeat, SessionID: c.sessionID, SeqNum: 0, Length: uint16(len(payload))}
			if pkt, err := common.EncryptPacket(c.sessionKey, head, payload); err == nil {
				cc.mu.Lock()
				_, _ = cc.udp.Write(pkt)
				cc.mu.Unlock()
			}
		}
		c.connMu.RUnlock()
	}
}

func parseServerAddr(server string, ctrlPort int) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return server, ctrlPort, nil
		}
		return "", 0, err
	}
	if portStr == "" {
		return host, ctrlPort, nil
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, p, nil
}

func fetchSession(ctrlAddr string, cfg clientConfig) ([]byte, uint32, int, string, string, error) {
	tlsCfg, err := clientTLSConfig(cfg)
	if err != nil {
		return nil, 0, 0, "", "", err
	}
	if host, _, herr := net.SplitHostPort(ctrlAddr); herr == nil {
		c := tlsCfg.Clone()
		c.ServerName = host
		tlsCfg = c
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()

	tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ctrlAddr)
	if err != nil {
		return nil, 0, 0, "", "", classifyTLSError(err)
	}
	conn := tls.Client(tcpConn, tlsCfg)
	deadline := time.Now().Add(controlTimeout)
	_ = conn.SetDeadline(deadline)

	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, 0, 0, "", "", classifyTLSError(err)
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	req := common.ControlRequest{ClientName: cfg.Client}
	buf, _ := req.Marshal()
	if _, err := conn.Write(buf); err != nil {
		return nil, 0, 0, "", "", err
	}
	_ = conn.CloseWrite()
	respData, err := io.ReadAll(conn)
	if err != nil {
		return nil, 0, 0, "", "", err
	}
	var resp common.ControlResponse
	if err := resp.Unmarshal(respData); err != nil {
		return nil, 0, 0, "", "", err
	}
	key, err := common.DecodeKeyBase64(resp.SessionKey)
	if err != nil {
		return nil, 0, 0, "", "", err
	}
	return key, resp.SessionID, resp.UDPPort, resp.ClientIP, resp.ClientIPv6, nil
}

func addIPv6CIDR(ip string) string {
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + "/64"
}

func classifyTLSError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "i/o timeout") {
		return fmt.Errorf("timeout nella connessione/handshake TLS con il server di controllo: %v", err)
	}
	if strings.Contains(err.Error(), "tls: bad certificate") {
		return fmt.Errorf("il server ha rifiutato il certificato client (bad certificate): verifica che il client .pem contenga cert e key corretti e siano firmati dalla CA")
	}
	var ua *x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		return fmt.Errorf("CA sconosciuta: verifica il certificato CA nel bundle .pem e il server usato")
	}
	var hn *x509.HostnameError
	if errors.As(err, &hn) {
		return fmt.Errorf("il nome del server non corrisponde al certificato (%s)", hn.Error())
	}
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) {
		switch ci.Reason {
		case x509.Expired:
			return fmt.Errorf("certificato scaduto: rigenera o usa un certificato valido")
		default:
			return fmt.Errorf("certificato non valido: %v", ci)
		}
	}
	if strings.Contains(err.Error(), "handshake failure") {
		return fmt.Errorf("handshake TLS fallita: %v", err)
	}
	return err
}

func clientTLSConfig(cfg clientConfig) (*tls.Config, error) {
	pkiDir := expandPath(cfg.PKI)
	bundlePath := filepath.Join(pkiDir, cfg.Client+".pem")
	caPool, cert, err := parseBundlePEM(bundlePath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func dialConn(server *net.UDPAddr, iface, ip string) (*clientConn, error) {
	dialer, err := common.NewBoundUDPDialer(iface, ip)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.Dial("udp", server.String())
	if err != nil {
		return nil, err
	}
	udp := conn.(*net.UDPConn)
	cc := &clientConn{udp: udp, addr: server, iface: iface}
	cc.alive.Store(true)
	return cc, nil
}

func startBondingClientWithStats(cfg clientConfig, statsView *tview.TextView, app *tview.Application) (func(), error) {
	state, stop, err := startBondingClientCore(cfg)
	if err != nil {
		return nil, err
	}
	state.statsView = statsView
	if statsView != nil && app != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-state.ctx.Done():
					return
				case <-ticker.C:
					app.QueueUpdateDraw(func() {
						state.updateStats()
					})
				}
			}
		}()
	}
	return stop, nil
}

func (c *clientState) updateStats() {
	if c.statsView == nil {
		return
	}
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	var lines []string
	lines = append(lines, "[yellow]Bonding Stats:[white]")
	var totalTx, totalRx uint64
	for _, cc := range c.conns {
		tx := cc.bytesSent.Load()
		rx := cc.bytesRecv.Load()
		totalTx += tx
		totalRx += rx
		alive := "[red]DOWN"
		if cc.alive.Load() {
			alive = "[green]UP"
		}
		rtt := time.Duration(cc.rttNano.Load())
		lines = append(lines, fmt.Sprintf("  %s %s | TX: %s | RX: %s | RTT: %v", cc.iface, alive, fmtBytes(tx), fmtBytes(rx), rtt.Round(time.Millisecond)))
	}
	lines = append(lines, fmt.Sprintf("\n[cyan]Total TX:[white] %s  [cyan]Total RX:[white] %s", fmtBytes(totalTx), fmtBytes(totalRx)))
	c.statsView.SetText(strings.Join(lines, "\n"))
}
