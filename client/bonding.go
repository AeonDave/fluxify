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
	"runtime"
	"strconv"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

const (
	bondingDialBackoff    = 1 * time.Second
	bondingDialMaxBackoff = 10 * time.Second
	// bondingDeadAfter is how long a path may stay silent (no inbound
	// datagrams) before its connection is recycled.
	bondingDeadAfter = 10 * time.Second
	// bondingSessionDeadAfter is how long the whole session may stay silent
	// before the client renegotiates it over the control plane (covers
	// server restarts and pruned sessions).
	bondingSessionDeadAfter = 20 * time.Second
)

var (
	defaultDNS4 = []string{"1.1.1.1", "8.8.8.8"}
	defaultDNS6 = []string{"2606:4700:4700::1111", "2001:4860:4860::8888"}
)

type ifaceDNSBackup struct {
	iface string
	dns4  []string
	dns6  []string
}

type bondingRunner struct{}

func (bondingRunner) Run(name string, args ...string) error {
	return common.RunPrivileged(name, args...)
}

func (bondingRunner) Output(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
}

func (bondingRunner) OutputSafe(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
}

func isUsableLocalIP(ip net.IP, wantV4 bool) bool {
	if ip == nil {
		return false
	}
	if wantV4 {
		ip = ip.To4()
		if ip == nil {
			return false
		}
	} else {
		if ip.To4() != nil {
			return false
		}
		ip = ip.To16()
		if ip == nil {
			return false
		}
	}
	// Exclude loopback + link-local; RFC1918 / ULA are fine.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	return ip.IsGlobalUnicast()
}

// ipForIface returns a usable local IP on the interface for the requested
// address family.
func ipForIface(ifaceName string, wantV4 bool) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup iface %q: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addrs for iface %q: %w", ifaceName, err)
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if isUsableLocalIP(ip, wantV4) {
			return ip, nil
		}
	}
	family := "IPv4"
	if !wantV4 {
		family = "IPv6"
	}
	return nil, fmt.Errorf("no usable %s address found on iface %q", family, ifaceName)
}

func startBondingClientCore(cfg clientConfig) (*clientState, func(), error) {
	cfg.Ifaces = sanitizeIfaces(cfg.Ifaces, true)
	if len(cfg.Ifaces) < 1 {
		return nil, nil, fmt.Errorf("need at least 1 usable interface")
	}
	if len(cfg.Ifaces) == 1 {
		vlogf("bonding: single interface mode, no aggregation possible")
	}
	if !common.IsRoot() {
		switch runtime.GOOS {
		case "windows":
			return nil, nil, fmt.Errorf("run the client as administrator on windows to create the TUN interface")
		case "linux":
			return nil, nil, fmt.Errorf("run the client with sudo/root on linux to create the TUN interface")
		}
	}
	certInfo := cfg.Cert
	if certInfo == "" {
		certInfo = "(auto)"
	}
	vlogf("bonding: starting with cert=%s server=%s pki=%s", certInfo, cfg.Server, cfg.PKI)
	vlogf("bonding: selected interfaces: %v", cfg.Ifaces)
	ctrlHost, ctrlPort, err := parseServerAddr(cfg.Server, cfg.Ctrl)
	if err != nil {
		return nil, nil, err
	}
	ctrlAddr := net.JoinHostPort(ctrlHost, fmt.Sprintf("%d", ctrlPort))

	vlogf("bonding: fetching session from %s", ctrlAddr)
	sessID, dataPort, clientIP, clientIPv6, err := fetchSession(ctrlAddr, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("control: %w", err)
	}
	vlogf("bonding: session id=%d data_port=%d ip4=%s ip6=%s", sessID, dataPort, clientIP, clientIPv6)

	serverAddr := net.JoinHostPort(ctrlHost, fmt.Sprintf("%d", dataPort))
	ctx, cancel := context.WithCancel(context.Background())
	state := &clientState{
		serverAddr: serverAddr,
		sessionID:  sessID,
		clientIP:   clientIP,
		clientIPv6: clientIPv6,
		mode:       cfg.Mode,
		ctx:        ctx,
		cancel:     cancel,
		ctrlAddr:   ctrlAddr,
		cfg:        cfg,
		rateByPath: make(map[*pathConn]*ifaceRate),
	}
	for i, iface := range cfg.Ifaces {
		localIP := ""
		if i < len(cfg.IPs) {
			localIP = strings.TrimSpace(cfg.IPs[i])
		}
		state.paths = append(state.paths, newPathConn(iface, localIP))
	}

	// Inbound reorder buffer absorbs cross-path delivery skew (striping).
	bufSize := cfg.ReorderBufferSize
	if bufSize <= 0 {
		bufSize = 512
	}
	flush := cfg.ReorderFlushTimeout
	if flush <= 0 {
		flush = 50 * time.Millisecond
	}
	state.inReorder = common.NewReorderBuffer(bufSize, flush)
	state.wg.Add(1)
	go state.inboundReorderFlushLoop()
	telemetryStop, err := startTelemetryLogger(ctx, state, cfg.Telemetry)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	vlogf("bonding: creating TUN device")
	tun, err := platform.CreateTunDevice()
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("tun: %w", err)
	}
	state.tun = tun
	state.tunWriteCh = make(chan []byte, tunQueueLen)
	vlogf("TUN up: %s", tun.Name())
	enableIPv6 := clientIPv6 != ""
	if runtime.GOOS == "windows" && len(cfg.DNS6) == 0 {
		enableIPv6 = false
		vlogf("bonding: ipv6 disabled (no dns6 configured)")
	}
	state.ipv6Enabled = enableIPv6
	ipv6CIDR := ""
	if enableIPv6 {
		ipv6CIDR = addIPv6CIDR(clientIPv6)
	}
	// Determine MTU to use
	mtu := common.MTU
	if cfg.MTU > 0 {
		mtu = cfg.MTU
		vlogf("bonding: using custom MTU %d", mtu)
	}

	// Conservative sizing budgets.
	//
	// The underlay must carry: IP+UDP headers + QUIC packet (containing a
	// DATAGRAM frame) whose payload is DataPlaneHdr + inner IP packet.
	const (
		maxIPUDPOverhead         = 48 // IPv6(40)+UDP(8); worst-case safe even if underlay is IPv4
		datagramFrameOverhead    = 4  // type + varint length (worst-case budget)
		quicPacketOverheadBudget = 48 // short header + packet number + AEAD tag + misc (budget)
	)

	// Dynamic MTU adaptation: always probe if MTU not fixed by user.
	if (cfg.ProbePMTUD || cfg.MTU == 0) && ctrlHost != "" {
		vlogf("bonding: probing path MTU to %s...", ctrlHost)
		// Keep this short: if ICMP is blocked, probing will never succeed.
		probeTimeout := 1 * time.Second
		wireMTU, result := common.AutoProbePMTUD(ctrlHost, probeTimeout)

		if result.Success {
			vlogf("PMTUD: path supports wire MTU %d", wireMTU)
			safeTunMTU := wireMTU - maxIPUDPOverhead - quicPacketOverheadBudget - datagramFrameOverhead - common.DataPlaneHdrSize
			if safeTunMTU < 1000 {
				safeTunMTU = 1000
			}
			if cfg.MTU == 0 {
				log.Printf("PMTUD: auto-configured TUN MTU %d (wire %d - headers/overhead budget %d)", safeTunMTU, wireMTU, maxIPUDPOverhead+quicPacketOverheadBudget+datagramFrameOverhead+common.DataPlaneHdrSize)
				mtu = safeTunMTU
			} else if cfg.MTU > safeTunMTU {
				log.Printf("WARNING: configured MTU %d + overhead > wire MTU %d. Packet loss likely.", cfg.MTU, wireMTU)
			}
		} else {
			log.Printf("PMTUD: all probes failed, defaulting to conservative MTU")
			if cfg.MTU == 0 {
				// 1200 is universally safe (well below 1280 IPv6 minimum after all overhead).
				mtu = 1200
			}
		}
	}

	// Persist the final MTU so per-path QUIC configs see it.
	cfg.MTU = mtu
	state.cfg.MTU = mtu

	vlogf("bonding: configuring TUN with %s/24 (IPv4) and %s (IPv6), MTU=%d", clientIP, ipv6CIDR, mtu)
	if err := common.ConfigureTUN(common.TUNConfig{IfaceName: tun.Name(), CIDR: clientIP + "/24", IPv6CIDR: ipv6CIDR, MTU: mtu}); err != nil {
		_ = state.tun.Close()
		cancel()
		return nil, nil, err
	}
	if runtime.GOOS == "windows" {
		dns4 := cfg.DNS4
		dns6 := cfg.DNS6
		if len(dns4) == 0 && len(dns6) == 0 {
			dns4 = defaultDNS4
			if enableIPv6 {
				dns6 = defaultDNS6
			}
		}
		if err := common.SetInterfaceDNS(tun.Name(), dns4, dns6); err != nil {
			log.Printf("bonding: warning: set DNS failed: %v", err)
		} else {
			state.revertDNS = func() {
				_ = common.ClearInterfaceDNS(tun.Name())
			}
		}
		state.ifaceDNS = applyIfaceDNS(cfg.Ifaces, dns4, dns6)
	}

	// Configure VPN routing: save old default route, add per-uplink host
	// routes to the server, then point the default route at the TUN.
	vlogf("bonding: configuring VPN routes")
	oldRoute, _, _, err := common.GetDefaultRoute()
	if err != nil {
		log.Printf("bonding: warning: could not get default route: %v", err)
	}
	var oldRoute6 string
	if enableIPv6 {
		oldRoute6, _, _, _ = common.GetDefaultRoute6()
	}

	// One host route to the VPN server per bonding interface, with distinct
	// metrics so they coexist. Together with the per-interface socket
	// binding this keeps every path's traffic on its own uplink.
	serverIP, _, _ := net.SplitHostPort(serverAddr)
	if serverIP != "" {
		for i, iface := range cfg.Ifaces {
			gw, err := platform.GatewayForIface(bondingRunner{}, iface)
			if err != nil || gw == "" {
				vvlogf("bonding: skipping host route for %s (no gateway: %v)", iface, err)
				continue
			}
			if err := common.AddHostRouteMetric(serverIP, gw, iface, i+1); err != nil {
				vlogf("bonding: warning: could not add host route for server via %s/%s: %v", gw, iface, err)
			} else {
				vlogf("bonding: added host route for %s via %s/%s metric %d", serverIP, gw, iface, i+1)
			}
		}
	}

	// Set default route via TUN (on-link).
	if err := common.SetDefaultRouteDev(tun.Name()); err != nil {
		log.Printf("bonding: warning: could not set default route via TUN: %v", err)
	} else {
		vlogf("bonding: set default route via %s (on-link)", tun.Name())
	}
	if enableIPv6 && clientIPv6 != "" {
		if err := common.SetDefaultRouteDev6(tun.Name()); err != nil {
			log.Printf("bonding: warning: could not set IPv6 default route via TUN: %v", err)
		}
	}

	state.revertRoute = func() {
		vlogf("bonding: restoring original routes")
		if oldRoute != "" {
			if err := common.ReplaceDefaultRoute(oldRoute); err != nil {
				log.Printf("bonding: warning: could not restore default route: %v", err)
			}
		}
		if enableIPv6 && oldRoute6 != "" {
			if err := common.ReplaceDefaultRoute6(oldRoute6); err != nil {
				log.Printf("bonding: warning: could not restore IPv6 default route: %v", err)
			}
		}
		if serverIP != "" {
			_ = common.DeleteHostRoutes(serverIP)
		}
	}

	// Per-path goroutines: lifecycle (dial/receive/redial), sender, heartbeat.
	for _, pc := range state.paths {
		state.wg.Add(3)
		go state.pathLoop(pc)
		go state.pathSender(pc)
		go state.pathHeartbeat(pc)
	}

	// Shared loops: stats sampling, liveness monitor, TUN I/O, scheduler.
	state.wg.Add(2)
	go state.statsLoop()
	go state.monitorLoop()

	go state.tunWriteLoop()

	workCh := make(chan []byte, tunQueueLen)
	go state.tunReader(workCh)
	state.wg.Add(1)
	go state.sendScheduler(workCh)

	stop := func() {
		cancel()
		telemetryStop()
		if state.revertRoute != nil {
			state.revertRoute()
		}
		if state.revertDNS != nil {
			state.revertDNS()
		}
		restoreIfaceDNS(state.ifaceDNS)
		if state.tun != nil {
			_ = state.tun.Close()
		}
		state.closeAllConns()
		state.wg.Wait()
		// Final cleanup: flush DNS cache to ensure interfaces reconnect properly.
		if runtime.GOOS == "windows" {
			_ = common.RunPrivileged("ipconfig", "/flushdns")
		}
	}
	return state, stop, nil
}

// ============================================================================
// Per-path lifecycle
// ============================================================================

// pathLoop dials the path's QUIC connection and pumps inbound datagrams,
// redialing with backoff whenever the connection dies.
func (c *clientState) pathLoop(pc *pathConn) {
	defer c.wg.Done()
	backoff := bondingDialBackoff
	for {
		if c.ctx.Err() != nil {
			return
		}
		sessID, serverAddr := c.sessionSnapshot()
		conn, udp, err := c.dialPath(pc, serverAddr)
		if err != nil {
			vlogf("bonding: %s: dial failed: %v (retry in %v)", pc.iface, err, backoff)
			if !sleepWithContext(c.ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = bondingDialBackoff
		pc.setConn(conn, udp)
		pc.rate.Reset(common.DefaultInitialRateBps)
		pc.lastRecv.Store(time.Now().UnixNano())
		c.setPathState(pc, true, "connected")
		c.refreshServerAlive()
		vlogf("bonding: %s: QUIC connected %s -> %s", pc.iface, conn.LocalAddr(), conn.RemoteAddr())

		// Announce this path to the server so downlink striping can use it
		// before any uplink data flows on it.
		c.sendHandshake(conn, sessID)

		c.pathReceive(pc, conn)

		c.setPathState(pc, false, "receive closed")
		pc.closeConn("recycle")
		c.refreshServerAlive()
	}
}

// pathReceive pumps inbound datagrams until the connection dies.
func (c *clientState) pathReceive(pc *pathConn, conn *quic.Conn) {
	for {
		dat, err := conn.ReceiveDatagram(c.ctx)
		if err != nil {
			if c.ctx.Err() == nil {
				vlogf("bonding: %s: receive error: %v", pc.iface, err)
			}
			return
		}
		h, payload, err := common.ParseDataPlaneDatagram(dat)
		if err != nil {
			vvlogf("bonding: %s: parse datagram error: %v", pc.iface, err)
			continue
		}
		pc.bytesRecv.Add(uint64(len(payload)))
		pc.lastRecv.Store(time.Now().UnixNano())

		switch h.Type {
		case common.DPTypeIP:
			vvlogf("bonding: %s: IP packet seq=%d len=%d", pc.iface, h.SeqNum, len(payload))
			for _, p := range c.inReorder.Insert(h.SeqNum, payload) {
				c.enqueueTunWrite(p)
			}
		case common.DPTypeHeartbeat:
			var hb common.HeartbeatPayload
			if err := hb.Unmarshal(payload); err != nil {
				continue
			}
			rtt := common.CalcRTT(hb.SendTime)
			c.updatePathRTTJitter(pc, rtt)
			pc.hbRecv.Add(1)
			vvlogf("bonding: %s: heartbeat RTT=%v", pc.iface, rtt)
		case common.DPTypeHandshake:
			vvlogf("bonding: %s: handshake ack", pc.iface)
		}
	}
}

// pathSender drains the path's send queue into the QUIC connection.
// SendDatagram blocks when the transport's datagram queue is full, which is
// the congestion backpressure that makes the queue occupancy meaningful.
func (c *clientState) pathSender(pc *pathConn) {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case dg := <-pc.sendCh:
			if conn := pc.currentConn(); conn != nil {
				if err := conn.SendDatagram(dg); err != nil {
					var tooLarge *quic.DatagramTooLargeError
					if errors.As(err, &tooLarge) {
						vlogf("bonding: %s: datagram too large (%d > %d), check MTU", pc.iface, len(dg), tooLarge.MaxDatagramPayloadSize)
					} else {
						vvlogf("bonding: %s: send error: %v", pc.iface, err)
					}
				} else {
					pc.bytesSent.Add(uint64(len(dg)))
				}
			}
			pc.queued.Add(-int64(len(dg)))
			common.PutBuffer(dg)
		}
	}
}

// pathHeartbeat periodically sends a heartbeat on the path's own connection
// (it must not go through the scheduler: it measures this specific path).
func (c *clientState) pathHeartbeat(pc *pathConn) {
	defer c.wg.Done()
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			conn := pc.currentConn()
			if conn == nil {
				continue
			}
			sessID, _ := c.sessionSnapshot()
			hb := common.HeartbeatPayload{SendTime: common.NowMonoNano()}
			head := common.DataPlaneHeader{Version: common.DataPlaneVersion, Type: common.DPTypeHeartbeat, SessionID: sessID}
			dg, err := common.BuildDataPlaneDatagram(nil, head, hb.Marshal())
			if err != nil {
				continue
			}
			if err := conn.SendDatagram(dg); err == nil {
				pc.hbSent.Add(1)
			}
		}
	}
}

func (c *clientState) sendHandshake(conn *quic.Conn, sessID uint32) {
	head := common.DataPlaneHeader{Version: common.DataPlaneVersion, Type: common.DPTypeHandshake, SessionID: sessID}
	dg, err := common.BuildDataPlaneDatagram(nil, head, nil)
	if err != nil {
		return
	}
	if err := conn.SendDatagram(dg); err != nil {
		vlogf("bonding: handshake send failed: %v", err)
	}
}

// dialPath creates the bound UDP socket and QUIC connection for one path.
func (c *clientState) dialPath(pc *pathConn, serverAddr string) (*quic.Conn, *net.UDPConn, error) {
	tlsCfg, err := clientTLSConfig(c.cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("tls config: %w", err)
	}
	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"fluxify-quic"}

	ua, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve addr: %w", err)
	}
	wantV4 := ua.IP.To4() != nil
	network := "udp6"
	if wantV4 {
		network = "udp4"
	}

	var localIP net.IP
	if pc.localIP != "" {
		localIP = net.ParseIP(pc.localIP)
		if !isUsableLocalIP(localIP, wantV4) {
			return nil, nil, fmt.Errorf("invalid local IP %q for iface %q", pc.localIP, pc.iface)
		}
	} else {
		localIP, err = ipForIface(pc.iface, wantV4)
		if err != nil {
			return nil, nil, err
		}
	}

	udp, err := common.ListenUDPBound(network, localIP, pc.iface)
	if err != nil {
		return nil, nil, fmt.Errorf("bind socket: %w", err)
	}

	dialCtx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	conn, err := quic.Dial(dialCtx, udp, ua, tlsCfg, clientQUICConfig(c.cfg, wantV4))
	if err != nil {
		_ = udp.Close()
		return nil, nil, fmt.Errorf("quic dial: %w", err)
	}
	return conn, udp, nil
}

// clientQUICConfig sizes the QUIC packet budget so a full TUN MTU packet
// (plus dataplane header) fits into a single DATAGRAM frame.
func clientQUICConfig(cfg clientConfig, wantV4 bool) *quic.Config {
	const (
		datagramFrameOverhead    = 4  // type + varint length budget
		quicPacketOverheadBudget = 48 // short header + packet number + AEAD tag + misc (budget)
		ipv6MinUDPPayload        = 1232
	)
	initialPacketSize := uint16(1500)
	if cfg.MTU > 0 {
		required := cfg.MTU + common.DataPlaneHdrSize + datagramFrameOverhead + quicPacketOverheadBudget
		if required < 1500 {
			initialPacketSize = uint16(required)
		}
		if initialPacketSize < 1200 {
			initialPacketSize = 1200
		}
	}
	if !wantV4 && initialPacketSize > ipv6MinUDPPayload {
		initialPacketSize = ipv6MinUDPPayload
	}
	return &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: initialPacketSize,
		MaxIdleTimeout:    2 * time.Minute,
		KeepAlivePeriod:   5 * time.Second,
	}
}

// ============================================================================
// Shared loops: stats, liveness
// ============================================================================

// statsLoop refreshes each path's delivered-rate estimate and smoothed RTT,
// which feed the striping scheduler.
func (c *clientState) statsLoop() {
	defer c.wg.Done()
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-t.C:
			for _, pc := range c.paths {
				pc.rate.Update(pc.bytesSent.Load(), now)
				if conn := pc.currentConn(); conn != nil {
					st := conn.ConnectionStats()
					pc.rttNano.Store(int64(st.SmoothedRTT))
				}
			}
		}
	}
}

// monitorLoop recycles silent paths and renegotiates the session when the
// server has been silent on every path for too long.
func (c *clientState) monitorLoop() {
	defer c.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	sessionEpoch := time.Now().UnixNano()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			now := time.Now().UnixNano()
			var lastAny int64
			for _, pc := range c.paths {
				last := pc.lastRecv.Load()
				if last > lastAny {
					lastAny = last
				}
				if pc.currentConn() == nil {
					continue
				}
				if time.Duration(now-last) > bondingDeadAfter {
					c.setPathState(pc, false, "stale")
					pc.closeConn("stale")
				}
			}
			c.refreshServerAlive()
			if lastAny > sessionEpoch {
				sessionEpoch = lastAny
			}
			if time.Duration(now-sessionEpoch) > bondingSessionDeadAfter {
				sessionEpoch = now // back off before re-triggering
				c.ensureReconnect()
			}
		}
	}
}

// ============================================================================
// Send path: TUN -> scheduler -> per-path queues
// ============================================================================

// tunReader reads IP packets from the TUN, leaving room for the dataplane
// header so the scheduler can stamp it in place (no extra copy).
func (c *clientState) tunReader(workCh chan<- []byte) {
	for {
		buf := common.GetBuffer()
		n, err := c.tun.Read(buf[common.DataPlaneHdrSize:])
		if err != nil {
			common.PutBuffer(buf)
			select {
			case <-c.ctx.Done():
				return
			default:
				vlogf("bonding: TUN read error: %v", err)
				return
			}
		}
		select {
		case workCh <- buf[:common.DataPlaneHdrSize+n]:
		case <-c.ctx.Done():
			common.PutBuffer(buf)
			return
		}
	}
}

// sendScheduler assigns the global sequence number and stripes packets
// across paths by earliest estimated delivery time.
func (c *clientState) sendScheduler(workCh <-chan []byte) {
	defer c.wg.Done()
	metrics := make([]common.PathMetrics, len(c.paths))
	for {
		select {
		case <-c.ctx.Done():
			return
		case buf, ok := <-workCh:
			if !ok {
				return
			}
			c.dispatch(buf, metrics)
		}
	}
}

// dispatch stamps the dataplane header into buf (which already reserves the
// leading header bytes) and enqueues it on the best path. Paths with a full
// queue are skipped; if every path is saturated the packet is dropped, which
// is the correct backpressure for tunneled traffic.
func (c *clientState) dispatch(buf []byte, metrics []common.PathMetrics) {
	sessID, _ := c.sessionSnapshot()
	head := common.DataPlaneHeader{
		Version:   common.DataPlaneVersion,
		Type:      common.DPTypeIP,
		SessionID: sessID,
		SeqNum:    c.nextSeq.Add(1),
	}
	if _, err := head.MarshalTo(buf[:common.DataPlaneHdrSize]); err != nil {
		common.PutBuffer(buf)
		return
	}
	for i, pc := range c.paths {
		metrics[i] = pc.metrics()
	}
	for {
		idx := common.PickPath(metrics, len(buf))
		if idx < 0 {
			vvlogf("bonding: all paths saturated/down, dropping packet")
			common.PutBuffer(buf)
			return
		}
		pc := c.paths[idx]
		pc.queued.Add(int64(len(buf)))
		select {
		case pc.sendCh <- buf:
			return
		default:
			pc.queued.Add(-int64(len(buf)))
			metrics[idx].Alive = false // full; try the next-best path
		}
	}
}

// ============================================================================
// Receive path: reorder -> TUN
// ============================================================================

func (c *clientState) inboundReorderFlushLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.inReorder.FlushCh():
			for _, p := range c.inReorder.FlushTimeout() {
				c.enqueueTunWrite(p)
			}
		}
	}
}

// enqueueTunWrite adds a packet to the TUN write queue (drop when full).
func (c *clientState) enqueueTunWrite(buf []byte) {
	select {
	case c.tunWriteCh <- buf:
	default:
		c.tunDrops.Add(1)
		common.PutBuffer(buf)
	}
}

// tunWriteLoop writes packets to the TUN device.
func (c *clientState) tunWriteLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case buf, ok := <-c.tunWriteCh:
			if !ok {
				return
			}
			if c.tun != nil {
				_, _ = c.tun.Write(buf)
			}
			common.PutBuffer(buf)
		}
	}
}

// ============================================================================
// Session / control plane
// ============================================================================

func (c *clientState) sessionSnapshot() (uint32, string) {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.sessionID, c.serverAddr
}

func (c *clientState) ensureReconnect() {
	if !c.reconnectOn.CompareAndSwap(false, true) {
		return
	}
	go c.reconnectLoop()
}

func (c *clientState) reconnectLoop() {
	defer c.reconnectOn.Store(false)
	backoff := bondingDialBackoff
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		vlogf("bonding: reconnecting control plane...")
		sessID, dataPort, clientIP, clientIPv6, err := fetchSession(c.ctrlAddr, c.cfg)
		if err != nil {
			vlogf("bonding: control reconnect failed: %v", err)
			if !sleepWithContext(c.ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		if err := c.updateSession(sessID, dataPort, clientIP, clientIPv6); err != nil {
			log.Printf("bonding: session update failed: %v", err)
			if !sleepWithContext(c.ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		log.Printf("server reconnected")
		vlogf("bonding: session refreshed")
		return
	}
}

func (c *clientState) updateSession(sessID uint32, dataPort int, clientIP, clientIPv6 string) error {
	host, _, err := net.SplitHostPort(c.ctrlAddr)
	if err != nil {
		host = c.ctrlAddr
	}
	serverAddr := net.JoinHostPort(host, fmt.Sprintf("%d", dataPort))
	c.sessMu.Lock()
	oldIP := c.clientIP
	oldIPv6 := c.clientIPv6
	c.sessionID = sessID
	c.serverAddr = serverAddr
	c.clientIP = clientIP
	c.clientIPv6 = clientIPv6
	c.sessMu.Unlock()
	if c.tun != nil && (clientIP != oldIP || clientIPv6 != oldIPv6) {
		ipv6CIDR := ""
		if c.ipv6Enabled {
			ipv6CIDR = addIPv6CIDR(clientIPv6)
		}
		if err := common.ConfigureTUN(common.TUNConfig{IfaceName: c.tun.Name(), CIDR: clientIP + "/24", IPv6CIDR: ipv6CIDR, MTU: common.MTU}); err != nil {
			log.Printf("bonding: tun reconfigure failed: %v", err)
		}
	}
	// Both directions restart their numbering with the new session.
	c.nextSeq.Store(0)
	if c.inReorder != nil {
		c.inReorder.Reset()
	}
	c.resetConns("session refresh")
	return nil
}

// resetConns recycles every path connection (the path loops redial with the
// current session parameters).
func (c *clientState) resetConns(reason string) {
	for _, pc := range c.paths {
		c.setPathState(pc, false, reason)
		pc.closeConn(reason)
	}
}

// closeAllConns closes all QUIC connections and sockets (shutdown).
func (c *clientState) closeAllConns() {
	for _, pc := range c.paths {
		pc.closeConn("shutdown")
	}
}

func fetchSession(ctrlAddr string, cfg clientConfig) (uint32, int, string, string, error) {
	tlsCfg, err := clientTLSConfig(cfg)
	if err != nil {
		return 0, 0, "", "", err
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
		return 0, 0, "", "", classifyTLSError(err)
	}
	conn := tls.Client(tcpConn, tlsCfg)
	deadline := time.Now().Add(controlTimeout)
	_ = conn.SetDeadline(deadline)

	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return 0, 0, "", "", classifyTLSError(err)
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	req := common.ControlRequest{}
	buf, _ := req.Marshal()
	if _, err := conn.Write(buf); err != nil {
		return 0, 0, "", "", err
	}
	_ = conn.CloseWrite()
	respData, err := io.ReadAll(conn)
	if err != nil {
		return 0, 0, "", "", err
	}
	var resp common.ControlResponse
	if err := resp.Unmarshal(respData); err != nil {
		return 0, 0, "", "", err
	}
	return resp.SessionID, resp.DataPort, resp.ClientIP, resp.ClientIPv6, nil
}

// ============================================================================
// State transitions / metrics helpers
// ============================================================================

func (c *clientState) setPathState(pc *pathConn, alive bool, reason string) {
	var changed bool
	if alive {
		changed = pc.alive.CompareAndSwap(false, true)
	} else {
		changed = pc.alive.CompareAndSwap(true, false)
	}
	if !changed {
		return
	}
	state := "disconnected"
	if alive {
		state = "connected"
	}
	log.Printf("iface %s %s (%s)", pc.iface, state, reason)
}

func (c *clientState) refreshServerAlive() {
	active := 0
	for _, pc := range c.paths {
		if pc.alive.Load() {
			active++
		}
	}
	c.setServerState(active > 0)
	trayPublishStatus(active > 0, active, len(c.paths))
}

func (c *clientState) setServerState(alive bool) {
	if alive {
		if c.serverAlive.CompareAndSwap(false, true) {
			log.Printf("server connected")
		}
		return
	}
	if c.serverAlive.CompareAndSwap(true, false) {
		log.Printf("server disconnected")
	}
}

// updatePathRTTJitter folds a heartbeat RTT sample into the path's jitter
// EMA. The scheduler RTT comes from QUIC stats; heartbeats feed the
// jitter/loss quality metrics.
func (c *clientState) updatePathRTTJitter(pc *pathConn, sample time.Duration) {
	prev := pc.lastHbRTT.Swap(int64(sample))
	if prev > 0 {
		delta := sample - time.Duration(prev)
		if delta < 0 {
			delta = -delta
		}
		j := time.Duration(pc.jitterNano.Load())
		j += (delta - j) / 16
		pc.jitterNano.Store(int64(j))
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > bondingDialMaxBackoff {
		return bondingDialMaxBackoff
	}
	if d < bondingDialBackoff {
		return bondingDialBackoff
	}
	return d
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
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

// ============================================================================
// DNS / addressing helpers
// ============================================================================

func applyIfaceDNS(ifaces, dns4, dns6 []string) []ifaceDNSBackup {
	if len(ifaces) == 0 {
		return nil
	}
	backups := make([]ifaceDNSBackup, 0, len(ifaces))
	for _, iface := range ifaces {
		if strings.TrimSpace(iface) == "" {
			continue
		}
		cur4, cur6, err := common.GetInterfaceDNS(iface)
		if err != nil {
			log.Printf("bonding: warning: read DNS for %s: %v", iface, err)
		}
		backups = append(backups, ifaceDNSBackup{iface: iface, dns4: cur4, dns6: cur6})
		if err := common.SetInterfaceDNS(iface, dns4, dns6); err != nil {
			log.Printf("bonding: warning: set DNS for %s: %v", iface, err)
		}
	}
	return backups
}

func restoreIfaceDNS(backups []ifaceDNSBackup) {
	for _, b := range backups {
		if strings.TrimSpace(b.iface) == "" {
			continue
		}
		if len(b.dns4) == 0 && len(b.dns6) == 0 {
			_ = common.ClearInterfaceDNS(b.iface)
			continue
		}
		if err := common.SetInterfaceDNS(b.iface, b.dns4, b.dns6); err != nil {
			log.Printf("bonding: warning: restore DNS for %s: %v", b.iface, err)
		}
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

func addIPv6CIDR(ip string) string {
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + "/64"
}

func defaultGatewayIP(clientIP string) string {
	ip := net.ParseIP(clientIP).To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.1", ip[0], ip[1], ip[2])
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
	bundlePath := cfg.Cert
	if bundlePath == "" {
		var err error
		bundlePath, err = common.DetectClientBundlePath(cfg.PKI)
		if err != nil {
			return nil, err
		}
	} else {
		bundlePath = common.ExpandPath(bundlePath)
	}
	return common.LoadClientBundle(bundlePath)
}

// ============================================================================
// TUI stats
// ============================================================================

func startBondingClientWithStats(cfg clientConfig, statsView *tview.TextView, app *tview.Application) (func(), error) {
	state, stop, err := startBondingClientCore(cfg)
	if err != nil {
		return nil, err
	}
	state.statsView = statsView
	if statsView != nil && app != nil {
		go func() {
			defer recoverPanic("bondingStatsUpdater")
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
	var lines []string
	lines = append(lines, "[yellow]Bonding Paths:[white]")
	now := time.Now()
	var totalTx, totalRx uint64
	var totalRateTx, totalRateRx float64
	var totalRate, maxRate float64
	active := 0
	var rttSum, rttMin, rttMax time.Duration
	rttCount := 0
	var totalHbSent, totalHbRecv uint64
	var jitterSum, scoreSum float64
	jitterCount := 0
	for _, pc := range c.paths {
		tx := pc.bytesSent.Load()
		rx := pc.bytesRecv.Load()
		totalTx += tx
		totalRx += rx
		isAlive := pc.alive.Load()
		if isAlive {
			active++
		}
		rtt := time.Duration(pc.rttNano.Load())
		jitterMs := float64(time.Duration(pc.jitterNano.Load())) / float64(time.Millisecond)
		sent := pc.hbSent.Load()
		recv := pc.hbRecv.Load()
		totalHbSent += sent
		totalHbRecv += recv
		loss := lossPercent(sent, recv)
		rttMs := float64(rtt) / float64(time.Millisecond)
		score := stabilityScore(loss.percent, jitterMs, rttMs)
		if isAlive && rtt > 0 {
			rttSum += rtt
			if rttMin == 0 || rtt < rttMin {
				rttMin = rtt
			}
			if rtt > rttMax {
				rttMax = rtt
			}
			rttCount++
		}
		rateTxK, rateRxK := c.pathRates(pc, tx, rx, now)
		totalRateTx += rateTxK
		totalRateRx += rateRxK
		rateSumK := rateTxK + rateRxK
		if isAlive {
			totalRate += rateSumK
			if rateSumK > maxRate {
				maxRate = rateSumK
			}
			jitterSum += jitterMs
			jitterCount++
			scoreSum += score
		}
		alive := "[red]DOWN"
		if isAlive {
			alive = "[green]UP"
		}
		lossText := "-"
		if loss.ok {
			lossText = fmt.Sprintf("%.1f%%", loss.percent)
		}
		queued := pc.queued.Load()
		if queued < 0 {
			queued = 0
		}
		lines = append(lines, fmt.Sprintf("  %s %s | est: %.1f Mbps | queue: %s | loss: %s | jitter: %.1f ms | score: %3.0f | TX: %s (%.1f kbps) | RX: %s (%.1f kbps) | RTT: %v",
			pc.iface, alive, pc.rate.Rate()*8/1e6, fmtBytes(uint64(queued)), lossText, jitterMs, score,
			fmtBytes(tx), rateTxK, fmtBytes(rx), rateRxK, rtt.Round(time.Millisecond)))
	}
	lines = append(lines, fmt.Sprintf("\n[cyan]Total TX:[white] %s (%.1f kbps)  [cyan]Total RX:[white] %s (%.1f kbps)",
		fmtBytes(totalTx), totalRateTx, fmtBytes(totalRx), totalRateRx))
	gain := 0.0
	if maxRate > 0 {
		gain = totalRate / maxRate
	}
	rttLine := "n/a"
	if rttCount > 0 {
		rttAvg := time.Duration(int64(rttSum) / int64(rttCount))
		rttLine = fmt.Sprintf("avg %s min %s max %s", rttAvg.Round(time.Millisecond), rttMin.Round(time.Millisecond), rttMax.Round(time.Millisecond))
	}
	lossText := "n/a"
	if loss := lossPercent(totalHbSent, totalHbRecv); loss.ok {
		lossText = fmt.Sprintf("%.1f%%", loss.percent)
	}
	jitterText := "n/a"
	if jitterCount > 0 {
		jitterText = fmt.Sprintf("%.1f ms", jitterSum/float64(jitterCount))
	}
	scoreText := "n/a"
	if jitterCount > 0 {
		scoreText = fmt.Sprintf("%.0f", scoreSum/float64(jitterCount))
	}
	server := "down"
	if c.serverAlive.Load() {
		server = "up"
	}
	lines = append(lines, fmt.Sprintf("[cyan]Active:[white] %d/%d  [cyan]Gain:[white] %.2fx  [cyan]Loss:[white] %s  [cyan]Jitter:[white] %s  [cyan]Score:[white] %s  [cyan]RTT:[white] %s  [cyan]Server:[white] %s",
		active, len(c.paths), gain, lossText, jitterText, scoreText, rttLine, server))

	rs := c.inReorder.Stats()
	lines = append(lines, "")
	lines = append(lines, "[yellow]Inbound Reorder (server->client):[white]")
	lines = append(lines, fmt.Sprintf("  buffered: %d  reordered: %d  dropped: %d  flushes: %d  maxDepth: %d  tunDrops: %d",
		rs.Buffered, rs.Reordered, rs.Dropped, rs.Flushes, rs.MaxDepth, c.tunDrops.Load()))
	c.statsView.SetText(strings.Join(lines, "\n"))
}

func (c *clientState) pathRates(pc *pathConn, tx, rx uint64, now time.Time) (float64, float64) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	rate, ok := c.rateByPath[pc]
	if !ok {
		rate = &ifaceRate{lastTx: tx, lastRx: rx, lastAt: now}
		c.rateByPath[pc] = rate
		return 0, 0
	}
	dt := now.Sub(rate.lastAt).Seconds()
	if dt <= 0 {
		return rate.rateTxK, rate.rateRxK
	}
	rate.rateTxK = float64(tx-rate.lastTx) * 8 / 1000.0 / dt
	rate.rateRxK = float64(rx-rate.lastRx) * 8 / 1000.0 / dt
	rate.lastTx = tx
	rate.lastRx = rx
	rate.lastAt = now
	return rate.rateTxK, rate.rateRxK
}
