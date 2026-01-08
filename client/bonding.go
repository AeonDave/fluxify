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
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

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

// collectLocalAddrs builds a strict allowlist of local IPs for the selected interfaces.
// If cfg.IPs provides an entry for an interface, that IP is used (no iface lookup).
// Otherwise, we try to discover a usable address on that interface.
func collectLocalAddrs(ifaces []string, ips []string, wantV4 bool) ([]net.IP, error) {
	var out []net.IP
	seen := make(map[string]struct{})

	for i, ifaceName := range ifaces {
		ipStr := ""
		if i < len(ips) {
			ipStr = strings.TrimSpace(ips[i])
		}

		if ipStr != "" {
			parsed := net.ParseIP(ipStr)
			if !isUsableLocalIP(parsed, wantV4) {
				return nil, fmt.Errorf("invalid local IP %q for iface %q", ipStr, ifaceName)
			}
			key := parsed.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				out = append(out, parsed)
			}
			continue
		}

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("lookup iface %q: %w", ifaceName, err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addrs for iface %q: %w", ifaceName, err)
		}

		var picked net.IP
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
				picked = ip
				break
			}
		}
		if picked == nil {
			if wantV4 {
				return nil, fmt.Errorf("no usable IPv4 address found on iface %q", ifaceName)
			}
			return nil, fmt.Errorf("no usable IPv6 address found on iface %q", ifaceName)
		}
		key := picked.String()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, picked)
		}
	}

	// Keep list deterministic.
	stable := make([]net.IP, 0, len(out))
	stableSeen := make(map[string]struct{}, len(out))
	for _, ip := range out {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		k := addr.String()
		if _, ok := stableSeen[k]; ok {
			continue
		}
		stableSeen[k] = struct{}{}
		stable = append(stable, ip)
	}

	return stable, nil
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

const (
	bondingDialBackoff    = 1 * time.Second
	bondingDialMaxBackoff = 10 * time.Second
	bondingDeadAfter      = 10 * time.Second
	bondingRouteRefresh   = 5 * time.Second
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

func startBondingClientCore(cfg clientConfig) (*clientState, func(), error) {
	cfg.Ifaces = sanitizeIfaces(cfg.Ifaces, true)
	if len(cfg.Ifaces) < 1 {
		return nil, nil, fmt.Errorf("need at least 1 usable interface")
	}
	// Allow single-interface mode for testing (multipath disabled)
	if len(cfg.Ifaces) == 1 {
		vlogf("bonding: WARNING - single interface mode, multipath disabled")
	}
	if runtime.GOOS == "windows" && !common.IsRoot() {
		return nil, nil, fmt.Errorf("run the client as administrator on windows to create the TUN interface")
	}
	if runtime.GOOS == "linux" && !common.IsRoot() {
		return nil, nil, fmt.Errorf("run the client with sudo/root on linux to create the TUN interface")
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
		serverAddr:    serverAddr,
		sessionID:     sessID,
		clientIP:      clientIP,
		clientIPv6:    clientIPv6,
		mode:          cfg.Mode,
		ctx:           ctx,
		cancel:        cancel,
		ctrlAddr:      ctrlAddr,
		cfg:           cfg,
		rateByConn:    make(map[*clientConn]*ifaceRate),
		stopInReorder: make(chan struct{}),
	}
	// Inbound reorder buffer is required for server->client packet striping.
	bufSize := cfg.ReorderBufferSize
	if bufSize <= 0 {
		bufSize = 128
	}
	flush := cfg.ReorderFlushTimeout
	if flush <= 0 {
		flush = 50 * time.Millisecond
	}
	state.inReorder = newClientReorderBuffer(bufSize, flush)
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
	state.tunWriteCh = make(chan []byte, 256)
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
	// We need the underlay to carry: IP+UDP headers + QUIC packet (which contains a DATAGRAM frame)
	// where the DATAGRAM payload is: DataPlaneHdr (11) + inner IP packet (<= TUN MTU).
	//
	// The previous logic subtracted a single "overhead" value from the probed MTU, but it didn't
	// include IP+UDP headers or the dataplane header, which can easily push us over the real wire MTU
	// and manifest as high loss / stalls on Windows.
	const (
		maxIPUDPOverhead         = 48 // IPv6(40)+UDP(8); worst-case safe even if underlay is IPv4
		datagramFrameOverhead    = 4  // type + varint length (worst-case budget)
		quicPacketOverheadBudget = 48 // short header + packet number + AEAD tag + misc (budget)
	)

	// Dynamic MTU adaptation: always probe if MTU not fixed by user
	// If user specifically requested probing, or if in auto mode (MTU=0)
	if (cfg.ProbePMTUD || cfg.MTU == 0) && ctrlHost != "" {
		vlogf("bonding: probing path MTU to %s...", ctrlHost)
		// Use AutoProbe to find the actual working wire MTU
		// Keep this short: if ICMP is blocked, probing will never succeed.
		probeTimeout := 1 * time.Second
		wireMTU, result := common.AutoProbePMTUD(ctrlHost, probeTimeout)

		if result.Success {
			vlogf("PMTUD: path supports wire MTU %d", wireMTU)
			// Calculate max safe TUN MTU.
			// Ensure: max wire packet size >= IP+UDP + QUIC packet size.
			// QUIC packet must fit a DATAGRAM with DataPlaneHdr + inner IP packet.
			safeTunMTU := wireMTU - maxIPUDPOverhead - quicPacketOverheadBudget - datagramFrameOverhead - common.DataPlaneHdrSize

			// Start with conservative defaults if calculation yields weird results
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
				// Standard safe fallback when ICMP is blocked.
				// 1200 is universally safe (well below 1280 IPv6 minimum after all overhead).
				mtu = 1200
			}
		}
	}

	// Update the config with the final determined MTU so that dialQUICMultipath sees it
	cfg.MTU = mtu
	state.cfg.MTU = mtu // Ensure state has the updated config!

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

	// Configure VPN routing: save old default route, add host routes for server via ALL interfaces, set default via TUN
	vlogf("bonding: dialing QUIC multipath with %d interfaces: %v", len(cfg.Ifaces), cfg.Ifaces)
	vlogf("bonding: configuring VPN routes")
	oldRoute, _, _, err := common.GetDefaultRoute()
	if err != nil {
		log.Printf("bonding: warning: could not get default route: %v", err)
	}
	var oldRoute6, oldVia6, oldDev6 string
	if enableIPv6 {
		oldRoute6, oldVia6, oldDev6, _ = common.GetDefaultRoute6()
	}

	// Add host routes for VPN server via ALL bonding interfaces (required for multipath)
	serverIP, _, _ := net.SplitHostPort(serverAddr)
	var addedHostRoutes []string
	if serverIP != "" {
		for _, iface := range cfg.Ifaces {
			gw, err := platform.GatewayForIface(bondingRunner{}, iface)
			if err != nil || gw == "" {
				vvlogf("bonding: skipping host route for %s (no gateway: %v)", iface, err)
				continue
			}
			// Use AddHostRoute (doesn't delete existing) so we can have multiple routes
			if err := common.AddHostRoute(serverIP, gw, iface); err != nil {
				vlogf("bonding: warning: could not add host route for server via %s/%s: %v", gw, iface, err)
			} else {
				vlogf("bonding: added host route for %s via %s/%s", serverIP, gw, iface)
				addedHostRoutes = append(addedHostRoutes, iface)
			}
		}
	}

	// Set default route via TUN
	// On Windows, use on-link routing (no explicit gateway) for TUN point-to-point
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

	// Save revert function
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
		// Remove host route for server
		if serverIP != "" {
			_ = common.DeleteHostRoute(serverIP)
		}
	}
	// Suppress unused variable warnings
	_, _, _ = oldVia6, oldDev6, oldRoute6

	// Create single MP-QUIC connection for multipath bonding
	cc := &clientConn{addr: serverAddr, iface: "multipath"}
	cc.alive.Store(true)
	state.connMu.Lock()
	state.conns = append(state.conns, cc)
	state.connMu.Unlock()

	// Start MP-QUIC read loop (handles datagram reception)
	state.wg.Add(1)
	go state.mpquicReadLoop(cc)

	// Start heartbeat loop (server alive + RTT/jitter sampling)
	state.wg.Add(1)
	go state.heartbeatLoop(cc)

	// Start TUN write loop
	go state.tunWriteLoop()

	// Start TUN reader with worker pool for sending
	workCh := make(chan []byte, 256)
	go state.tunReader(workCh)
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	for i := 0; i < numWorkers; i++ {
		state.wg.Add(1)
		go state.workerLoop(workCh)
	}

	stop := func() {
		cancel()
		telemetryStop()
		close(state.stopInReorder)
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
		// Final cleanup: flush DNS cache to ensure interfaces reconnect properly
		if runtime.GOOS == "windows" {
			_ = common.RunPrivileged("ipconfig", "/flushdns")
		}
	}
	return state, stop, nil
}

func (c *clientState) inboundReorderFlushLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.stopInReorder:
			return
		case <-c.inReorder.flushCh:
			c.inReorderStats.flushes.Add(1)
			pkts := c.inReorder.FlushTimeout()
			for _, p := range pkts {
				c.enqueueTunWrite(p)
			}
		}
	}
}

func addHostRoute(ip, via, dev string, useAdd bool) error {
	if useAdd {
		return common.AddHostRoute(ip, via, dev)
	}
	return common.EnsureHostRoute(ip, via, dev)
}

func addHostRoute6(ip, via, dev string, useAdd bool) error {
	if useAdd {
		return common.AddHostRoute6(ip, via, dev)
	}
	return common.EnsureHostRoute6(ip, via, dev)
}

func (c *clientState) setIfaceState(cc *clientConn, up bool) {
	if cc.iface == "" {
		return
	}
	if !updateIfaceUp(cc, up) {
		return
	}
	state := "down"
	if up {
		state = "up"
	}
	log.Printf("iface %s %s", cc.iface, state)
	vlogf("bonding: iface %s %s", cc.iface, state)
}

func (c *clientState) setConnState(cc *clientConn, alive bool, reason string) {
	if !updateConnAlive(cc, alive) {
		return
	}
	state := "disconnected"
	if alive {
		state = "connected"
	}
	label := cc.iface
	if label == "" {
		label = "default"
	}
	log.Printf("iface %s %s (%s)", label, state, reason)
	vlogf("bonding: iface=%s %s reason=%s local_ip=%s", label, state, reason, cc.localIP)
}

func updateConnAlive(cc *clientConn, alive bool) bool {
	if alive {
		return cc.alive.CompareAndSwap(false, true)
	}
	return cc.alive.CompareAndSwap(true, false)
}

func updateIfaceUp(cc *clientConn, up bool) bool {
	if up {
		return cc.ifaceUp.CompareAndSwap(false, true)
	}
	return cc.ifaceUp.CompareAndSwap(true, false)
}

func (c *clientState) setServerState(alive bool) {
	if alive {
		if c.serverAlive.CompareAndSwap(false, true) {
			log.Printf("server connected")
			vlogf("bonding: server connected")
		}
		return
	}
	if c.serverAlive.CompareAndSwap(true, false) {
		log.Printf("server disconnected")
		vlogf("bonding: server disconnected")
	}
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
	c.resetConns("session refresh")
	return nil
}

func (c *clientState) resetConns(reason string) {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	for _, cc := range c.conns {
		cc.mu.Lock()
		qc := cc.quicConn
		cc.mu.Unlock()
		if qc != nil {
			c.setConnState(cc, false, reason)
			_ = qc.CloseWithError(0, reason)
		}
		cc.lastRecv.Store(0)
	}
}

func (c *clientState) routeMonitor(routeTarget string, ifaces []string, serverIsV4 bool, fallbackVia, fallbackDev, fallbackVia6, fallbackDev6 string) {
	defer c.wg.Done()
	ticker := time.NewTicker(bondingRouteRefresh)
	defer ticker.Stop()
	runner := bondingRunner{}
	lastDev := ""
	lastVia := ""
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		if routeTarget == "" {
			continue
		}
		dev, via := pickGateway(runner, ifaces, !serverIsV4)
		if dev == "" {
			if serverIsV4 {
				dev = fallbackDev
				via = fallbackVia
			} else {
				dev = fallbackDev6
				via = fallbackVia6
			}
		}
		if dev == "" || (dev == lastDev && via == lastVia) {
			continue
		}
		var err error
		if serverIsV4 {
			err = common.EnsureHostRoute(routeTarget, via, dev)
		} else {
			err = common.EnsureHostRoute6(routeTarget, via, dev)
		}
		if err != nil {
			log.Printf("bonding: route refresh failed for %s via %s/%s: %v", routeTarget, dev, via, err)
			continue
		}
		lastDev = dev
		lastVia = via
	}
}

func pickGateway(r bondingRunner, ifaces []string, v6 bool) (string, string) {
	for _, iface := range ifaces {
		if !ifaceUp(iface) {
			continue
		}
		if v6 {
			gw6, err := platform.GatewayForIface6(r, iface)
			if err == nil && gw6 != "" {
				return iface, gw6
			}
			continue
		}
		gw, err := platform.GatewayForIface(r, iface)
		if err == nil && gw != "" {
			return iface, gw
		}
	}
	return "", ""
}

func ifaceUp(name string) bool {
	if name == "" {
		return true
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	return ifc.Flags&net.FlagUp != 0
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

func (c *clientState) closeConn(cc *clientConn) {
	cc.mu.Lock()
	if cc.quicConn != nil {
		_ = cc.quicConn.CloseWithError(0, "close")
		cc.quicConn = nil
	}
	if cc.packetConn != nil {
		_ = cc.packetConn.Close()
		cc.packetConn = nil
	}
	cc.mu.Unlock()
}

func (c *clientState) resetConnTelemetry(cc *clientConn) {
	cc.hbSent.Store(0)
	cc.hbRecv.Store(0)
	cc.jitterNano.Store(0)
	cc.rttNano.Store(0)
}

func (c *clientState) updateConnRTT(cc *clientConn, sample time.Duration) {
	prev := cc.rttNano.Load()
	if prev > 0 {
		delta := sample - time.Duration(prev)
		if delta < 0 {
			delta = -delta
		}
		j := time.Duration(cc.jitterNano.Load())
		j += (delta - j) / 16
		cc.jitterNano.Store(int64(j))
	}
	cc.rttNano.Store(int64(sample))
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

func dialUDP(server *net.UDPAddr, iface, ip string) (*net.UDPConn, error) {
	dialer, err := common.NewBoundUDPDialer(iface, ip)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.Dial("udp", server.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

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
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	var lines []string
	lines = append(lines, "[yellow]Bonding Metrics:[white]")
	now := time.Now()
	type connMetric struct {
		cc       *clientConn
		tx       uint64
		rx       uint64
		rateTxK  float64
		rateRxK  float64
		jitterMs float64
		loss     lossStats
		score    float64
		rtt      time.Duration
		isAlive  bool
		rateSumK float64
	}
	metrics := make([]connMetric, 0, len(c.conns))
	var totalTx, totalRx uint64
	var totalRateTx, totalRateRx float64
	var totalRate float64
	var maxRate float64
	active := 0
	var rttSum time.Duration
	var rttMin time.Duration
	var rttMax time.Duration
	rttCount := 0
	var totalHbSent uint64
	var totalHbRecv uint64
	var jitterSum float64
	var jitterCount int
	var scoreSum float64
	for _, cc := range c.conns {
		tx := cc.bytesSent.Load()
		rx := cc.bytesRecv.Load()
		totalTx += tx
		totalRx += rx
		isAlive := cc.alive.Load()
		if isAlive {
			active++
		}
		rtt := time.Duration(cc.rttNano.Load())
		jitterMs := float64(time.Duration(cc.jitterNano.Load())) / float64(time.Millisecond)
		sent := cc.hbSent.Load()
		recv := cc.hbRecv.Load()
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
		rateTxK, rateRxK := c.connRates(cc, tx, rx, now)
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
		metrics = append(metrics, connMetric{
			cc:       cc,
			tx:       tx,
			rx:       rx,
			rateTxK:  rateTxK,
			rateRxK:  rateRxK,
			jitterMs: jitterMs,
			loss:     loss,
			score:    score,
			rateSumK: rateSumK,
			rtt:      rtt,
			isAlive:  isAlive,
		})
	}
	for _, m := range metrics {
		alive := "[red]DOWN"
		if m.isAlive {
			alive = "[green]UP"
		}
		share := 0.0
		if totalRate > 0 {
			share = m.rateSumK / totalRate * 100
		}
		lossText := "-"
		if m.loss.ok {
			lossText = fmt.Sprintf("%.1f%%", m.loss.percent)
		}
		lines = append(lines, fmt.Sprintf("  %s %s | share: %3.0f%% | loss: %s | jitter: %.1f ms | score: %3.0f | TX: %s (%.1f kbps) | RX: %s (%.1f kbps) | RTT: %v",
			m.cc.iface, alive, share, lossText, m.jitterMs, m.score, fmtBytes(m.tx), m.rateTxK, fmtBytes(m.rx), m.rateRxK, m.rtt.Round(time.Millisecond)))
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
		active, len(c.conns), gain, lossText, jitterText, scoreText, rttLine, server))

	// Inbound reorder stats (server -> client)
	if c.inReorder != nil {
		lines = append(lines, "")
		lines = append(lines, "[yellow]Inbound Reorder (server->client):[white]")
		lines = append(lines, fmt.Sprintf("  bufferedEvents: %d  reorderedEvents: %d  drops: %d  flushes: %d  maxDepth: %d",
			c.inReorderStats.packetsBuffered.Load(),
			c.inReorderStats.packetsReordered.Load(),
			c.inReorderStats.packetsDropped.Load(),
			c.inReorderStats.flushes.Load(),
			c.inReorderStats.maxDepth.Load(),
		))
	}
	c.statsView.SetText(strings.Join(lines, "\n"))
}

func (c *clientState) connRates(cc *clientConn, tx, rx uint64, now time.Time) (float64, float64) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	rate, ok := c.rateByConn[cc]
	if !ok {
		rate = &ifaceRate{lastTx: tx, lastRx: rx, lastAt: now}
		c.rateByConn[cc] = rate
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

// ============================================================================
// MP-QUIC Functions
// ============================================================================

// mpquicReadLoop handles incoming QUIC datagrams (replaces old readLoop with UDP)
func (c *clientState) mpquicReadLoop(cc *clientConn) {
	defer c.wg.Done()
	backoff := bondingDialBackoff

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		cc.mu.Lock()
		qc := cc.quicConn
		cc.mu.Unlock()

		if qc == nil {
			// Dial QUIC multipath connection
			vlogf("bonding: dialing QUIC multipath to %s", c.serverAddr)
			conn, pconn, mpCtrl, err := dialQUICMultipath(c.ctx, c.serverAddr, c.cfg)
			if err != nil {
				vlogf("bonding: QUIC dial failed: %v, retry in %v", err, backoff)
				if !sleepWithContext(c.ctx, backoff) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
			cc.mu.Lock()
			cc.quicConn = conn
			cc.packetConn = pconn
			cc.mu.Unlock()
			c.mpController = mpCtrl
			cc.alive.Store(true)
			c.serverAlive.Store(true)
			backoff = bondingDialBackoff
			// Log path count from multipath controller
			numPaths := 0
			if mpCtrl != nil {
				numPaths = len(mpCtrl.GetAvailablePaths())
			}
			vlogf("bonding: QUIC multipath connected (paths=%d)", numPaths)
			qc = conn

			// Give QUIC time to stabilize before receiving
			time.Sleep(100 * time.Millisecond)
		}

		// Receive datagram from QUIC connection
		dat, err := qc.ReceiveDatagram(c.ctx)
		if err != nil {
			vlogf("bonding: QUIC receive error: %v", err)
			cc.mu.Lock()
			if cc.quicConn != nil {
				_ = cc.quicConn.CloseWithError(0, "receive error")
				if cc.packetConn != nil {
					_ = cc.packetConn.Close()
				}
			}
			cc.quicConn = nil
			cc.packetConn = nil
			cc.mu.Unlock()
			cc.alive.Store(false)
			c.serverAlive.Store(false)
			continue
		}

		vlogf("bonding: received raw datagram len=%d", len(dat))

		// Parse DataPlane datagram
		h, payload, err := common.ParseDataPlaneDatagram(dat)
		if err != nil {
			vlogf("bonding: parse datagram error: %v", err)
			continue
		}
		vvlogf("bonding: received datagram type=%d len=%d flags=0x%x seq=%d", h.Type, len(payload), h.Flags, h.SeqNum)

		cc.bytesRecv.Add(uint64(len(payload)))
		cc.lastRecv.Store(time.Now().UnixNano())

		switch h.Type {
		case common.DPTypeIP:
			// Compression disabled - use raw payload directly
			vvlogf("bonding: received IP packet seq=%d len=%d", h.SeqNum, len(payload))
			// Insert into reorder buffer and deliver in-order packets
			ordered := c.inReorder.Insert(h.SeqNum, payload)
			for _, p := range ordered {
				vvlogf("bonding: writing to TUN len=%d", len(p))
				c.enqueueTunWrite(p)
			}

		case common.DPTypeHeartbeat:
			var hb common.HeartbeatPayload
			if err := hb.Unmarshal(payload); err != nil {
				vlogf("bonding: heartbeat unmarshal error: %v", err)
				continue
			}
			rtt := common.CalcRTT(hb.SendTime)
			c.updateConnRTT(cc, rtt)
			cc.hbRecv.Add(1)
			vlogf("bonding: heartbeat received RTT=%v total=%d", rtt, cc.hbRecv.Load())
		}
	}
}

func (c *clientState) heartbeatLoop(cc *clientConn) {
	defer c.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			cc.mu.Lock()
			qc := cc.quicConn
			cc.mu.Unlock()
			if qc == nil {
				continue
			}
			hb := common.HeartbeatPayload{SendTime: common.NowMonoNano()}
			head := common.DataPlaneHeader{Version: common.DataPlaneVersion, Type: common.DPTypeHeartbeat, SessionID: c.sessionID, SeqNum: 0, Flags: 0}
			dg, err := common.BuildDataPlaneDatagram(nil, head, hb.Marshal())
			if err != nil {
				continue
			}
			if err := qc.SendDatagram(dg); err == nil {
				cc.hbSent.Add(1)
				vlogf("bonding: heartbeat sent total=%d", cc.hbSent.Load())
			} else {
				vlogf("bonding: heartbeat send error: %v", err)
			}
		}
	}
}

// dialQUICMultipath creates a MP-QUIC connection with multipath support
func dialQUICMultipath(ctx context.Context, addr string, cfg clientConfig) (*quic.Conn, net.PacketConn, *quic.DefaultMultipathController, error) {
	tlsCfg, err := clientTLSConfig(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tls config: %w", err)
	}
	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"fluxify-quic"}

	// Configure multipath controller with LowLatency scheduler.
	// LowLatencyScheduler uses the fastest path (lowest RTT), which is safer with asymmetric setups.
	// NOTE: RoundRobinScheduler causes issues with path/ACK synchronization, disabled for now.
	mpCtrl := quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler())
	// NOTE: Packet duplication is DISABLED - it causes PROTOCOL_VIOLATION errors
	// "received an ACK for skipped packet number" when multipath sends duplicate ACKs
	// mpCtrl.EnablePacketDuplication(true)
	// mpCtrl.SetDuplicationParameters(true, 10)
	maxPaths := len(cfg.Ifaces)
	if maxPaths < 2 {
		maxPaths = 2
	}
	if maxPaths > 8 {
		maxPaths = 8
	}

	// Resolve server address
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve addr: %w", err)
	}

	wantV4 := ua.IP.To4() != nil
	localAddrs, err := collectLocalAddrs(cfg.Ifaces, cfg.IPs, wantV4)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("collect local addrs: %w", err)
	}
	// Log at verbose level (not very-verbose) so multipath setup is visible in normal -v runs
	vlogf("bonding: multipath local addresses=%v (ifaces=%v, ipv4=%v)", localAddrs, cfg.Ifaces, wantV4)

	// Choose a conservative QUIC InitialPacketSize.
	// This value is also used by mp-quic-go as the initial path MTU estimate.
	// If it's too SMALL, SendDatagram can fail with "DATAGRAM frame too large".
	// If it's too LARGE, some paths (esp. Wi-Fi / ISP) may drop packets.
	//
	// We need to fit: DataPlaneHdr (11) + inner IP packet (<= MTU) as QUIC DATAGRAM payload.
	// Budget some space for the DATAGRAM frame encoding and QUIC header/encryption overhead.
	//
	// NOTE: InitialPacketSize is the UDP payload size (QUIC packet size), i.e. it does NOT include
	// IP+UDP headers. For IPv6 underlay, the minimum MTU is 1280, so max UDP payload is 1232.
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

	vlogf("bonding: QUIC InitialPacketSize=%d (cfg.MTU=%d)", initialPacketSize, cfg.MTU)

	// On Windows, multipath doesn't work reliably (neither MultiSocketManager nor MultipathAutoPaths).
	// Force single-path mode on Windows until we find a working solution.
	forceSinglePath := len(localAddrs) <= 1
	if runtime.GOOS == "windows" && len(localAddrs) > 1 {
		vlogf("bonding: WARNING - Windows multipath not yet supported, using first interface only")
		localAddrs = localAddrs[:1] // Use only the first interface
		forceSinglePath = true
	}

	if forceSinglePath {
		vlogf("bonding: using SINGLE PATH mode (simpler socket handling)")
	} else {
		vlogf("bonding: using MULTIPATH mode with %d interfaces", len(localAddrs))
	}

	// In single-path mode, set MultipathAutoAddrs to nil to avoid any multipath logic
	var autoAddrs []net.IP
	if !forceSinglePath {
		autoAddrs = localAddrs
	}

	qc := &quic.Config{
		EnableDatagrams:        true,
		InitialPacketSize:      initialPacketSize,
		MaxIdleTimeout:         2 * time.Minute,
		KeepAlivePeriod:        5 * time.Second,
		MaxPaths:               1,   // Force single path when forceSinglePath
		MultipathController:    nil, // No multipath controller in single-path mode
		MultipathAutoPaths:     false,
		MultipathAutoAdvertise: false,
		MultipathAutoAddrs:     nil,
	}
	if !forceSinglePath {
		qc.MaxPaths = maxPaths
		qc.MultipathController = mpCtrl
		qc.MultipathAutoPaths = true
		qc.MultipathAutoAdvertise = len(localAddrs) > 0
		qc.MultipathAutoAddrs = autoAddrs
	}

	// Base socket determines the local port; the manager binds additional sockets to the same port.
	// On Windows, using network "udp" may create a dual-stack socket that is shown as [::]
	// even when we intend IPv4. Force the address family to keep multipath socket/path bookkeeping
	// consistent.
	baseNetwork := "udp6"
	baseIP := net.IPv6unspecified
	if wantV4 {
		baseNetwork = "udp4"
		baseIP = net.IPv4zero.To4()
	}
	base, err := net.ListenUDP(baseNetwork, &net.UDPAddr{IP: baseIP, Port: 0})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen udp base: %w", err)
	}
	vvlogf("bonding: QUIC base UDP local=%s", base.LocalAddr())

	// For single-path mode, use the base socket directly without MultiSocketManager
	// This simplifies the receive path and may fix issues with socket/path mismatches
	if forceSinglePath {
		vlogf("bonding: using direct UDP socket (no MultiSocketManager)")

		// On Windows, bind to specific IP to ensure responses come back on the right socket
		if runtime.GOOS == "windows" && len(localAddrs) > 0 {
			_ = base.Close() // close the 0.0.0.0 socket
			specificAddr := &net.UDPAddr{IP: localAddrs[0], Port: 0}
			base, err = net.ListenUDP(baseNetwork, specificAddr)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("listen udp specific: %w", err)
			}
			vlogf("bonding: bound to specific IP %s", base.LocalAddr())
		}

		conn, err := quic.Dial(ctx, base, ua, tlsCfg, qc)
		if err != nil {
			_ = base.Close()
			return nil, nil, nil, fmt.Errorf("quic dial: %w", err)
		}
		vlogf("bonding: QUIC connected local=%s remote=%s", conn.LocalAddr(), conn.RemoteAddr())
		return conn, base, mpCtrl, nil
	}

	// Multipath mode (Linux only for now - Windows uses single-path above)
	basePort := 0
	if la, ok := base.LocalAddr().(*net.UDPAddr); ok {
		basePort = la.Port
	}

	mgr, err := quic.NewMultiSocketManager(quic.MultiSocketManagerConfig{
		BaseConn:        base,
		ListenPort:      basePort,
		LocalAddrs:      localAddrs,
		RefreshInterval: 0,
		IncludeLoopback: false,
		AllowIPv6:       !wantV4,
	})
	if err != nil {
		_ = base.Close()
		return nil, nil, nil, fmt.Errorf("multi-socket manager: %w", err)
	}

	conn, err := quic.Dial(ctx, mgr, ua, tlsCfg, qc)
	if err != nil {
		_ = mgr.Close()
		return nil, nil, nil, fmt.Errorf("quic dial: %w", err)
	}
	vvlogf("bonding: QUIC connected local=%s remote=%s", conn.LocalAddr(), conn.RemoteAddr())

	return conn, mgr, mpCtrl, nil
}

// tunWriteLoop writes packets to TUN device
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

// tunReader reads from TUN and sends to worker channel
func (c *clientState) tunReader(workCh chan<- []byte) {
	for {
		buf := common.GetBuffer()
		n, err := c.tun.Read(buf)
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
		case workCh <- buf[:n]:
		case <-c.ctx.Done():
			common.PutBuffer(buf)
			return
		}
	}
}

// workerLoop processes TUN packets and sends them via QUIC
func (c *clientState) workerLoop(workCh <-chan []byte) {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case data, ok := <-workCh:
			if !ok {
				return
			}
			c.processAndSend(data)
		}
	}
}

// processAndSend builds and sends a datagram via QUIC
func (c *clientState) processAndSend(data []byte) {
	if c.ctx.Err() != nil {
		common.PutBuffer(data)
		return
	}
	cc := c.pickBestConn()
	if cc == nil {
		common.PutBuffer(data)
		return
	}

	cc.mu.Lock()
	qc := cc.quicConn
	cc.mu.Unlock()
	if qc == nil {
		common.PutBuffer(data)
		return
	}

	seq := c.nextSeqSend.Add(1)

	head := common.DataPlaneHeader{
		Version:   common.DataPlaneVersion,
		Type:      common.DPTypeIP,
		SessionID: c.sessionID,
		SeqNum:    seq,
		Flags:     0, // No compression
	}

	dgram, err := common.BuildDataPlaneDatagram(nil, head, data)
	if err != nil {
		common.PutBuffer(data)
		return
	}

	if err := qc.SendDatagram(dgram); err != nil {
		// During shutdown / reconnects it's normal for queued packets to fail sending.
		// Don't spam logs for expected close-related errors.
		if c.ctx.Err() == nil && c.serverAlive.Load() {
			vlogf("bonding: send datagram error: %v", err)
		} else {
			vvlogf("bonding: send datagram error (suppressed): %v", err)
		}
	} else {
		cc.bytesSent.Add(uint64(len(data)))
	}
	common.PutBuffer(data)
}

// enqueueTunWrite adds a packet to the TUN write queue
func (c *clientState) enqueueTunWrite(buf []byte) {
	select {
	case c.tunWriteCh <- buf:
	default:
		// Queue full, drop packet
		common.PutBuffer(buf)
	}
}

// pickBestConn returns the best connection (MP-QUIC handles path selection internally)
func (c *clientState) pickBestConn() *clientConn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	for _, cc := range c.conns {
		if cc.alive.Load() {
			return cc
		}
	}
	if len(c.conns) > 0 {
		return c.conns[0]
	}
	return nil
}

// closeAllConns closes all QUIC connections
func (c *clientState) closeAllConns() {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	for _, cc := range c.conns {
		cc.mu.Lock()
		if cc.quicConn != nil {
			_ = cc.quicConn.CloseWithError(0, "shutdown")
		}
		if cc.packetConn != nil {
			_ = cc.packetConn.Close()
		}
		cc.quicConn = nil
		cc.packetConn = nil
		cc.mu.Unlock()
	}
}

// sessionSnapshot returns current session info (no longer returns key)
func (c *clientState) sessionSnapshot() (uint32, string) {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.sessionID, c.serverAddr
}
