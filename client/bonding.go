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

	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

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
	if len(cfg.Ifaces) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 usable interfaces for bonding")
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
	ctrlHost, ctrlPort, err := parseServerAddr(cfg.Server, cfg.Ctrl)
	if err != nil {
		return nil, nil, err
	}
	ctrlAddr := net.JoinHostPort(ctrlHost, fmt.Sprintf("%d", ctrlPort))

	vlogf("bonding: fetching session from %s", ctrlAddr)
	key, sessID, udpPort, clientIP, clientIPv6, err := fetchSession(ctrlAddr, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("control: %w", err)
	}
	vlogf("bonding: session id=%d udp=%d ip4=%s ip6=%s", sessID, udpPort, clientIP, clientIPv6)

	serverUDP, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ctrlHost, fmt.Sprintf("%d", udpPort)))
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &clientState{
		serverUDP:  serverUDP,
		sessionID:  sessID,
		sessionKey: key,
		clientIP:   clientIP,
		clientIPv6: clientIPv6,
		mode:       cfg.Mode,
		ctx:        ctx,
		cancel:     cancel,
		ctrlAddr:   ctrlAddr,
		cfg:        cfg,
		rateByConn: make(map[*clientConn]*ifaceRate),
	}

	vlogf("bonding: creating TUN device")
	tun, err := createTunDevice()
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
	vlogf("bonding: configuring TUN with %s/24 (IPv4) and %s (IPv6)", clientIP, ipv6CIDR)
	if err := common.ConfigureTUN(common.TUNConfig{IfaceName: tun.Name(), CIDR: clientIP + "/24", IPv6CIDR: ipv6CIDR, MTU: common.MTU}); err != nil {
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

	isLoopback := serverUDP.IP != nil && serverUDP.IP.IsLoopback()
	serverIsV4 := serverUDP.IP.To4() != nil
	routeTarget := ""
	var fallbackVia, fallbackDev, fallbackVia6, fallbackDev6 string
	if !isLoopback {
		vlogf("bonding: setting up routing")
		oldRoute, via, dev, err := common.GetDefaultRoute()
		if err != nil {
			_ = state.tun.Close()
			cancel()
			return nil, nil, fmt.Errorf("get default route: %w", err)
		}
		fallbackVia = via
		fallbackDev = dev
		oldRoute6, via6, dev6, err := common.GetDefaultRoute6()
		if err != nil {
			_ = state.tun.Close()
			cancel()
			return nil, nil, fmt.Errorf("get default route v6: %w", err)
		}
		fallbackVia6 = via6
		fallbackDev6 = dev6
		serverHost, _, _ := net.SplitHostPort(cfg.Server)
		serverIP := serverUDP.IP.String()
		routeTarget = serverHost
		if net.ParseIP(routeTarget) == nil && serverIP != "" {
			routeTarget = serverIP
		}
		if routeTarget == "" {
			routeTarget = serverIP
		}
		runner := bondingRunner{}
		routesAdded := 0
		useAddRoute := runtime.GOOS == "windows"
		if serverIsV4 {
			if useAddRoute {
				_ = common.DeleteHostRoute(routeTarget)
			}
			for _, iface := range cfg.Ifaces {
				gw, err := platform.GatewayForIface(runner, iface)
				if err != nil || gw == "" {
					continue
				}
				if err := addHostRoute(routeTarget, gw, iface, useAddRoute); err != nil {
					log.Printf("bonding: warning: host route via %s/%s failed: %v", iface, gw, err)
					continue
				}
				routesAdded++
			}
			if routesAdded == 0 {
				if err := addHostRoute(routeTarget, via, dev, useAddRoute); err != nil {
					return nil, nil, fmt.Errorf("host route to server failed: %w", err)
				}
				routesAdded++
			}
		} else {
			if useAddRoute {
				_ = common.DeleteHostRoute6(routeTarget)
			}
			for _, iface := range cfg.Ifaces {
				gw6, err := platform.GatewayForIface6(runner, iface)
				if err != nil || gw6 == "" {
					continue
				}
				if err := addHostRoute6(routeTarget, gw6, iface, useAddRoute); err != nil {
					log.Printf("bonding: warning: host route v6 via %s/%s failed: %v", iface, gw6, err)
					continue
				}
				routesAdded++
			}
			if routesAdded == 0 {
				if err := addHostRoute6(routeTarget, via6, dev6, useAddRoute); err != nil {
					return nil, nil, fmt.Errorf("host route v6 to server failed: %w", err)
				}
				routesAdded++
			}
		}
		if runtime.GOOS == "windows" {
			gw := defaultGatewayIP(clientIP)
			if err := common.SetDefaultRouteDevWithGateway(tun.Name(), gw); err != nil {
				if serverIsV4 {
					_ = common.DeleteHostRoute(routeTarget)
				} else {
					_ = common.DeleteHostRoute6(routeTarget)
				}
				_ = state.tun.Close()
				cancel()
				return nil, nil, fmt.Errorf("set default route: %w", err)
			}
		} else if err := common.SetDefaultRouteDev(tun.Name()); err != nil {
			if serverIsV4 {
				_ = common.DeleteHostRoute(routeTarget)
			} else {
				_ = common.DeleteHostRoute6(routeTarget)
			}
			_ = state.tun.Close()
			cancel()
			return nil, nil, fmt.Errorf("set default route: %w", err)
		}
		if enableIPv6 {
			if err := common.SetDefaultRouteDev6(tun.Name()); err != nil {
				log.Printf("bonding: warning: failed to set IPv6 default via TUN: %v", err)
			}
		}
		state.revertRoute = func() {
			_ = common.ReplaceDefaultRoute(oldRoute)
			if enableIPv6 && oldRoute6 != "" {
				_ = common.ReplaceDefaultRoute6(oldRoute6)
			}
			if serverIsV4 {
				_ = common.DeleteHostRoute(routeTarget)
			} else {
				_ = common.DeleteHostRoute6(routeTarget)
			}
		}
	} else {
		vlogf("bonding: loopback server detected (%s); skipping route changes and iface binding for testing", serverUDP.String())
	}

	numConns := len(cfg.Ifaces)
	for i := 0; i < numConns; i++ {
		iface := pickIndex(cfg.Ifaces, i)
		ip := pickIndex(cfg.IPs, i)
		if isLoopback {
			iface = ""
			ip = ""
		}
		cc := &clientConn{addr: serverUDP, iface: iface, localIP: ip}
		cc.ifaceUp.Store(ifaceUp(iface))
		state.connMu.Lock()
		state.conns = append(state.conns, cc)
		state.connMu.Unlock()
		state.wg.Add(1)
		go state.readLoop(cc)
	}

	if runtime.GOOS == "linux" && !isLoopback && routeTarget != "" {
		state.wg.Add(1)
		go state.routeMonitor(routeTarget, cfg.Ifaces, serverIsV4, fallbackVia, fallbackDev, fallbackVia6, fallbackDev6)
	}

	// Worker pool for TUN -> UDP
	numWorkers := runtime.NumCPU()
	workCh := make(chan []byte, numWorkers*10)

	state.wg.Add(1)
	go state.tunWriteLoop()

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
			c.mu.Lock()
			if c.udp != nil {
				_ = c.udp.Close()
				c.udp = nil
			}
			c.mu.Unlock()
		}
		state.connMu.Unlock()
		if state.tun != nil {
			_ = state.tun.Close()
		}
		state.wg.Wait()
		if state.revertDNS != nil {
			state.revertDNS()
		}
		if len(state.ifaceDNS) > 0 {
			restoreIfaceDNS(state.ifaceDNS)
		}
		if state.revertRoute != nil {
			state.revertRoute()
		}
	}
	return state, stop, nil
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
		key, sessID, udpPort, clientIP, clientIPv6, err := fetchSession(c.ctrlAddr, c.cfg)
		if err != nil {
			vlogf("bonding: control reconnect failed: %v", err)
			if !sleepWithContext(c.ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		if err := c.updateSession(key, sessID, udpPort, clientIP, clientIPv6); err != nil {
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

func (c *clientState) updateSession(key []byte, sessID uint32, udpPort int, clientIP, clientIPv6 string) error {
	host, _, err := net.SplitHostPort(c.ctrlAddr)
	if err != nil {
		host = c.ctrlAddr
	}
	serverUDP, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", udpPort)))
	if err != nil {
		return err
	}
	c.sessMu.Lock()
	oldIP := c.clientIP
	oldIPv6 := c.clientIPv6
	c.sessionKey = key
	c.sessionID = sessID
	c.serverUDP = serverUDP
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
		udp := cc.udp
		cc.mu.Unlock()
		if udp != nil {
			c.setConnState(cc, false, reason)
			c.closeConn(cc, udp)
		}
		cc.lastRecv.Store(0)
	}
}

func (c *clientState) sessionSnapshot() ([]byte, uint32, *net.UDPAddr) {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.sessionKey, c.sessionID, c.serverUDP
}

func (c *clientState) sessionServer() *net.UDPAddr {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.serverUDP
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

func (c *clientState) closeConn(cc *clientConn, udp *net.UDPConn) {
	cc.mu.Lock()
	if cc.udp == udp {
		_ = cc.udp.Close()
		cc.udp = nil
	}
	cc.mu.Unlock()
}

func (c *clientState) resetConnTelemetry(cc *clientConn) {
	cc.hbSent.Store(0)
	cc.hbRecv.Store(0)
	cc.jitterNano.Store(0)
	cc.lastRTTSample.Store(0)
	cc.rttNano.Store(0)
}

func (c *clientState) updateConnRTT(cc *clientConn, sample time.Duration) {
	prev := cc.lastRTTSample.Load()
	if prev > 0 {
		delta := sample - time.Duration(prev)
		if delta < 0 {
			delta = -delta
		}
		j := time.Duration(cc.jitterNano.Load())
		j += (delta - j) / 16
		cc.jitterNano.Store(int64(j))
	}
	cc.lastRTTSample.Store(int64(sample))
	cc.rttNano.Store(int64(sample))
}

func dialUDPWithFallback(server *net.UDPAddr, iface, ip string) (*net.UDPConn, string, error) {
	udp, err := dialUDP(server, iface, ip)
	if err == nil || ip == "" {
		return udp, ip, err
	}
	udp, err = dialUDP(server, iface, "")
	if err != nil {
		return nil, ip, err
	}
	return udp, "", nil
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

func (c *clientState) readLoop(cc *clientConn) {
	defer c.wg.Done()
	// Reuse buffer for reading UDP packets.
	buf := common.GetBuffer()
	defer common.PutBuffer(buf)
	backoff := bondingDialBackoff

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		cc.mu.Lock()
		udp := cc.udp
		cc.mu.Unlock()
		if udp == nil {
			up := ifaceUp(cc.iface)
			c.setIfaceState(cc, up)
			if !up {
				c.setConnState(cc, false, "interface down")
				if !sleepWithContext(c.ctx, backoff) {
					return
				}
				continue
			}
			server := c.sessionServer()
			if server == nil {
				c.setConnState(cc, false, "no server")
				if !sleepWithContext(c.ctx, backoff) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
			udp, usedIP, err := dialUDPWithFallback(server, cc.iface, cc.localIP)
			if err != nil {
				c.setConnState(cc, false, "dial error")
				vlogf("conn %s dial err: %v", cc.iface, err)
				if !sleepWithContext(c.ctx, backoff) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
			cc.localIP = usedIP
			backoff = bondingDialBackoff
			cc.mu.Lock()
			cc.udp = udp
			cc.mu.Unlock()
			c.resetConnTelemetry(cc)
			cc.lastConn.Store(time.Now().UnixNano())
			c.setConnState(cc, true, "connected")
			c.sendHandshake(cc)
		}

		cc.mu.Lock()
		udp = cc.udp
		cc.mu.Unlock()
		if udp == nil {
			continue
		}
		_ = udp.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := udp.Read(buf)
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
			c.setConnState(cc, false, "read error")
			vlogf("conn %s read err: %v", cc.iface, err)
			c.closeConn(cc, udp)
			continue
		}

		cc.lastRecv.Store(time.Now().UnixNano())
		c.setConnState(cc, true, "traffic")

		// Decrypt into a separate buffer to avoid invalid overlap (panic).
		plainBuf := common.GetBuffer()
		key, _, _ := c.sessionSnapshot()
		if len(key) == 0 {
			common.PutBuffer(plainBuf)
			continue
		}
		h, payload, err := common.DecryptPacketInto(plainBuf, key, buf[:n])
		if err != nil {
			common.PutBuffer(plainBuf)
			continue
		}
		cc.bytesRecv.Add(uint64(len(payload)))

		switch h.Type {
		case common.PacketHeartbeat:
			var hb common.HeartbeatPayload
			if err := hb.Unmarshal(payload); err == nil {
				c.updateConnRTT(cc, common.CalcRTT(hb.SendTime))
				cc.hbRecv.Add(1)
			}
			common.PutBuffer(plainBuf)
		case common.PacketIP:
			// Handle compression
			if h.Reserved[0] == common.CompressionGzip {
				// Decompress into yet another buffer
				outBuf := common.GetBuffer()
				dec, err := common.DecompressPayloadInto(outBuf, payload, common.MaxPacketSize)
				if err == nil {
					c.enqueueTunWrite(dec)
				} else {
					log.Printf("decompress err: %v", err)
					common.PutBuffer(outBuf)
				}
				common.PutBuffer(plainBuf) // Release compressed payload buffer
			} else {
				c.enqueueTunWrite(plainBuf[:len(payload)])
			}
		default:
			common.PutBuffer(plainBuf)
		}
	}
}

func (c *clientState) enqueueTunWrite(buf []byte) {
	if len(buf) == 0 {
		common.PutBuffer(buf)
		return
	}
	select {
	case <-c.ctx.Done():
		common.PutBuffer(buf)
	case c.tunWriteCh <- buf:
	default:
		vlogf("tun: drop inbound len=%d", len(buf))
		common.PutBuffer(buf)
	}
}

func (c *clientState) tunWriteLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case buf := <-c.tunWriteCh:
			if c.tun == nil {
				common.PutBuffer(buf)
				continue
			}
			if _, err := c.tun.Write(buf); err != nil {
				log.Printf("tun write err: %v", err)
			}
			common.PutBuffer(buf)
		}
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
		if n == 0 {
			common.PutBuffer(buf)
			continue
		}
		pkt := buf[:n]
		if !isIPPacket(pkt) {
			vlogf("tun: dropping non-ip packet len=%d", n)
			common.PutBuffer(buf)
			continue
		}
		// Send valid slice to worker
		select {
		case workCh <- pkt:
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

	key, sessID, _ := c.sessionSnapshot()
	if len(key) == 0 || sessID == 0 {
		return
	}
	head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketIP, SessionID: sessID, SeqNum: seq, Length: uint16(len(compressed))}
	head.Reserved[0] = byte(compressFlag)

	// Encrypt into new packet buffer
	pktBuf := common.GetBuffer()
	defer common.PutBuffer(pktBuf)

	pkt, err := common.EncryptPacketInto(pktBuf, key, head, compressed)
	if err != nil {
		return
	}

	cc.mu.Lock()
	if cc.udp != nil {
		_, _ = cc.udp.Write(pkt)
	}
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
	key, sessID, _ := c.sessionSnapshot()
	if len(key) == 0 || sessID == 0 {
		return
	}
	head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketHandshake, SessionID: sessID, SeqNum: 0, Length: 0}
	pkt, err := common.EncryptPacket(key, head, nil)
	if err != nil {
		return
	}
	cc.mu.Lock()
	if cc.udp != nil {
		_, _ = cc.udp.Write(pkt)
	}
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
		now := time.Now()
		key, sessID, _ := c.sessionSnapshot()
		if len(key) == 0 || sessID == 0 {
			continue
		}
		hb := common.HeartbeatPayload{SendTime: common.NowMonoNano()}
		payload := hb.Marshal()
		c.connMu.RLock()
		anyAlive := false
		for _, cc := range c.conns {
			up := ifaceUp(cc.iface)
			c.setIfaceState(cc, up)
			if !up {
				c.setConnState(cc, false, "interface down")
			}
			if last := cc.lastRecv.Load(); last > 0 && now.Sub(time.Unix(0, last)) > bondingDeadAfter {
				c.setConnState(cc, false, "timeout")
				cc.mu.Lock()
				udp := cc.udp
				cc.mu.Unlock()
				if udp != nil {
					c.closeConn(cc, udp)
				}
			} else if last == 0 {
				if connAt := cc.lastConn.Load(); connAt > 0 && now.Sub(time.Unix(0, connAt)) > bondingDeadAfter {
					c.setConnState(cc, false, "no response")
					cc.mu.Lock()
					udp := cc.udp
					cc.mu.Unlock()
					if udp != nil {
						c.closeConn(cc, udp)
					}
				}
			}
			if cc.alive.Load() {
				anyAlive = true
			}
			head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketHeartbeat, SessionID: sessID, SeqNum: 0, Length: uint16(len(payload))}
			if pkt, err := common.EncryptPacket(key, head, payload); err == nil {
				cc.mu.Lock()
				if cc.udp != nil {
					_, _ = cc.udp.Write(pkt)
					cc.hbSent.Add(1)
				}
				cc.mu.Unlock()
			}
		}
		c.connMu.RUnlock()
		c.setServerState(anyAlive)
		if !anyAlive {
			c.ensureReconnect()
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

	req := common.ControlRequest{}
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
		bundlePath, err = detectClientBundlePath(cfg.PKI)
		if err != nil {
			return nil, err
		}
	} else {
		bundlePath = expandPath(bundlePath)
	}
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
