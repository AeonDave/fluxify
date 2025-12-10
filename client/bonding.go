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
	"strconv"
	"strings"
	"time"

	"github.com/songgao/water"

	"fluxify/common"
)

func startBondingClientCore(cfg clientConfig) (*clientState, func(), error) {
	if cfg.Client == "" {
		return nil, nil, fmt.Errorf("client name required")
	}
	// Bonding requires TUN device which needs root
	if common.NeedsElevation() {
		log.Printf("bonding: TUN requires root, requesting elevation...")
		// Pass current config as CLI args so the elevated process starts with same settings
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
		// RelaunchWithPkexec uses syscall.Exec, so we won't reach here on success
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
	state := &clientState{serverUDP: serverUDP, sessionID: sessID, sessionKey: key, mode: cfg.Mode, ctx: ctx, cancel: cancel}

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

	// Determine if the server is a loopback address. In that case we should NOT
	// manipulate routing or bind sockets to specific interfaces, otherwise
	// localhost testing breaks (SO_BINDTODEVICE cannot reach 127.0.0.1).
	isLoopback := serverUDP.IP != nil && serverUDP.IP.IsLoopback()
	if !isLoopback {
		log.Printf("bonding: setting up routing")
		// Ensure server control address remains reachable after changing default route.
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
		// host route to control/server via current default so TLS/UDP stay reachable.
		if serverUDP.IP.To4() != nil {
			_ = common.EnsureHostRoute(serverHost, via, dev)
		} else {
			_ = common.EnsureHostRoute6(serverHost, via6, dev6)
		}
		// Replace default routes to go via TUN device.
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
			// best-effort restore
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
			// Do not bind to a specific device or local IP when talking to 127.0.0.1
			// or ::1 — binding breaks loopback delivery.
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

	state.wg.Add(1)
	go state.tunToServer()
	state.wg.Add(1)
	go state.heartbeat()

	stop := func() {
		// Signal goroutines to stop first
		cancel()
		// Proactively close dataplane sockets to unblock any blocking I/O:
		// - Close UDP conns so readLoop exits immediately (without waiting for read deadlines)
		state.connMu.Lock()
		for _, c := range state.conns {
			_ = c.udp.Close()
		}
		state.connMu.Unlock()
		// - Close TUN so tunToServer unblocks from Read and exits promptly
		if state.tun != nil {
			_ = state.tun.Close()
		}
		// Wait for all goroutines to finish after resources are closed
		state.wg.Wait()
		// Finally, revert any route changes
		if state.revertRoute != nil {
			state.revertRoute()
		}
	}
	return state, stop, nil
}

func parseServerAddr(server string, ctrlPort int) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		// if missing port, use provided ctrlPort
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

	// Ensure ServerName is set for SNI/verification when using tls.Client.
	if host, _, herr := net.SplitHostPort(ctrlAddr); herr == nil {
		// Clone to avoid mutating shared config
		c := tlsCfg.Clone()
		c.ServerName = host
		tlsCfg = c
	}

	// Establish TCP with a context timeout, then perform TLS handshake with a deadline.
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()

	tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ctrlAddr)
	if err != nil {
		return nil, 0, 0, "", "", classifyTLSError(err)
	}

	// Wrap with TLS client and perform handshake explicitly so we can apply deadlines and classify errors.
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
	// Ensure the server sees EOF so it can finish io.ReadAll.
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

// addIPv6CIDR appends /64 to a bare IPv6 address.
func addIPv6CIDR(ip string) string {
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + "/64"
}

// classifyTLSError maps low-level TLS/x509/timeout errors to user-friendly messages.
func classifyTLSError(err error) error {
	// Deadline/timeout
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "i/o timeout") {
		return fmt.Errorf("timeout nella connessione/handshake TLS con il server di controllo: %v", err)
	}
	// Server rejected client cert during handshake
	if strings.Contains(err.Error(), "tls: bad certificate") {
		return fmt.Errorf("il server ha rifiutato il certificato client (bad certificate): verifica che il client .pem contenga cert e key corretti e siano firmati dalla CA")
	}
	// Unknown CA
	var ua *x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		return fmt.Errorf("CA sconosciuta: verifica il certificato CA nel bundle .pem e il server usato")
	}
	// Hostname mismatch
	var hn *x509.HostnameError
	if errors.As(err, &hn) {
		return fmt.Errorf("il nome del server non corrisponde al certificato (%s)", hn.Error())
	}
	// Certificate invalid/expired
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) {
		switch ci.Reason {
		case x509.Expired:
			return fmt.Errorf("certificato scaduto: rigenera o usa un certificato valido")
		default:
			return fmt.Errorf("certificato non valido: %v", ci)
		}
	}
	// Generic handshake failure
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
