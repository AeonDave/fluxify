package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rivo/tview"
	"github.com/songgao/water"

	"fluxify/common"
)

const (
	modeBonding     = "bonding"
	modeLoadBalance = "load-balance"
	controlTimeout  = 10 * time.Second
)

type clientConn struct {
	udp       *net.UDPConn
	addr      *net.UDPAddr
	iface     string
	alive     atomic.Bool
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	rttNano   atomic.Int64
	mu        sync.Mutex
}

type clientState struct {
	serverUDP   *net.UDPAddr
	sessionID   uint32
	sessionKey  []byte
	conns       []*clientConn
	connMu      sync.RWMutex
	nextSeqSend atomic.Uint32
	tun         *water.Interface
	mode        string
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	revertRoute func()
	statsView   *tview.TextView // for dynamic updates
}

type clientConfig struct {
	Server        string
	Ifaces        []string
	IPs           []string
	Conns         int
	Mode          string
	PKI           string
	Client        string
	Ctrl          int
	PolicyRouting bool
	Gateways      []string
}

type storedConfig struct {
	Server string   `json:"server"`
	Mode   string   `json:"mode"`
	Ifaces []string `json:"ifaces"`
	Client string   `json:"client"`
	PKI    string   `json:"pki"`
	Ctrl   int      `json:"ctrl"`
}

// splitCSV splits a comma-separated string into trimmed parts.
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

// pickIndex picks element i modulo len(list) or empty string.
func pickIndex(list []string, i int) string {
	if len(list) == 0 {
		return ""
	}
	return list[i%len(list)]
}

func main() {
	server := flag.String("server", "", "server host:port (optional, overridden by TUI)")
	ifacesStr := flag.String("ifaces", "", "comma-separated interface names (optional)")
	localIPs := flag.String("ips", "", "comma-separated source IPs (optional)")
	nconns := flag.Int("conns", 2, "number of parallel UDP conns")
	bondingFlag := flag.Bool("b", false, "force bonding mode")
	loadBalanceFlag := flag.Bool("l", false, "force load-balance mode")
	tuiAutoStart := flag.Bool("tui-autostart", false, "internal: launch TUI and auto-start (used after elevation)")
	pkiDir := flag.String("pki", "", "PKI directory (defaults to ~/.fluxify)")
	clientName := flag.String("client", "", "client certificate name (CN)")
	ctrlPort := flag.Int("ctrl", 8443, "control TLS port")
	policyRouting := flag.Bool("policy-routing", false, "install per-interface policy routing (linux only)")
	gateways := flag.String("gws", "", "comma-separated gateways matching ifaces/IPs (optional)")
	flag.Parse()

	chosenPKI := *pkiDir
	if chosenPKI == "" || chosenPKI == "./pki" {
		chosenPKI = defaultPKIDir()
	}
	initialCfg := clientConfig{
		Server:        *server,
		Ifaces:        splitCSV(*ifacesStr),
		IPs:           splitCSV(*localIPs),
		Conns:         *nconns,
		Mode:          modeBonding,
		PKI:           chosenPKI,
		Client:        *clientName,
		Ctrl:          *ctrlPort,
		PolicyRouting: *policyRouting,
		Gateways:      splitCSV(*gateways),
	}

	// If -pki was explicitly provided, don't let stored config override it (important for elevated relaunch)
	pkiFromCLI := *pkiDir != ""
	initialCfg = mergeWithStoredConfig(initialCfg, pkiFromCLI)
	if *loadBalanceFlag {
		initialCfg.Mode = modeLoadBalance
	} else if *bondingFlag {
		initialCfg.Mode = modeBonding
	}

	if err := ensureConfigAndPKI(initialCfg.PKI); err != nil {
		log.Fatalf("ensure base dirs: %v", err)
	}

	// If launched with --tui-autostart (after elevation), go to TUI with auto-start
	if *tuiAutoStart {
		runTUI(initialCfg, true)
		return
	}

	autoMode := *loadBalanceFlag || *bondingFlag
	if !autoMode {
		runTUI(initialCfg, false)
		return
	}

	cfg := initialCfg
	if cfg.Conns <= 0 {
		cfg.Conns = len(cfg.Ifaces)
	}
	if len(cfg.Ifaces) < 2 {
		log.Fatalf("need at least 2 interfaces (found %d)", len(cfg.Ifaces))
	}
	if cfg.Mode == modeBonding && cfg.Server == "" {
		log.Fatalf("server is required in bonding mode")
	}
	if cfg.Mode == modeBonding && cfg.Client == "" {
		name, err := detectClientCertName(cfg.PKI)
		if err != nil {
			log.Fatalf("client cert: %v", err)
		}
		cfg.Client = name
	}

	stop, err := startClient(cfg)
	if err != nil {
		log.Fatalf("start: %v", err)
	}
	saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Client: cfg.Client, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
	log.Printf("running in %s mode; press Ctrl-C to stop", cfg.Mode)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	<-sigc
	if stop != nil {
		stop()
	}
	log.Printf("stopped")
}

func mergeWithStoredConfig(cfg clientConfig, pkiFromCLI bool) clientConfig {
	if stored, err := loadStoredConfig(); err == nil {
		if stored.Server != "" {
			cfg.Server = stored.Server
		}
		if stored.Mode != "" {
			cfg.Mode = stored.Mode
		}
		if len(stored.Ifaces) > 0 {
			cfg.Ifaces = stored.Ifaces
		}
		if stored.Client != "" {
			cfg.Client = stored.Client
		}
		// Only use stored PKI if CLI didn't explicitly provide one (crucial for elevated relaunch)
		if stored.PKI != "" && !pkiFromCLI {
			cfg.PKI = stored.PKI
		}
		if stored.Ctrl != 0 {
			cfg.Ctrl = stored.Ctrl
		}
	}
	if cfg.PKI == "" {
		cfg.PKI = defaultPKIDir()
	}
	// Normalize legacy /pki suffix to flat layout
	cfg.PKI = normalizePKIPath(cfg.PKI)
	// Expand to absolute path so pkexec relaunch continues to use the original user's PKI dir.
	cfg.PKI = expandPath(cfg.PKI)
	return cfg
}

// normalizePKIPath currently returns the path as-is; kept for future normalization hooks.
func normalizePKIPath(p string) string {
	return p
}

func loadStoredConfig() (storedConfig, error) {
	var sc storedConfig
	path, err := configFilePath()
	if err != nil {
		return sc, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return sc, err
	}
	if err := json.Unmarshal(b, &sc); err != nil {
		return sc, err
	}
	return sc, nil
}

func saveStoredConfig(sc storedConfig) {
	path, err := configFilePath()
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	b, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o600)
}

func configFilePath() (string, error) {
	base, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "config.json"), nil
}

func userConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".fluxify"), nil
}

// expandPath resolves leading "~" to the user home and returns a cleaned path.
func expandPath(p string) string {
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Clean(filepath.Join(home, strings.TrimPrefix(p, "~")))
		}
	}
	return filepath.Clean(p)
}

func defaultPKIDir() string {
	base, err := userConfigDir()
	if err != nil || base == "" {
		return "./.fluxify"
	}
	return base
}

// ensureConfigAndPKI guarantees config dir exists (flat layout, no subfolders).
func ensureConfigAndPKI(pkiDir string) error {
	base, err := userConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	if pkiDir == "" {
		pkiDir = defaultPKIDir()
	}
	return os.MkdirAll(expandPath(pkiDir), 0o700)
}

// detectClientCertName scans pkiDir for a single bundle .pem containing cert+key.
// Ignores ca.pem, config.json, and files without a private key.
func detectClientCertName(pkiDir string) (string, error) {
	pkiDir = expandPath(pkiDir)
	ents, err := os.ReadDir(pkiDir)
	if err != nil {
		return "", fmt.Errorf("read dir %s: %w", pkiDir, err)
	}
	var names []string
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".pem") {
			continue
		}
		// Skip well-known non-client files
		if name == "ca.pem" || name == "server.pem" || name == "server-key.pem" {
			continue
		}
		base := strings.TrimSuffix(name, ".pem")
		// Must be a bundle with private key inside
		if hasCertAndKey(filepath.Join(pkiDir, name)) {
			names = append(names, base)
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no client bundle found in %s (need .pem with cert+key)", pkiDir)
	}
	if len(names) > 1 {
		return "", fmt.Errorf("multiple client bundles found: %s", strings.Join(names, ", "))
	}
	return names[0], nil
}

// hasCertAndKey reports whether the PEM file contains at least one CERTIFICATE and one private key.
func hasCertAndKey(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var hasCert, hasKey bool
	rem := b
	for {
		var blk *pem.Block
		blk, rem = pem.Decode(rem)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			hasCert = true
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			hasKey = true
		}
	}
	return hasCert && hasKey
}

// parseBundlePEM reads a single PEM file and extracts CA pool, client cert, and key.
// Expected content: CA cert(s), client cert, private key (order flexible).
func parseBundlePEM(path string) (caPool *x509.CertPool, cert tls.Certificate, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	var certs [][]byte
	var keyDER []byte
	var keyType string
	rem := b
	for {
		var blk *pem.Block
		blk, rem = pem.Decode(rem)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			certs = append(certs, blk.Bytes)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if keyDER == nil {
				keyDER = blk.Bytes
				keyType = blk.Type
			}
		}
	}
	if len(certs) < 2 {
		return nil, tls.Certificate{}, fmt.Errorf("bundle needs CA + client cert (found %d certs)", len(certs))
	}
	if keyDER == nil {
		return nil, tls.Certificate{}, fmt.Errorf("no private key in bundle")
	}
	// First cert(s) except last are CA chain; last is client cert
	caPool = x509.NewCertPool()
	for i := 0; i < len(certs)-1; i++ {
		c, err := x509.ParseCertificate(certs[i])
		if err != nil {
			return nil, tls.Certificate{}, fmt.Errorf("parse CA cert: %w", err)
		}
		caPool.AddCert(c)
	}
	// Last cert is client cert
	clientCertDER := certs[len(certs)-1]
	var privKey interface{}
	switch keyType {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(keyDER)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(keyDER)
	default:
		privKey, err = x509.ParsePKCS8PrivateKey(keyDER)
	}
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("parse private key: %w", err)
	}
	cert = tls.Certificate{
		Certificate: [][]byte{clientCertDER},
		PrivateKey:  privKey,
	}
	return caPool, cert, nil
}

// startClient boots the data-plane; returns a stop func.
func startClient(cfg clientConfig) (func(), error) {
	return startClientWithStats(cfg, nil, nil)
}

func startClientWithStats(cfg clientConfig, statsView *tview.TextView, app *tview.Application) (func(), error) {
	if cfg.Mode == modeLoadBalance {
		return startLocalBalancerWithStats(cfg, statsView, app)
	}
	return startBondingClientWithStats(cfg, statsView, app)
}

func (c *clientState) readLoop(cc *clientConn) {
	defer c.wg.Done()
	buf := make([]byte, common.HeaderSize+common.MaxPacketSize)
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
		h, payload, err := common.DecryptPacket(c.sessionKey, buf[:n])
		if err != nil {
			continue
		}
		cc.bytesRecv.Add(uint64(len(payload)))
		switch h.Type {
		case common.PacketHeartbeat:
			var hb common.HeartbeatPayload
			if err := hb.Unmarshal(payload); err == nil {
				cc.rttNano.Store(int64(common.CalcRTT(hb.SendTime)))
			}
		case common.PacketIP:
			pay := payload
			if h.Reserved[0] == common.CompressionGzip {
				if dec, err := common.DecompressPayload(payload, common.MaxPacketSize); err == nil {
					pay = dec
				} else {
					log.Printf("decompress err: %v", err)
					continue
				}
			}
			_, _ = c.tun.Write(pay)
		}
	}
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

func (c *clientState) tunToServer() {
	defer c.wg.Done()
	buf := make([]byte, common.MTU+100)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		n, err := c.tun.Read(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			log.Printf("tun read err: %v", err)
			continue
		}
		data := buf[:n]
		compressed := data
		compressFlag := common.CompressionNone
		if comp, err := common.CompressPayload(data); err == nil {
			if len(comp) < len(data) {
				compressed = comp
				compressFlag = common.CompressionGzip
			}
		}
		seq := c.nextSeqSend.Add(1)
		cc := c.pickBestConn()
		if cc == nil {
			continue
		}
		head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketIP, SessionID: c.sessionID, SeqNum: seq, Length: uint16(len(compressed))}
		head.Reserved[0] = byte(compressFlag)
		pkt, err := common.EncryptPacket(c.sessionKey, head, compressed)
		if err != nil {
			continue
		}
		cc.mu.Lock()
		_, _ = cc.udp.Write(pkt)
		cc.mu.Unlock()
		cc.bytesSent.Add(uint64(len(data)))
	}
}

func (c *clientState) pickBestConn() *clientConn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	if len(c.conns) == 0 {
		return nil
	}
	if c.mode == modeBonding {
		// simple round-robin over alive
		start := rand.Intn(len(c.conns))
		for i := 0; i < len(c.conns); i++ {
			cand := c.conns[(start+i)%len(c.conns)]
			if cand.alive.Load() {
				return cand
			}
		}
		return c.conns[start]
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
			head := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketHeartbeat, SessionID: c.sessionID, SeqNum: 0, Length: uint16(len(payload))}
			pkt, err := common.EncryptPacket(c.sessionKey, head, payload)
			if err != nil {
				continue
			}
			cc.mu.Lock()
			_, _ = cc.udp.Write(pkt)
			cc.mu.Unlock()
		}
		c.connMu.RUnlock()
		c.updateStats()
	}
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
		if rtt == 0 {
			rtt = 0
		}
		lines = append(lines, fmt.Sprintf("  %s %s | TX: %s | RX: %s | RTT: %v", cc.iface, alive, fmtBytes(tx), fmtBytes(rx), rtt.Round(time.Millisecond)))
	}
	lines = append(lines, fmt.Sprintf("\n[cyan]Total TX:[white] %s  [cyan]Total RX:[white] %s", fmtBytes(totalTx), fmtBytes(totalRx)))
	c.statsView.SetText(strings.Join(lines, "\n"))
}

func fmtBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	kb := float64(b) / unit
	if kb < unit {
		return fmt.Sprintf("%.1f KB", kb)
	}
	mb := kb / unit
	if mb < unit {
		return fmt.Sprintf("%.1f MB", mb)
	}
	gb := mb / unit
	return fmt.Sprintf("%.2f GB", gb)
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
