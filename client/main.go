package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

var logFatalf = log.Fatalf
var realRunTUI = runTUI
var runTUIHook = runTUI
var homeDirFunc = os.UserHomeDir
var lookupUser = user.Lookup
var isRoot = common.IsRoot
var panicHandlerEnabled = true

func parseDNSServers(list []string) ([]string, []string, error) {
	var dns4 []string
	var dns6 []string
	for _, s := range list {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid DNS server %q", s)
		}
		if ip.To4() != nil {
			dns4 = append(dns4, ip.String())
		} else {
			dns6 = append(dns6, ip.String())
		}
	}
	return dns4, dns6, nil
}

func main() {
	// Global panic handler to keep window open and log error
	defer func() {
		if !panicHandlerEnabled {
			return
		}
		if r := recover(); r != nil {
			msg := fmt.Sprintf("PANIC: %v\nStack:\n%s", r, debug.Stack())
			_, _ = fmt.Fprintln(os.Stderr, msg)
			// Try to write to a file in the same directory
			if exe, err := os.Executable(); err == nil {
				logFile := filepath.Join(filepath.Dir(exe), "client_panic.log")
				_ = os.WriteFile(logFile, []byte(msg), 0644)
			}
			fmt.Println("Application crashed. Keeping window open for 60s...")
			time.Sleep(60 * time.Second)
			os.Exit(1)
		}
	}()
	exitIf := func(cond bool, msg string, args ...interface{}) {
		if cond {
			logFatalf(msg, args...)
		}
	}

	server := flag.String("server", "", "server host:port (optional, overridden by TUI)")
	ifacesStr := flag.String("ifaces", "", "comma-separated interface names (optional)")
	localIPs := flag.String("ips", "", "comma-separated source IPs (optional)")
	bondingFlag := flag.Bool("b", false, "force bonding mode")
	loadBalanceFlag := flag.Bool("l", false, "force load-balance mode")
	pkiDir := flag.String("pki", "", "PKI directory (defaults to ~/.fluxify)")
	certPath := flag.String("cert", "", "path to client bundle (.pem with cert+key)")
	dnsServers := flag.String("dns", "", "comma-separated DNS servers for TUN (optional)")
	ctrlPort := flag.Int("ctrl", 8443, "control TLS port")
	mtuOverride := flag.Int("mtu", 0, "TUN MTU override (0=auto/default 1400, or specify e.g. 1280, 1350)")
	probePMTUD := flag.Bool("probe-pmtud", false, "probe path MTU at startup and warn if default MTU may cause blackhole")
	verbose := flag.Bool("v", false, "enable verbose logs")
	telemetryPath := flag.String("telemetry", "", "write MP-QUIC telemetry to file (JSON lines, snapshot every 5s)")
	flag.Parse()
	setVerboseLogging(*verbose)
	platform.SetVerbose(*verbose)

	exitIf(*bondingFlag && *loadBalanceFlag, "-b and -l are mutually exclusive")

	chosenPKI := *pkiDir
	if chosenPKI == "" || chosenPKI == "./pki" {
		chosenPKI = defaultPKIDir()
	}
	dns4, dns6, err := parseDNSServers(common.SplitCSV(*dnsServers))
	exitIf(err != nil, "invalid -dns: %v", err)
	initialCfg := clientConfig{
		Server:     *server,
		Ifaces:     common.SplitCSV(*ifacesStr),
		IPs:        common.SplitCSV(*localIPs),
		Mode:       modeBonding,
		PKI:        chosenPKI,
		Cert:       *certPath,
		Telemetry:  *telemetryPath,
		Ctrl:       *ctrlPort,
		DNS4:       dns4,
		DNS6:       dns6,
		MTU:        *mtuOverride,
		ProbePMTUD: *probePMTUD,
	}

	// If -pki was explicitly provided, don't let stored config override it.
	pkiFromCLI := *pkiDir != ""
	certFromCLI := *certPath != ""
	initialCfg = mergeWithStoredConfig(initialCfg, pkiFromCLI, certFromCLI)
	if *loadBalanceFlag {
		initialCfg.Mode = modeLoadBalance
	} else if *bondingFlag {
		initialCfg.Mode = modeBonding
	}

	// Client must be started with elevated privileges on supported platforms.
	if runtime.GOOS == "windows" && !isRoot() {
		logFatalf("run the client as administrator on windows")
	}
	if runtime.GOOS == "linux" && !isRoot() {
		logFatalf("run the client with sudo/root on linux")
	}

	if err := ensureConfigAndPKI(initialCfg.PKI); err != nil {
		logFatalf("ensure base dirs: %v", err)
	}

	autoMode := *loadBalanceFlag || *bondingFlag
	if !autoMode {
		runTUIHook(initialCfg)
		return
	}

	cfg := initialCfg
	exitIf(len(cfg.Ifaces) < 2, "need at least 2 interfaces (found %d)", len(cfg.Ifaces))
	exitIf(cfg.Mode == modeBonding && cfg.Server == "", "server is required in bonding mode")
	if cfg.Mode == modeBonding && cfg.Cert == "" {
		path, err := common.DetectClientBundlePath(cfg.PKI)
		exitIf(err != nil, "client cert: %v", err)
		cfg.Cert = path
	}
	if cfg.Cert != "" {
		cfg.Cert = common.ExpandPath(cfg.Cert)
	}

	stop, err := startClient(cfg)
	if err != nil {
		logFatalf("start: %v", err)
	}

	// Ensure cleanup on panic
	defer func() {
		if r := recover(); r != nil {
			if stop != nil {
				stop()
			}
			panic(r)
		}
	}()

	saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Cert: cfg.Cert, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
	log.Printf("running in %s mode; press Ctrl-C to stop", cfg.Mode)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	<-sigc
	if stop != nil {
		stop()
	}
	log.Printf("stopped")
}

func mergeWithStoredConfig(cfg clientConfig, pkiFromCLI, certFromCLI bool) clientConfig {
	storedClient := ""
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
		if stored.Cert != "" && !certFromCLI {
			cfg.Cert = stored.Cert
		}
		if stored.Client != "" {
			storedClient = stored.Client
		}
		// Only use stored PKI if CLI didn't explicitly provide one.
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
	// Expand to absolute path for consistent config usage.
	cfg.PKI = common.ExpandPath(cfg.PKI)
	if cfg.Cert == "" {
		if storedClient != "" && !certFromCLI {
			cfg.Cert = filepath.Join(cfg.PKI, storedClient+".pem")
		}
	}
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
	chownToSudoUser(path)
}

func configFilePath() (string, error) {
	base, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "config.json"), nil
}

func userConfigDir() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := lookupUser(sudoUser); err == nil && u.HomeDir != "" {
			return filepath.Join(u.HomeDir, ".fluxify"), nil
		}
	}
	home, err := homeDirFunc()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".fluxify"), nil
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
	pkiPath := common.ExpandPath(pkiDir)
	if err := os.MkdirAll(pkiPath, 0o700); err != nil {
		return err
	}
	chownToSudoUser(base, pkiPath)
	return nil
}

// chownToSudoUser makes config/PKI paths owned by the original sudo user.
// It is best-effort and only applies on Linux when running as root via sudo.
func chownToSudoUser(paths ...string) {
	if runtime.GOOS != "linux" || !common.IsRoot() {
		return
	}
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		return
	}
	u, err := user.Lookup(sudoUser)
	if err != nil {
		log.Printf("chown: lookup sudo user %s failed: %v", sudoUser, err)
		return
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		log.Printf("chown: invalid uid %q: %v", u.Uid, err)
		return
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		log.Printf("chown: invalid gid %q: %v", u.Gid, err)
		return
	}
	home := filepath.Clean(u.HomeDir)
	seen := make(map[string]bool)
	for _, p := range paths {
		if p == "" {
			continue
		}
		cp := filepath.Clean(p)
		if seen[cp] {
			continue
		}
		seen[cp] = true
		if !pathWithinHome(cp, home) {
			log.Printf("chown: skipping %s (outside %s)", cp, home)
			continue
		}
		if _, err := os.Stat(cp); err != nil {
			continue
		}
		_ = filepath.WalkDir(cp, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if derr := os.Chown(path, uid, gid); derr != nil {
				log.Printf("chown: %s: %v", path, derr)
			}
			return nil
		})
	}
}

func pathWithinHome(p, home string) bool {
	rel, err := filepath.Rel(home, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
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
