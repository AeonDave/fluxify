package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

// recoverPanic is a helper to recover from panics in goroutines
func recoverPanic(name string) {
	if r := recover(); r != nil {
		msg := fmt.Sprintf("PANIC in %s: %v\nStack:\n%s", name, r, debug.Stack())
		log.Printf("%s", msg) // Attempt to log to TUI/stderr
		// Try to write to a file
		if exe, err := os.Executable(); err == nil {
			logFile := filepath.Join(filepath.Dir(exe), "client_panic.log")
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if f != nil {
				fmt.Fprintf(f, "\n%s\n%s\n", time.Now().Format(time.RFC3339), msg)
				f.Close()
			}
		}
		// We can't keep the window open easily from a background goroutine panic,
		// but at least we logged it.
		// Force exit to ensure we don't hang in undefined state
		os.Exit(1)
	}
}

type uplink struct {
	iface   string
	gw      string
	gw6     string
	alive   bool
	alive4  bool
	alive6  bool
	fail    int
	fail6   int
	bytesTx uint64
	bytesRx uint64
	lastTx  uint64
	lastRx  uint64
	rateTxK float64
	rateRxK float64
}

type uplinkSet struct {
	mu        sync.RWMutex
	list      []uplink
	statsView *tview.TextView
}

func (u *uplinkSet) snapshot() []uplink {
	u.mu.RLock()
	defer u.mu.RUnlock()
	cp := make([]uplink, len(u.list))
	copy(cp, u.list)
	return cp
}

func (u *uplinkSet) update(index int, fn func(*uplink)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if index < 0 || index >= len(u.list) {
		return
	}
	fn(&u.list[index])
}

type cmdRunner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	OutputSafe(name string, args ...string) ([]byte, error)
}

type sysRunner struct{}

func (sysRunner) Run(name string, args ...string) error {
	return common.RunPrivilegedSilent(name, args...)
}

func (sysRunner) Output(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
}

func (sysRunner) OutputSafe(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
}

var runner cmdRunner = sysRunner{}

var (
	// healthCheckInterval controls how often uplinks are probed.
	// Tests override this to keep suites fast.
	healthCheckInterval = 5 * time.Second
	// healthFailThreshold is the consecutive-failure count to mark a family down.
	healthFailThreshold = 3
)

func startLocalBalancerWithStats(cfg clientConfig, statsView *tview.TextView, app *tview.Application) (func(), error) {
	if runtime.GOOS == "windows" && !common.IsRoot() {
		return nil, fmt.Errorf("run the client as administrator on windows to configure routes")
	}
	if len(cfg.Ifaces) < 2 {
		return nil, fmt.Errorf("need at least 2 interfaces for load-balance")
	}
	oldRoute, _, _, err := common.GetDefaultRoute()
	if err != nil {
		return nil, fmt.Errorf("get default route: %w", err)
	}
	oldRoute6, _, _, err := common.GetDefaultRoute6()
	if err != nil {
		return nil, fmt.Errorf("get default route v6: %w", err)
	}
	log.Printf("Saved old route: %s", oldRoute)

	rawUplinks, err := discoverGateways(cfg.Ifaces)
	if err != nil {
		return nil, err
	}
	if len(rawUplinks) == 0 {
		return nil, fmt.Errorf("no gateways discovered for selected interfaces")
	}
	log.Printf("Discovered %d uplinks", len(rawUplinks))

	ups := &uplinkSet{list: rawUplinks, statsView: statsView}
	hasV4 := false
	hasV6 := false
	for _, u := range rawUplinks {
		if u.gw != "" {
			hasV4 = true
		}
		if u.gw6 != "" {
			hasV6 = true
		}
	}

	snapshot := ups.snapshot()
	if hasV4 {
		if err := addMasqueradeRules(snapshot); err != nil {
			return nil, err
		}
		log.Printf("Added MASQUERADE rules")
	}
	if hasV6 {
		if err := addMasqueradeRules6(snapshot); err != nil {
			_ = removeMasqueradeRules(snapshot)
			return nil, err
		}
		log.Printf("Added IPv6 MASQUERADE rules")
	}

	// Install multipath default route directly (no TUN needed for simple load-balance)
	if hasV4 {
		if err := installMultipathDefault(snapshot); err != nil {
			_ = removeMasqueradeRules(snapshot)
			if hasV6 {
				_ = removeMasqueradeRules6(snapshot)
			}
			return nil, err
		}
		log.Printf("Installed multipath default route")
	}
	if hasV6 {
		if err := installMultipathDefault6(snapshot); err != nil {
			_ = removeMasqueradeRules(snapshot)
			_ = removeMasqueradeRules6(snapshot)
			return nil, err
		}
		log.Printf("Installed IPv6 multipath default route")
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Show initial stats immediately so the UI doesn't stay on the placeholder.
	updateLBStats(ups)
	go healthMonitor(ctx, ups)
	if statsView != nil && app != nil {
		go statsUpdater(ctx, ups, app)
	}

	stop := func() {
		cancel()
		log.Printf("Restoring old route: %s", oldRoute)
		snapshot := ups.snapshot()
		if oldRoute != "" {
			_ = common.ReplaceDefaultRoute(oldRoute)
		}
		if oldRoute6 != "" {
			_ = common.ReplaceDefaultRoute6(oldRoute6)
		}
		if hasV4 {
			_ = removeMasqueradeRules(snapshot)
		}
		if hasV6 {
			_ = removeMasqueradeRules6(snapshot)
		}
		log.Printf("Load-balancer stopped")
	}
	return stop, nil
}

func statsUpdater(ctx context.Context, ups *uplinkSet, app *tview.Application) {
	defer recoverPanic("statsUpdater")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshInterfaceStats(ups)
			app.QueueUpdateDraw(func() {
				updateLBStats(ups)
			})
		}
	}
}

func updateLBStats(ups *uplinkSet) {
	if ups.statsView == nil {
		return
	}
	ups.mu.RLock()
	defer ups.mu.RUnlock()
	var lines []string
	lines = append(lines, "[yellow]Load-Balance Stats:[white]")
	var totalTx, totalRx uint64
	for _, u := range ups.list {
		totalTx += u.bytesTx
		totalRx += u.bytesRx
		status := "[red]DOWN"
		if u.alive {
			status = "[green]UP"
		}
		gwLabel := u.gw
		if u.gw6 != "" {
			if gwLabel != "" {
				gwLabel += " / "
			}
			gwLabel += u.gw6
		}
		fam := fmt.Sprintf("(v4:%s v6:%s)", upDown(u.alive4), upDown(u.alive6))
		lines = append(lines, fmt.Sprintf("  %s (%s) %s %s | TX: %s (%.1f kbps) | RX: %s (%.1f kbps)", u.iface, gwLabel, status, fam, fmtBytes(u.bytesTx), u.rateTxK, fmtBytes(u.bytesRx), u.rateRxK))
	}
	lines = append(lines, fmt.Sprintf("\n[cyan]Total TX:[white] %s  [cyan]Total RX:[white] %s", fmtBytes(totalTx), fmtBytes(totalRx)))
	ups.statsView.SetText(strings.Join(lines, "\n"))
}

func upDown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

func refreshInterfaceStats(ups *uplinkSet) {
	ups.mu.Lock()
	defer ups.mu.Unlock()
	for i := range ups.list {
		rx, tx, err := platform.ReadInterfaceBytes(ups.list[i].iface)
		if err != nil {
			continue
		}
		if ups.list[i].lastRx != 0 {
			dRx := rx - ups.list[i].lastRx
			dTx := tx - ups.list[i].lastTx
			ups.list[i].rateRxK = float64(dRx*8) / 1000.0
			ups.list[i].rateTxK = float64(dTx*8) / 1000.0
		}
		ups.list[i].lastRx = rx
		ups.list[i].lastTx = tx
		ups.list[i].bytesRx = rx
		ups.list[i].bytesTx = tx
	}
}

func discoverGateways(ifaces []string) ([]uplink, error) {
	uplinks := make([]uplink, 0)
	for _, ifc := range ifaces {
		if strings.TrimSpace(ifc) == "" {
			continue
		}
		gw, err := platform.GatewayForIface(runner, ifc)
		if err != nil {
			log.Printf("gateway lookup failed for %s: %v", ifc, err)
			continue
		}
		gw6, err := platform.GatewayForIface6(runner, ifc)
		if err != nil {
			log.Printf("gateway6 lookup failed for %s: %v", ifc, err)
		}
		if gw == "" && gw6 == "" {
			log.Printf("no gateway found for %s", ifc)
			continue
		}
		uplinks = append(uplinks, uplink{iface: ifc, gw: gw, gw6: gw6, alive: gw != "" || gw6 != "", alive4: gw != "", alive6: gw6 != ""})
	}
	return uplinks, nil
}

func toPlatformUplinks(us []uplink) []platform.Uplink {
	out := make([]platform.Uplink, 0, len(us))
	for _, u := range us {
		out = append(out, platform.Uplink{
			Iface:  u.iface,
			Gw:     u.gw,
			Gw6:    u.gw6,
			Alive4: u.alive4,
			Alive6: u.alive6,
		})
	}
	return out
}

func installMultipathDefault(uplinks []uplink) error {
	return platform.InstallMultipathDefault(runner, toPlatformUplinks(uplinks))
}

func installMultipathDefault6(uplinks []uplink) error {
	return platform.InstallMultipathDefault6(runner, toPlatformUplinks(uplinks))
}

func addMasqueradeRules(uplinks []uplink) error {
	return platform.AddMasqueradeRules(runner, toPlatformUplinks(uplinks))
}

func addMasqueradeRules6(uplinks []uplink) error {
	return platform.AddMasqueradeRules6(runner, toPlatformUplinks(uplinks))
}

func removeMasqueradeRules(uplinks []uplink) error {
	return platform.RemoveMasqueradeRules(runner, toPlatformUplinks(uplinks))
}

func removeMasqueradeRules6(uplinks []uplink) error {
	return platform.RemoveMasqueradeRules6(runner, toPlatformUplinks(uplinks))
}

// updateUplinkAfterPing updates a single uplink's health for v4 or v6 based on ping success.
// It returns true if the health transition requires a route refresh for that family.
func updateUplinkAfterPing(u *uplink, ok bool, v6 bool) bool {
	changed := false
	if v6 {
		prev := u.alive6
		if !ok {
			u.fail6++
			if u.fail6 >= healthFailThreshold && u.alive6 {
				u.alive6 = false
				if prev {
					changed = true
				}
			}
		} else {
			u.fail6 = 0
			u.alive6 = true
			if !prev {
				changed = true
			}
		}
	} else {
		prev := u.alive4
		if !ok {
			u.fail++
			if u.fail >= healthFailThreshold && u.alive4 {
				u.alive4 = false
				if prev {
					changed = true
				}
			}
		} else {
			u.fail = 0
			u.alive4 = true
			if !prev {
				changed = true
			}
		}
	}
	u.alive = u.alive4 || u.alive6
	return changed
}

func healthMonitor(ctx context.Context, ups *uplinkSet) {
	defer recoverPanic("healthMonitor")
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			changed4 := false
			changed6 := false
			snap := ups.snapshot()
			for i := range snap {
				idx := i
				if snap[i].gw != "" {
					err := platform.PingIfaceV4(runner, snap[i].iface)
					ups.update(idx, func(u *uplink) {
						changed4 = changed4 || updateUplinkAfterPing(u, err == nil, false)
					})
				}
				if snap[i].gw6 != "" {
					err := platform.PingIfaceV6(runner, snap[i].iface)
					ups.update(idx, func(u *uplink) {
						changed6 = changed6 || updateUplinkAfterPing(u, err == nil, true)
					})
				}
			}
			if changed4 {
				if err := installMultipathDefault(ups.snapshot()); err != nil {
					log.Printf("multipath update failed (ipv4): %v", err)
				}
			}
			if changed6 {
				if err := installMultipathDefault6(ups.snapshot()); err != nil {
					log.Printf("multipath update failed (ipv6): %v", err)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
