package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
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
				_, _ = fmt.Fprintf(f, "\n%s\n%s\n", time.Now().Format(time.RFC3339), msg)
				_ = f.Close()
			}
		}
	}
}

type uplink struct {
	iface     string
	gw        string
	gw6       string
	alive     bool
	alive4    bool
	alive6    bool
	fail      int
	fail6     int
	pingSent4 uint64
	pingRecv4 uint64
	pingSent6 uint64
	pingRecv6 uint64
	jitter4Ms float64
	jitter6Ms float64
	lastRtt4  time.Duration
	lastRtt6  time.Duration
	bytesTx   uint64
	bytesRx   uint64
	lastTx    uint64
	lastRx    uint64
	rateTxK   float64
	rateRxK   float64
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

type ifaceLister interface {
	Interfaces() ([]net.Interface, error)
}

type defaultIfaceLister struct{}

func (defaultIfaceLister) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

var ifaceProvider ifaceLister = defaultIfaceLister{}

func startLocalBalancerWithStats(cfg clientConfig, statsView *tview.TextView, app *tview.Application) (func(), error) {
	if runtime.GOOS == "windows" && !common.IsRoot() {
		return nil, fmt.Errorf("run the client as administrator on windows to configure routes")
	}
	cfg.Ifaces = sanitizeIfaces(cfg.Ifaces, false)
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
	vlogf("Saved old route: %s", oldRoute)

	rawUplinks, err := discoverGateways(cfg.Ifaces)
	if err != nil {
		return nil, err
	}
	if len(rawUplinks) == 0 {
		return nil, fmt.Errorf("no gateways discovered for selected interfaces")
	}
	vlogf("Discovered %d uplinks", len(rawUplinks))

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
		vlogf("Added MASQUERADE rules")
	}
	if hasV6 {
		if err := addMasqueradeRules6(snapshot); err != nil {
			_ = removeMasqueradeRules(snapshot)
			return nil, err
		}
		vlogf("Added IPv6 MASQUERADE rules")
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
		vlogf("Installed multipath default route")
	}
	if hasV6 {
		if err := installMultipathDefault6(snapshot); err != nil {
			_ = removeMasqueradeRules(snapshot)
			_ = removeMasqueradeRules6(snapshot)
			return nil, err
		}
		vlogf("Installed IPv6 multipath default route")
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
		vlogf("Restoring old route: %s", oldRoute)
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
		vlogf("Load-balancer stopped")
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
	lines = append(lines, "[yellow]Load-Balance Metrics:[white]")
	var totalTx, totalRx uint64
	var totalRateTx, totalRateRx float64
	var totalRate float64
	maxShare := 0.0
	active := 0
	var totalPingSent uint64
	var totalPingRecv uint64
	var jitterSum float64
	var jitterCount int
	var scoreSum float64
	for _, u := range ups.list {
		totalTx += u.bytesTx
		totalRx += u.bytesRx
		totalRateTx += u.rateTxK
		totalRateRx += u.rateRxK
		rateSum := u.rateTxK + u.rateRxK
		totalRate += rateSum
		totalPingSent += u.pingSent4 + u.pingSent6
		totalPingRecv += u.pingRecv4 + u.pingRecv6
		status := "[red]DOWN"
		if u.alive {
			status = "[green]UP"
			active++
		}
		gwLabel := u.gw
		if u.gw6 != "" {
			if gwLabel != "" {
				gwLabel += " / "
			}
			gwLabel += u.gw6
		}
		fam := fmt.Sprintf("(v4:%s v6:%s)", upDown(u.alive4), upDown(u.alive6))
		share := 0.0
		if totalRate > 0 {
			share = rateSum / totalRate * 100
			if share > maxShare {
				maxShare = share
			}
		}
		loss := combinedLoss(u)
		jitterMs, jitterOk := combinedJitterMs(u)
		score := stabilityScore(loss.percent, jitterMs, 0)
		if jitterOk {
			jitterSum += jitterMs
			jitterCount++
			scoreSum += score
		}
		lossText := "-"
		if loss.ok {
			lossText = fmt.Sprintf("%.1f%%", loss.percent)
		}
		jitterText := "-"
		if jitterOk {
			jitterText = fmt.Sprintf("%.1f ms", jitterMs)
		}
		scoreText := "-"
		if loss.ok || jitterOk {
			scoreText = fmt.Sprintf("%.0f", score)
		}
		lines = append(lines, fmt.Sprintf("  %s (%s) %s %s | share: %3.0f%% | TX: %s (%.1f kbps) | RX: %s (%.1f kbps)",
			u.iface, gwLabel, status, fam, share, fmtBytes(u.bytesTx), u.rateTxK, fmtBytes(u.bytesRx), u.rateRxK))
		lines[len(lines)-1] += fmt.Sprintf(" | loss: %s | jitter: %s | score: %s", lossText, jitterText, scoreText)
	}
	lines = append(lines, fmt.Sprintf("\n[cyan]Total TX:[white] %s (%.1f kbps)  [cyan]Total RX:[white] %s (%.1f kbps)  [cyan]Active:[white] %d/%d",
		fmtBytes(totalTx), totalRateTx, fmtBytes(totalRx), totalRateRx, active, len(ups.list)))
	lossText := "n/a"
	if loss := lossPercent(totalPingSent, totalPingRecv); loss.ok {
		lossText = fmt.Sprintf("%.1f%%", loss.percent)
	}
	jitterText := "n/a"
	scoreText := "n/a"
	if jitterCount > 0 {
		jitterText = fmt.Sprintf("%.1f ms", jitterSum/float64(jitterCount))
		scoreText = fmt.Sprintf("%.0f", scoreSum/float64(jitterCount))
	}
	lines = append(lines, fmt.Sprintf("[cyan]Loss:[white] %s  [cyan]Jitter:[white] %s  [cyan]Score:[white] %s", lossText, jitterText, scoreText))
	if totalRate > 0 && len(ups.list) > 1 {
		lines = append(lines, fmt.Sprintf("[cyan]Distribution:[white] max %.0f%% on a single iface", maxShare))
	}
	ups.statsView.SetText(strings.Join(lines, "\n"))
}

func combinedLoss(u uplink) lossStats {
	s4 := lossPercent(u.pingSent4, u.pingRecv4)
	s6 := lossPercent(u.pingSent6, u.pingRecv6)
	switch {
	case s4.ok && s6.ok:
		return lossPercent(u.pingSent4+u.pingSent6, u.pingRecv4+u.pingRecv6)
	case s4.ok:
		return s4
	case s6.ok:
		return s6
	default:
		return lossStats{percent: 0, ok: false}
	}
}

func combinedJitterMs(u uplink) (float64, bool) {
	ok4 := u.pingRecv4 >= 3
	ok6 := u.pingRecv6 >= 3
	switch {
	case ok4 && ok6:
		if u.jitter4Ms >= u.jitter6Ms {
			return u.jitter4Ms, true
		}
		return u.jitter6Ms, true
	case ok4:
		return u.jitter4Ms, true
	case ok6:
		return u.jitter6Ms, true
	default:
		return 0, false
	}
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
			vlogf("gateway lookup failed for %s: %v", ifc, err)
			continue
		}
		gw6, err := platform.GatewayForIface6(runner, ifc)
		if err != nil {
			vlogf("gateway6 lookup failed for %s: %v", ifc, err)
		}
		if gw == "" && gw6 == "" {
			vlogf("no gateway found for %s", ifc)
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

func recordPing(u *uplink, ok bool, rtt time.Duration, v6 bool) {
	if v6 {
		u.pingSent6++
		if !ok {
			return
		}
		u.pingRecv6++
		if rtt > 0 {
			if u.lastRtt6 > 0 {
				delta := rtt - u.lastRtt6
				if delta < 0 {
					delta = -delta
				}
				deltaMs := float64(delta) / float64(time.Millisecond)
				u.jitter6Ms += (deltaMs - u.jitter6Ms) / 16
			}
			u.lastRtt6 = rtt
		}
		return
	}
	u.pingSent4++
	if !ok {
		return
	}
	u.pingRecv4++
	if rtt > 0 {
		if u.lastRtt4 > 0 {
			delta := rtt - u.lastRtt4
			if delta < 0 {
				delta = -delta
			}
			deltaMs := float64(delta) / float64(time.Millisecond)
			u.jitter4Ms += (deltaMs - u.jitter4Ms) / 16
		}
		u.lastRtt4 = rtt
	}
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
					rtt, err := platform.PingIfaceV4(runner, snap[i].iface)
					ups.update(idx, func(u *uplink) {
						recordPing(u, err == nil, rtt, false)
						changed4 = changed4 || updateUplinkAfterPing(u, err == nil, false)
					})
				}
				if snap[i].gw6 != "" {
					rtt, err := platform.PingIfaceV6(runner, snap[i].iface)
					ups.update(idx, func(u *uplink) {
						recordPing(u, err == nil, rtt, true)
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

func sanitizeIfaces(raw []string, allowDown bool) []string {
	seen := make(map[string]bool)
	trimmed := make([]string, 0, len(raw))
	for _, name := range raw {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		trimmed = append(trimmed, name)
	}
	if len(trimmed) == 0 {
		return nil
	}
	ifaces, err := ifaceProvider.Interfaces()
	if err != nil {
		log.Printf("list interfaces: %v", err)
		return trimmed
	}
	info := make(map[string]net.Interface, len(ifaces))
	for _, ifc := range ifaces {
		info[ifc.Name] = ifc
	}
	type candidate struct {
		name string
		mtu  int
	}
	var candidates []candidate
	for _, name := range trimmed {
		ifc, ok := info[name]
		if !ok {
			vlogf("iface %s not found; skipping", name)
			continue
		}
		if ifc.Flags&net.FlagLoopback != 0 {
			vlogf("iface %s is loopback; skipping", name)
			continue
		}
		if ifc.Flags&net.FlagUp == 0 {
			if !allowDown {
				vlogf("iface %s is down; skipping", name)
				continue
			}
			vlogf("iface %s is down; keeping for recovery", name)
		}
		candidates = append(candidates, candidate{name: name, mtu: ifc.MTU})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].mtu == candidates[j].mtu {
			return candidates[i].name < candidates[j].name
		}
		return candidates[i].mtu > candidates[j].mtu
	})
	result := make([]string, len(candidates))
	for i, c := range candidates {
		result[i] = c.name
	}
	return result
}
