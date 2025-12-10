package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"

	"fluxify/common"
)

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
	return common.RunPrivileged(name, args...)
}

func (sysRunner) Output(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
}

func (sysRunner) OutputSafe(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

var runner cmdRunner = sysRunner{}

func startLocalBalancerWithStats(cfg clientConfig, statsView *tview.TextView, app *tview.Application) (func(), error) {
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
		rx, tx, err := readInterfaceBytes(ups.list[i].iface)
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

func readInterfaceBytes(iface string) (rx, tx uint64, err error) {
	read := func(path string) (uint64, error) {
		b, e := os.ReadFile(path)
		if e != nil {
			return 0, e
		}
		v, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if e != nil {
			return 0, e
		}
		return v, nil
	}
	rx, err = read(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", iface))
	if err != nil {
		return
	}
	tx, err = read(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface))
	return
}

func discoverGateways(ifaces []string) ([]uplink, error) {
	uplinks := make([]uplink, 0)
	for _, ifc := range ifaces {
		if strings.TrimSpace(ifc) == "" {
			continue
		}
		gw, err := gatewayForIface(ifc)
		if err != nil {
			log.Printf("gateway lookup failed for %s: %v", ifc, err)
			continue
		}
		gw6, err := gatewayForIface6(ifc)
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

func gatewayForIface(iface string) (string, error) {
	out, err := runner.OutputSafe("ip", "route", "get", "8.8.8.8", "oif", iface)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" {
			return fields[i+1], nil
		}
	}
	return "", nil
}

func gatewayForIface6(iface string) (string, error) {
	out, err := runner.OutputSafe("ip", "-6", "route", "get", "2001:4860:4860::8888", "oif", iface)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" {
			return fields[i+1], nil
		}
	}
	return "", nil
}

func installMultipathDefault(uplinks []uplink) error {
	args := []string{"route", "replace", "default", "scope", "global"}
	for _, u := range uplinks {
		if !u.alive4 || u.gw == "" {
			continue
		}
		args = append(args, "nexthop", "via", u.gw, "dev", u.iface, "weight", "1")
	}
	if len(args) == 5 { // no nexthops added
		return fmt.Errorf("no alive uplinks to install")
	}
	return runner.Run("ip", args...)
}

func installMultipathDefault6(uplinks []uplink) error {
	args := []string{"-6", "route", "replace", "default"}
	for _, u := range uplinks {
		if !u.alive6 || u.gw6 == "" {
			continue
		}
		args = append(args, "nexthop", "via", u.gw6, "dev", u.iface, "weight", "1")
	}
	if len(args) == 4 {
		return fmt.Errorf("no alive ipv6 uplinks to install")
	}
	return runner.Run("ip", args...)
}

func addMasqueradeRules(uplinks []uplink) error {
	for _, u := range uplinks {
		if err := runner.Run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", u.iface, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("iptables add %s: %w", u.iface, err)
		}
	}
	return nil
}

func addMasqueradeRules6(uplinks []uplink) error {
	for _, u := range uplinks {
		if u.gw6 == "" {
			continue
		}
		if err := runner.Run("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-o", u.iface, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("ip6tables add %s: %w", u.iface, err)
		}
	}
	return nil
}

func removeMasqueradeRules(uplinks []uplink) error {
	for _, u := range uplinks {
		_ = runner.Run("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", u.iface, "-j", "MASQUERADE")
	}
	return nil
}

func removeMasqueradeRules6(uplinks []uplink) error {
	for _, u := range uplinks {
		if u.gw6 == "" {
			continue
		}
		_ = runner.Run("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-o", u.iface, "-j", "MASQUERADE")
	}
	return nil
}

func healthMonitor(ctx context.Context, ups *uplinkSet) {
	ticker := time.NewTicker(5 * time.Second)
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
					err := runner.Run("ping", "-c", "1", "-W", "1", "-I", snap[i].iface, "1.1.1.1")
					if err != nil {
						ups.update(idx, func(u *uplink) {
							prev := u.alive4
							u.fail++
							if u.fail >= 3 && u.alive4 {
								u.alive4 = false
								changed4 = changed4 || prev
							}
							u.alive = u.alive4 || u.alive6
						})
					} else {
						ups.update(idx, func(u *uplink) {
							prev := u.alive4
							u.fail = 0
							u.alive4 = true
							if !prev {
								changed4 = true
							}
							u.alive = u.alive4 || u.alive6
						})
					}
				}
				if snap[i].gw6 != "" {
					err := runner.Run("ping", "-6", "-c", "1", "-W", "1", "-I", snap[i].iface, "2606:4700:4700::1111")
					if err != nil {
						ups.update(idx, func(u *uplink) {
							prev := u.alive6
							u.fail6++
							if u.fail6 >= 3 && u.alive6 {
								u.alive6 = false
								changed6 = changed6 || prev
							}
							u.alive = u.alive4 || u.alive6
						})
					} else {
						ups.update(idx, func(u *uplink) {
							prev := u.alive6
							u.fail6 = 0
							u.alive6 = true
							if !prev {
								changed6 = true
							}
							u.alive = u.alive4 || u.alive6
						})
					}
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
