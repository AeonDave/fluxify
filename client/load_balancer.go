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
	alive   bool
	fail    int
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
}

type sysRunner struct{}

func (sysRunner) Run(name string, args ...string) error {
	return common.RunPrivileged(name, args...)
}

func (sysRunner) Output(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
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

	snapshot := ups.snapshot()
	if err := addMasqueradeRules(snapshot); err != nil {
		return nil, err
	}
	log.Printf("Added MASQUERADE rules")

	// Install multipath default route directly (no TUN needed for simple load-balance)
	if err := installMultipathDefault(snapshot); err != nil {
		_ = removeMasqueradeRules(snapshot)
		return nil, err
	}
	log.Printf("Installed multipath default route")

	ctx, cancel := context.WithCancel(context.Background())
	go healthMonitor(ctx, ups)
	if statsView != nil && app != nil {
		go statsUpdater(ctx, ups, app)
	}

	stop := func() {
		cancel()
		log.Printf("Restoring old route: %s", oldRoute)
		snapshot := ups.snapshot()
		_ = common.ReplaceDefaultRoute(oldRoute)
		_ = removeMasqueradeRules(snapshot)
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
		lines = append(lines, fmt.Sprintf("  %s (%s) %s | TX: %s (%.1f kbps) | RX: %s (%.1f kbps)", u.iface, u.gw, status, fmtBytes(u.bytesTx), u.rateTxK, fmtBytes(u.bytesRx), u.rateRxK))
	}
	lines = append(lines, fmt.Sprintf("\n[cyan]Total TX:[white] %s  [cyan]Total RX:[white] %s", fmtBytes(totalTx), fmtBytes(totalRx)))
	ups.statsView.SetText(strings.Join(lines, "\n"))
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
		if gw == "" {
			log.Printf("no gateway found for %s", ifc)
			continue
		}
		uplinks = append(uplinks, uplink{iface: ifc, gw: gw, alive: true})
	}
	return uplinks, nil
}

func gatewayForIface(iface string) (string, error) {
	cmd := exec.Command("ip", "route", "get", "8.8.8.8", "oif", iface)
	out, err := cmd.Output()
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
		if !u.alive || u.gw == "" {
			continue
		}
		args = append(args, "nexthop", "via", u.gw, "dev", u.iface, "weight", "1")
	}
	if len(args) == 5 { // no nexthops added
		return fmt.Errorf("no alive uplinks to install")
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

func removeMasqueradeRules(uplinks []uplink) error {
	for _, u := range uplinks {
		_ = runner.Run("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", u.iface, "-j", "MASQUERADE")
	}
	return nil
}

func healthMonitor(ctx context.Context, ups *uplinkSet) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			changed := false
			snap := ups.snapshot()
			for i := range snap {
				idx := i
				err := runner.Run("ping", "-c", "1", "-W", "1", "-I", snap[i].iface, "1.1.1.1")
				if err != nil {
					ups.update(idx, func(u *uplink) {
						u.fail++
						if u.fail >= 3 && u.alive {
							u.alive = false
							changed = true
						}
					})
				} else {
					ups.update(idx, func(u *uplink) {
						u.fail = 0
						if !u.alive {
							u.alive = true
							changed = true
						}
					})
				}
			}
			if changed {
				if err := installMultipathDefault(ups.snapshot()); err != nil {
					log.Printf("multipath update failed: %v", err)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
