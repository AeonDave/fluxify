package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	runs    [][]string
	outputs map[string][]byte
	err     error
	runHook func(name string, args ...string) error
}

type fakeIfaceProvider struct {
	ifaces []net.Interface
	err    error
}

func (f fakeIfaceProvider) Interfaces() ([]net.Interface, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ifaces, nil
}

func (f *fakeRunner) Run(name string, args ...string) error {
	if f.runHook != nil {
		return f.runHook(name, args...)
	}
	f.runs = append(f.runs, append([]string{name}, args...))
	return f.err
}

func (f *fakeRunner) Output(name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if out, ok := f.outputs[key]; ok {
		return out, nil
	}
	if f.err != nil {
		return nil, f.err
	}
	return nil, errors.New("unexpected command")
}

func (f *fakeRunner) OutputSafe(name string, args ...string) ([]byte, error) {
	return f.Output(name, args...)
}

func TestSanitizeIfacesFiltersAndSortsByMTU(t *testing.T) {
	old := ifaceProvider
	ifaceProvider = fakeIfaceProvider{ifaces: []net.Interface{
		{Name: "eth0", MTU: 9000, Flags: net.FlagUp},
		{Name: "eth1", MTU: 1500, Flags: net.FlagUp},
		{Name: "lo", MTU: 65536, Flags: net.FlagLoopback | net.FlagUp},
		{Name: "down0", MTU: 1500},
	}}
	t.Cleanup(func() { ifaceProvider = old })

	got := sanitizeIfaces([]string{"eth1", "lo", "eth1", "eth0", "down0", "missing", ""})
	want := []string{"eth0", "eth1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestSanitizeIfacesFallsBackOnError(t *testing.T) {
	old := ifaceProvider
	ifaceProvider = fakeIfaceProvider{err: errors.New("boom")}
	t.Cleanup(func() { ifaceProvider = old })

	got := sanitizeIfaces([]string{"eth0", "eth0", "wlan0", " ", ""})
	want := []string{"eth0", "wlan0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestHealthMonitorFlapsAndUpdatesRoutes(t *testing.T) {
	oldInterval := healthCheckInterval
	healthCheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { healthCheckInterval = oldInterval })

	// ping fails twice then succeeds, toggling an uplink down then up and causing route refresh
	seq := 0
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	fr.runHook = func(name string, args ...string) error {
		if name == "ping" {
			seq++
			if seq == 1 {
				return errors.New("timeout")
			}
			return nil
		}
		fr.runs = append(fr.runs, append([]string{name}, args...))
		return nil
	}
	old := runner
	runner = fr
	defer func() { runner = old }()

	ups := &uplinkSet{list: []uplink{{iface: "eth0", gw: "10.0.0.1", alive: true, alive4: true, fail: 2}}}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(120*time.Millisecond, cancel)
	healthMonitor(ctx, ups)

	// After flapping, multipath should be attempted multiple times
	calls := 0
	for _, run := range fr.runs {
		if len(run) >= 3 && run[0] == "ip" && run[1] == "route" && run[2] == "replace" {
			calls++
		}
	}
	if calls == 0 {
		t.Fatalf("expected multipath updates after flaps (got %d)", calls)
	}
	snap := ups.snapshot()[0]
	if !snap.alive {
		t.Fatalf("uplink should be alive after recovery")
	}
}

func TestInstallMultipathDefaultBuildsArgs(t *testing.T) {
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	uplinks := []uplink{{iface: "eth0", gw: "10.0.0.1", alive: true, alive4: true}, {iface: "eth1", gw: "10.0.1.1", alive: true, alive4: true}}
	if err := installMultipathDefault(uplinks); err != nil {
		t.Fatalf("installMultipathDefault error: %v", err)
	}
	if len(fr.runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(fr.runs))
	}
	got := strings.Join(fr.runs[0], " ")
	want := "ip route replace default scope global nexthop via 10.0.0.1 dev eth0 weight 1 nexthop via 10.0.1.1 dev eth1 weight 1"
	if got != want {
		t.Fatalf("unexpected args\n got: %s\nwant: %s", got, want)
	}
}

func TestInstallMultipathDefaultNoAlive(t *testing.T) {
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	if err := installMultipathDefault([]uplink{}); err == nil {
		t.Fatalf("expected error when no alive uplinks")
	}
}

func TestInstallMultipathDefault6BuildsArgs(t *testing.T) {
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	uplinks := []uplink{{iface: "eth0", gw6: "fe80::1", alive: true, alive6: true}}
	if err := installMultipathDefault6(uplinks); err != nil {
		t.Fatalf("installMultipathDefault6 error: %v", err)
	}
	if len(fr.runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(fr.runs))
	}
	got := strings.Join(fr.runs[0], " ")
	want := "ip -6 route replace default nexthop via fe80::1 dev eth0 weight 1"
	if got != want {
		t.Fatalf("unexpected args\n got: %s\nwant: %s", got, want)
	}
}

func TestInstallMultipathDefault6NoAlive(t *testing.T) {
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	if err := installMultipathDefault6([]uplink{}); err == nil {
		t.Fatalf("expected error when no alive ipv6 uplinks")
	}
}

func TestGatewayForIfaceParsesVia(t *testing.T) {
	fr := &fakeRunner{outputs: map[string][]byte{"ip route get 8.8.8.8 oif eth0": []byte("8.8.8.8 via 10.0.0.1 dev eth0")}}
	old := runner
	runner = fr
	defer func() { runner = old }()

	gw, err := gatewayForIface("eth0")
	if err != nil {
		t.Fatalf("gatewayForIface error: %v", err)
	}
	if gw != "10.0.0.1" {
		t.Fatalf("unexpected gw: %s", gw)
	}
}

func TestGatewayForIface6ParsesVia(t *testing.T) {
	fr := &fakeRunner{outputs: map[string][]byte{"ip -6 route get 2001:4860:4860::8888 oif eth0": []byte("2001:4860:4860::8888 via fe80::1 dev eth0")}}
	old := runner
	runner = fr
	defer func() { runner = old }()

	gw, err := gatewayForIface6("eth0")
	if err != nil {
		t.Fatalf("gatewayForIface6 error: %v", err)
	}
	if gw != "fe80::1" {
		t.Fatalf("unexpected gw6: %s", gw)
	}
}

func TestAddMasqueradeRules6(t *testing.T) {
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	if err := addMasqueradeRules6([]uplink{{iface: "eth0", gw6: "fe80::1"}}); err != nil {
		t.Fatalf("addMasqueradeRules6 error: %v", err)
	}
	if len(fr.runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(fr.runs))
	}
	if run := strings.Join(fr.runs[0], " "); run != "ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" {
		t.Fatalf("unexpected run: %s", run)
	}
}

func TestHealthMonitorTracksIPv6(t *testing.T) {
	oldInterval := healthCheckInterval
	healthCheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { healthCheckInterval = oldInterval })

	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	// First ping -6 fails then succeeds to trigger route updates
	call := 0
	fr.runHook = func(name string, args ...string) error {
		if name == "ping" && len(args) > 0 && args[0] == "-6" {
			call++
			if call == 1 {
				return errors.New("fail")
			}
		}
		fr.runs = append(fr.runs, append([]string{name}, args...))
		return nil
	}

	ups := &uplinkSet{list: []uplink{{iface: "eth0", gw6: "fe80::1", alive: true, alive6: true, fail6: 2}}}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(120*time.Millisecond, cancel)
	healthMonitor(ctx, ups)

	callsV6 := 0
	for _, run := range fr.runs {
		if len(run) >= 3 && run[0] == "ip" && run[1] == "-6" && run[2] == "route" {
			callsV6++
		}
	}
	if callsV6 == 0 {
		t.Fatalf("expected ipv6 route updates, got %d", callsV6)
	}
}

func TestDiscoverGatewaysSkipsOnError(t *testing.T) {
	fr := &fakeRunner{err: errors.New("boom"), outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	ups, err := discoverGateways([]string{"eth0"})
	if err != nil {
		t.Fatalf("discoverGateways should not return error: %v", err)
	}
	if len(ups) != 0 {
		t.Fatalf("expected 0 uplinks on error, got %d", len(ups))
	}
}

func TestHealthMonitorMarksDownAfterConsecutiveFailures(t *testing.T) {
	oldInterval := healthCheckInterval
	healthCheckInterval = 5 * time.Millisecond
	t.Cleanup(func() { healthCheckInterval = oldInterval })

	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	fr.runHook = func(name string, args ...string) error {
		if name == "ping" && len(args) > 0 && args[len(args)-2] == "eth0" {
			return errors.New("down")
		}
		fr.runs = append(fr.runs, append([]string{name}, args...))
		return nil
	}

	ups := &uplinkSet{list: []uplink{
		{iface: "eth0", gw: "10.0.0.1", alive: true, alive4: true},
		{iface: "eth1", gw: "10.0.0.2", alive: true, alive4: true},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(80*time.Millisecond, cancel)
	healthMonitor(ctx, ups)

	snap := ups.snapshot()
	if snap[0].alive4 || snap[0].alive {
		t.Fatalf("eth0 should be marked down after repeated failures")
	}
	if snap[0].fail < 3 {
		t.Fatalf("expected fail counter to reach threshold, got %d", snap[0].fail)
	}
	if !snap[1].alive4 {
		t.Fatalf("eth1 should remain healthy")
	}

	routeUpdates := 0
	for _, run := range fr.runs {
		if len(run) >= 3 && run[0] == "ip" && run[1] == "route" && run[2] == "replace" {
			routeUpdates++
		}
	}
	if routeUpdates == 0 {
		t.Fatalf("expected multipath updates after link failure")
	}
}

func TestHealthMonitorKeepsAliveWhenIPv6Healthy(t *testing.T) {
	oldInterval := healthCheckInterval
	healthCheckInterval = 5 * time.Millisecond
	t.Cleanup(func() { healthCheckInterval = oldInterval })

	fr := &fakeRunner{outputs: make(map[string][]byte)}
	old := runner
	runner = fr
	defer func() { runner = old }()

	fr.runHook = func(name string, args ...string) error {
		if name == "ping" && len(args) > 0 && args[0] != "-6" {
			return errors.New("ipv4 down")
		}
		fr.runs = append(fr.runs, append([]string{name}, args...))
		return nil
	}

	ups := &uplinkSet{list: []uplink{{iface: "eth0", gw: "10.0.0.1", gw6: "fe80::1", alive: true, alive4: true, alive6: true}}}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(80*time.Millisecond, cancel)
	healthMonitor(ctx, ups)

	snap := ups.snapshot()[0]
	if snap.alive4 {
		t.Fatalf("ipv4 should be marked down")
	}
	if !snap.alive6 {
		t.Fatalf("ipv6 should remain healthy")
	}
	if !snap.alive {
		t.Fatalf("overall alive should remain true when ipv6 is up")
	}
}
