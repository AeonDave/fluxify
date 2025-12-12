//go:build linux
// +build linux

package main

import (
	"context"
	"errors"
	"fluxify/client/platform"
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

func TestHealthMonitorFlapsAndUpdatesRoutes(t *testing.T) {
	// ping fails once then succeeds, toggling an uplink down then up and causing route refresh.
	seq := 0
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	fr.runHook = func(name string, args ...string) error {
		if name == "ping" && (len(args) == 0 || args[0] != "-6") {
			seq++
			if seq == 1 {
				return errors.New("timeout")
			}
			return nil
		}
		fr.runs = append(fr.runs, append([]string{name}, args...))
		return nil
	}
	oldRunner, oldInterval, oldThreshold := runner, healthCheckInterval, healthFailThreshold
	runner = fr
	healthCheckInterval = 10 * time.Millisecond
	healthFailThreshold = 3
	t.Cleanup(func() {
		runner = oldRunner
		healthCheckInterval = oldInterval
		healthFailThreshold = oldThreshold
	})

	ups := &uplinkSet{list: []uplink{{iface: "eth0", gw: "10.0.0.1", alive: true, alive4: true, fail: healthFailThreshold - 1}}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(35 * time.Millisecond)
		cancel()
	}()
	healthMonitor(ctx, ups)

	calls := 0
	for _, run := range fr.runs {
		if len(run) >= 3 && run[0] == "ip" && run[1] == "route" && run[2] == "replace" {
			calls++
		}
	}
	if calls < 1 {
		t.Fatalf("expected multipath updates after flaps (got %d)", calls)
	}
	snap := ups.snapshot()[0]
	if !snap.alive4 || !snap.alive {
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

	gw, err := platform.GatewayForIface(fr, "eth0")
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

	gw, err := platform.GatewayForIface6(fr, "eth0")
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
	fr := &fakeRunner{outputs: make(map[string][]byte)}
	call := 0
	fr.runHook = func(name string, args ...string) error {
		if name == "ping" && len(args) > 0 && args[0] == "-6" {
			call++
			if call == 1 {
				return errors.New("fail")
			}
			return nil
		}
		fr.runs = append(fr.runs, append([]string{name}, args...))
		return nil
	}

	oldRunner, oldInterval, oldThreshold := runner, healthCheckInterval, healthFailThreshold
	runner = fr
	healthCheckInterval = 10 * time.Millisecond
	healthFailThreshold = 3
	t.Cleanup(func() {
		runner = oldRunner
		healthCheckInterval = oldInterval
		healthFailThreshold = oldThreshold
	})

	ups := &uplinkSet{list: []uplink{{iface: "eth0", gw6: "fe80::1", alive: true, alive6: true, fail6: healthFailThreshold - 1}}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(35 * time.Millisecond)
		cancel()
	}()
	healthMonitor(ctx, ups)

	callsV6 := 0
	for _, run := range fr.runs {
		if len(run) >= 3 && run[0] == "ip" && run[1] == "-6" && run[2] == "route" {
			callsV6++
		}
	}
	if callsV6 < 1 {
		t.Fatalf("expected ipv6 route updates, got %d", callsV6)
	}
}

func TestUpdateUplinkAfterPingV4ThresholdAndRecovery(t *testing.T) {
	oldThreshold := healthFailThreshold
	healthFailThreshold = 3
	t.Cleanup(func() { healthFailThreshold = oldThreshold })

	u := &uplink{alive4: true, alive: true}
	for i := 0; i < healthFailThreshold-1; i++ {
		if updateUplinkAfterPing(u, false, false) {
			t.Fatalf("unexpected change before threshold (i=%d)", i)
		}
		if !u.alive4 {
			t.Fatalf("alive4 should remain up before threshold")
		}
	}
	if !updateUplinkAfterPing(u, false, false) {
		t.Fatalf("expected change at threshold")
	}
	if u.alive4 {
		t.Fatalf("alive4 should be down at threshold")
	}

	if !updateUplinkAfterPing(u, true, false) {
		t.Fatalf("expected change on recovery")
	}
	if !u.alive4 || u.fail != 0 || !u.alive {
		t.Fatalf("unexpected state after recovery: %+v", *u)
	}
	if updateUplinkAfterPing(u, true, false) {
		t.Fatalf("unexpected change when already up")
	}
}

func TestUpdateUplinkAfterPingV6KeepsOverallAlive(t *testing.T) {
	oldThreshold := healthFailThreshold
	healthFailThreshold = 3
	t.Cleanup(func() { healthFailThreshold = oldThreshold })

	u := &uplink{alive4: true, alive6: true, alive: true, fail: healthFailThreshold - 1}
	if !updateUplinkAfterPing(u, false, false) {
		t.Fatalf("expected v4 change at threshold")
	}
	if u.alive4 || !u.alive6 || !u.alive {
		t.Fatalf("overall alive should remain true when v6 still up: %+v", *u)
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
