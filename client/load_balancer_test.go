package main

import (
	"context"
	"errors"
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

func TestHealthMonitorFlapsAndUpdatesRoutes(t *testing.T) {
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

	ups := &uplinkSet{list: []uplink{{iface: "eth0", gw: "10.0.0.1", alive: true, fail: 2}}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// allow enough ticks for down->up transition
		time.Sleep(12 * time.Second)
		cancel()
	}()
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

	uplinks := []uplink{{iface: "eth0", gw: "10.0.0.1", alive: true}, {iface: "eth1", gw: "10.0.1.1", alive: true}}
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
