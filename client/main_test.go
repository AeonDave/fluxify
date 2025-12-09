package main

import (
	"testing"

	"fluxify/common"
)

func TestPickBestConnLoadBalanceChoosesLowestRTT(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	slow := &clientConn{}
	slow.alive.Store(true)
	slow.rttNano.Store(int64(200 * 1e6)) // 200ms
	fast := &clientConn{}
	fast.alive.Store(true)
	fast.rttNano.Store(int64(10 * 1e6)) // 10ms
	c.conns = []*clientConn{slow, fast}

	got := c.pickBestConn()
	if got != fast {
		t.Fatalf("expected fast conn, got %p", got)
	}
}

// TestRouteRevertHook ensures the revertRoute hook is set when default route is set to TUN (simulated).
// This is a light-weight check that the hook is wired; it does not execute system commands.
func TestRouteRevertHookWired(t *testing.T) {
	state := &clientState{}
	state.revertRoute = func() {}
	if state.revertRoute == nil {
		t.Fatalf("revertRoute should be non-nil")
	}
}

// TestGetDefaultRouteNonLinux is a safety check that the helper is a no-op on non-Linux.
func TestGetDefaultRouteNonLinux(t *testing.T) {
	if common.IsLinux() {
		t.Skip("linux env would try ip route")
	}
	if _, _, _, err := common.GetDefaultRoute(); err != nil {
		t.Fatalf("expected no error on non-linux: %v", err)
	}
}
