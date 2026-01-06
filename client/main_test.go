package main

import "testing"

func TestPickBestConnLoadBalanceFallsBackWhenNoneAlive(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	a := &clientConn{}
	b := &clientConn{}
	a.alive.Store(false)
	b.alive.Store(false)
	c.conns = []*clientConn{a, b}

	got := c.pickBestConn()
	if got != a {
		t.Fatalf("expected fallback to first conn, got %p", got)
	}
}

func TestPickBestConnBondingPrefersAlive(t *testing.T) {
	c := &clientState{mode: modeBonding}
	dead := &clientConn{}
	alive := &clientConn{}
	dead.alive.Store(false)
	alive.alive.Store(true)
	c.conns = []*clientConn{dead, alive}

	got := c.pickBestConn()
	if got == nil || !got.alive.Load() {
		t.Fatalf("expected an alive conn, got %#v", got)
	}
}
