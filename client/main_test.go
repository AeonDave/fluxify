package main

import (
	"testing"
	"time"
)

func TestPickBestConnLoadBalanceChoosesLowestRTT(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	slow := &clientConn{}
	slow.alive.Store(true)
	slow.rttNano.Store(int64(200 * time.Millisecond))
	fast := &clientConn{}
	fast.alive.Store(true)
	fast.rttNano.Store(int64(10 * time.Millisecond))
	c.conns = []*clientConn{slow, fast}

	got := c.pickBestConn()
	if got != fast {
		t.Fatalf("expected fast conn, got %p", got)
	}
}

func TestPickBestConnLoadBalanceTreatsZeroRTTAsPenalty(t *testing.T) {
	c := &clientState{mode: modeLoadBalance}
	unknown := &clientConn{}
	unknown.alive.Store(true)
	unknown.rttNano.Store(0)
	known := &clientConn{}
	known.alive.Store(true)
	known.rttNano.Store(int64(20 * time.Millisecond))
	c.conns = []*clientConn{unknown, known}

	got := c.pickBestConn()
	if got != known {
		t.Fatalf("expected known RTT conn, got %p", got)
	}
}

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
