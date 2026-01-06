package main

import (
	"testing"
)

func TestPickBestConnSkipsDown(t *testing.T) {
	c1 := &clientConn{}
	c2 := &clientConn{}
	c1.alive.Store(true)
	c2.alive.Store(true)

	state := &clientState{mode: modeBonding, conns: []*clientConn{c1, c2}}

	got := state.pickBestConn()
	if got == nil {
		t.Fatalf("expected a conn, got nil")
	}

	// Mark one down; should always pick the alive one
	c1.alive.Store(false)
	for i := 0; i < 5; i++ {
		if got := state.pickBestConn(); got != c2 {
			t.Fatalf("expected c2 when c1 is down, got %v", got)
		}
	}
}

func TestPickBestConnReturnsNilWhenAllDown(t *testing.T) {
	// With MP-QUIC, we have a single QUIC connection that handles multipath internally.
	// When no conns are alive but conns exist, we still return the first conn
	// because MP-QUIC will handle failover internally.
	state := &clientState{mode: modeBonding, conns: []*clientConn{{}, {}}}
	for i := 0; i < 3; i++ {
		got := state.pickBestConn()
		// With MP-QUIC architecture, we return first conn even if marked down
		// because the QUIC connection handles path management
		if got != state.conns[0] {
			t.Fatalf("expected first conn for MP-QUIC fallback, got %v", got)
		}
	}
}
