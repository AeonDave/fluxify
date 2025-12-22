package main

import (
	"testing"
)

func TestPickBestConnRoundRobinSkipsDown(t *testing.T) {
	c1 := &clientConn{}
	c2 := &clientConn{}
	c1.alive.Store(true)
	c2.alive.Store(true)

	state := &clientState{mode: modeBonding, conns: []*clientConn{c1, c2}}

	first := state.pickBestConn()
	second := state.pickBestConn()
	if first == nil || second == nil {
		t.Fatalf("expected conns, got first=%v second=%v", first, second)
	}
	if first == second {
		t.Fatalf("expected round-robin to advance, got same conn twice (%v)", first)
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
	state := &clientState{mode: modeBonding, conns: []*clientConn{{}, {}}}
	for i := 0; i < 3; i++ {
		if got := state.pickBestConn(); got != nil {
			t.Fatalf("expected nil when all conns down, got %v", got)
		}
	}
}
