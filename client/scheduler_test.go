package main

import (
	"testing"
	"time"
)

func TestPickWeightedConn_AllDown_ReturnsNil(t *testing.T) {
	state := &clientState{mode: modeBonding, cfg: clientConfig{ReorderFlushTimeout: 50 * time.Millisecond}}
	c1 := &clientConn{}
	c2 := &clientConn{}
	state.conns = []*clientConn{c1, c2}
	if got := state.pickBestConn(); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestPickWeightedConn_SingleAlive_ReturnsThat(t *testing.T) {
	state := &clientState{mode: modeBonding, cfg: clientConfig{ReorderFlushTimeout: 50 * time.Millisecond}, schedDeficit: map[*clientConn]float64{}}
	c1 := &clientConn{}
	c1.alive.Store(true)
	state.conns = []*clientConn{c1}
	if got := state.pickBestConn(); got != c1 {
		t.Fatalf("expected c1, got %v", got)
	}
}

func TestPickWeightedConn_DownIsNeverPicked(t *testing.T) {
	state := &clientState{mode: modeBonding, cfg: clientConfig{ReorderFlushTimeout: 50 * time.Millisecond}, schedDeficit: map[*clientConn]float64{}}
	cUp := &clientConn{}
	cDown := &clientConn{}
	cUp.alive.Store(true)
	cDown.alive.Store(false)
	state.conns = []*clientConn{cUp, cDown}
	for i := 0; i < 100; i++ {
		if got := state.pickBestConn(); got != cUp {
			t.Fatalf("expected up conn, got %v", got)
		}
	}
}

func TestPickWeightedConn_BadConnExcluded(t *testing.T) {
	state := &clientState{mode: modeBonding, cfg: clientConfig{ReorderFlushTimeout: 50 * time.Millisecond}, schedDeficit: map[*clientConn]float64{}}
	good := &clientConn{}
	bad := &clientConn{}
	good.alive.Store(true)
	bad.alive.Store(true)
	// Make bad clearly bad: high jitter and high loss.
	bad.jitterNano.Store(int64(500 * time.Millisecond))
	bad.hbSent.Store(100)
	bad.hbRecv.Store(0)
	good.hbSent.Store(100)
	good.hbRecv.Store(100)
	good.rttNano.Store(int64(20 * time.Millisecond))
	bad.rttNano.Store(int64(100 * time.Millisecond))

	state.conns = []*clientConn{good, bad}
	for i := 0; i < 200; i++ {
		if got := state.pickBestConn(); got != good {
			t.Fatalf("expected good conn, got %v", got)
		}
	}
}

func TestPickConnForPacket_FlowPinned(t *testing.T) {
	state := &clientState{mode: modeBonding, cfg: clientConfig{ReorderFlushTimeout: 50 * time.Millisecond}, schedDeficit: map[*clientConn]float64{}}
	c1 := &clientConn{}
	c2 := &clientConn{}
	c1.alive.Store(true)
	c2.alive.Store(true)
	c1.rttNano.Store(int64(10 * time.Millisecond))
	c2.rttNano.Store(int64(20 * time.Millisecond))
	state.conns = []*clientConn{c1, c2}

	// IPv4 TCP packet with stable 5-tuple.
	pkt := make([]byte, 20+20)
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	pkt[20] = 0x1f
	pkt[21] = 0x90
	pkt[22] = 0x00
	pkt[23] = 0x50

	first := state.pickConnForPacket(pkt)
	if first == nil {
		t.Fatalf("expected conn")
	}
	for i := 0; i < 50; i++ {
		got := state.pickConnForPacket(pkt)
		if got != first {
			t.Fatalf("expected same conn for flow, got %v want %v", got, first)
		}
	}

	// If pinned conn goes down, it should re-pick.
	first.alive.Store(false)
	second := state.pickConnForPacket(pkt)
	if second == nil || second == first {
		t.Fatalf("expected repick when pinned conn down")
	}
}
