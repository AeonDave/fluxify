package main

import (
	"testing"
	"time"
)

func TestUpdateConnRTT_InitializesJitter(t *testing.T) {
	cc := &clientConn{}
	state := &clientState{}

	state.updateConnRTT(cc, 50*time.Millisecond)
	if cc.rttNano.Load() != int64(50*time.Millisecond) {
		t.Errorf("expected RTT 50ms, got %v", time.Duration(cc.rttNano.Load()))
	}
	if cc.jitterNano.Load() != 0 {
		t.Errorf("first sample should not set jitter, got %v", time.Duration(cc.jitterNano.Load()))
	}

	// Second sample: jitter should update
	state.updateConnRTT(cc, 70*time.Millisecond)
	if cc.rttNano.Load() != int64(70*time.Millisecond) {
		t.Errorf("expected RTT 70ms, got %v", time.Duration(cc.rttNano.Load()))
	}
	jitter := time.Duration(cc.jitterNano.Load())
	if jitter == 0 {
		t.Error("jitter should be >0 after second sample with delta")
	}
}

func TestResetConnTelemetry_ZerosCounters(t *testing.T) {
	cc := &clientConn{}
	cc.hbSent.Store(10)
	cc.hbRecv.Store(8)
	cc.jitterNano.Store(int64(5 * time.Millisecond))
	cc.rttNano.Store(int64(20 * time.Millisecond))

	state := &clientState{}
	state.resetConnTelemetry(cc)

	if cc.hbSent.Load() != 0 {
		t.Errorf("expected hbSent=0, got %d", cc.hbSent.Load())
	}
	if cc.hbRecv.Load() != 0 {
		t.Errorf("expected hbRecv=0, got %d", cc.hbRecv.Load())
	}
	if cc.jitterNano.Load() != 0 {
		t.Errorf("expected jitter=0, got %v", time.Duration(cc.jitterNano.Load()))
	}
	if cc.rttNano.Load() != 0 {
		t.Errorf("expected rtt=0, got %v", time.Duration(cc.rttNano.Load()))
	}
}

func TestSetServerState_TransitionsAreLogged(t *testing.T) {
	state := &clientState{}
	state.serverAlive.Store(false)

	// Transition to alive
	state.setServerState(true)
	if !state.serverAlive.Load() {
		t.Error("server should be marked alive")
	}

	// Transition to dead
	state.setServerState(false)
	if state.serverAlive.Load() {
		t.Error("server should be marked dead")
	}
}

func TestSetConnState_MarksAliveAndReason(t *testing.T) {
	cc := &clientConn{iface: "eth0"}
	state := &clientState{}

	state.setConnState(cc, true, "connected")
	if !cc.alive.Load() {
		t.Error("conn should be marked alive")
	}

	state.setConnState(cc, false, "timeout")
	if cc.alive.Load() {
		t.Error("conn should be marked dead")
	}
}

func TestSessionSnapshot_ReturnsIDAndServerAddr(t *testing.T) {
	state := &clientState{
		sessionID:  777,
		serverAddr: "vpn.example.com:8443",
	}
	id, addr := state.sessionSnapshot()
	if id != 777 {
		t.Errorf("expected session 777, got %d", id)
	}
	if addr != "vpn.example.com:8443" {
		t.Errorf("expected addr vpn.example.com:8443, got %s", addr)
	}
}

func TestPickBestConn_ReturnsFirstAlive(t *testing.T) {
	cc1 := &clientConn{iface: "eth0"}
	cc2 := &clientConn{iface: "wlan0"}
	cc1.alive.Store(false)
	cc2.alive.Store(true)

	state := &clientState{conns: []*clientConn{cc1, cc2}}
	best := state.pickBestConn()
	if best == nil {
		t.Fatal("expected a conn, got nil")
	}
	if best.iface != "wlan0" {
		t.Errorf("expected wlan0, got %s", best.iface)
	}
}

func TestPickBestConn_ReturnsFirstWhenNoneAlive(t *testing.T) {
	cc1 := &clientConn{iface: "eth0"}
	cc1.alive.Store(false)
	state := &clientState{conns: []*clientConn{cc1}}

	best := state.pickBestConn()
	if best != cc1 {
		t.Error("expected fallback to first conn")
	}
}
