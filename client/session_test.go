package main

import (
	"testing"
	"time"
)

func TestUpdatePathRTTJitter(t *testing.T) {
	pc := testPath("eth0", 1)
	state := &clientState{}

	state.updatePathRTTJitter(pc, 50*time.Millisecond)
	if pc.jitterNano.Load() != 0 {
		t.Errorf("first sample should not set jitter, got %v", time.Duration(pc.jitterNano.Load()))
	}

	state.updatePathRTTJitter(pc, 70*time.Millisecond)
	if pc.jitterNano.Load() == 0 {
		t.Error("jitter should be >0 after second sample with delta")
	}
}

func TestSetServerStateTransitions(t *testing.T) {
	state := &clientState{}
	state.serverAlive.Store(false)

	state.setServerState(true)
	if !state.serverAlive.Load() {
		t.Error("server should be marked alive")
	}

	state.setServerState(false)
	if state.serverAlive.Load() {
		t.Error("server should be marked dead")
	}
}

func TestSetPathStateTransitions(t *testing.T) {
	pc := testPath("eth0", 1)
	state := &clientState{}

	state.setPathState(pc, true, "connected")
	if !pc.alive.Load() {
		t.Error("path should be marked alive")
	}

	state.setPathState(pc, false, "timeout")
	if pc.alive.Load() {
		t.Error("path should be marked dead")
	}
}

func TestRefreshServerAliveFollowsPaths(t *testing.T) {
	p0 := testPath("eth0", 1)
	p1 := testPath("wlan0", 1)
	state := &clientState{paths: []*pathConn{p0, p1}}

	state.refreshServerAlive()
	if state.serverAlive.Load() {
		t.Error("no paths alive: server must be down")
	}

	p1.alive.Store(true)
	state.refreshServerAlive()
	if !state.serverAlive.Load() {
		t.Error("one path alive: server must be up")
	}
}

func TestSessionSnapshotReturnsIDAndServerAddr(t *testing.T) {
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
