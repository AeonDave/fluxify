package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStartTelemetryLoggerRejectsNonBondingMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := &clientState{mode: modeLoadBalance}
	tmpfile := filepath.Join(t.TempDir(), "telemetry.log")

	_, err := startTelemetryLogger(ctx, state, tmpfile)
	if err == nil {
		t.Fatal("expected error for non-bonding mode")
	}
	if err.Error() != "telemetry is only supported in bonding mode" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartTelemetryLoggerEmptyPathIsNoOp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := &clientState{mode: modeBonding}
	stop, err := startTelemetryLogger(ctx, state, "")
	if err != nil {
		t.Fatalf("expected no error for empty path: %v", err)
	}
	stop()
}

func TestStartTelemetryLoggerWritesSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	state := &clientState{
		mode:      modeBonding,
		sessionID: 12345,
	}
	state.serverAlive.Store(true)
	tmpfile := filepath.Join(t.TempDir(), "telemetry.log")

	stop, err := startTelemetryLogger(ctx, state, tmpfile)
	if err != nil {
		t.Fatalf("startTelemetryLogger: %v", err)
	}
	defer stop()

	// Wait for the initial snapshot.
	time.Sleep(300 * time.Millisecond)

	data, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("read telemetry: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("telemetry file is empty")
	}

	var snap telemetrySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if snap.SessionID != 12345 {
		t.Errorf("expected session 12345, got %d", snap.SessionID)
	}
	if snap.Mode != modeBonding {
		t.Errorf("expected mode bonding, got %s", snap.Mode)
	}
	if !snap.Aggregate.ServerAlive {
		t.Error("expected server alive")
	}
}

func TestBuildTelemetrySnapshotAggregatesPaths(t *testing.T) {
	state := &clientState{
		mode:      modeBonding,
		sessionID: 999,
	}
	state.serverAlive.Store(true)
	p0 := testPath("eth0", 1)
	p0.alive.Store(true)
	p0.bytesSent.Store(1000)
	p0.bytesRecv.Store(2000)
	p0.hbSent.Store(10)
	p0.hbRecv.Store(9)
	p1 := testPath("wlan0", 1)
	p1.bytesSent.Store(500)
	state.paths = []*pathConn{p0, p1}

	snap := buildTelemetrySnapshot(state)
	if snap.SessionID != 999 {
		t.Errorf("expected session 999, got %d", snap.SessionID)
	}
	if snap.Aggregate.TxBytes != 1500 {
		t.Errorf("expected tx 1500, got %d", snap.Aggregate.TxBytes)
	}
	if snap.Aggregate.RxBytes != 2000 {
		t.Errorf("expected rx 2000, got %d", snap.Aggregate.RxBytes)
	}
	if snap.Aggregate.ActivePaths != 1 {
		t.Errorf("expected 1 active path, got %d", snap.Aggregate.ActivePaths)
	}
	if snap.Aggregate.HBLossPct < 9 || snap.Aggregate.HBLossPct > 11 {
		t.Errorf("expected ~10%% loss, got %.2f%%", snap.Aggregate.HBLossPct)
	}
	if len(snap.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(snap.Paths))
	}
	if snap.Paths[0].Iface != "eth0" || !snap.Paths[0].Alive {
		t.Errorf("unexpected path[0]: %+v", snap.Paths[0])
	}
	if snap.Paths[1].Iface != "wlan0" || snap.Paths[1].Alive {
		t.Errorf("unexpected path[1]: %+v", snap.Paths[1])
	}
}
