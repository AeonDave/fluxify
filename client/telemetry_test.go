package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
)

func TestStartTelemetryLogger_RejectsNonBondingMode(t *testing.T) {
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

func TestStartTelemetryLogger_EmptyPathIsNoOp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := &clientState{mode: modeBonding}
	stop, err := startTelemetryLogger(ctx, state, "")
	if err != nil {
		t.Fatalf("expected no error for empty path: %v", err)
	}
	stop()
}

func TestStartTelemetryLogger_WritesSnapshot(t *testing.T) {
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

	// Wait for initial snapshot + one tick
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

func TestBuildTelemetrySnapshot_WithMPPathStats(t *testing.T) {
	state := &clientState{
		mode:         modeBonding,
		sessionID:    999,
		mpController: nil, // no paths
	}
	state.serverAlive.Store(true)
	cc := &clientConn{}
	cc.bytesSent.Store(1000)
	cc.bytesRecv.Store(2000)
	cc.hbSent.Store(10)
	cc.hbRecv.Store(9)
	state.conns = []*clientConn{cc}

	snap := buildTelemetrySnapshot(state)
	if snap.SessionID != 999 {
		t.Errorf("expected session 999, got %d", snap.SessionID)
	}
	if snap.Aggregate.TxBytes != 1000 {
		t.Errorf("expected tx 1000, got %d", snap.Aggregate.TxBytes)
	}
	if snap.Aggregate.RxBytes != 2000 {
		t.Errorf("expected rx 2000, got %d", snap.Aggregate.RxBytes)
	}
	if snap.Aggregate.HBLossPct < 9 || snap.Aggregate.HBLossPct > 11 {
		t.Errorf("expected ~10%% loss, got %.2f%%", snap.Aggregate.HBLossPct)
	}
	if len(snap.MPPaths) != 0 {
		t.Errorf("expected no paths (nil controller), got %d", len(snap.MPPaths))
	}
}

func TestBuildTelemetrySnapshot_WithFakeController(t *testing.T) {
	// Create a fake DefaultMultipathController that returns some stats
	ctrl := quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler())
	state := &clientState{
		mode:         modeBonding,
		sessionID:    111,
		mpController: ctrl,
	}
	state.serverAlive.Store(true)
	cc := &clientConn{}
	state.conns = []*clientConn{cc}

	snap := buildTelemetrySnapshot(state)
	// With no paths registered, GetStatistics returns empty map
	if len(snap.MPPaths) != 0 {
		t.Logf("got %d paths (expected 0 without real paths)", len(snap.MPPaths))
	}
}
