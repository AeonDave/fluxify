package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	quic "github.com/AeonDave/mp-quic-go"

	"fluxify/common"
)

type telemetryAggregate struct {
	TxBytes     uint64  `json:"tx_bytes"`
	RxBytes     uint64  `json:"rx_bytes"`
	ActivePaths int     `json:"active_paths"`
	HBSent      uint64  `json:"hb_sent"`
	HBRecv      uint64  `json:"hb_recv"`
	HBLossPct   float64 `json:"hb_loss_pct"`
	ServerAlive bool    `json:"server_alive"`
}

type telemetryReorder struct {
	Buffered  uint64 `json:"buffered"`
	Reordered uint64 `json:"reordered"`
	Dropped   uint64 `json:"dropped"`
	Flushes   uint64 `json:"flushes"`
	MaxDepth  uint32 `json:"max_depth"`
}

type telemetryMPPath struct {
	PathID      int     `json:"path_id"`
	Local       string  `json:"local,omitempty"`
	Remote      string  `json:"remote,omitempty"`
	RTTMs       float64 `json:"rtt_ms"`
	CWND        uint64  `json:"cwnd"`
	InFlight    uint64  `json:"in_flight"`
	BytesSent   uint64  `json:"bytes_sent"`
	PacketsSent uint64  `json:"packets_sent"`
	PacketsLost uint64  `json:"packets_lost"`
	LossPct     float64 `json:"loss_pct"`
}

type telemetrySnapshot struct {
	Timestamp string             `json:"timestamp"`
	Mode      string             `json:"mode"`
	SessionID uint32             `json:"session_id"`
	Aggregate telemetryAggregate `json:"aggregate"`
	Reorder   telemetryReorder   `json:"reorder"`
	MPPaths   []telemetryMPPath  `json:"mp_paths,omitempty"`
}

func startTelemetryLogger(ctx context.Context, state *clientState, path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	if state == nil {
		return nil, fmt.Errorf("telemetry: nil state")
	}
	if state.mode != modeBonding {
		return nil, fmt.Errorf("telemetry is only supported in bonding mode")
	}

	p := common.ExpandPath(path)
	dir := filepath.Dir(p)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("telemetry: mkdir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("telemetry: open %s: %w", p, err)
	}

	stop := make(chan struct{})
	go func() {
		defer func() { _ = f.Close() }()
		enc := json.NewEncoder(f)
		enc.SetEscapeHTML(false)
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()

		// Write an initial snapshot immediately.
		_ = enc.Encode(buildTelemetrySnapshot(state))
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				_ = enc.Encode(buildTelemetrySnapshot(state))
			}
		}
	}()

	return func() { close(stop) }, nil
}

func buildTelemetrySnapshot(state *clientState) telemetrySnapshot {
	var tx, rx, hbSent, hbRecv uint64
	state.connMu.RLock()
	if len(state.conns) > 0 {
		cc := state.conns[0]
		tx = cc.bytesSent.Load()
		rx = cc.bytesRecv.Load()
		hbSent = cc.hbSent.Load()
		hbRecv = cc.hbRecv.Load()
	}
	state.connMu.RUnlock()

	hbLossPct := 0.0
	if hbSent >= 3 {
		if hbRecv > hbSent {
			hbRecv = hbSent
		}
		hbLossPct = float64(hbSent-hbRecv) * 100 / float64(hbSent)
	}

	mpStats := state.GetMPPathStats()
	paths := make([]telemetryMPPath, 0, len(mpStats))
	if len(mpStats) > 0 {
		ids := make([]quic.PathID, 0, len(mpStats))
		for id := range mpStats {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			ps := mpStats[id]
			local := ""
			remote := ""
			if state.mpController != nil {
				if info, ok := state.mpController.PathInfoForID(id); ok {
					if info.LocalAddr != nil {
						local = info.LocalAddr.String()
					}
					if info.RemoteAddr != nil {
						remote = info.RemoteAddr.String()
					}
				}
			}
			lossPct := 0.0
			if ps.PacketsSent > 0 {
				lossPct = float64(ps.PacketsLost) * 100 / float64(ps.PacketsSent)
			}
			paths = append(paths, telemetryMPPath{
				PathID:      int(ps.PathID),
				Local:       local,
				Remote:      remote,
				RTTMs:       float64(ps.SmoothedRTT) / float64(time.Millisecond),
				CWND:        uint64(ps.CongestionWindow),
				InFlight:    uint64(ps.BytesInFlight),
				BytesSent:   uint64(ps.BytesSent),
				PacketsSent: ps.PacketsSent,
				PacketsLost: ps.PacketsLost,
				LossPct:     lossPct,
			})
		}
	}

	snap := telemetrySnapshot{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Mode:      state.mode,
		SessionID: state.sessionID,
		Aggregate: telemetryAggregate{
			TxBytes:     tx,
			RxBytes:     rx,
			ActivePaths: len(paths),
			HBSent:      hbSent,
			HBRecv:      hbRecv,
			HBLossPct:   hbLossPct,
			ServerAlive: state.serverAlive.Load(),
		},
		Reorder: telemetryReorder{
			Buffered:  state.inReorderStats.packetsBuffered.Load(),
			Reordered: state.inReorderStats.packetsReordered.Load(),
			Dropped:   state.inReorderStats.packetsDropped.Load(),
			Flushes:   state.inReorderStats.flushes.Load(),
			MaxDepth:  state.inReorderStats.maxDepth.Load(),
		},
		MPPaths: paths,
	}
	return snap
}
