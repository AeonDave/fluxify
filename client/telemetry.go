package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	TunDrops  uint64 `json:"tun_drops"`
}

type telemetryPath struct {
	Iface       string  `json:"iface"`
	Local       string  `json:"local,omitempty"`
	Remote      string  `json:"remote,omitempty"`
	Alive       bool    `json:"alive"`
	RTTMs       float64 `json:"rtt_ms"`
	JitterMs    float64 `json:"jitter_ms"`
	RateBps     float64 `json:"rate_bps"`
	QueuedBytes int64   `json:"queued_bytes"`
	BytesSent   uint64  `json:"bytes_sent"`
	BytesRecv   uint64  `json:"bytes_recv"`
	PacketsSent uint64  `json:"packets_sent"`
	PacketsLost uint64  `json:"packets_lost"`
	LossPct     float64 `json:"loss_pct"`
	HBSent      uint64  `json:"hb_sent"`
	HBRecv      uint64  `json:"hb_recv"`
}

type telemetrySnapshot struct {
	Timestamp string             `json:"timestamp"`
	Mode      string             `json:"mode"`
	SessionID uint32             `json:"session_id"`
	Aggregate telemetryAggregate `json:"aggregate"`
	Reorder   telemetryReorder   `json:"reorder"`
	Paths     []telemetryPath    `json:"paths,omitempty"`
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
	active := 0
	paths := make([]telemetryPath, 0, len(state.paths))
	for _, pc := range state.paths {
		tp := telemetryPath{
			Iface:       pc.iface,
			Alive:       pc.alive.Load(),
			RTTMs:       float64(time.Duration(pc.rttNano.Load())) / float64(time.Millisecond),
			JitterMs:    float64(time.Duration(pc.jitterNano.Load())) / float64(time.Millisecond),
			RateBps:     pc.rate.Rate(),
			QueuedBytes: pc.queued.Load(),
			BytesSent:   pc.bytesSent.Load(),
			BytesRecv:   pc.bytesRecv.Load(),
			HBSent:      pc.hbSent.Load(),
			HBRecv:      pc.hbRecv.Load(),
		}
		if conn := pc.currentConn(); conn != nil {
			tp.Local = conn.LocalAddr().String()
			tp.Remote = conn.RemoteAddr().String()
			st := conn.ConnectionStats()
			tp.PacketsSent = st.PacketsSent
			tp.PacketsLost = st.PacketsLost
			if st.PacketsSent > 0 {
				tp.LossPct = float64(st.PacketsLost) * 100 / float64(st.PacketsSent)
			}
		}
		tx += tp.BytesSent
		rx += tp.BytesRecv
		hbSent += tp.HBSent
		hbRecv += tp.HBRecv
		if tp.Alive {
			active++
		}
		paths = append(paths, tp)
	}

	hbLossPct := 0.0
	if hbSent >= 3 {
		if hbRecv > hbSent {
			hbRecv = hbSent
		}
		hbLossPct = float64(hbSent-hbRecv) * 100 / float64(hbSent)
	}

	var rs common.ReorderStats
	if state.inReorder != nil {
		rs = state.inReorder.Stats()
	}
	sessID, _ := state.sessionSnapshot()
	return telemetrySnapshot{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Mode:      state.mode,
		SessionID: sessID,
		Aggregate: telemetryAggregate{
			TxBytes:     tx,
			RxBytes:     rx,
			ActivePaths: active,
			HBSent:      hbSent,
			HBRecv:      hbRecv,
			HBLossPct:   hbLossPct,
			ServerAlive: state.serverAlive.Load(),
		},
		Reorder: telemetryReorder{
			Buffered:  rs.Buffered,
			Reordered: rs.Reordered,
			Dropped:   rs.Dropped,
			Flushes:   rs.Flushes,
			MaxDepth:  rs.MaxDepth,
			TunDrops:  state.tunDrops.Load(),
		},
		Paths: paths,
	}
}
