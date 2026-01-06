//go:build linux
// +build linux

package main

import (
	"fmt"
	"sort"
	"time"
)

type serverConnMetric struct {
	Addr      string
	Alive     bool
	RTT       time.Duration
	Jitter    time.Duration
	BytesSent uint64
	BytesRecv uint64
	LastSeen  time.Duration
}

type serverSessionMetrics struct {
	SessionID uint32
	Name      string
	Conns     []serverConnMetric

	ReorderPacketsReordered uint64
	ReorderPacketsDropped   uint64
	ReorderMaxDepth         uint32
}

func (s *serverSession) snapshotMetrics() serverSessionMetrics {
	out := serverSessionMetrics{
		SessionID:               s.id,
		Name:                    s.name,
		ReorderPacketsReordered: s.reorderStats.packetsReordered.Load(),
		ReorderPacketsDropped:   s.reorderStats.packetsDropped.Load(),
		ReorderMaxDepth:         s.reorderStats.maxBufferDepth.Load(),
	}

	now := time.Now().UnixNano()
	s.connMu.RLock()
	out.Conns = make([]serverConnMetric, 0, len(s.conns))
	for _, c := range s.conns {
		last := time.Duration(now - c.lastSeen.Load())
		rtt := time.Duration(c.lastRTT.Load())
		jitter := time.Duration(c.jitterNano.Load())
		out.Conns = append(out.Conns, serverConnMetric{
			Addr:      addrString(c),
			Alive:     c.alive.Load(),
			RTT:       rtt,
			Jitter:    jitter,
			BytesSent: c.bytesSent.Load(),
			BytesRecv: c.bytesRecv.Load(),
			LastSeen:  last,
		})
	}
	s.connMu.RUnlock()

	sort.Slice(out.Conns, func(i, j int) bool { return out.Conns[i].Addr < out.Conns[j].Addr })
	return out
}

func addrString(c *serverConn) string {
	if c == nil || c.addr == "" {
		return "-"
	}
	return c.addr
}

func formatServerSessionMetrics(m serverSessionMetrics) string {
	line := fmt.Sprintf("session=%d name=%s reorder(reordered=%d dropped=%d maxDepth=%d)",
		m.SessionID, m.Name, m.ReorderPacketsReordered, m.ReorderPacketsDropped, m.ReorderMaxDepth)
	if len(m.Conns) == 0 {
		return line + " conns=0"
	}
	parts := make([]string, 0, len(m.Conns))
	for _, c := range m.Conns {
		alive := "down"
		if c.Alive {
			alive = "up"
		}
		parts = append(parts, fmt.Sprintf("%s(%s rtt=%s jitter=%s last=%s tx=%d rx=%d)",
			c.Addr, alive, c.RTT.Round(time.Millisecond), c.Jitter.Round(time.Millisecond), c.LastSeen.Round(time.Millisecond), c.BytesSent, c.BytesRecv))
	}
	return line + " " + fmt.Sprintf("conns=%d ", len(m.Conns)) + joinParts(parts)
}

func joinParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += " | " + parts[i]
	}
	return out
}
