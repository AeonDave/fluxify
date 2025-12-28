//go:build linux
// +build linux

package main

import (
	"strings"
	"testing"
	"time"
)

func TestFormatServerSessionMetrics_ContainsReorderAndConnInfo(t *testing.T) {
	m := serverSessionMetrics{
		SessionID:               123,
		Name:                    "alice",
		ReorderPacketsReordered: 9,
		ReorderPacketsDropped:   2,
		ReorderMaxDepth:         7,
		Conns: []serverConnMetric{
			{Addr: "1.2.3.4:1111", Alive: true, RTT: 10 * time.Millisecond, LastSeen: 20 * time.Millisecond, BytesSent: 100, BytesRecv: 200},
		},
	}
	out := formatServerSessionMetrics(m)
	for _, want := range []string{
		"session=123",
		"name=alice",
		"reordered=9",
		"dropped=2",
		"maxDepth=7",
		"conns=1",
		"1.2.3.4:1111",
		"tx=100",
		"rx=200",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}
