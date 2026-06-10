package common

import (
	"testing"
	"time"
)

func TestPickPathNoAlive(t *testing.T) {
	paths := []PathMetrics{
		{Alive: false, RateBps: 1e6},
		{Alive: false, RateBps: 1e6},
	}
	if got := PickPath(paths, 1400); got != -1 {
		t.Fatalf("expected -1, got %d", got)
	}
	if got := PickPath(nil, 1400); got != -1 {
		t.Fatalf("expected -1 for empty slice, got %d", got)
	}
}

func TestPickPathIdlePrefersLowRTT(t *testing.T) {
	paths := []PathMetrics{
		{Alive: true, RateBps: 10e6, RTT: 80 * time.Millisecond},
		{Alive: true, RateBps: 10e6, RTT: 10 * time.Millisecond},
	}
	if got := PickPath(paths, 1400); got != 1 {
		t.Fatalf("expected fastest-RTT path 1, got %d", got)
	}
}

func TestPickPathSpillsWhenFastPathBacklogged(t *testing.T) {
	// Fast path has 12ms RTT but a 500KB backlog at 10MB/s -> ~50ms queue delay.
	// Slow path has 40ms RTT and empty queue -> ETA ~20ms + serialization.
	paths := []PathMetrics{
		{Alive: true, RateBps: 10e6, RTT: 12 * time.Millisecond, QueuedBytes: 500_000},
		{Alive: true, RateBps: 2e6, RTT: 40 * time.Millisecond},
	}
	if got := PickPath(paths, 1400); got != 1 {
		t.Fatalf("expected spillover to path 1, got %d", got)
	}
}

func TestPickPathSkipsDead(t *testing.T) {
	paths := []PathMetrics{
		{Alive: false, RateBps: 100e6, RTT: time.Millisecond},
		{Alive: true, RateBps: 1e6, RTT: 100 * time.Millisecond},
	}
	if got := PickPath(paths, 1400); got != 1 {
		t.Fatalf("expected only-alive path 1, got %d", got)
	}
}

func TestPickPathRateFloorKeepsProbing(t *testing.T) {
	// A path that measured ~0 must still win once the other path's queue
	// delay exceeds the floor-rate serialization estimate.
	paths := []PathMetrics{
		{Alive: true, RateBps: 10e6, RTT: 5 * time.Millisecond, QueuedBytes: 2_000_000}, // 200ms backlog
		{Alive: true, RateBps: 0, RTT: 5 * time.Millisecond},
	}
	if got := PickPath(paths, 1400); got != 1 {
		t.Fatalf("expected floor-rate probe of path 1, got %d", got)
	}
}

func TestPickPathProportionalSpread(t *testing.T) {
	// Simulate scheduling a burst and draining queues at each path's rate:
	// the split should roughly follow the 3:1 capacity ratio.
	paths := []PathMetrics{
		{Alive: true, RateBps: 3e6, RTT: 20 * time.Millisecond},
		{Alive: true, RateBps: 1e6, RTT: 20 * time.Millisecond},
	}
	const pkt = 1400
	// Offered load slightly above aggregate capacity, so queues build and the
	// backlog term steers the split.
	const arrivalBps = 4.4e6
	counts := [2]int{}
	for i := 0; i < 4000; i++ {
		idx := PickPath(paths[:], pkt)
		counts[idx]++
		paths[idx].QueuedBytes += pkt
		// Advance wall-clock by the packet inter-arrival time; each path
		// drains at its own rate during that interval.
		dt := float64(pkt) / arrivalBps
		for j := range paths {
			drained := int64(dt * paths[j].RateBps)
			if paths[j].QueuedBytes < drained {
				paths[j].QueuedBytes = 0
			} else {
				paths[j].QueuedBytes -= drained
			}
		}
	}
	ratio := float64(counts[0]) / float64(counts[1])
	if ratio < 2.0 || ratio > 4.5 {
		t.Fatalf("expected ~3:1 split, got %d:%d (ratio %.2f)", counts[0], counts[1], ratio)
	}
}

func TestRateEstimatorConverges(t *testing.T) {
	now := time.Unix(0, 0)
	e := NewRateEstimator(DefaultInitialRateBps, time.Second)
	var total uint64
	// 1 MB/s for 5 seconds in 100ms steps.
	for i := 0; i < 50; i++ {
		now = now.Add(100 * time.Millisecond)
		total += 100_000
		e.Update(total, now)
	}
	rate := e.Rate()
	if rate < 0.8e6 || rate > 1.3e6 {
		t.Fatalf("expected ~1MB/s, got %.0f", rate)
	}
}

func TestRateEstimatorCounterReset(t *testing.T) {
	now := time.Unix(0, 0)
	e := NewRateEstimator(1e6, time.Second)
	e.Update(1_000_000, now)
	e.Update(2_000_000, now.Add(time.Second))
	before := e.Rate()
	// Counter goes backwards (reconnect): must not panic or spike.
	e.Update(10, now.Add(2*time.Second))
	if e.Rate() != before {
		t.Fatalf("rate changed on counter reset: %.0f -> %.0f", before, e.Rate())
	}
	// Next sample resumes normally.
	e.Update(500_010, now.Add(3*time.Second))
	if e.Rate() <= 0 {
		t.Fatalf("rate should stay positive, got %.0f", e.Rate())
	}
}

func TestRateEstimatorReset(t *testing.T) {
	e := NewRateEstimator(1e6, time.Second)
	e.Update(0, time.Unix(0, 0))
	e.Update(10_000_000, time.Unix(1, 0))
	e.Reset(2e6)
	if e.Rate() != 2e6 {
		t.Fatalf("expected reset rate 2e6, got %.0f", e.Rate())
	}
}
