package common

import "time"

// PathMetrics is a send-side snapshot of one path, used for scheduling.
type PathMetrics struct {
	// QueuedBytes is the amount of data accepted for this path but not yet
	// handed to the transport (application-level backlog).
	QueuedBytes int64
	// RateBps is the estimated delivered throughput in bytes/sec.
	RateBps float64
	// RTT is the smoothed round-trip time of the path (0 if unknown).
	RTT time.Duration
	// Alive reports whether the path currently has a usable connection.
	Alive bool
}

// PickPath selects the path with the earliest estimated delivery time for a
// packet of pktLen bytes:
//
//	ETA = (queued + pktLen) / max(rate, MinPathRateBps) + RTT/2
//
// With idle queues this degenerates to lowest-RTT selection, keeping sparse
// traffic on the fastest path. Under load the backlog term dominates and
// packets spread across paths proportionally to their measured capacity,
// which is what produces bandwidth aggregation. Returns -1 if no path is
// alive.
func PickPath(paths []PathMetrics, pktLen int) int {
	best := -1
	var bestETA float64
	for i, p := range paths {
		if !p.Alive {
			continue
		}
		rate := p.RateBps
		if rate < MinPathRateBps {
			rate = MinPathRateBps
		}
		eta := (float64(p.QueuedBytes)+float64(pktLen))/rate + p.RTT.Seconds()/2
		if best == -1 || eta < bestETA {
			best = i
			bestETA = eta
		}
	}
	return best
}
