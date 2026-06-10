package common

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultInitialRateBps seeds a new path optimistically (~20 Mbit/s) so the
	// scheduler offers it real traffic before any measurement exists.
	DefaultInitialRateBps = 2.5 * 1024 * 1024
	// MinPathRateBps is the floor used when estimating queue drain time, so a
	// path that measured ~0 still gets re-probed once faster paths back up.
	MinPathRateBps = 128 * 1024
	// DefaultRateTau is the EWMA time constant for rate estimation.
	DefaultRateTau = time.Second
)

// RateEstimator tracks the delivered throughput of a path as a time-aware EWMA
// over samples of a cumulative byte counter. Rate() is safe to call from hot
// paths; Update is expected to be called periodically (e.g. every 100ms).
type RateEstimator struct {
	mu        sync.Mutex
	lastBytes uint64
	lastAt    time.Time
	primed    bool
	tau       time.Duration
	rateBits  atomic.Uint64 // float64 bits, bytes/sec
}

func NewRateEstimator(initialBps float64, tau time.Duration) *RateEstimator {
	if initialBps <= 0 {
		initialBps = DefaultInitialRateBps
	}
	if tau <= 0 {
		tau = DefaultRateTau
	}
	e := &RateEstimator{tau: tau}
	e.rateBits.Store(math.Float64bits(initialBps))
	return e
}

// Update feeds a new sample of the cumulative byte counter. A counter going
// backwards (connection reset) re-primes the estimator without distorting the
// current rate.
func (e *RateEstimator) Update(totalBytes uint64, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.primed || totalBytes < e.lastBytes {
		e.lastBytes = totalBytes
		e.lastAt = now
		e.primed = true
		return
	}
	dt := now.Sub(e.lastAt).Seconds()
	if dt <= 0 {
		return
	}
	inst := float64(totalBytes-e.lastBytes) / dt
	alpha := 1 - math.Exp(-dt/e.tau.Seconds())
	rate := math.Float64frombits(e.rateBits.Load())
	rate += alpha * (inst - rate)
	e.rateBits.Store(math.Float64bits(rate))
	e.lastBytes = totalBytes
	e.lastAt = now
}

// Rate returns the current estimate in bytes/sec.
func (e *RateEstimator) Rate() float64 {
	return math.Float64frombits(e.rateBits.Load())
}

// Reset re-seeds the estimator (e.g. after a reconnect) so the path is probed
// again instead of carrying over a stale measurement.
func (e *RateEstimator) Reset(initialBps float64) {
	if initialBps <= 0 {
		initialBps = DefaultInitialRateBps
	}
	e.mu.Lock()
	e.primed = false
	e.rateBits.Store(math.Float64bits(initialBps))
	e.mu.Unlock()
}
