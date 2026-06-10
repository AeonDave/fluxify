package common

import (
	"sync"
	"sync/atomic"
	"time"
)

// ReorderStats is a snapshot of a ReorderBuffer's counters.
type ReorderStats struct {
	Buffered  uint64 // packets parked because they arrived out of order
	Reordered uint64 // parked packets later delivered in order
	Dropped   uint64 // old/duplicate packets discarded
	Flushes   uint64 // timeout flushes that released packets
	MaxDepth  uint32 // maximum simultaneously parked packets
}

// ReorderBuffer holds out-of-order packets and delivers them in sequence.
type ReorderBuffer struct {
	mu           sync.Mutex
	packets      map[uint32][]byte // seqNum -> packet data
	nextExpected uint32            // next sequence number we expect
	maxSize      int               // max packets to buffer
	timer        *time.Timer       // flush timer
	flushCh      chan struct{}     // signal to flush
	flushTimeout time.Duration

	statBuffered  atomic.Uint64
	statReordered atomic.Uint64
	statDropped   atomic.Uint64
	statFlushes   atomic.Uint64
	statMaxDepth  atomic.Uint32
}

// NewReorderBuffer creates a new buffer for packet reordering.
func NewReorderBuffer(maxSize int, flushTimeout time.Duration) *ReorderBuffer {
	if maxSize < 4 {
		maxSize = 4
	}
	if flushTimeout < 1*time.Millisecond {
		flushTimeout = 50 * time.Millisecond
	}
	return &ReorderBuffer{
		packets:      make(map[uint32][]byte),
		nextExpected: 1, // Start from 1 (first packet)
		maxSize:      maxSize,
		flushCh:      make(chan struct{}, 1),
		flushTimeout: flushTimeout,
	}
}

// Insert adds a packet and returns any packets that can now be delivered in order.
func (rb *ReorderBuffer) Insert(seq uint32, data []byte) [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Ignore old/duplicate packets (seq < nextExpected)
	if seq < rb.nextExpected {
		rb.statDropped.Add(1)
		PutBuffer(data)
		return nil
	}

	// Is this the packet we're waiting for?
	if seq == rb.nextExpected {
		result := [][]byte{data}
		rb.nextExpected++

		// Deliver any consecutive buffered packets
		for {
			if pkt, ok := rb.packets[rb.nextExpected]; ok {
				result = append(result, pkt)
				rb.statReordered.Add(1)
				delete(rb.packets, rb.nextExpected)
				rb.nextExpected++
			} else {
				break
			}
		}

		// Cancel flush timer if buffer is now empty
		if len(rb.packets) == 0 && rb.timer != nil {
			rb.timer.Stop()
			rb.timer = nil
		}

		return result
	}

	// Out-of-order packet: buffer it
	if seq > rb.nextExpected {
		// Don't store if already exists (duplicate)
		if _, exists := rb.packets[seq]; exists {
			rb.statDropped.Add(1)
			PutBuffer(data)
			return nil
		}

		rb.packets[seq] = data
		rb.statBuffered.Add(1)
		if depth := uint32(len(rb.packets)); depth > rb.statMaxDepth.Load() {
			rb.statMaxDepth.Store(depth)
		}

		// Start flush timer if this is the first buffered packet
		if len(rb.packets) == 1 {
			if rb.timer != nil {
				rb.timer.Stop()
			}
			rb.timer = time.AfterFunc(rb.flushTimeout, func() {
				select {
				case rb.flushCh <- struct{}{}:
				default:
				}
			})
		}

		// Buffer overflow: force flush oldest packets
		if len(rb.packets) > rb.maxSize {
			// Find the smallest seq in buffer and force deliver
			minSeq := rb.nextExpected
			for s := range rb.packets {
				if s < minSeq || minSeq == rb.nextExpected {
					minSeq = s
				}
			}
			if pkt, ok := rb.packets[minSeq]; ok {
				delete(rb.packets, minSeq)
				rb.nextExpected = minSeq + 1
				return [][]byte{pkt}
			}
		}
	}

	return nil
}

// FlushCh returns the channel used to signal flush timeouts.
func (rb *ReorderBuffer) FlushCh() <-chan struct{} {
	return rb.flushCh
}

// FlushTimeout forces delivery of buffered packets when timeout occurs.
func (rb *ReorderBuffer) FlushTimeout() [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.packets) == 0 {
		return nil
	}

	result := [][]byte{}

	// Deliver consecutive packets starting from nextExpected
	for {
		if pkt, ok := rb.packets[rb.nextExpected]; ok {
			result = append(result, pkt)
			delete(rb.packets, rb.nextExpected)
			rb.nextExpected++
		} else {
			// Gap detected: skip to next available packet
			if len(rb.packets) > 0 {
				// Find smallest seq >= nextExpected
				minSeq := uint32(1<<32 - 1)
				found := false
				for s := range rb.packets {
					if s >= rb.nextExpected && s < minSeq {
						minSeq = s
						found = true
					}
				}
				if found {
					// Jump over gap
					rb.nextExpected = minSeq
					continue
				}
			}
			break
		}
	}

	if rb.timer != nil {
		rb.timer.Stop()
		rb.timer = nil
	}

	if len(result) > 0 {
		rb.statFlushes.Add(1)
		rb.statReordered.Add(uint64(len(result)))
	}
	return result
}

// Stats returns a snapshot of the buffer's counters.
func (rb *ReorderBuffer) Stats() ReorderStats {
	return ReorderStats{
		Buffered:  rb.statBuffered.Load(),
		Reordered: rb.statReordered.Load(),
		Dropped:   rb.statDropped.Load(),
		Flushes:   rb.statFlushes.Load(),
		MaxDepth:  rb.statMaxDepth.Load(),
	}
}

// Reset drops all buffered packets and rewinds the expected sequence to the
// beginning, e.g. after a session refresh restarts the sender's numbering.
func (rb *ReorderBuffer) Reset() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.timer != nil {
		rb.timer.Stop()
		rb.timer = nil
	}
	for _, pkt := range rb.packets {
		PutBuffer(pkt)
	}
	rb.packets = make(map[uint32][]byte)
	rb.nextExpected = 1
}

// Close cleans up resources.
func (rb *ReorderBuffer) Close() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.timer != nil {
		rb.timer.Stop()
	}
	for _, pkt := range rb.packets {
		PutBuffer(pkt)
	}
	rb.packets = nil
}
