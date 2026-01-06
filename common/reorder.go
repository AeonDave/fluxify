package common

import (
	"sync"
	"time"
)

// ReorderBuffer holds out-of-order packets and delivers them in sequence.
type ReorderBuffer struct {
	mu           sync.Mutex
	packets      map[uint32][]byte // seqNum -> packet data
	nextExpected uint32            // next sequence number we expect
	maxSize      int               // max packets to buffer
	timer        *time.Timer       // flush timer
	flushCh      chan struct{}     // signal to flush
	flushTimeout time.Duration
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
			PutBuffer(data)
			return nil
		}

		rb.packets[seq] = data

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

	return result
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
