package main

import (
	"sync"
	"time"

	"fluxify/common"
)

// reorderBuffer holds out-of-order packets (pool-backed) and delivers them in sequence.
//
// This is used client-side for inbound (server->client) and server-side for inbound (client->server).
// The client variant uses the same semantics:
//   - Insert takes ownership of data (pool buffer) unless it is returned in the output.
//   - If packet is old/duplicate it is returned to pool.
type reorderBuffer struct {
	mu           sync.Mutex
	packets      map[uint32][]byte
	nextExpected uint32
	maxSize      int
	flushTimeout time.Duration
	timer        *time.Timer
	flushCh      chan struct{}
}

func newClientReorderBuffer(maxSize int, flushTimeout time.Duration) *reorderBuffer {
	if maxSize < 4 {
		maxSize = 4
	}
	if flushTimeout < time.Millisecond {
		flushTimeout = time.Millisecond
	}
	return &reorderBuffer{
		packets:      make(map[uint32][]byte),
		nextExpected: 1,
		maxSize:      maxSize,
		flushTimeout: flushTimeout,
		flushCh:      make(chan struct{}, 1),
	}
}

// Insert adds a packet and returns any packets that can now be delivered in order.
func (rb *reorderBuffer) Insert(seq uint32, data []byte) [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if seq < rb.nextExpected {
		common.PutBuffer(data)
		return nil
	}

	if seq == rb.nextExpected {
		result := [][]byte{data}
		rb.nextExpected++
		for {
			pkt, ok := rb.packets[rb.nextExpected]
			if !ok {
				break
			}
			result = append(result, pkt)
			delete(rb.packets, rb.nextExpected)
			rb.nextExpected++
		}
		if len(rb.packets) == 0 && rb.timer != nil {
			rb.timer.Stop()
			rb.timer = nil
		}
		return result
	}

	// seq > nextExpected
	if _, exists := rb.packets[seq]; exists {
		common.PutBuffer(data)
		return nil
	}
	rb.packets[seq] = data

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

	// overflow
	if len(rb.packets) > rb.maxSize {
		minSeq := uint32(0)
		for s := range rb.packets {
			if minSeq == 0 || s < minSeq {
				minSeq = s
			}
		}
		if minSeq != 0 {
			pkt := rb.packets[minSeq]
			delete(rb.packets, minSeq)
			// Jump forward.
			if minSeq >= rb.nextExpected {
				rb.nextExpected = minSeq + 1
			}
			return [][]byte{pkt}
		}
	}

	return nil
}

// FlushTimeout forces delivery of buffered packets when timeout occurs.
func (rb *reorderBuffer) FlushTimeout() [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.packets) == 0 {
		return nil
	}
	result := [][]byte{}
	for {
		pkt, ok := rb.packets[rb.nextExpected]
		if ok {
			result = append(result, pkt)
			delete(rb.packets, rb.nextExpected)
			rb.nextExpected++
			continue
		}
		// jump to next available
		minSeq := uint32(0)
		for s := range rb.packets {
			if s >= rb.nextExpected && (minSeq == 0 || s < minSeq) {
				minSeq = s
			}
		}
		if minSeq == 0 {
			break
		}
		rb.nextExpected = minSeq
	}
	if rb.timer != nil {
		rb.timer.Stop()
		rb.timer = nil
	}
	return result
}

func (rb *reorderBuffer) Close() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.timer != nil {
		rb.timer.Stop()
		rb.timer = nil
	}
	for _, b := range rb.packets {
		common.PutBuffer(b)
	}
	rb.packets = nil
}
