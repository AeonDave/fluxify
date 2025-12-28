//go:build linux
// +build linux

package main

import (
	"fluxify/common"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	connStaleTimeout           = 5 * time.Second
	sessionIdleTimeout         = 2 * time.Minute
	defaultReorderBufferSize   = 128                   // max packets to buffer
	defaultReorderFlushTimeout = 50 * time.Millisecond // max wait for missing packet
)

var (
	serverReorderBufferSize   = defaultReorderBufferSize
	serverReorderFlushTimeout = defaultReorderFlushTimeout
)

type serverConn struct {
	udp           *net.UDPConn
	addr          *net.UDPAddr
	alive         atomic.Bool
	bytesSent     atomic.Uint64
	bytesRecv     atomic.Uint64
	lastRTT       atomic.Int64 // nanos
	lastRTTSample atomic.Int64 // nanos
	jitterNano    atomic.Int64 // nanos (EMA)
	lastSeen      atomic.Int64 // nanos (time since last packet from this addr)
	hbRecv        atomic.Uint64
}

// reorderBuffer holds out-of-order packets and delivers them in sequence

type reorderBuffer struct {
	mu           sync.Mutex
	packets      map[uint32][]byte // seqNum -> packet data
	nextExpected uint32            // next sequence number we expect
	maxSize      int               // max packets to buffer
	timer        *time.Timer       // flush timer
	flushCh      chan struct{}     // signal to flush
}

func newReorderBuffer(maxSize int) *reorderBuffer {
	return &reorderBuffer{
		packets:      make(map[uint32][]byte),
		nextExpected: 1, // Start from 1 (first packet from client)
		maxSize:      maxSize,
		flushCh:      make(chan struct{}, 1),
	}
}

func setServerReorderConfig(size int, flushTimeout time.Duration) {
	if size < 4 {
		size = 4
	}
	if flushTimeout < 1*time.Millisecond {
		flushTimeout = 1 * time.Millisecond
	}
	serverReorderBufferSize = size
	serverReorderFlushTimeout = flushTimeout
}

// Insert adds a packet and returns any packets that can now be delivered in order
func (rb *reorderBuffer) Insert(seq uint32, data []byte) [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Ignore old/duplicate packets (seq < nextExpected)
	if seq < rb.nextExpected {
		common.PutBuffer(data)
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
			common.PutBuffer(data)
			return nil
		}

		rb.packets[seq] = data

		// Start flush timer if this is the first buffered packet
		if len(rb.packets) == 1 {
			if rb.timer != nil {
				rb.timer.Stop()
			}
			rb.timer = time.AfterFunc(serverReorderFlushTimeout, func() {
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

// FlushTimeout forces delivery of buffered packets when timeout occurs
func (rb *reorderBuffer) FlushTimeout() [][]byte {
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

type serverSession struct {
	id          uint32
	name        string
	conns       []*serverConn
	connMu      sync.RWMutex
	clientIP    net.IP // 10.8.0.X assigned
	clientIPv6  net.IP
	key         []byte
	nextSeqSend atomic.Uint32
	lastSeen    atomic.Int64 // nanos
	reorderBuf  *reorderBuffer
	stopReorder chan struct{}

	// Outbound scheduler state (server -> client) for packet-level striping.
	schedMu      sync.Mutex
	schedDeficit map[*serverConn]float64
	nextConnRR   atomic.Uint32 // fallback round-robin index when all links bad

	// Flow scheduler (server -> client): keep packets of same flow on same conn.
	flowMu     sync.Mutex
	flowToConn map[common.FlowKey]*serverConn

	reorderStats struct {
		packetsReordered atomic.Uint64
		packetsDropped   atomic.Uint64
		maxBufferDepth   atomic.Uint32
	}
}

func newServerSession(id uint32, name string, key []byte, ip4, ip6 net.IP) *serverSession {
	sess := &serverSession{
		id:           id,
		name:         name,
		key:          key,
		clientIP:     ip4,
		clientIPv6:   ip6,
		conns:        make([]*serverConn, 0, 4),
		reorderBuf:   newReorderBuffer(serverReorderBufferSize),
		stopReorder:  make(chan struct{}),
		schedDeficit: make(map[*serverConn]float64),
	}
	sess.touch()
	return sess
}

// pickConnForIPPacket selects an outbound conn for a TUN-read IP packet.
// Phase 2: flow-based scheduling. Packets from the same 5-tuple flow are
// pinned to the same conn (if still alive) to avoid TCP collapse due to reordering.
func (s *serverSession) pickConnForIPPacket(pkt []byte) *serverConn {
	key, ok := common.FlowKeyFromIPPacket(pkt)
	if !ok {
		return s.pickStripedConn()
	}

	s.flowMu.Lock()
	if s.flowToConn == nil {
		s.flowToConn = make(map[common.FlowKey]*serverConn)
	}
	if c, exists := s.flowToConn[key]; exists {
		if c != nil && c.alive.Load() {
			s.flowMu.Unlock()
			return c
		}
		delete(s.flowToConn, key)
	}
	s.flowMu.Unlock()

	c := s.pickStripedConn()
	if c == nil {
		return nil
	}
	s.flowMu.Lock()
	s.flowToConn[key] = c
	s.flowMu.Unlock()
	return c
}

// pickStripedConn selects a connection for outbound packets using adaptive
// good/bad link classification based on RTT ratio, jitter, and freshness.
//
// Goal: distribute packets across good links to aggregate bandwidth, while
// excluding high-jitter or high-latency links that would cause excessive
// packet reordering and TCP throughput collapse.
func (s *serverSession) pickStripedConn() *serverConn {
	s.connMu.RLock()
	if len(s.conns) == 0 {
		s.connMu.RUnlock()
		return nil
	}
	now := time.Now().UnixNano()
	alive := make([]*serverConn, 0, len(s.conns))
	for _, c := range s.conns {
		if !c.alive.Load() {
			continue
		}
		last := c.lastSeen.Load()
		if time.Duration(now-last) > connStaleTimeout {
			continue
		}
		alive = append(alive, c)
	}
	s.connMu.RUnlock()

	if len(alive) == 0 {
		return nil
	}
	if len(alive) == 1 {
		return alive[0]
	}

	// Phase 1: strict bad-link exclusion.
	// Mixed RTT links (ETH + 5G hotspot) collapse TCP even with tiny shares.
	flush := serverReorderFlushTimeout
	if flush <= 0 {
		flush = 50 * time.Millisecond
	}
	maxJitter := clampDuration(time.Duration(float64(flush)*0.3), 10*time.Millisecond, 25*time.Millisecond)
	maxRttRatio := 1.5

	// maxLastSeenGap: if lastSeen > this, link is stale (already filtered above by connStaleTimeout)
	// We use a tighter threshold for scheduling decisions
	maxLastSeenGap := flush * 2
	if maxLastSeenGap < 100*time.Millisecond {
		maxLastSeenGap = 100 * time.Millisecond
	}

	// --- Find minRTT among alive connections ---
	minRTT := int64(500 * time.Millisecond)
	for _, c := range alive {
		rtt := c.lastRTT.Load()
		if rtt > 0 && rtt < minRTT {
			minRTT = rtt
		}
	}

	// --- Classify links as good/bad ---
	good := make([]*serverConn, 0, len(alive))
	for _, c := range alive {
		rtt := c.lastRTT.Load()
		jitter := c.jitterNano.Load()
		lastSeen := time.Duration(now - c.lastSeen.Load())

		// Check bad conditions
		isBad := false

		// 1. High jitter
		if jitter > int64(maxJitter) {
			isBad = true
		}

		// 2. High RTT ratio vs best link
		if rtt > 0 && minRTT > 0 {
			ratio := float64(rtt) / float64(minRTT)
			if ratio > maxRttRatio {
				isBad = true
			}
		}

		// 3. Stale (no recent heartbeat response)
		if lastSeen > maxLastSeenGap {
			isBad = true
		}

		if !isBad {
			good = append(good, c)
		}
	}

	// Fallback: if all links are bad/unknown, pick the best RTT alive.
	if len(good) == 0 {
		var best *serverConn
		bestRTT := int64(1<<63 - 1)
		for _, c := range alive {
			rtt := c.lastRTT.Load()
			if rtt <= 0 {
				rtt = int64(500 * time.Millisecond)
			}
			if rtt < bestRTT {
				bestRTT = rtt
				best = c
			}
		}
		if best != nil {
			return best
		}
		idx := s.nextConnRR.Add(1) - 1
		return alive[int(idx)%len(alive)]
	}

	// --- Weighted deficit round-robin on good links ---
	const minShare = 0.15 // floor share to ensure all good links get some traffic

	// Compute weights based on inverse RTT (higher weight = more packets)
	weights := make(map[*serverConn]float64, len(good))
	var totalWeight float64
	for _, c := range good {
		rtt := c.lastRTT.Load()
		if rtt <= 0 {
			rtt = int64(50 * time.Millisecond) // default for unknown RTT
		}
		rttMs := float64(rtt) / float64(time.Millisecond)
		if rttMs < 1 {
			rttMs = 1
		}
		// Weight = 1/RTT (lower RTT = higher weight)
		w := 1.0 / rttMs
		weights[c] = w
		totalWeight += w
	}

	// Normalize and apply floor share
	if totalWeight > 0 {
		for c := range weights {
			share := weights[c] / totalWeight
			if share < minShare {
				share = minShare
			}
			weights[c] = share
		}
	}

	// --- Deficit round-robin ---
	s.schedMu.Lock()
	defer s.schedMu.Unlock()

	if s.schedDeficit == nil {
		s.schedDeficit = make(map[*serverConn]float64)
	}

	// Add weighted credit to each good connection
	for c, w := range weights {
		s.schedDeficit[c] += w
	}

	// Pick the connection with highest deficit
	var best *serverConn
	bestDef := -1e18
	for c := range weights {
		if s.schedDeficit[c] > bestDef {
			bestDef = s.schedDeficit[c]
			best = c
		}
	}

	if best == nil {
		return good[0]
	}

	// Consume 1 credit
	s.schedDeficit[best] -= 1.0
	return best
}

// Close cleanup resources for the session
func (s *serverSession) Close() {
	close(s.stopReorder)
	if s.reorderBuf != nil && s.reorderBuf.timer != nil {
		s.reorderBuf.timer.Stop()
	}
}

func (s *serverSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (c *serverConn) touch() {
	c.lastSeen.Store(time.Now().UnixNano())
	c.alive.Store(true)
}

// clampDuration constrains d within [min, max].
func clampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

// updateServerConnRTT updates RTT and computes jitter EMA for a connection.
// Call this whenever a heartbeat RTT sample arrives.
func updateServerConnRTT(c *serverConn, rtt time.Duration) {
	c.hbRecv.Add(1)
	rttNano := int64(rtt)
	prevSample := c.lastRTTSample.Swap(rttNano)
	c.lastRTT.Store(rttNano)

	// Jitter = EMA of |rtt - prevRtt|
	if prevSample > 0 {
		delta := rttNano - prevSample
		if delta < 0 {
			delta = -delta
		}
		const alpha = 0.25 // smoothing factor
		oldJitter := c.jitterNano.Load()
		newJitter := int64(float64(oldJitter)*(1-alpha) + float64(delta)*alpha)
		c.jitterNano.Store(newJitter)
	}
}

// updateOrAddConn updates an existing connection's alive status or adds a new one.
// Returns the connection object.
func (s *serverSession) updateOrAddConn(udp *net.UDPConn, addr *net.UDPAddr) *serverConn {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	addrStr := addr.String()
	for _, c := range s.conns {
		if c.addr.String() == addrStr {
			c.touch()
			return c
		}
	}

	// New connection
	sc := &serverConn{udp: udp, addr: addr}
	sc.touch()
	s.conns = append(s.conns, sc)
	return sc
}

// pickBestConn selects the alive connection with the lowest RTT.
func (s *serverSession) pickBestConn() *serverConn {
	s.connMu.RLock()
	defer s.connMu.RUnlock()

	if len(s.conns) == 0 {
		return nil
	}

	var best *serverConn
	bestRTT := int64(1<<63 - 1)
	now := time.Now().UnixNano()

	for _, c := range s.conns {
		if !c.alive.Load() {
			continue
		}
		// Ignore stale connections (no traffic for > 5s)
		last := c.lastSeen.Load()
		if time.Duration(now-last) > connStaleTimeout {
			continue
		}

		// prefer recently active connections with low RTT
		rtt := c.lastRTT.Load()
		if rtt <= 0 {
			rtt = int64(500 * time.Millisecond) // penalty for unknown RTT
		}

		if rtt < bestRTT {
			bestRTT = rtt
			best = c
		}
	}

	if best == nil && len(s.conns) > 0 {
		// If all marked dead or stale, try the most recently seen one as fallback
		var recent *serverConn
		var maxSeen int64
		for _, c := range s.conns {
			ls := c.lastSeen.Load()
			if ls > maxSeen {
				maxSeen = ls
				recent = c
			}
		}
		best = recent
	}
	return best
}

// pruneStaleConns removes connections that haven't been seen for a long time (e.g. 30s)
// to prevent memory leaks in the slice.
func (s *serverSession) pruneStaleConns() {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	active := s.conns[:0]
	now := time.Now().UnixNano()
	limit := int64(30 * time.Second)

	for _, c := range s.conns {
		if now-c.lastSeen.Load() < limit {
			active = append(active, c)
		}
	}
	s.conns = active
}

func (s *serverSession) isIdle() bool {
	return time.Duration(time.Now().UnixNano()-s.lastSeen.Load()) > sessionIdleTimeout
}

func (s *serverSession) encryptAndSend(conn *serverConn, ptype uint8, payload []byte, compress bool) error {
	if conn == nil {
		return nil
	}

	finalPayload := payload
	compFlag := common.CompressionNone

	if compress {
		if c, err := common.CompressPayload(payload); err == nil && len(c) < len(payload) {
			finalPayload = c
			compFlag = common.CompressionGzip
		}
	}

	seq := s.nextSeqSend.Add(1)
	head := common.PacketHeader{
		Version:   common.ProtoVersion,
		Type:      ptype,
		SessionID: s.id,
		SeqNum:    seq,
		Length:    uint16(len(finalPayload)),
	}
	head.Reserved[0] = byte(compFlag)

	// Use pool for encryption output
	pktBuf := common.GetBuffer()
	defer common.PutBuffer(pktBuf)

	pkt, err := common.EncryptPacketInto(pktBuf, s.key, head, finalPayload)
	if err != nil {
		return err
	}

	_, err = conn.udp.WriteToUDP(pkt, conn.addr)
	if err == nil {
		conn.bytesSent.Add(uint64(len(payload)))
	}
	return err
}
