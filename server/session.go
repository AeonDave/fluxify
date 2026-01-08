//go:build linux
// +build linux

package main

import (
	"fluxify/common"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
)

const (
	connStaleTimeout   = 5 * time.Second
	sessionIdleTimeout = 2 * time.Minute
)

type serverConn struct {
	conn          *quic.Conn
	addr          string
	alive         atomic.Bool
	bytesSent     atomic.Uint64
	bytesRecv     atomic.Uint64
	lastRTT       atomic.Int64 // nanos
	lastRTTSample atomic.Int64 // nanos
	jitterNano    atomic.Int64 // nanos (EMA)
	lastSeen      atomic.Int64 // nanos (time since last packet from this addr)
	hbRecv        atomic.Uint64
}

type serverSession struct {
	id          uint32
	name        string
	conns       []*serverConn
	connMu      sync.RWMutex
	clientIP    net.IP // 10.8.0.X assigned
	clientIPv6  net.IP
	nextSeqSend atomic.Uint32
	lastSeen    atomic.Int64 // nanos
	reorderBuf  *common.ReorderBuffer
	stopReorder chan struct{}

	reorderStats struct {
		packetsReordered atomic.Uint64
		packetsDropped   atomic.Uint64
		maxBufferDepth   atomic.Uint32
	}
}

func newServerSession(id uint32, name string, ip4, ip6 net.IP, reorderSize int, reorderFlush time.Duration) *serverSession {
	sess := &serverSession{
		id:          id,
		name:        name,
		clientIP:    ip4,
		clientIPv6:  ip6,
		conns:       make([]*serverConn, 0, 4),
		reorderBuf:  common.NewReorderBuffer(reorderSize, reorderFlush),
		stopReorder: make(chan struct{}),
	}
	sess.touch()
	return sess
}

// Close cleanup resources for the session
func (s *serverSession) Close() {
	close(s.stopReorder)
	if s.reorderBuf != nil {
		s.reorderBuf.Close()
	}
}

func (s *serverSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (c *serverConn) touch() {
	c.lastSeen.Store(time.Now().UnixNano())
	c.alive.Store(true)
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
func (s *serverSession) updateOrAddConn(conn *quic.Conn) *serverConn {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	addrStr := ""
	if conn != nil {
		addrStr = conn.RemoteAddr().String()
	}
	for _, c := range s.conns {
		if c.addr == addrStr {
			c.touch()
			return c
		}
	}

	// New connection
	sc := &serverConn{conn: conn, addr: addrStr}
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

func (s *serverSession) sendDatagram(conn *serverConn, ptype uint8, payload []byte) error {
	if conn == nil || conn.conn == nil {
		return nil
	}
	seq := s.nextSeqSend.Add(1)
	head := common.DataPlaneHeader{Version: common.DataPlaneVersion, Type: ptype, SessionID: s.id, SeqNum: seq, Flags: 0}
	buf := common.GetBuffer()
	defer common.PutBuffer(buf)
	dg, err := common.BuildDataPlaneDatagram(buf, head, payload)
	if err != nil {
		return err
	}
	err = conn.conn.SendDatagram(dg)
	if err == nil {
		conn.bytesSent.Add(uint64(len(payload)))
	}
	return err
}
