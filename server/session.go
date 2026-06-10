//go:build linux

package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"

	"fluxify/common"
)

const (
	connStaleTimeout   = 30 * time.Second
	sessionIdleTimeout = 2 * time.Minute
	// connSendQueueLen is the per-path downlink backlog (packets); its
	// occupancy is what the striping scheduler keys on.
	connSendQueueLen = 256
)

// serverConn is one client uplink path as seen from the server: a QUIC
// connection with its own sender goroutine, backlog and rate estimate used
// for downlink striping.
type serverConn struct {
	conn *quic.Conn
	addr string

	sendCh chan []byte
	queued atomic.Int64
	rate   *common.RateEstimator

	alive      atomic.Bool
	bytesSent  atomic.Uint64
	bytesRecv  atomic.Uint64
	rttNano    atomic.Int64 // smoothed RTT from QUIC stats
	jitterNano atomic.Int64 // RTT mean deviation from QUIC stats
	lastSeen   atomic.Int64 // unix nanos of last inbound datagram
	hbRecv     atomic.Uint64
}

func newServerConn(conn *quic.Conn) *serverConn {
	sc := &serverConn{
		conn:   conn,
		addr:   conn.RemoteAddr().String(),
		sendCh: make(chan []byte, connSendQueueLen),
		rate:   common.NewRateEstimator(common.DefaultInitialRateBps, common.DefaultRateTau),
	}
	sc.alive.Store(true)
	sc.touch()
	go sc.sender()
	return sc
}

// sender drains the downlink queue into the QUIC connection. SendDatagram
// blocks when the transport's datagram queue is full, which is the
// congestion backpressure that makes the queue occupancy meaningful.
func (c *serverConn) sender() {
	done := c.conn.Context().Done()
	for {
		select {
		case <-done:
			c.alive.Store(false)
			c.drainQueue()
			return
		case dg := <-c.sendCh:
			if err := c.conn.SendDatagram(dg); err == nil {
				c.bytesSent.Add(uint64(len(dg)))
			}
			c.queued.Add(-int64(len(dg)))
			common.PutBuffer(dg)
		}
	}
}

func (c *serverConn) drainQueue() {
	for {
		select {
		case dg := <-c.sendCh:
			c.queued.Add(-int64(len(dg)))
			common.PutBuffer(dg)
		default:
			return
		}
	}
}

// enqueue offers a datagram to this path without blocking; on a full queue
// the datagram is dropped (correct backpressure for tunneled traffic).
func (c *serverConn) enqueue(dg []byte) bool {
	c.queued.Add(int64(len(dg)))
	select {
	case c.sendCh <- dg:
		return true
	default:
		c.queued.Add(-int64(len(dg)))
		common.PutBuffer(dg)
		return false
	}
}

func (c *serverConn) touch() {
	c.lastSeen.Store(time.Now().UnixNano())
}

func (c *serverConn) usable() bool {
	return c.alive.Load() && c.conn.Context().Err() == nil
}

func (c *serverConn) metrics() common.PathMetrics {
	return common.PathMetrics{
		QueuedBytes: c.queued.Load(),
		RateBps:     c.rate.Rate(),
		RTT:         time.Duration(c.rttNano.Load()),
		Alive:       c.usable(),
	}
}

type serverSession struct {
	id          uint32
	name        string
	clientIP    net.IP // 10.8.0.X assigned
	clientIPv6  net.IP
	nextSeqSend atomic.Uint32
	lastSeen    atomic.Int64 // nanos
	reorderBuf  *common.ReorderBuffer
	stopReorder chan struct{}

	connMu sync.RWMutex
	conns  []*serverConn

	// dispatch scratch space; dispatch is only ever called from the single
	// TUN read loop, so no synchronization is needed for these.
	scratchConns   []*serverConn
	scratchMetrics []common.PathMetrics
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

// Close tears down the session: reorder buffer, paths and their senders.
func (s *serverSession) Close() {
	close(s.stopReorder)
	if s.reorderBuf != nil {
		s.reorderBuf.Close()
	}
	s.connMu.Lock()
	conns := s.conns
	s.conns = nil
	s.connMu.Unlock()
	for _, c := range conns {
		_ = c.conn.CloseWithError(0, "session closed")
	}
}

func (s *serverSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *serverSession) isIdle() bool {
	return time.Duration(time.Now().UnixNano()-s.lastSeen.Load()) > sessionIdleTimeout
}

// connFor returns the path entry for the given QUIC connection, creating it
// (and starting its sender) on first sight.
func (s *serverSession) connFor(conn *quic.Conn) *serverConn {
	s.connMu.RLock()
	for _, c := range s.conns {
		if c.conn == conn {
			s.connMu.RUnlock()
			return c
		}
	}
	s.connMu.RUnlock()

	s.connMu.Lock()
	defer s.connMu.Unlock()
	for _, c := range s.conns {
		if c.conn == conn {
			return c
		}
	}
	sc := newServerConn(conn)
	s.conns = append(s.conns, sc)
	return sc
}

// removeConn detaches a dead path from the session.
func (s *serverSession) removeConn(conn *quic.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for i, c := range s.conns {
		if c.conn == conn {
			c.alive.Store(false)
			s.conns = append(s.conns[:i], s.conns[i+1:]...)
			return
		}
	}
}

// dispatch stamps the dataplane header into buf (which reserves the leading
// header bytes) and stripes the packet across the session's live paths by
// earliest estimated delivery time. Called only from the TUN read loop.
func (s *serverSession) dispatch(buf []byte) {
	head := common.DataPlaneHeader{
		Version:   common.DataPlaneVersion,
		Type:      common.DPTypeIP,
		SessionID: s.id,
		SeqNum:    s.nextSeqSend.Add(1),
	}
	if _, err := head.MarshalTo(buf[:common.DataPlaneHdrSize]); err != nil {
		common.PutBuffer(buf)
		return
	}

	s.connMu.RLock()
	s.scratchConns = append(s.scratchConns[:0], s.conns...)
	s.connMu.RUnlock()
	s.scratchMetrics = s.scratchMetrics[:0]
	for _, c := range s.scratchConns {
		s.scratchMetrics = append(s.scratchMetrics, c.metrics())
	}

	for {
		idx := common.PickPath(s.scratchMetrics, len(buf))
		if idx < 0 {
			common.PutBuffer(buf)
			return
		}
		sc := s.scratchConns[idx]
		sc.queued.Add(int64(len(buf)))
		select {
		case sc.sendCh <- buf:
			return
		default:
			sc.queued.Add(-int64(len(buf)))
			s.scratchMetrics[idx].Alive = false // full; try the next-best path
		}
	}
}

// updateStats refreshes each path's rate estimate and RTT/jitter from the
// QUIC transport, feeding the striping scheduler.
func (s *serverSession) updateStats(now time.Time) {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	for _, c := range s.conns {
		c.rate.Update(c.bytesSent.Load(), now)
		if c.conn.Context().Err() != nil {
			c.alive.Store(false)
			continue
		}
		st := c.conn.ConnectionStats()
		c.rttNano.Store(int64(st.SmoothedRTT))
		c.jitterNano.Store(int64(st.MeanDeviation))
	}
}

// pruneStaleConns drops paths that are closed or have been silent too long.
func (s *serverSession) pruneStaleConns() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	now := time.Now().UnixNano()
	active := s.conns[:0]
	for _, c := range s.conns {
		dead := c.conn.Context().Err() != nil
		stale := time.Duration(now-c.lastSeen.Load()) > connStaleTimeout
		if dead || stale {
			c.alive.Store(false)
			_ = c.conn.CloseWithError(0, "stale path")
			continue
		}
		active = append(active, c)
	}
	s.conns = active
}
