package main

import (
	"fluxify/common"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	connStaleTimeout   = 5 * time.Second
	sessionIdleTimeout = 2 * time.Minute
)

type serverConn struct {
	udp       *net.UDPConn
	addr      *net.UDPAddr
	alive     atomic.Bool
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	lastRTT   atomic.Int64 // nanos
	lastSeen  atomic.Int64 // nanos (time since last packet from this addr)
}

type serverSession struct {
	id          uint32
	conns       []*serverConn
	connMu      sync.RWMutex
	clientIP    net.IP // 10.8.0.X assigned
	clientIPv6  net.IP
	key         []byte
	nextSeqSend atomic.Uint32
	lastSeen    atomic.Int64 // nanos
}

func newServerSession(id uint32, key []byte, ip4, ip6 net.IP) *serverSession {
	sess := &serverSession{
		id:         id,
		key:        key,
		clientIP:   ip4,
		clientIPv6: ip6,
		conns:      make([]*serverConn, 0, 4),
	}
	sess.touch()
	return sess
}

func (s *serverSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (c *serverConn) touch() {
	c.lastSeen.Store(time.Now().UnixNano())
	c.alive.Store(true)
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
