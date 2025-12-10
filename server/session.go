package main

import (
	"fluxify/common"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type serverConn struct {
	udp       *net.UDPConn
	addr      *net.UDPAddr
	alive     atomic.Bool
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	lastRTT   atomic.Int64 // nanos
}

type serverSession struct {
	id          uint32
	conns       []*serverConn
	connMu      sync.RWMutex
	clientIP    net.IP // 10.8.0.X assigned
	clientIPv6  net.IP
	key         []byte
	nextSeqSend atomic.Uint32
}

func newServerSession(id uint32, key []byte, ip4, ip6 net.IP) *serverSession {
	return &serverSession{
		id:         id,
		key:        key,
		clientIP:   ip4,
		clientIPv6: ip6,
		conns:      make([]*serverConn, 0, 4),
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
			if !c.alive.Load() {
				c.alive.Store(true)
			}
			return c
		}
	}

	// New connection
	sc := &serverConn{udp: udp, addr: addr}
	sc.alive.Store(true)
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

	for _, c := range s.conns {
		if !c.alive.Load() {
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
		// If all marked dead, try the first one (fallback)
		best = s.conns[0]
	}
	return best
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
