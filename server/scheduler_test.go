//go:build linux
// +build linux

package main

import (
	"net"
	"testing"
	"time"
)

func TestPickStripedConn_SingleConn(t *testing.T) {
	sess := newServerSession(1, "test", make([]byte, 32), net.IPv4(10, 8, 0, 2), nil)
	defer sess.Close()

	// Add one connection
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}
	conn := sess.updateOrAddConn(nil, addr)
	conn.lastRTT.Store(int64(20 * time.Millisecond))

	// Should always return the single conn
	picked := sess.pickStripedConn()
	if picked != conn {
		t.Errorf("expected single conn to be picked")
	}
}

func TestPickConnForIPPacket_FlowPinned(t *testing.T) {
	s := newServerSession(1, "test", []byte("01234567890123456789012345678901"), net.IPv4(10, 8, 0, 2), nil)
	c1 := &serverConn{}
	c2 := &serverConn{}
	c1.alive.Store(true)
	c2.alive.Store(true)
	c1.lastSeen.Store(time.Now().UnixNano())
	c2.lastSeen.Store(time.Now().UnixNano())
	c1.lastRTT.Store(int64(10 * time.Millisecond))
	c2.lastRTT.Store(int64(20 * time.Millisecond))
	s.conns = []*serverConn{c1, c2}

	// IPv4 TCP packet with stable 5-tuple.
	pkt := make([]byte, 20+20)
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	pkt[20] = 0x1f
	pkt[21] = 0x90
	pkt[22] = 0x00
	pkt[23] = 0x50

	first := s.pickConnForIPPacket(pkt)
	if first == nil {
		t.Fatalf("expected conn")
	}
	for i := 0; i < 50; i++ {
		got := s.pickConnForIPPacket(pkt)
		if got != first {
			t.Fatalf("expected same conn for flow")
		}
	}

	first.alive.Store(false)
	second := s.pickConnForIPPacket(pkt)
	if second == nil || second == first {
		t.Fatalf("expected repick")
	}
}

func TestPickStripedConn_GoodBadClassification(t *testing.T) {
	sess := newServerSession(2, "test", make([]byte, 32), net.IPv4(10, 8, 0, 3), nil)
	defer sess.Close()

	// Add two connections: one good, one bad (high jitter)
	addr1 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}
	conn1 := sess.updateOrAddConn(nil, addr1)
	conn1.lastRTT.Store(int64(20 * time.Millisecond))
	conn1.jitterNano.Store(int64(5 * time.Millisecond)) // Low jitter = good

	addr2 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 12346}
	conn2 := sess.updateOrAddConn(nil, addr2)
	conn2.lastRTT.Store(int64(25 * time.Millisecond))
	conn2.jitterNano.Store(int64(300 * time.Millisecond)) // High jitter = bad

	// Pick multiple times - should prefer conn1 (good link)
	goodCount := 0
	for i := 0; i < 100; i++ {
		picked := sess.pickStripedConn()
		if picked == conn1 {
			goodCount++
		}
	}

	// With conn2 classified as bad due to high jitter, all picks should go to conn1
	if goodCount < 90 {
		t.Errorf("expected good conn to be picked most times, got %d/100", goodCount)
	}
}

func TestPickStripedConn_HighRTTRatio(t *testing.T) {
	sess := newServerSession(3, "test", make([]byte, 32), net.IPv4(10, 8, 0, 4), nil)
	defer sess.Close()

	// Add two connections: one fast, one much slower (>3x RTT ratio)
	addr1 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}
	conn1 := sess.updateOrAddConn(nil, addr1)
	conn1.lastRTT.Store(int64(10 * time.Millisecond))
	conn1.jitterNano.Store(int64(1 * time.Millisecond))

	addr2 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 12346}
	conn2 := sess.updateOrAddConn(nil, addr2)
	conn2.lastRTT.Store(int64(100 * time.Millisecond)) // 10x RTT ratio = bad
	conn2.jitterNano.Store(int64(1 * time.Millisecond))

	// Pick multiple times - should strongly prefer conn1 (low RTT)
	goodCount := 0
	for i := 0; i < 100; i++ {
		picked := sess.pickStripedConn()
		if picked == conn1 {
			goodCount++
		}
	}

	// With conn2 classified as bad due to high RTT ratio, all picks should go to conn1
	if goodCount < 90 {
		t.Errorf("expected fast conn to be picked most times, got %d/100", goodCount)
	}
}

func TestPickStripedConn_AllBadFallback(t *testing.T) {
	sess := newServerSession(4, "test", make([]byte, 32), net.IPv4(10, 8, 0, 5), nil)
	defer sess.Close()

	// Add two connections both with high jitter (both bad)
	addr1 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}
	conn1 := sess.updateOrAddConn(nil, addr1)
	conn1.lastRTT.Store(int64(20 * time.Millisecond))
	conn1.jitterNano.Store(int64(500 * time.Millisecond)) // High jitter

	addr2 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 12346}
	conn2 := sess.updateOrAddConn(nil, addr2)
	conn2.lastRTT.Store(int64(25 * time.Millisecond))
	conn2.jitterNano.Store(int64(500 * time.Millisecond)) // High jitter

	// When all links are bad, should fallback to round-robin
	conn1Count := 0
	conn2Count := 0
	for i := 0; i < 100; i++ {
		picked := sess.pickStripedConn()
		if picked == conn1 {
			conn1Count++
		} else if picked == conn2 {
			conn2Count++
		}
	}

	// Round-robin should distribute roughly evenly
	if conn1Count < 40 || conn2Count < 40 {
		t.Errorf("expected round-robin distribution, got conn1=%d conn2=%d", conn1Count, conn2Count)
	}
}

func TestPickStripedConn_TwoGoodLinks(t *testing.T) {
	sess := newServerSession(5, "test", make([]byte, 32), net.IPv4(10, 8, 0, 6), nil)
	defer sess.Close()

	// Add two good connections with similar RTT
	addr1 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}
	conn1 := sess.updateOrAddConn(nil, addr1)
	conn1.lastRTT.Store(int64(20 * time.Millisecond))
	conn1.jitterNano.Store(int64(2 * time.Millisecond))

	addr2 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 12346}
	conn2 := sess.updateOrAddConn(nil, addr2)
	conn2.lastRTT.Store(int64(22 * time.Millisecond))
	conn2.jitterNano.Store(int64(3 * time.Millisecond))

	// Both links are good - should distribute across both
	conn1Count := 0
	conn2Count := 0
	for i := 0; i < 100; i++ {
		picked := sess.pickStripedConn()
		if picked == conn1 {
			conn1Count++
		} else if picked == conn2 {
			conn2Count++
		}
	}

	// With floor share of 15%, both should get at least some packets
	if conn1Count < 10 || conn2Count < 10 {
		t.Errorf("expected both good links to be used, got conn1=%d conn2=%d", conn1Count, conn2Count)
	}
}

func TestUpdateServerConnRTT(t *testing.T) {
	conn := &serverConn{}
	conn.alive.Store(true)

	// First RTT sample
	updateServerConnRTT(conn, 20*time.Millisecond)
	if conn.lastRTT.Load() != int64(20*time.Millisecond) {
		t.Errorf("expected lastRTT=20ms, got %v", time.Duration(conn.lastRTT.Load()))
	}
	if conn.hbRecv.Load() != 1 {
		t.Errorf("expected hbRecv=1, got %d", conn.hbRecv.Load())
	}
	// Jitter should be 0 after first sample (no delta)
	if conn.jitterNano.Load() != 0 {
		t.Errorf("expected jitter=0 after first sample, got %v", time.Duration(conn.jitterNano.Load()))
	}

	// Second RTT sample with variation
	updateServerConnRTT(conn, 25*time.Millisecond)
	if conn.lastRTT.Load() != int64(25*time.Millisecond) {
		t.Errorf("expected lastRTT=25ms, got %v", time.Duration(conn.lastRTT.Load()))
	}
	// Jitter should now be calculated (alpha=0.25 * 5ms = 1.25ms)
	jitter := conn.jitterNano.Load()
	if jitter == 0 {
		t.Errorf("expected non-zero jitter after second sample")
	}

	// Third RTT sample - jitter should accumulate
	updateServerConnRTT(conn, 22*time.Millisecond)
	newJitter := conn.jitterNano.Load()
	// EMA should update: 0.75 * oldJitter + 0.25 * |22-25|ms
	if newJitter == 0 {
		t.Errorf("expected non-zero jitter after third sample")
	}
}

func TestClampDuration(t *testing.T) {
	tests := []struct {
		d, min, max, want time.Duration
	}{
		{50 * time.Millisecond, 30 * time.Millisecond, 200 * time.Millisecond, 50 * time.Millisecond},
		{10 * time.Millisecond, 30 * time.Millisecond, 200 * time.Millisecond, 30 * time.Millisecond},
		{300 * time.Millisecond, 30 * time.Millisecond, 200 * time.Millisecond, 200 * time.Millisecond},
	}

	for _, tt := range tests {
		got := clampDuration(tt.d, tt.min, tt.max)
		if got != tt.want {
			t.Errorf("clampDuration(%v, %v, %v) = %v, want %v", tt.d, tt.min, tt.max, got, tt.want)
		}
	}
}
