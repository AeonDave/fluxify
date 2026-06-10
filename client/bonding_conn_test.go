package main

import (
	"testing"
	"time"

	"fluxify/common"
)

func testPath(iface string, queueCap int) *pathConn {
	pc := &pathConn{
		iface:  iface,
		sendCh: make(chan []byte, queueCap),
		rate:   common.NewRateEstimator(common.DefaultInitialRateBps, common.DefaultRateTau),
	}
	return pc
}

func testPacket(payload int) []byte {
	buf := common.GetBuffer()
	return buf[:common.DataPlaneHdrSize+payload]
}

func TestDispatchStampsHeaderAndEnqueues(t *testing.T) {
	pc := testPath("eth0", 4)
	pc.alive.Store(true)
	c := &clientState{sessionID: 42, paths: []*pathConn{pc}}

	c.dispatch(testPacket(100), make([]common.PathMetrics, 1))

	select {
	case dg := <-pc.sendCh:
		h, payload, err := common.ParseDataPlaneDatagram(dg)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if h.Type != common.DPTypeIP || h.SessionID != 42 || h.SeqNum != 1 {
			t.Fatalf("unexpected header: %+v", h)
		}
		if len(payload) != 100 {
			t.Fatalf("expected 100B payload, got %d", len(payload))
		}
		common.PutBuffer(dg)
	default:
		t.Fatal("expected packet enqueued")
	}
	if pc.queued.Load() != int64(common.DataPlaneHdrSize+100) {
		t.Fatalf("queued accounting wrong: %d", pc.queued.Load())
	}
}

func TestDispatchSkipsDeadPaths(t *testing.T) {
	dead := testPath("eth0", 4)
	alive := testPath("wlan0", 4)
	alive.alive.Store(true)
	c := &clientState{paths: []*pathConn{dead, alive}}

	c.dispatch(testPacket(50), make([]common.PathMetrics, 2))

	if len(dead.sendCh) != 0 {
		t.Fatal("dead path must not receive packets")
	}
	if len(alive.sendCh) != 1 {
		t.Fatal("alive path should have received the packet")
	}
	common.PutBuffer(<-alive.sendCh)
}

func TestDispatchSpillsToNextPathWhenQueueFull(t *testing.T) {
	// Path 0 has a 1-slot queue that we never drain; with equal RTTs the
	// scheduler must spill the second packet to path 1.
	p0 := testPath("eth0", 1)
	p1 := testPath("wlan0", 4)
	p0.alive.Store(true)
	p1.alive.Store(true)
	c := &clientState{paths: []*pathConn{p0, p1}}
	metrics := make([]common.PathMetrics, 2)

	c.dispatch(testPacket(100), metrics)
	c.dispatch(testPacket(100), metrics)
	c.dispatch(testPacket(100), metrics)

	if len(p0.sendCh) != 1 {
		t.Fatalf("expected exactly 1 packet on p0, got %d", len(p0.sendCh))
	}
	if len(p1.sendCh) != 2 {
		t.Fatalf("expected 2 packets spilled to p1, got %d", len(p1.sendCh))
	}
	common.PutBuffer(<-p0.sendCh)
	common.PutBuffer(<-p1.sendCh)
	common.PutBuffer(<-p1.sendCh)
}

func TestDispatchDropsWhenAllPathsUnavailable(t *testing.T) {
	p0 := testPath("eth0", 1)
	p0.alive.Store(true)
	c := &clientState{paths: []*pathConn{p0}}
	metrics := make([]common.PathMetrics, 1)

	c.dispatch(testPacket(10), metrics)
	c.dispatch(testPacket(10), metrics) // queue full -> dropped, must not block

	if len(p0.sendCh) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(p0.sendCh))
	}
	if p0.queued.Load() != int64(common.DataPlaneHdrSize+10) {
		t.Fatalf("queued accounting must exclude dropped packet: %d", p0.queued.Load())
	}
	common.PutBuffer(<-p0.sendCh)
}

func TestDispatchSequenceIncrements(t *testing.T) {
	pc := testPath("eth0", 8)
	pc.alive.Store(true)
	c := &clientState{paths: []*pathConn{pc}}
	metrics := make([]common.PathMetrics, 1)

	for i := 0; i < 3; i++ {
		c.dispatch(testPacket(10), metrics)
	}
	for want := uint32(1); want <= 3; want++ {
		dg := <-pc.sendCh
		h, _, err := common.ParseDataPlaneDatagram(dg)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if h.SeqNum != want {
			t.Fatalf("expected seq %d, got %d", want, h.SeqNum)
		}
		common.PutBuffer(dg)
	}
}

func TestPathMetricsSnapshot(t *testing.T) {
	pc := testPath("eth0", 4)
	pc.alive.Store(true)
	pc.queued.Store(1234)
	pc.rttNano.Store(int64(20 * time.Millisecond))

	m := pc.metrics()
	if !m.Alive || m.QueuedBytes != 1234 || m.RTT != 20*time.Millisecond {
		t.Fatalf("unexpected metrics: %+v", m)
	}
	if m.RateBps <= 0 {
		t.Fatalf("expected optimistic initial rate, got %f", m.RateBps)
	}
}
