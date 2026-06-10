package common

import (
	"testing"
	"time"
)

func reorderTestBuf(b byte) []byte {
	x := GetBuffer()
	x[0] = b
	return x[:1]
}

func TestReorderBufferInOrder(t *testing.T) {
	rb := NewReorderBuffer(16, 50*time.Millisecond)
	defer rb.Close()

	for i := 1; i <= 3; i++ {
		out := rb.Insert(uint32(i), reorderTestBuf(byte(i)))
		if len(out) != 1 || out[0][0] != byte(i) {
			t.Fatalf("seq %d: expected 1 packet [%d], got %v", i, i, out)
		}
		PutBuffer(out[0])
	}
}

func TestReorderBufferOutOfOrderThenFillGap(t *testing.T) {
	rb := NewReorderBuffer(16, 50*time.Millisecond)
	defer rb.Close()

	if out := rb.Insert(2, reorderTestBuf(2)); len(out) != 0 {
		t.Fatalf("expected no output for early packet, got %d", len(out))
	}
	out := rb.Insert(1, reorderTestBuf(1))
	if len(out) != 2 || out[0][0] != 1 || out[1][0] != 2 {
		t.Fatalf("expected ordered [1 2], got %v", out)
	}
	for _, b := range out {
		PutBuffer(b)
	}
}

func TestReorderBufferDuplicatesDropped(t *testing.T) {
	rb := NewReorderBuffer(16, 50*time.Millisecond)
	defer rb.Close()

	out := rb.Insert(1, reorderTestBuf(1))
	if len(out) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out))
	}
	PutBuffer(out[0])

	// Old duplicate must be dropped (and counted).
	if out := rb.Insert(1, reorderTestBuf(1)); len(out) != 0 {
		t.Fatalf("expected duplicate dropped, got %d packets", len(out))
	}
	// Duplicate of a parked packet must be dropped too.
	if out := rb.Insert(5, reorderTestBuf(5)); len(out) != 0 {
		t.Fatalf("expected parked, got %d", len(out))
	}
	if out := rb.Insert(5, reorderTestBuf(5)); len(out) != 0 {
		t.Fatalf("expected parked duplicate dropped, got %d", len(out))
	}
	if st := rb.Stats(); st.Dropped != 2 {
		t.Fatalf("expected 2 dropped, got %d", st.Dropped)
	}
}

func TestReorderBufferFlushTimeoutJumpsGap(t *testing.T) {
	rb := NewReorderBuffer(16, 5*time.Millisecond)
	defer rb.Close()

	rb.Insert(3, reorderTestBuf(3))
	rb.Insert(5, reorderTestBuf(5))

	select {
	case <-rb.FlushCh():
	case <-time.After(time.Second):
		t.Fatal("flush signal never fired")
	}
	out := rb.FlushTimeout()
	if len(out) != 2 || out[0][0] != 3 || out[1][0] != 5 {
		t.Fatalf("expected flushed [3 5], got %v", out)
	}
	for _, b := range out {
		PutBuffer(b)
	}
	// Sequence resumed after the highest flushed seq.
	out = rb.Insert(6, reorderTestBuf(6))
	if len(out) != 1 {
		t.Fatalf("expected 6 delivered immediately after flush, got %d", len(out))
	}
	PutBuffer(out[0])
	if st := rb.Stats(); st.Flushes != 1 {
		t.Fatalf("expected 1 flush, got %d", st.Flushes)
	}
}

func TestReorderBufferOverflowForcesDelivery(t *testing.T) {
	rb := NewReorderBuffer(4, time.Hour)
	defer rb.Close()

	// Fill beyond maxSize with a gap at seq 1.
	delivered := 0
	for i := 2; i <= 7; i++ {
		out := rb.Insert(uint32(i), reorderTestBuf(byte(i)))
		delivered += len(out)
		for _, b := range out {
			PutBuffer(b)
		}
	}
	if delivered == 0 {
		t.Fatal("expected overflow to force at least one delivery")
	}
}

func TestReorderBufferReset(t *testing.T) {
	rb := NewReorderBuffer(16, time.Hour)
	defer rb.Close()

	out := rb.Insert(1, reorderTestBuf(1))
	PutBuffer(out[0])
	rb.Insert(5, reorderTestBuf(5)) // parked

	rb.Reset()
	// After reset the numbering restarts from 1.
	out = rb.Insert(1, reorderTestBuf(9))
	if len(out) != 1 || out[0][0] != 9 {
		t.Fatalf("expected fresh seq 1 delivered after reset, got %v", out)
	}
	PutBuffer(out[0])
}

func TestReorderBufferStatsTracksBufferedAndReordered(t *testing.T) {
	rb := NewReorderBuffer(16, time.Hour)
	defer rb.Close()

	rb.Insert(2, reorderTestBuf(2))
	rb.Insert(3, reorderTestBuf(3))
	out := rb.Insert(1, reorderTestBuf(1))
	if len(out) != 3 {
		t.Fatalf("expected 3 delivered, got %d", len(out))
	}
	for _, b := range out {
		PutBuffer(b)
	}
	st := rb.Stats()
	if st.Buffered != 2 {
		t.Fatalf("expected 2 buffered, got %d", st.Buffered)
	}
	if st.Reordered != 2 {
		t.Fatalf("expected 2 reordered, got %d", st.Reordered)
	}
	if st.MaxDepth != 2 {
		t.Fatalf("expected max depth 2, got %d", st.MaxDepth)
	}
}
