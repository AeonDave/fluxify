package common

import "testing"

func TestGetBufferSizing(t *testing.T) {
	b := GetBuffer()
	if len(b) != PoolBufSize || cap(b) != PoolBufSize {
		t.Fatalf("unexpected buffer size: len=%d cap=%d", len(b), cap(b))
	}
	PutBuffer(b)
}

func TestPutBufferReslicesBeforeReuse(t *testing.T) {
	original := GetBuffer()
	sliced := original[:16]
	PutBuffer(sliced)

	next := GetBuffer()
	if len(next) != PoolBufSize {
		t.Fatalf("expected resliced buffer len=%d got=%d", PoolBufSize, len(next))
	}
	if cap(next) != PoolBufSize {
		t.Fatalf("expected resliced buffer cap=%d got=%d", PoolBufSize, cap(next))
	}
}

func TestPutBufferDiscardsTooSmall(t *testing.T) {
	small := make([]byte, PoolBufSize/2)
	PutBuffer(small)

	next := GetBuffer()
	if cap(next) != PoolBufSize {
		t.Fatalf("expected pool to ignore undersized buffers, got cap=%d", cap(next))
	}
}
