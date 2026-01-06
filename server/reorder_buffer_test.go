//go:build linux
// +build linux

package main

import (
	"testing"
	"time"

	"fluxify/common"
)

func TestReorderBuffer_Insert_InOrder(t *testing.T) {
	rb := common.NewReorderBuffer(16, 50*time.Millisecond)

	p1 := common.GetBuffer()
	copy(p1, []byte{1})
	out := rb.Insert(1, p1[:1])
	if len(out) != 1 || out[0][0] != 1 {
		for _, b := range out {
			common.PutBuffer(b)
		}
		t.Fatalf("expected 1 packet [1], got %v", out)
	}
	common.PutBuffer(out[0])
}

func TestReorderBuffer_Insert_OutOfOrderThenFillGap(t *testing.T) {
	rb := common.NewReorderBuffer(16, 50*time.Millisecond)

	p2 := common.GetBuffer()
	copy(p2, []byte{2})
	out := rb.Insert(2, p2[:1])
	if len(out) != 0 {
		for _, b := range out {
			common.PutBuffer(b)
		}
		t.Fatalf("expected no output, got %d", len(out))
	}

	p1 := common.GetBuffer()
	copy(p1, []byte{1})
	out = rb.Insert(1, p1[:1])
	if len(out) != 2 {
		for _, b := range out {
			common.PutBuffer(b)
		}
		t.Fatalf("expected 2 packets, got %d", len(out))
	}
	if out[0][0] != 1 || out[1][0] != 2 {
		for _, b := range out {
			common.PutBuffer(b)
		}
		t.Fatalf("unexpected order: %v %v", out[0], out[1])
	}
	common.PutBuffer(out[0])
	common.PutBuffer(out[1])
}

func TestReorderBuffer_Insert_DuplicateIsDroppedAndReturnedToPool(t *testing.T) {
	rb := common.NewReorderBuffer(16, 50*time.Millisecond)

	p2 := common.GetBuffer()
	copy(p2, []byte{2})
	out := rb.Insert(2, p2[:1])
	if len(out) != 0 {
		for _, b := range out {
			common.PutBuffer(b)
		}
		t.Fatalf("expected no output, got %d", len(out))
	}

	dup := common.GetBuffer()
	copy(dup, []byte{2})
	out = rb.Insert(2, dup[:1])
	if len(out) != 0 {
		for _, b := range out {
			common.PutBuffer(b)
		}
		t.Fatalf("expected no output for duplicate, got %d", len(out))
	}
}

func TestReorderBuffer_FlushTimeout_SkipsGap(t *testing.T) {
	rb := common.NewReorderBuffer(16, 50*time.Millisecond)

	p3 := common.GetBuffer()
	copy(p3, []byte{3})
	_ = rb.Insert(3, p3[:1])

	// nextExpected is still 1; flush should jump to 3 and return it
	out := rb.FlushTimeout()
	if len(out) != 1 || out[0][0] != 3 {
		for _, b := range out {
			common.PutBuffer(b)
		}
		t.Fatalf("expected flushed [3], got %v", out)
	}
	common.PutBuffer(out[0])
}
