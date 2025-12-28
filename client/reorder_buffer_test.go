package main

import (
	"testing"
	"time"

	"fluxify/common"
)

func bufWithByte(b byte, n int) []byte {
	x := common.GetBuffer()
	if n > cap(x) {
		n = cap(x)
	}
	x = x[:n]
	for i := range x {
		x[i] = b
	}
	return x
}

func TestClientReorderBuffer_InOrder(t *testing.T) {
	rb := newClientReorderBuffer(16, 10*time.Millisecond)
	defer rb.Close()

	for i := 1; i <= 3; i++ {
		out := rb.Insert(uint32(i), bufWithByte(byte(i), 10))
		if len(out) != 1 {
			t.Fatalf("expected 1 packet, got %d", len(out))
		}
		common.PutBuffer(out[0])
	}
}

func TestClientReorderBuffer_OutOfOrderThenFill(t *testing.T) {
	rb := newClientReorderBuffer(16, 10*time.Millisecond)
	defer rb.Close()

	// Insert 2 first (buffer)
	out := rb.Insert(2, bufWithByte(2, 10))
	if len(out) != 0 {
		t.Fatalf("expected 0 packets, got %d", len(out))
	}
	// Insert 1 then should release 1 and 2
	out = rb.Insert(1, bufWithByte(1, 10))
	if len(out) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(out))
	}
	common.PutBuffer(out[0])
	common.PutBuffer(out[1])
}

func TestClientReorderBuffer_DuplicateDropped(t *testing.T) {
	rb := newClientReorderBuffer(16, 10*time.Millisecond)
	defer rb.Close()

	out := rb.Insert(1, bufWithByte(1, 10))
	if len(out) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(out))
	}
	common.PutBuffer(out[0])

	// Old duplicate should be dropped and freed.
	out = rb.Insert(1, bufWithByte(1, 10))
	if len(out) != 0 {
		t.Fatalf("expected 0 packets, got %d", len(out))
	}
}
