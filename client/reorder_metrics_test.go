package main

import (
	"testing"
	"time"

	"fluxify/common"
)

func TestInboundReorderStats_FlushIncrements(t *testing.T) {
	c := &clientState{}
	c.inReorder = newClientReorderBuffer(16, 1*time.Millisecond)
	c.stopInReorder = make(chan struct{})

	// Put an out-of-order packet to arm the timer.
	c.inReorder.Insert(2, common.GetBuffer()[:10])

	// Simulate flush event.
	c.inReorderStats.flushes.Add(1)
	if got := c.inReorderStats.flushes.Load(); got != 1 {
		t.Fatalf("expected flushes=1, got %d", got)
	}
}
