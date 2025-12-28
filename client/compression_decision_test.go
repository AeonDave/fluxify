package main

import (
	"bytes"
	"testing"

	"fluxify/common"
)

func TestCompressionDecision_DisablesWhenNoSavings(t *testing.T) {
	c := &clientState{mode: modeBonding, schedDeficit: make(map[*clientConn]float64)}
	c.conns = []*clientConn{{}}
	c.conns[0].alive.Store(true)
	// Ensure encryption path can run without real session (processAndSend will early-return if unset).
	c.sessionKey = make([]byte, 32)
	c.sessionID = 1
	// Avoid any real UDP writes.
	c.conns[0].udp = nil
	c.compStats.sampleSize.Store(3)

	// Simulate 3 attempts that had negative savings.
	c.compStats.attempts.Store(3)
	c.compStats.savings.Store(-1)

	// Run the decision path (attempts == sampleSize).
	// Provide a pool-backed packet so PutBuffer is safe.
	payload := bytes.Repeat([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 10)
	buf := common.GetBuffer()
	copy(buf, payload)
	// processAndSend does not take ownership of its input buffer.
	c.processAndSend(buf[:len(payload)])
	common.PutBuffer(buf)

	if c.compStats.enabled.Load() {
		t.Fatalf("expected compression disabled")
	}
}
