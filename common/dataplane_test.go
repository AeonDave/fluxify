package common

import (
	"bytes"
	"testing"
)

func TestDataPlaneDatagramRoundTrip(t *testing.T) {
	h := DataPlaneHeader{
		Version:   DataPlaneVersion,
		Type:      DPTypeIP,
		SessionID: 42,
		SeqNum:    7,
		Flags:     DPFlagCompression,
	}
	payload := []byte("hello")
	dg, err := BuildDataPlaneDatagram(nil, h, payload)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	gotH, gotPayload, err := ParseDataPlaneDatagram(dg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if gotH != h {
		t.Fatalf("header mismatch: %+v vs %+v", gotH, h)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch: %q vs %q", gotPayload, payload)
	}
}

func TestDataPlaneDatagramShortHeader(t *testing.T) {
	if _, _, err := ParseDataPlaneDatagram([]byte{0x01}); err == nil {
		t.Fatalf("expected error on short header")
	}
}
