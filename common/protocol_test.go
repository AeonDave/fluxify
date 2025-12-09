package common

import (
	"bytes"
	"testing"
)

func TestPacketHeaderMarshalUnmarshal(t *testing.T) {
	h := PacketHeader{Version: ProtoVersion, Type: PacketIP, SessionID: 42, SeqNum: 7, Length: 123}
	h.Reserved[0] = 0xAA
	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var h2 PacketHeader
	if err := h2.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if h != h2 {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", h, h2)
	}
}

func TestSerializeParsePacket(t *testing.T) {
	payload := []byte("hello")
	h := PacketHeader{Version: ProtoVersion, Type: PacketHeartbeat, SessionID: 1, SeqNum: 2, Length: uint16(len(payload))}
	pkt, err := SerializePacket(h, payload)
	if err != nil {
		t.Fatalf("serialize error: %v", err)
	}
	gotH, gotPayload, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if gotH != h {
		t.Fatalf("header mismatch: %+v vs %+v", gotH, h)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch: %q vs %q", gotPayload, payload)
	}
}

func TestSerializePacketLengthMismatch(t *testing.T) {
	h := PacketHeader{Version: ProtoVersion, Type: PacketIP, SessionID: 1, SeqNum: 1, Length: 5}
	if _, err := SerializePacket(h, []byte("nope")); err == nil {
		t.Fatalf("expected length mismatch error")
	}
}

func TestParsePacketTooShort(t *testing.T) {
	if _, _, err := ParsePacket([]byte{0x01}); err == nil {
		t.Fatalf("expected error for short packet")
	}
}
