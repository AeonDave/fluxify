package common

import "testing"

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key, err := GenerateSessionKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	hdr := PacketHeader{Version: ProtoVersion, Type: PacketIP, SessionID: 123, SeqNum: 42}
	payload := []byte("secret data")

	pkt, err := EncryptPacket(key, hdr, payload)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	gotH, gotPayload, err := DecryptPacket(key, pkt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if gotH.SessionID != hdr.SessionID || gotH.SeqNum != hdr.SeqNum || gotH.Type != hdr.Type {
		t.Fatalf("header mismatch: %+v vs %+v", gotH, hdr)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload mismatch: %q vs %q", gotPayload, payload)
	}
}

func TestEncryptDecryptTamperFails(t *testing.T) {
	key, _ := GenerateSessionKey()
	hdr := PacketHeader{Version: ProtoVersion, Type: PacketIP, SessionID: 1, SeqNum: 1}
	pkt, err := EncryptPacket(key, hdr, []byte("abc"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// flip a byte in ciphertext
	pkt[len(pkt)-1] ^= 0xFF
	if _, _, err := DecryptPacket(key, pkt); err == nil {
		t.Fatalf("expected auth failure")
	}
}

func TestEncryptPacketKeyLength(t *testing.T) {
	_, err := EncryptPacket([]byte("short"), PacketHeader{}, nil)
	if err == nil {
		t.Fatalf("expected key length error")
	}
	if _, _, err := DecryptPacket([]byte("short"), []byte{0}); err == nil {
		t.Fatalf("expected key length error decrypt")
	}
}
