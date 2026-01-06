package common

import (
	"testing"
)

func TestDataPlaneHeader_Validation(t *testing.T) {
	tests := []struct {
		name    string
		header  DataPlaneHeader
		wantErr bool
	}{
		{
			name: "valid IP datagram",
			header: DataPlaneHeader{
				Version:   DataPlaneVersion,
				Type:      DPTypeIP,
				SessionID: 123,
				SeqNum:    456,
				Flags:     0,
			},
			wantErr: false,
		},
		{
			name: "valid heartbeat",
			header: DataPlaneHeader{
				Version:   DataPlaneVersion,
				Type:      DPTypeHeartbeat,
				SessionID: 789,
				SeqNum:    0,
				Flags:     0,
			},
			wantErr: false,
		},
		{
			name: "compression flag set",
			header: DataPlaneHeader{
				Version:   DataPlaneVersion,
				Type:      DPTypeIP,
				SessionID: 1,
				SeqNum:    2,
				Flags:     DPFlagCompression,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := BuildDataPlaneDatagram(nil, tt.header, nil)
			if err != nil {
				t.Fatalf("BuildDataPlaneDatagram: %v", err)
			}
			h, payload, err := ParseDataPlaneDatagram(buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDataPlaneDatagram() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if h.Type != tt.header.Type {
					t.Errorf("Type = %d, want %d", h.Type, tt.header.Type)
				}
				if h.SessionID != tt.header.SessionID {
					t.Errorf("SessionID = %d, want %d", h.SessionID, tt.header.SessionID)
				}
				if len(payload) != 0 {
					t.Errorf("expected empty payload for header-only, got %d bytes", len(payload))
				}
			}
		})
	}
}

func TestDataPlaneHeader_TooShort(t *testing.T) {
	shortBuf := []byte{1, 2, 3}
	_, _, err := ParseDataPlaneDatagram(shortBuf)
	if err == nil {
		t.Error("expected error for datagram shorter than header size")
	}
}

func TestBuildDataPlaneDatagram_WithPayload(t *testing.T) {
	h := DataPlaneHeader{
		Version:   DataPlaneVersion,
		Type:      DPTypeIP,
		SessionID: 999,
		SeqNum:    111,
		Flags:     DPFlagCompression,
	}
	payload := []byte("test payload")

	dg, err := BuildDataPlaneDatagram(nil, h, payload)
	if err != nil {
		t.Fatalf("BuildDataPlaneDatagram: %v", err)
	}

	h2, p2, err := ParseDataPlaneDatagram(dg)
	if err != nil {
		t.Fatalf("ParseDataPlaneDatagram: %v", err)
	}

	if h2.SessionID != h.SessionID {
		t.Errorf("SessionID = %d, want %d", h2.SessionID, h.SessionID)
	}
	if h2.SeqNum != h.SeqNum {
		t.Errorf("SeqNum = %d, want %d", h2.SeqNum, h.SeqNum)
	}
	if h2.Flags != h.Flags {
		t.Errorf("Flags = %d, want %d", h2.Flags, h.Flags)
	}
	if string(p2) != string(payload) {
		t.Errorf("Payload = %q, want %q", p2, payload)
	}
}

func TestIsIPPacket_DetectsIPv4(t *testing.T) {
	// IPv4 minimal header: version 4, IHL 5 (20 bytes)
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // version 4, IHL 5

	if !IsIPPacket(pkt) {
		t.Error("expected IsIPPacket to return true for IPv4")
	}
}

func TestIsIPPacket_DetectsIPv6(t *testing.T) {
	// IPv6 minimal header: version 6, 40 bytes
	pkt := make([]byte, 40)
	pkt[0] = 0x60 // version 6

	if !IsIPPacket(pkt) {
		t.Error("expected IsIPPacket to return true for IPv6")
	}
}

func TestIsIPPacket_RejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", []byte{}},
		{"wrong version", append([]byte{0x35}, make([]byte, 19)...)}, // version 3
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsIPPacket(tt.pkt) {
				t.Errorf("IsIPPacket returned true for %s", tt.name)
			}
		})
	}
}
