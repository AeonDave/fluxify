package common

import "testing"

func TestFlowKeyFromIPPacket_IPv4TCPStable(t *testing.T) {
	// Minimal IPv4 header + TCP ports.
	pkt := make([]byte, 20+20)
	pkt[0] = 0x45 // v4, IHL=5
	pkt[9] = 6    // TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	// TCP ports
	pkt[20] = 0x1f
	pkt[21] = 0x90 // 8080
	pkt[22] = 0x00
	pkt[23] = 0x50 // 80

	k1, ok := FlowKeyFromIPPacket(pkt)
	if !ok {
		t.Fatalf("expected ok")
	}
	k2, ok := FlowKeyFromIPPacket(pkt)
	if !ok {
		t.Fatalf("expected ok")
	}
	if k1 != k2 {
		t.Fatalf("expected stable key")
	}
}

func TestFlowKeyFromIPPacket_DifferentPortsDifferentKey(t *testing.T) {
	pkt1 := make([]byte, 20+8)
	pkt1[0] = 0x45
	pkt1[9] = 17 // UDP
	copy(pkt1[12:16], []byte{1, 2, 3, 4})
	copy(pkt1[16:20], []byte{5, 6, 7, 8})
	pkt1[20] = 0x00
	pkt1[21] = 0x35 // 53
	pkt1[22] = 0x13
	pkt1[23] = 0x89 // 5001

	pkt2 := make([]byte, len(pkt1))
	copy(pkt2, pkt1)
	// change dst port
	pkt2[22] = 0x13
	pkt2[23] = 0x8a

	k1, _ := FlowKeyFromIPPacket(pkt1)
	k2, _ := FlowKeyFromIPPacket(pkt2)
	if k1 == k2 {
		t.Fatalf("expected different keys")
	}
}
