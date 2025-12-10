package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"fluxify/common"
)

// Validate that processAndSend encrypts (and compresses when beneficial) using pooled buffers.
func TestProcessAndSendWithCompressionAndPool(t *testing.T) {
	key, err := common.GenerateSessionKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	// UDP sink to capture encrypted packets.
	recv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer recv.Close()

	send, err := net.DialUDP("udp", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer send.Close()

	cc := &clientConn{udp: send}
	cc.alive.Store(true)

	state := &clientState{
		sessionKey: key,
		sessionID:  99,
		conns:      []*clientConn{cc},
		mode:       modeBonding,
	}

	// Highly compressible payload to exercise gzip branch.
	payload := common.GetBuffer()
	defer common.PutBuffer(payload)
	data := bytes.Repeat([]byte("A"), 512)
	copy(payload, data)

	state.processAndSend(payload[:len(data)])

	// Read encrypted packet and verify contents.
	buf := make([]byte, 2048)
	recv.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := recv.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}

	hdr, plain, err := common.DecryptPacket(key, buf[:n])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if hdr.Type != common.PacketIP || hdr.SessionID != state.sessionID {
		t.Fatalf("unexpected header: %+v", hdr)
	}
	if hdr.Reserved[0] == common.CompressionGzip {
		plain, err = common.DecompressPayload(plain, common.MaxPacketSize)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
	}
	if !bytes.Equal(plain, data) {
		t.Fatalf("payload mismatch")
	}
	if cc.bytesSent.Load() != uint64(len(data)) {
		t.Fatalf("bytesSent not incremented")
	}
}
