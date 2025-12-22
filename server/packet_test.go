//go:build linux
// +build linux

package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"fluxify/common"
)

func TestHandlePacketIPPassesThroughUncompressed(t *testing.T) {
	key, err := common.GenerateSessionKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	sess := newServerSession(1, "test", key, nil, nil)

	s := &Server{tunWriteCh: make(chan []byte, 1)}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	payload := []byte{1, 2, 3, 4, 5}
	payloadBuf := common.GetBuffer()
	copy(payloadBuf, payload)
	hdr := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketIP, SessionID: sess.id, SeqNum: 1, Length: uint16(len(payload))}

	s.handlePacket(sess, addr, hdr, payloadBuf[:len(payload)], payloadBuf)

	select {
	case got := <-s.tunWriteCh:
		if !bytes.Equal(got, payload) {
			common.PutBuffer(got)
			t.Fatalf("payload mismatch: got=%v want=%v", got, payload)
		}
		common.PutBuffer(got)
	case <-time.After(time.Second):
		t.Fatal("expected packet on tunWriteCh")
	}
}

func TestHandlePacketIPDecompressesGzip(t *testing.T) {
	key, err := common.GenerateSessionKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	sess := newServerSession(1, "test", key, nil, nil)

	s := &Server{tunWriteCh: make(chan []byte, 1)}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	plain := bytes.Repeat([]byte("A"), 128)
	comp, err := common.CompressPayload(plain)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	payloadBuf := common.GetBuffer()
	copy(payloadBuf, comp)
	hdr := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketIP, SessionID: sess.id, SeqNum: 1, Length: uint16(len(comp))}
	hdr.Reserved[0] = common.CompressionGzip

	s.handlePacket(sess, addr, hdr, payloadBuf[:len(comp)], payloadBuf)

	select {
	case got := <-s.tunWriteCh:
		if !bytes.Equal(got, plain) {
			common.PutBuffer(got)
			t.Fatalf("decompressed mismatch")
		}
		common.PutBuffer(got)
	case <-time.After(time.Second):
		t.Fatal("expected decompressed packet on tunWriteCh")
	}
}

func TestHandlePacketIPDropsOnBadGzip(t *testing.T) {
	key, err := common.GenerateSessionKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	sess := newServerSession(1, "test", key, nil, nil)

	s := &Server{tunWriteCh: make(chan []byte, 1)}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	bad := []byte("not-gzip")
	payloadBuf := common.GetBuffer()
	copy(payloadBuf, bad)
	hdr := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketIP, SessionID: sess.id, SeqNum: 1, Length: uint16(len(bad))}
	hdr.Reserved[0] = common.CompressionGzip

	s.handlePacket(sess, addr, hdr, payloadBuf[:len(bad)], payloadBuf)

	select {
	case got := <-s.tunWriteCh:
		common.PutBuffer(got)
		t.Fatal("expected no packet for bad gzip")
	case <-time.After(50 * time.Millisecond):
		// ok
	}
}
