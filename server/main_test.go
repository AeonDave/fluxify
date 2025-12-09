package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"fluxify/common"
)

// Test that sendToSession picks the lowest-RTT alive connection and only delivers there.
func TestSendToSessionSelectsLowestRTT(t *testing.T) {
	key, err := common.GenerateSessionKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	sess := &serverSession{id: 42, key: key}

	recvFast, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fast: %v", err)
	}
	defer func(recvFast *net.UDPConn) {
		_ = recvFast.Close()
	}(recvFast)

	recvSlow, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen slow: %v", err)
	}
	defer func(recvSlow *net.UDPConn) {
		_ = recvSlow.Close()
	}(recvSlow)

	sendFast, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("send fast: %v", err)
	}
	defer func(sendFast *net.UDPConn) {
		_ = sendFast.Close()
	}(sendFast)

	sendSlow, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("send slow: %v", err)
	}
	defer func(sendSlow *net.UDPConn) {
		_ = sendSlow.Close()
	}(sendSlow)

	fastConn := &serverConn{udp: sendFast, addr: recvFast.LocalAddr().(*net.UDPAddr)}
	slowConn := &serverConn{udp: sendSlow, addr: recvSlow.LocalAddr().(*net.UDPAddr)}
	fastConn.alive.Store(true)
	slowConn.alive.Store(true)
	fastConn.lastRTT.Store(int64(10 * time.Millisecond))
	slowConn.lastRTT.Store(int64(300 * time.Millisecond))

	sess.conns = []*serverConn{slowConn, fastConn}

	s := &serverState{}
	payload := []byte("hello")

	s.sendToSession(sess, payload)

	// Fast receiver should get the packet
	recvFast.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, _, err := recvFast.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("fast recv err: %v", err)
	}
	hdr, plain, err := common.DecryptPacket(key, buf[:n])
	if err != nil {
		t.Fatalf("decrypt fast: %v", err)
	}
	if hdr.Type != common.PacketIP || !bytes.Equal(plain, payload) {
		t.Fatalf("unexpected payload: hdr=%+v plain=%q", hdr, plain)
	}

	// Slow receiver should not receive anything
	recvSlow.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err := recvSlow.ReadFromUDP(buf); err == nil {
		t.Fatalf("slow receiver should be idle, got %d bytes", n)
	}
}

// Test that handlePacket processes heartbeat: updates RTT and echoes back encrypted.
func TestHandlePacketHeartbeatEcho(t *testing.T) {
	key, err := common.GenerateSessionKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	sess := &serverSession{id: 7, key: key}

	clientRecv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	defer func(clientRecv *net.UDPConn) {
		_ = clientRecv.Close()
	}(clientRecv)

	serverSend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("server send: %v", err)
	}
	defer func(serverSend *net.UDPConn) {
		_ = serverSend.Close()
	}(serverSend)

	addr := clientRecv.LocalAddr().(*net.UDPAddr)

	hb := common.HeartbeatPayload{SendTime: common.NowMonoNano()}
	payload := hb.Marshal()
	hdr := common.PacketHeader{Version: common.ProtoVersion, Type: common.PacketHeartbeat, SessionID: sess.id, SeqNum: 3, Length: uint16(len(payload))}

	s := &serverState{}
	s.handlePacket(sess, serverSend, addr, hdr, payload)

	clientRecv.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientRecv.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	eh, ep, err := common.DecryptPacket(key, buf[:n])
	if err != nil {
		t.Fatalf("decrypt echo: %v", err)
	}
	if eh.Type != common.PacketHeartbeat || eh.SessionID != hdr.SessionID || eh.SeqNum != hdr.SeqNum {
		t.Fatalf("unexpected echo header: %+v", eh)
	}
	var hbResp common.HeartbeatPayload
	if err := hbResp.Unmarshal(ep); err != nil {
		t.Fatalf("echo payload: %v", err)
	}

	if len(sess.conns) != 1 {
		t.Fatalf("expected 1 connection recorded, got %d", len(sess.conns))
	}
	if rtt := sess.conns[0].lastRTT.Load(); rtt <= 0 {
		t.Fatalf("expected RTT stored, got %d", rtt)
	}
}
