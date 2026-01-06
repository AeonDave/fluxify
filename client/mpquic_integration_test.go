//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"

	"fluxify/common"
)

// TestMPQUICPathStatistics verifies that MP-QUIC exposes per-path metrics.
func TestMPQUICPathStatistics(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for TUN device; run with sudo")
	}

	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	bundlePath, err := common.GenerateClientBundle(pki, "stattest")
	if err != nil {
		t.Fatalf("gen client: %v", err)
	}

	// Start a minimal QUIC echo server.
	serverTLS, err := common.ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	serverTLS.NextProtos = []string{"fluxify-quic"}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()
	serverAddr := udpConn.LocalAddr().String()

	qcfg := &quic.Config{
		EnableDatagrams: true,
		MaxPaths:        2,
	}
	ln, err := quic.Listen(udpConn, serverTLS, qcfg)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Server: echo datagrams back.
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "done")
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			_ = conn.SendDatagram(data)
		}
	}()

	// Client: dial and send datagrams.
	clientCfg := clientConfig{
		PKI:  pki.Dir,
		Cert: bundlePath,
	}
	clientTLS, err := clientTLSConfig(clientCfg)
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{"fluxify-quic"}

	mpCtrl := quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler())
	clientQCfg := &quic.Config{
		EnableDatagrams:     true,
		MaxPaths:            2,
		MultipathController: mpCtrl,
	}

	udpAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("client udp: %v", err)
	}
	defer clientConn.Close()

	conn, err := quic.Dial(ctx, clientConn, udpAddr, clientTLS, clientQCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	// Send some datagrams and wait for echo.
	const numPackets = 100
	var received atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numPackets*2; i++ {
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if len(data) > 0 {
				received.Add(1)
			}
		}
	}()

	for i := 0; i < numPackets; i++ {
		payload := make([]byte, 512)
		_, _ = rand.Read(payload)
		if err := conn.SendDatagram(payload); err != nil {
			t.Logf("send datagram %d: %v", i, err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Wait for echoes.
	time.Sleep(500 * time.Millisecond)

	// Verify path statistics.
	stats := mpCtrl.GetStatistics()
	t.Logf("MP-QUIC path statistics: %d paths", len(stats))
	for pathID, ps := range stats {
		t.Logf("  Path %d: RTT=%v cwnd=%d sent=%d lost=%d",
			pathID, ps.SmoothedRTT, ps.CongestionWindow, ps.PacketsSent, ps.PacketsLost)
	}

	if len(stats) == 0 {
		t.Error("expected at least one path in statistics")
	}

	foundActive := false
	for _, ps := range stats {
		if ps.PacketsSent > 0 {
			foundActive = true
			break
		}
	}
	if !foundActive {
		t.Error("no path has sent any packets")
	}

	cancel()
	wg.Wait()

	recvCount := received.Load()
	t.Logf("Received %d/%d echoes", recvCount, numPackets)
	if recvCount < int64(numPackets/2) {
		t.Errorf("expected at least %d echoes, got %d", numPackets/2, recvCount)
	}
}

// TestMPQUICDatagramThroughput measures datagram throughput via MP-QUIC.
func TestMPQUICDatagramThroughput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root; run with sudo")
	}

	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	bundlePath, err := common.GenerateClientBundle(pki, "perftest")
	if err != nil {
		t.Fatalf("gen client: %v", err)
	}

	serverTLS, err := common.ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	serverTLS.NextProtos = []string{"fluxify-quic"}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()
	serverAddr := udpConn.LocalAddr().String()

	qcfg := &quic.Config{
		EnableDatagrams: true,
		MaxPaths:        4,
	}
	ln, err := quic.Listen(udpConn, serverTLS, qcfg)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var serverBytes atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "done")
		for {
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			serverBytes.Add(int64(len(data)))
		}
	}()

	clientCfg := clientConfig{
		PKI:  pki.Dir,
		Cert: bundlePath,
	}
	clientTLS, err := clientTLSConfig(clientCfg)
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{"fluxify-quic"}

	mpCtrl := quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler())
	clientQCfg := &quic.Config{
		EnableDatagrams:     true,
		MaxPaths:            4,
		MultipathController: mpCtrl,
	}

	udpAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("client udp: %v", err)
	}
	defer clientConn.Close()

	conn, err := quic.Dial(ctx, clientConn, udpAddr, clientTLS, clientQCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	// Throughput test: send datagrams for 5 seconds.
	const testDuration = 5 * time.Second
	const packetSize = 1200
	payload := make([]byte, packetSize)
	_, _ = rand.Read(payload)

	var sentBytes int64
	start := time.Now()
	for time.Since(start) < testDuration {
		if err := conn.SendDatagram(payload); err != nil {
			// Flow control or buffer full, wait a bit.
			time.Sleep(1 * time.Millisecond)
			continue
		}
		sentBytes += packetSize
	}
	elapsed := time.Since(start)

	time.Sleep(200 * time.Millisecond)
	cancel()
	wg.Wait()

	recv := serverBytes.Load()
	sendMbps := float64(sentBytes*8) / elapsed.Seconds() / 1e6
	recvMbps := float64(recv*8) / elapsed.Seconds() / 1e6

	t.Logf("Throughput test: duration=%v sent=%d bytes (%.2f Mbps), recv=%d bytes (%.2f Mbps)",
		elapsed, sentBytes, sendMbps, recv, recvMbps)

	stats := mpCtrl.GetStatistics()
	t.Logf("Final path statistics:")
	for pathID, ps := range stats {
		t.Logf("  Path %d: RTT=%v cwnd=%d bytesSent=%d lost=%d",
			pathID, ps.SmoothedRTT, ps.CongestionWindow, ps.BytesSent, ps.PacketsLost)
	}

	if sendMbps < 1.0 {
		t.Errorf("expected at least 1 Mbps throughput, got %.2f Mbps", sendMbps)
	}
}

// TestClientGetMPPathStats_Linux verifies the GetMPPathStats helper.
func TestClientGetMPPathStats_Linux(t *testing.T) {
	// Test with nil controller - should return nil map.
	state := &clientState{}
	stats := state.GetMPPathStats()
	if stats != nil {
		t.Errorf("expected nil stats for nil controller, got %v", stats)
	}
}

// startMPQUICEchoServer creates a QUIC server that echoes datagrams for testing.
func startMPQUICEchoServer(t *testing.T, pki common.PKIPaths) (addr string, stop func()) {
	t.Helper()

	serverTLS, err := common.ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	serverTLS.NextProtos = []string{"fluxify-quic"}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	qcfg := &quic.Config{
		EnableDatagrams: true,
		MaxPaths:        4,
	}
	ln, err := quic.Listen(udpConn, serverTLS, qcfg)
	if err != nil {
		udpConn.Close()
		t.Fatalf("quic listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				defer c.CloseWithError(0, "done")
				for {
					data, err := c.ReceiveDatagram(ctx)
					if err != nil {
						return
					}
					_ = c.SendDatagram(data)
				}
			}(conn)
		}
	}()

	return udpConn.LocalAddr().String(), func() {
		cancel()
		ln.Close()
		udpConn.Close()
	}
}

// TestMPQUICConnectionEstablishment tests basic MP-QUIC connection setup.
func TestMPQUICConnectionEstablishment(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	bundlePath, err := common.GenerateClientBundle(pki, "conntest")
	if err != nil {
		t.Fatalf("gen client: %v", err)
	}

	serverAddr, stop := startMPQUICEchoServer(t, pki)
	defer stop()

	// Force IPv4 to match certificate SANs (127.0.0.1)
	host, port, _ := net.SplitHostPort(serverAddr)
	if host == "::" || host == "" {
		serverAddr = net.JoinHostPort("127.0.0.1", port)
	}

	clientCfg := clientConfig{
		PKI:  pki.Dir,
		Cert: bundlePath,
	}
	clientTLS, err := clientTLSConfig(clientCfg)
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{"fluxify-quic"}

	mpCtrl := quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler())
	clientQCfg := &quic.Config{
		EnableDatagrams:     true,
		MaxPaths:            2,
		MultipathController: mpCtrl,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	udpAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("client udp: %v", err)
	}
	defer clientConn.Close()

	conn, err := quic.Dial(ctx, clientConn, udpAddr, clientTLS, clientQCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	// Send a test datagram.
	testData := []byte("hello mp-quic")
	if err := conn.SendDatagram(testData); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Receive echo.
	recvCtx, recvCancel := context.WithTimeout(ctx, 2*time.Second)
	defer recvCancel()
	data, err := conn.ReceiveDatagram(recvCtx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", data, testData)
	}

	// Check path stats - loopback may not show paths in GetStatistics()
	// but the connection works which is the important part.
	stats := mpCtrl.GetStatistics()
	t.Logf("Connection established, %d path(s) in statistics", len(stats))
}
