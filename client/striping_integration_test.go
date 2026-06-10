package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"fluxify/common"
)

// TestStripingIntegration verifies end-to-end packet striping over two real
// QUIC connections on loopback: every striped packet is delivered, carries
// the right session/sequence header, and the per-path senders drain their
// queues into the transport.
func TestStripingIntegration(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	bundlePath, err := common.GenerateClientBundle(pki, "striptest")
	if err != nil {
		t.Fatalf("gen client bundle: %v", err)
	}

	// Minimal datagram-collecting QUIC server.
	serverTLS, err := common.ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	serverTLS = serverTLS.Clone()
	serverTLS.NextProtos = []string{"fluxify-quic"}
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = serverUDP.Close() }()
	ln, err := quic.Listen(serverUDP, serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	const totalPackets = 300
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var mu sync.Mutex
	received := make(map[uint32]bool)
	perConn := make(map[string]int)
	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func(conn *quic.Conn) {
				addr := conn.RemoteAddr().String()
				for {
					dat, err := conn.ReceiveDatagram(ctx)
					if err != nil {
						return
					}
					h, _, err := common.ParseDataPlaneDatagram(dat)
					if err != nil || h.Type != common.DPTypeIP || h.SessionID != 7 {
						continue
					}
					mu.Lock()
					if !received[h.SeqNum] {
						received[h.SeqNum] = true
						perConn[addr]++
						if len(received) == totalPackets {
							close(done)
						}
					}
					mu.Unlock()
				}
			}(conn)
		}
	}()

	// Client state with two loopback paths (no interface binding needed).
	clientTLS, err := common.LoadClientBundle(bundlePath)
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{"fluxify-quic"}
	clientTLS.ServerName = "127.0.0.1"

	cctx, ccancel := context.WithCancel(context.Background())
	c := &clientState{sessionID: 7, ctx: cctx, cancel: ccancel}
	for i := 0; i < 2; i++ {
		pc := newPathConn(fmt.Sprintf("path%d", i), "")
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("client udp %d: %v", i, err)
		}
		conn, err := quic.Dial(ctx, u, serverUDP.LocalAddr(), clientTLS.Clone(), &quic.Config{EnableDatagrams: true})
		if err != nil {
			t.Fatalf("quic dial %d: %v", i, err)
		}
		pc.setConn(conn, u)
		pc.alive.Store(true)
		c.paths = append(c.paths, pc)
		c.wg.Add(1)
		go c.pathSender(pc)
	}
	defer func() {
		ccancel()
		c.closeAllConns()
		c.wg.Wait()
	}()

	metrics := make([]common.PathMetrics, len(c.paths))
	for i := 0; i < totalPackets; i++ {
		buf := common.GetBuffer()
		// Payload content is irrelevant; the header is stamped by dispatch.
		c.dispatch(buf[:common.DataPlaneHdrSize+64], metrics)
	}

	select {
	case <-done:
	case <-ctx.Done():
		mu.Lock()
		got := len(received)
		mu.Unlock()
		t.Fatalf("timeout: received %d/%d packets", got, totalPackets)
	}

	mu.Lock()
	defer mu.Unlock()
	for seq := uint32(1); seq <= totalPackets; seq++ {
		if !received[seq] {
			t.Fatalf("missing seq %d", seq)
		}
	}
	t.Logf("striping distribution across connections: %v", perConn)
}
