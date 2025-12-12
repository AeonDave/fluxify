//go:build linux
// +build linux

package main

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"fluxify/common"
)

// startTestControlServer spins up a TLS listener on 127.0.0.1:0 using the provided Server.
func startTestControlServer(t *testing.T, st *Server, pki common.PKIPaths) (addr string, stop func()) {
	t.Helper()

	tlsCfg, err := common.ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls config: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	st.running.Store(true) // Ensure server is marked running if needed
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go st.handleControl(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestControlServerIssuesSession(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	if _, _, err := common.GenerateClientCert(pki, "alice", false); err != nil {
		t.Fatalf("gen client: %v", err)
	}

	st := NewServer(9999, 0, "", pki, false) // Use constructor to init maps
	addr, stop := startTestControlServer(t, st, pki)
	defer stop()

	tlsCfg, err := common.ClientTLSConfig(pki,
		filepath.Join(pki.ClientsDir, "alice.pem"),
		filepath.Join(pki.ClientsDir, "alice-key.pem"))
	if err != nil {
		t.Fatalf("client tls config: %v", err)
	}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	req := common.ControlRequest{ClientName: "alice"}
	b, _ := req.Marshal()
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write req: %v", err)
	}
	// half-close to let server finish ReadAll
	_ = conn.CloseWrite()

	respBytes := make([]byte, 4096)
	n, err := conn.Read(respBytes)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	var resp common.ControlResponse
	if err := resp.Unmarshal(respBytes[:n]); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if resp.SessionID == 0 || resp.SessionKey == "" || resp.UDPPort != 9999 || resp.ClientIP == "" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
	key, err := common.DecodeKeyBase64(resp.SessionKey)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if len(key) != common.SessionKeySize {
		t.Fatalf("key size: %d", len(key))
	}

	// session stored
	if got := st.getSession(resp.SessionID); got == nil {
		t.Fatalf("session not stored")
	}
}

func TestControlServerUsesCertCNWhenClientNameEmpty(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	if _, _, err := common.GenerateClientCert(pki, "alice", false); err != nil {
		t.Fatalf("gen client: %v", err)
	}

	st := NewServer(9999, 0, "", pki, false)
	addr, stop := startTestControlServer(t, st, pki)
	defer stop()

	tlsCfg, err := common.ClientTLSConfig(pki,
		filepath.Join(pki.ClientsDir, "alice.pem"),
		filepath.Join(pki.ClientsDir, "alice-key.pem"))
	if err != nil {
		t.Fatalf("client tls config: %v", err)
	}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Empty ClientName should fall back to certificate CN.
	req := common.ControlRequest{}
	b, _ := req.Marshal()
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write req: %v", err)
	}
	_ = conn.CloseWrite()

	respBytes := make([]byte, 4096)
	n, err := conn.Read(respBytes)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	var resp common.ControlResponse
	if err := resp.Unmarshal(respBytes[:n]); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if resp.SessionID == 0 {
		t.Fatalf("expected session id")
	}
	if st.clientSessions["alice"] == nil {
		t.Fatalf("expected session registered under CN alice")
	}
}
