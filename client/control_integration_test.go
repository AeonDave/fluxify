package main

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"fluxify/common"
)

// startTempControlServer spins a minimal control-plane listener compatible with fetchSession.
func startTempControlServer(t *testing.T, pki common.PKIPaths) (addr string, stop func()) {
	t.Helper()
	tlsCfg, err := common.ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls config: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn *tls.Conn) {
				defer func(conn *tls.Conn) {
					_ = conn.Close()
				}(conn)
				if err := conn.Handshake(); err != nil {
					return
				}
				reqBytes, err := io.ReadAll(conn)
				if err != nil {
					return
				}
				var req common.ControlRequest
				if err := req.Unmarshal(reqBytes); err != nil {
					return
				}
				sessID, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
				key, err := common.GenerateSessionKey()
				if err != nil {
					return
				}
				resp := common.ControlResponse{
					SessionID:  uint32(sessID.Int64()),
					SessionKey: common.EncodeKeyBase64(key),
					UDPPort:    7777,
					ClientIP:   "10.8.0.2",
				}
				b, _ := resp.Marshal()
				_, _ = conn.Write(b)
			}(c.(*tls.Conn))
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestFetchSessionEndToEnd(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	certPath, keyPath, err := common.GenerateClientCert(pki, "bob", false)
	if err != nil {
		t.Fatalf("gen client: %v", err)
	}
	// Create bundle: CA + client cert + key in single file
	bundlePath := filepath.Join(pki.Dir, "bob.pem")
	caBytes, _ := os.ReadFile(pki.CACert)
	certBytes, _ := os.ReadFile(certPath)
	keyBytes, _ := os.ReadFile(keyPath)
	bundle := append(caBytes, '\n')
	bundle = append(bundle, certBytes...)
	bundle = append(bundle, '\n')
	bundle = append(bundle, keyBytes...)
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	addr, stop := startTempControlServer(t, pki)
	defer stop()

	cfg := clientConfig{Server: addr, PKI: pki.Dir, Client: "bob", Ctrl: 0}
	key, sessID, udpPort, clientIP, err := fetchSession(addr, cfg)
	if err != nil {
		t.Fatalf("fetchSession: %v", err)
	}
	if sessID == 0 || udpPort != 7777 || clientIP == "" {
		t.Fatalf("unexpected response: id=%d udp=%d ip=%s", sessID, udpPort, clientIP)
	}
	if len(key) != common.SessionKeySize {
		t.Fatalf("key size mismatch: %d", len(key))
	}
}

func TestFetchSessionRejectsWithoutCert(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(dir, "pki"))
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1", "localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	addr, stop := startTempControlServer(t, pki)
	defer stop()

	// Missing client cert/key should fail during tls.Dial
	cfg := clientConfig{Server: addr, PKI: pki.Dir, Client: "missing", Ctrl: 0}
	if _, _, _, _, err := fetchSession(addr, cfg); err == nil {
		t.Fatalf("expected error without client cert")
	}
}
