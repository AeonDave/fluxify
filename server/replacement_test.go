package main

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"fluxify/common"
)

func TestSessionReplacementReusesIP(t *testing.T) {
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

	// Helper to dial and get session
	getSession := func() (uint32, string, string) {
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

		req := common.ControlRequest{ClientName: "alice"}
		b, _ := req.Marshal()
		_, _ = conn.Write(b)
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
		return resp.SessionID, resp.ClientIP, resp.ClientIPv6
	}

	// 1. First connection
	id1, ip1, ipv6_1 := getSession()
	if id1 == 0 || ip1 == "" {
		t.Fatalf("invalid session 1")
	}

	// Verify session 1 exists
	if st.getSession(id1) == nil {
		t.Fatalf("session 1 not found in server")
	}

	// 2. Second connection (same client "alice")
	id2, ip2, ipv6_2 := getSession()
	if id2 == 0 {
		t.Fatalf("invalid session 2")
	}

	// Verify IPs reused
	if ip1 != ip2 {
		t.Errorf("IP mismatch: want %s, got %s", ip1, ip2)
	}
	if ipv6_1 != ipv6_2 {
		t.Errorf("IPv6 mismatch: want %s, got %s", ipv6_1, ipv6_2)
	}

	// Verify session 1 is gone
	if st.getSession(id1) != nil {
		t.Errorf("session 1 (id=%d) still exists after replacement", id1)
	}

	// Verify session 2 exists
	if st.getSession(id2) == nil {
		t.Errorf("session 2 (id=%d) not found", id2)
	}
}
