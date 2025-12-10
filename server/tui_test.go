package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fluxify/common"

	"github.com/atotto/clipboard"
)

func TestDownloadClientCertCopiesDated(t *testing.T) {
	base := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(base, "pki"))
	if err := common.EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	_, _, _, _, err := common.GenerateDatedClientCert(pki, "alice", time.Now())
	if err != nil {
		t.Fatalf("generate dated: %v", err)
	}

	var captured string
	clipWrite = func(s string) error {
		captured = s
		return nil
	}
	t.Cleanup(func() { clipWrite = clipboard.WriteAll })

	if err := downloadClientCert(pki, "alice"); err != nil {
		t.Fatalf("download: %v", err)
	}

	if !strings.Contains(captured, "BEGIN CERTIFICATE") {
		t.Fatalf("clipboard missing cert: %q", captured)
	}
	if !strings.Contains(captured, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("clipboard missing key: %q", captured)
	}
}

func TestDownloadClientCertFallsBackToAny(t *testing.T) {
	base := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(base, "pki"))
	if err := os.MkdirAll(pki.ClientsDir, 0o700); err != nil {
		t.Fatalf("mkdir clients: %v", err)
	}
	if err := os.WriteFile(pki.CACert, []byte("dummy-ca"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	certPath := filepath.Join(pki.ClientsDir, "bob.pem")
	keyPath := filepath.Join(pki.ClientsDir, "bob-key.pem")
	if err := os.WriteFile(certPath, []byte("dummy-cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("dummy-key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	var captured string
	clipWrite = func(s string) error {
		captured = s
		return nil
	}
	t.Cleanup(func() { clipWrite = clipboard.WriteAll })

	if err := downloadClientCert(pki, "bob"); err != nil {
		t.Fatalf("download fallback: %v", err)
	}

	if !strings.Contains(captured, "dummy-cert") || !strings.Contains(captured, "dummy-key") {
		t.Fatalf("clipboard missing fallback data: %q", captured)
	}
}
