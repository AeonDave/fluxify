package common

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureBasePKIAndClient(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)

	if err := EnsureBasePKI(pki, []string{"localhost", "127.0.0.1"}, false); err != nil {
		t.Fatalf("ensure base pki: %v", err)
	}

	// files should exist
	for _, f := range []string{pki.CACert, pki.CAKey, pki.ServerCert, pki.ServerKey} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("expected file %s: %v", f, err)
		}
	}

	certFile, keyFile, err := GenerateClientCert(pki, "client1", false)
	if err != nil {
		t.Fatalf("generate client: %v", err)
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Fatalf("client cert missing: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("client key missing: %v", err)
	}

	// TLS configs should load
	if _, err := ServerTLSConfig(pki); err != nil {
		t.Fatalf("server tls config: %v", err)
	}
	if _, err := ClientTLSConfig(pki, certFile, keyFile); err != nil {
		t.Fatalf("client tls config: %v", err)
	}

	// Validate CA parse
	caPEM, err := os.ReadFile(pki.CACert)
	if err != nil {
		t.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append ca failed")
	}
}

func TestGenerateClientCertRegenerateFalse(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, []string{"localhost"}, false); err != nil {
		t.Fatalf("ensure base: %v", err)
	}
	cert1, key1, err := GenerateClientCert(pki, "c1", false)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	// regenerate=false should not overwrite
	cert2, key2, err := GenerateClientCert(pki, "c1", false)
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	if cert1 != cert2 || key1 != key2 {
		t.Fatalf("expected same paths")
	}
	info1, _ := os.Stat(cert1)
	info2, _ := os.Stat(cert2)
	if info1.ModTime() != info2.ModTime() {
		t.Fatalf("expected same file unchanged")
	}
}

func TestDefaultPKIPaths(t *testing.T) {
	base := filepath.Join(t.TempDir(), "pki")
	pki := DefaultPKI(base)
	if pki.Dir != base {
		t.Fatalf("dir mismatch")
	}
	if pki.ClientsDir == "" || filepath.Dir(pki.ClientsDir) != base {
		t.Fatalf("clients dir under base expected")
	}
}

func TestFindLatestDatedClientCertSplitsBundle(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, []string{"localhost"}, false); err != nil {
		t.Fatalf("ensure base: %v", err)
	}
	datedCert, datedKey, _, _, err := GenerateDatedClientCert(pki, "combo", time.Now())
	if err != nil {
		t.Fatalf("generate dated: %v", err)
	}
	certPEM, _ := os.ReadFile(datedCert)
	keyPEM, _ := os.ReadFile(datedKey)
	if err := os.WriteFile(datedCert, append(certPEM, append([]byte("\n"), keyPEM...)...), 0o600); err != nil {
		t.Fatalf("write combined: %v", err)
	}
	_ = os.Remove(datedKey)

	c, k, err := FindLatestDatedClientCert(pki, "combo")
	if err != nil {
		t.Fatalf("find latest: %v", err)
	}
	if c != datedCert {
		t.Fatalf("cert path mismatch: %s", c)
	}
	if k != strings.TrimSuffix(datedCert, ".pem")+"-key.pem" {
		t.Fatalf("key path mismatch: %s", k)
	}
	data, err := os.ReadFile(k)
	if err != nil || !strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatalf("key not written correctly")
	}
	certData, _ := os.ReadFile(c)
	if strings.Contains(string(certData), "PRIVATE KEY") {
		t.Fatalf("cert file still contains private key")
	}
}

func TestResolveClientCertKeyCanonicalBundle(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, []string{"localhost"}, false); err != nil {
		t.Fatalf("ensure base: %v", err)
	}
	certFile, keyFile, err := GenerateClientCert(pki, "single", false)
	if err != nil {
		t.Fatalf("generate client: %v", err)
	}
	certPEM, _ := os.ReadFile(certFile)
	keyPEM, _ := os.ReadFile(keyFile)
	if err := os.WriteFile(certFile, append(certPEM, append([]byte("\n"), keyPEM...)...), 0o600); err != nil {
		t.Fatalf("write combined: %v", err)
	}
	_ = os.Remove(keyFile)

	c, k, err := ResolveClientCertKey(pki, "single")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c != certFile || k != keyFile {
		t.Fatalf("unexpected paths %s %s", c, k)
	}
	if _, err := os.Stat(k); err != nil {
		t.Fatalf("key not recreated: %v", err)
	}

	// Should load via TLS after splitting.
	if _, err := ClientTLSConfig(pki, c, k); err != nil {
		t.Fatalf("tls config: %v", err)
	}
}
