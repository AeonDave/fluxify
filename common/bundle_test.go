package common

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBundleFormatCompressed verifies that bundles are compressed (base64+gzip)
func TestBundleFormatCompressed(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}

	bundlePath, err := GenerateClientBundle(pki, "testclient")
	if err != nil {
		t.Fatalf("generate bundle: %v", err)
	}

	// Read bundle file
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	// Verify it's base64 (no newlines, no PEM headers)
	dataStr := string(data)
	if strings.Contains(dataStr, "-----BEGIN") {
		t.Fatalf("bundle should be compressed (base64+gzip), found PEM header")
	}
	if strings.Contains(dataStr, "\n") {
		t.Fatalf("bundle should be single-line base64")
	}

	// Verify it can be loaded
	tlsCfg, err := LoadClientBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}

	if tlsCfg.RootCAs == nil {
		t.Fatalf("expected CA pool")
	}
}

// TestLoadClientBundleRejectsPlainPEM ensures old format is not accepted
func TestLoadClientBundleRejectsPlainPEM(t *testing.T) {
	dir := t.TempDir()
	pemFile := filepath.Join(dir, "test.pem")

	// Write plain PEM (old format)
	plainPEM := `-----BEGIN CERTIFICATE-----
MIICxjCCAa4CCQDTest123456789ABGkqhkiG9w0BAQsFADAjMSEwHwYDVQQD
DBhGbHV4aWZ5VGVzdENBDQoAAAAAAAAAAAA=
-----END CERTIFICATE-----`

	if err := os.WriteFile(pemFile, []byte(plainPEM), 0600); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	// Should fail to load (not base64+gzip)
	_, err := LoadClientBundle(pemFile)
	if err == nil {
		t.Fatalf("expected error loading plain PEM, got nil")
	}
}

// TestBundleRoundtrip verifies generate+load cycle
func TestBundleRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, []string{"localhost"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}

	// Generate bundle
	bundlePath, err := GenerateClientBundle(pki, "alice")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Load bundle
	tlsCfg, err := LoadClientBundle(bundlePath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Test TLS handshake
	serverCfg, err := ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}

	// Mock handshake (verify cert chain parses)
	if len(tlsCfg.Certificates) == 0 {
		t.Fatalf("no client certificates")
	}

	cert := tlsCfg.Certificates[0]
	if cert.PrivateKey == nil {
		t.Fatalf("no private key")
	}

	if serverCfg.ClientCAs == nil {
		t.Fatalf("server has no CA pool")
	}
}

// TestDetectClientBundlePathFindsBundle verifies detection logic
func TestDetectClientBundlePathFindsBundle(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}

	bundlePath, err := GenerateClientBundle(pki, "bob")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Detect should find it
	detected, err := DetectClientBundlePath(pki.ClientsDir)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	if detected != bundlePath {
		t.Fatalf("expected %s, got %s", bundlePath, detected)
	}
}

// TestBundleBaseNameExtractsName verifies name extraction
func TestBundleBaseNameExtractsName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/path/to/alice.bundle", "alice"},
		{"/path/to/bob.pem", "bob"},
		{"charlie.bundle", "charlie"},
		{"/complex/path/device123.bundle", "device123"},
	}

	for _, tt := range tests {
		got := BundleBaseName(tt.path)
		if got != tt.want {
			t.Errorf("BundleBaseName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// TestMultipleBundlesError verifies detection fails with multiple bundles
func TestMultipleBundlesError(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}

	// Create two bundles
	_, err := GenerateClientBundle(pki, "alice")
	if err != nil {
		t.Fatalf("generate alice: %v", err)
	}

	_, err = GenerateClientBundle(pki, "bob")
	if err != nil {
		t.Fatalf("generate bob: %v", err)
	}

	// Detection should fail
	_, err = DetectClientBundlePath(pki.ClientsDir)
	if err == nil {
		t.Fatalf("expected error with multiple bundles, got nil")
	}

	if !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("expected 'multiple' in error, got: %v", err)
	}
}

// TestLoadClientBundleHandlesCorrupted verifies error handling
func TestLoadClientBundleHandlesCorrupted(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.bundle")

	// Write invalid base64
	if err := os.WriteFile(corrupt, []byte("!!!invalid base64!!!"), 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	_, err := LoadClientBundle(corrupt)
	if err == nil {
		t.Fatalf("expected error loading corrupted bundle, got nil")
	}
}

// TestServerAndClientUseSameFormat verifies interoperability
func TestServerAndClientUseSameFormat(t *testing.T) {
	dir := t.TempDir()
	pki := DefaultPKI(dir)
	if err := EnsureBasePKI(pki, []string{"127.0.0.1"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}

	// Server generates bundle
	bundlePath, err := GenerateClientBundle(pki, "device1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Client loads bundle
	clientCfg, err := LoadClientBundle(bundlePath)
	if err != nil {
		t.Fatalf("client load: %v", err)
	}

	// Server loads CA
	serverCfg, err := ServerTLSConfig(pki)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}

	// Verify compatibility (both configs exist and have required fields)
	if len(clientCfg.Certificates) == 0 {
		t.Fatalf("client has no certificates")
	}

	if clientCfg.RootCAs == nil {
		t.Fatalf("client has no CA pool")
	}

	if len(serverCfg.Certificates) == 0 {
		t.Fatalf("server has no certificates")
	}

	if serverCfg.ClientCAs == nil {
		t.Fatalf("server has no client CA pool")
	}

	// Verify client auth is required
	if serverCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server should require client certs")
	}
}
