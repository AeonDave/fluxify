//go:build linux
// +build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fluxify/common"
)

func TestWriteClientBundleCreatesBundle(t *testing.T) {
	base := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(base, "pki"))
	if err := common.EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	certPath, keyPath, _, _, err := common.GenerateDatedClientCert(pki, "alice", time.Now())
	if err != nil {
		t.Fatalf("generate dated: %v", err)
	}

	if err := writeClientBundle(pki, certPath, keyPath); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	bundlePath := strings.TrimSuffix(certPath, ".pem") + ".bundle"
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	caBytes, err := os.ReadFile(pki.CACert)
	if err != nil {
		t.Fatalf("read ca: %v", err)
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	caIndex := bytes.Index(bundleBytes, caBytes)
	certIndex := bytes.Index(bundleBytes, certBytes)
	keyIndex := bytes.Index(bundleBytes, keyBytes)
	if caIndex == -1 || certIndex == -1 || keyIndex == -1 {
		t.Fatalf("bundle missing expected parts")
	}
	if !(caIndex < certIndex && certIndex < keyIndex) {
		t.Fatalf("bundle order incorrect")
	}
}

func TestDeleteClientCertsRemovesBundle(t *testing.T) {
	base := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(base, "pki"))
	if err := common.EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	certPath, keyPath, _, _, err := common.GenerateDatedClientCert(pki, "bob", time.Now())
	if err != nil {
		t.Fatalf("generate dated: %v", err)
	}
	if err := writeClientBundle(pki, certPath, keyPath); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	bundlePath := strings.TrimSuffix(certPath, ".pem") + ".bundle"
	if err := deleteClientCerts(pki, "bob"); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	if _, err := os.Stat(bundlePath); err == nil {
		t.Fatalf("bundle still exists after delete")
	}
}
