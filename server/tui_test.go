//go:build linux
// +build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"fluxify/common"
)

func TestWriteClientBundleCreatesBundle(t *testing.T) {
	base := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(base, "pki"))
	if err := common.EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}

	bundlePath, err := common.GenerateClientBundle(pki, "alice")
	if err != nil {
		t.Fatalf("generate bundle: %v", err)
	}

	// Verify bundle exists and can be loaded
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle not created: %v", err)
	}

	// Verify bundle can be loaded (tests compressed format)
	_, err = common.LoadClientBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
}

func TestDeleteClientCertsRemovesBundle(t *testing.T) {
	base := t.TempDir()
	pki := common.DefaultPKI(filepath.Join(base, "pki"))
	if err := common.EnsureBasePKI(pki, nil, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}

	bundlePath, err := common.GenerateClientBundle(pki, "bob")
	if err != nil {
		t.Fatalf("generate bundle: %v", err)
	}

	if err := deleteClientBundle(pki, "bob"); err != nil {
		t.Fatalf("delete client: %v", err)
	}

	if _, err := os.Stat(bundlePath); err == nil {
		t.Fatalf("bundle still exists after delete")
	}
}
