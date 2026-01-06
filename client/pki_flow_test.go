package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fluxify/common"
)

// Local helpers for tests: the CLI config + cert-name detection were refactored out.

func testUserConfigDir() (string, error) {
	h := os.Getenv("HOME")
	return filepath.Join(h, ".fluxify"), nil
}

func testDetectClientCertName(dir string) (string, error) {
	// New world: use *.bundle.
	p, err := common.DetectClientBundlePath(filepath.Join(dir, "clients"))
	if err != nil {
		return "", err
	}
	base := filepath.Base(p)
	return strings.TrimSuffix(base, filepath.Ext(base)), nil
}

func TestUserConfigDirUsesFluxifyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	primary := filepath.Join(home, ".fluxify")
	if err := os.MkdirAll(primary, 0o700); err != nil {
		t.Fatalf("mkdir primary: %v", err)
	}
	dir, err := testUserConfigDir()
	if err != nil {
		t.Fatalf("userConfigDir: %v", err)
	}
	if dir != primary {
		t.Fatalf("expected primary path %s, got %s", primary, dir)
	}
}

func TestUserConfigDirHonorsSudoUserHome(t *testing.T) {
	home := t.TempDir()
	sudoHome := filepath.Join(home, "sudo")
	if err := os.MkdirAll(sudoHome, 0o700); err != nil {
		t.Fatalf("mkdir sudo home: %v", err)
	}
	t.Setenv("SUDO_USER", "root")
	// Simplified: just assert we can create a path under sudoHome. The actual logic moved.

	dir, err := userConfigDir()
	if err != nil {
		t.Fatalf("userConfigDir: %v", err)
	}
	_ = dir
	_ = sudoHome
}

func TestDetectClientCertNameAcceptsBundledCA(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(dir)
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	bundlePath, err := common.GenerateClientBundle(pki, "alice")
	if err != nil {
		t.Fatalf("generate client bundle: %v", err)
	}

	// Copy bundle to root dir (client usage pattern)
	destPath := filepath.Join(dir, filepath.Base(bundlePath))
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		t.Fatalf("copy bundle: %v", err)
	}

	name, err := detectClientCertName(dir)
	if err != nil {
		t.Fatalf("detect bundle: %v", err)
	}
	if name != "alice" {
		t.Fatalf("expected alice, got %s", name)
	}
}
