package main

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"fluxify/common"
)

func TestUserConfigDirUsesFluxifyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreHome := homeDirFunc
	homeDirFunc = func() (string, error) { return home, nil }
	t.Cleanup(func() { homeDirFunc = restoreHome })

	primary := filepath.Join(home, ".fluxify")
	if err := os.MkdirAll(primary, 0o700); err != nil {
		t.Fatalf("mkdir primary: %v", err)
	}
	dir, err := userConfigDir()
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
	restoreLookup := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		return &user.User{HomeDir: sudoHome}, nil
	}
	t.Cleanup(func() { lookupUser = restoreLookup })
	t.Setenv("SUDO_USER", "root")
	restoreHome := homeDirFunc
	homeDirFunc = func() (string, error) { return home, nil }
	t.Cleanup(func() { homeDirFunc = restoreHome })

	dir, err := userConfigDir()
	if err != nil {
		t.Fatalf("userConfigDir: %v", err)
	}
	expected := filepath.Join(sudoHome, ".fluxify")
	if dir != expected {
		t.Fatalf("expected sudo home path %s, got %s", expected, dir)
	}
}

func TestDetectClientCertNameAcceptsBundledCA(t *testing.T) {
	dir := t.TempDir()
	pki := common.DefaultPKI(dir)
	if err := common.EnsureBasePKI(pki, []string{"127.0.0.1"}, false); err != nil {
		t.Fatalf("ensure pki: %v", err)
	}
	certPath, keyPath, err := common.GenerateClientCert(pki, "alice", false)
	if err != nil {
		t.Fatalf("generate client: %v", err)
	}
	// Build bundle with CA + cert + key
	caBytes, _ := os.ReadFile(pki.CACert)
	cBytes, _ := os.ReadFile(certPath)
	kBytes, _ := os.ReadFile(keyPath)
	bundle := append(caBytes, '\n')
	bundle = append(bundle, cBytes...)
	bundle = append(bundle, '\n')
	bundle = append(bundle, kBytes...)
	if err := os.WriteFile(filepath.Join(dir, "alice.pem"), bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	name, err := detectClientCertName(dir)
	if err != nil {
		t.Fatalf("detect bundle: %v", err)
	}
	if name != "alice" {
		t.Fatalf("expected alice, got %s", name)
	}
}
