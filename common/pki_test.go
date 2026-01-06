package common

import "testing"

func TestClientBundleFlow(t *testing.T) {
	tmp := t.TempDir()
	p := DefaultPKI(tmp)
	_ = EnsureBasePKI(p, []string{"localhost"}, false)

	b, err := GenerateClientBundle(p, "testcli")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}

	if !FileExists(b) {
		t.Fatal("no bundle")
	}

	cfg, err := LoadClientBundle(b)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(cfg.Certificates) == 0 {
		t.Fatal("no cert")
	}
}

func TestServerTLS(t *testing.T) {
	tmp := t.TempDir()
	p := DefaultPKI(tmp)
	_ = EnsureBasePKI(p, []string{"localhost"}, false)
	_, err := ServerTLSConfig(p)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
}
