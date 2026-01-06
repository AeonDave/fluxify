//go:build !linux && !windows

package common

import "testing"

// IPv6 helpers should be harmless no-ops on non-Linux platforms.
func TestIPv6HelpersNoopOnNonLinux(t *testing.T) {
	if line, via, dev, err := GetDefaultRoute6(); err != nil || line != "" || via != "" || dev != "" {
		t.Fatalf("GetDefaultRoute6 unexpected: %q %q %q err=%v", line, via, dev, err)
	}
	if err := ReplaceDefaultRoute6(""); err != nil {
		t.Fatalf("ReplaceDefaultRoute6 should be no-op on non-linux: %v", err)
	}
	if err := SetDefaultRouteDev6(""); err != nil {
		t.Fatalf("SetDefaultRouteDev6 should be no-op on non-linux: %v", err)
	}
	if err := EnsureHostRoute6("", "", ""); err != nil {
		t.Fatalf("EnsureHostRoute6 should be no-op on non-linux: %v", err)
	}
	if err := DeleteHostRoute6(""); err != nil {
		t.Fatalf("DeleteHostRoute6 should ignore empty input, got %v", err)
	}
}
