package main

import (
	"strings"
	"testing"
)

func TestAddIPv6CIDR(t *testing.T) {
	if got := addIPv6CIDR(""); got != "" {
		t.Fatalf("expected empty for empty input, got %q", got)
	}
	if got := addIPv6CIDR("fd00::2"); got != "fd00::2/64" {
		t.Fatalf("expected /64 appended, got %q", got)
	}
	if got := addIPv6CIDR("fd00::2/56"); got != "fd00::2/56" {
		t.Fatalf("expected existing prefix preserved, got %q", got)
	}
}

func TestCollectLocalAddrs_UsesProvidedIPsV4(t *testing.T) {
	ifaces := []string{"eth0", "wlan0"}
	ips := []string{"192.168.1.10", "10.0.0.5"}
	addrs, err := collectLocalAddrs(ifaces, ips, true)
	if err != nil {
		t.Fatalf("collectLocalAddrs: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addrs, got %d", len(addrs))
	}
	if got := addrs[0].To4(); got == nil {
		t.Fatalf("expected v4 addr[0], got %v", addrs[0])
	}
	if got := addrs[1].To4(); got == nil {
		t.Fatalf("expected v4 addr[1], got %v", addrs[1])
	}
}

func TestCollectLocalAddrs_RejectsIPv6WhenWantV4(t *testing.T) {
	ifaces := []string{"eth0"}
	ips := []string{"fd00::2"}
	_, err := collectLocalAddrs(ifaces, ips, true)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestCollectLocalAddrs_DedupesProvidedIPs(t *testing.T) {
	ifaces := []string{"eth0", "wlan0"}
	ips := []string{"192.168.1.10", "192.168.1.10"}
	addrs, err := collectLocalAddrs(ifaces, ips, true)
	if err != nil {
		t.Fatalf("collectLocalAddrs: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 deduped addr, got %d", len(addrs))
	}
}

// testAddIPv6CIDR is a local helper for the test, replicating addIPv6CIDR logic
func testAddIPv6CIDR(s string) string {
	if s == "" {
		return ""
	}
	if strings.Contains(s, "/") {
		return s
	}
	return s + "/64"
}
