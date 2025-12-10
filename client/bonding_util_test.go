package main

import "testing"

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
