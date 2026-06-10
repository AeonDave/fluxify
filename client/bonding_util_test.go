package main

import (
	"net"
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

func TestIsUsableLocalIP(t *testing.T) {
	cases := []struct {
		ip     string
		wantV4 bool
		ok     bool
	}{
		{"192.168.1.10", true, true},
		{"10.0.0.5", true, true},
		{"127.0.0.1", true, false},     // loopback
		{"169.254.1.1", true, false},   // link-local
		{"fd00::2", true, false},       // v6 when v4 wanted
		{"fd00::2", false, true},       // ULA ok for v6
		{"fe80::1", false, false},      // link-local v6
		{"192.168.1.10", false, false}, // v4 when v6 wanted
		{"2001:db8::1", false, true},   // global v6
	}
	for _, tc := range cases {
		if got := isUsableLocalIP(net.ParseIP(tc.ip), tc.wantV4); got != tc.ok {
			t.Errorf("isUsableLocalIP(%s, v4=%v) = %v, want %v", tc.ip, tc.wantV4, got, tc.ok)
		}
	}
	if isUsableLocalIP(nil, true) {
		t.Error("nil IP must not be usable")
	}
}
