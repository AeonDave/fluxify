//go:build linux
// +build linux

package main

import (
	"net"
	"testing"

	"fluxify/common"
)

func TestAssignClientIPsStartsAtTwo(t *testing.T) {
	s := NewServer(0, 0, "", common.DefaultPKI("./pki"), false)
	s.nextIPOctet.Store(0)

	ip4, ip6 := s.assignClientIPs()
	if ip4.String() != "10.8.0.2" {
		t.Fatalf("expected first IPv4 10.8.0.2, got %s", ip4)
	}
	want6 := net.ParseIP("fd00:8:0::2")
	if ip6 == nil || !ip6.Equal(want6) {
		t.Fatalf("expected first IPv6 fd00:8:0::2, got %v", ip6)
	}
}

func TestAssignClientIPsWrapsAfter250(t *testing.T) {
	s := NewServer(0, 0, "", common.DefaultPKI("./pki"), false)
	s.nextIPOctet.Store(250)

	ip4, ip6 := s.assignClientIPs()
	if ip4.String() != "10.8.0.2" || !ip6.Equal(net.ParseIP("fd00:8:0::2")) {
		t.Fatalf("expected wrap to ::2, got %s / %s", ip4, ip6)
	}
	if got := s.nextIPOctet.Load(); got != 2 {
		t.Fatalf("counter not reset after wrap, got %d", got)
	}
}

func TestRegisterSessionSkipsNilIPs(t *testing.T) {
	s := NewServer(0, 0, "", common.DefaultPKI("./pki"), false)
	sess := newServerSession(1, "test", []byte("k"), net.IPv4(10, 8, 0, 2), nil)
	s.registerSession(sess)

	if len(s.ipToSession) != 1 {
		t.Fatalf("expected only IPv4 entry, got %d", len(s.ipToSession))
	}
	if _, ok := s.ipToSession["<nil>"]; ok {
		t.Fatalf("unexpected <nil> key present")
	}
	if got := s.lookupSessionByIP(nil); got != nil {
		t.Fatalf("lookupSessionByIP(nil) should return nil")
	}
}

func TestExtractDstIPParsesV4AndV6(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	copy(v4[16:20], net.IPv4(1, 2, 3, 4).To4())
	if ip := extractDstIP(v4); ip == nil || !ip.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("extractDstIP v4 failed, got %v", ip)
	}

	v6 := make([]byte, 40)
	v6[0] = 0x60
	dst6 := net.ParseIP("fd00:8:0::5")
	copy(v6[24:40], dst6.To16())
	if ip := extractDstIP(v6); ip == nil || !ip.Equal(dst6) {
		t.Fatalf("extractDstIP v6 failed, got %v", ip)
	}
}

func TestExtractDstIPInvalidReturnsNil(t *testing.T) {
	if ip := extractDstIP(nil); ip != nil {
		t.Fatalf("expected nil for empty packet, got %v", ip)
	}
	shortV4 := []byte{0x45}
	if ip := extractDstIP(shortV4); ip != nil {
		t.Fatalf("expected nil for short v4, got %v", ip)
	}
	shortV6 := make([]byte, 10)
	shortV6[0] = 0x60
	if ip := extractDstIP(shortV6); ip != nil {
		t.Fatalf("expected nil for short v6, got %v", ip)
	}
	unknown := []byte{0x10}
	if ip := extractDstIP(unknown); ip != nil {
		t.Fatalf("expected nil for unknown version, got %v", ip)
	}
}
