package common

import (
	"net"
	"runtime"
	"testing"
)

func TestNewBoundUDPDialerNoBind(t *testing.T) {
	d, err := NewBoundUDPDialer("", "")
	if err != nil {
		t.Fatalf("dialer error: %v", err)
	}
	if d.LocalAddr != nil {
		t.Fatalf("expected nil LocalAddr, got %v", d.LocalAddr)
	}
}

func TestNewBoundUDPDialerLocalIP(t *testing.T) {
	d, err := NewBoundUDPDialer("", "127.0.0.1")
	if err != nil {
		t.Fatalf("dialer error: %v", err)
	}
	if d.LocalAddr == nil {
		t.Fatalf("expected LocalAddr set")
	}
	if addr, ok := d.LocalAddr.(*net.UDPAddr); !ok || addr.IP.String() != "127.0.0.1" {
		t.Fatalf("unexpected LocalAddr: %v", d.LocalAddr)
	}
}

func TestEnsurePolicyRoutingNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("policy routing modifies system; skip on linux")
	}
	if err := EnsurePolicyRouting(100, "10.0.0.0/24", "10.0.0.1", "eth0"); err != nil {
		t.Fatalf("expected no-op on non-linux: %v", err)
	}
}
