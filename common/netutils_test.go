package common

import (
	"net"
	"runtime"
	"testing"
)

func TestListenUDPBoundNoIface(t *testing.T) {
	conn, err := ListenUDPBound("udp4", net.ParseIP("127.0.0.1"), "")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP.String() != "127.0.0.1" {
		t.Fatalf("unexpected local addr: %v", conn.LocalAddr())
	}
	if addr.Port == 0 {
		t.Fatalf("expected ephemeral port assigned")
	}
}

func TestListenUDPBoundAnyAddr(t *testing.T) {
	conn, err := ListenUDPBound("udp4", nil, "")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	_ = conn.Close()
}

func TestEnsurePolicyRoutingNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("policy routing modifies system; skip on linux")
	}
	if err := EnsurePolicyRouting(100, "10.0.0.0/24", "10.0.0.1", "eth0"); err != nil {
		t.Fatalf("expected no-op on non-linux: %v", err)
	}
}
