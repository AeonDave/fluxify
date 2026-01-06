package common

import (
	"net"
	"testing"
	"time"
)

func TestGetLocalIPs_ReturnsNonLoopback(t *testing.T) {
	ips, err := GetLocalIPs()
	if err != nil {
		t.Fatalf("GetLocalIPs: %v", err)
	}

	// Should return at least one IP (unless system has no network interfaces)
	if len(ips) == 0 {
		t.Skip("no network interfaces with IPs found (may be expected in some environments)")
	}

	// Verify all returned IPs are valid and non-loopback
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Errorf("invalid IP returned: %s", ipStr)
			continue
		}
		if ip.IsLoopback() {
			t.Errorf("loopback IP should not be returned: %s", ipStr)
		}
		if ip.IsLinkLocalUnicast() {
			t.Errorf("link-local IP should not be returned: %s", ipStr)
		}
	}
}

func TestGetLocalIPs_FiltersLoopbackAndLinkLocal(t *testing.T) {
	ips, err := GetLocalIPs()
	if err != nil {
		t.Fatalf("GetLocalIPs: %v", err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip.IsLoopback() {
			t.Errorf("found loopback IP: %s", ipStr)
		}
		if ip.IsLinkLocalUnicast() {
			t.Errorf("found link-local IP: %s", ipStr)
		}
		// Should not be 127.x.x.x or 169.254.x.x or fe80::
		if ip.To4() != nil && ip[0] == 127 {
			t.Errorf("found 127.x.x.x IP: %s", ipStr)
		}
	}
}

func TestListPhysicalInterfaces_ExcludesLoopback(t *testing.T) {
	ifaces, err := ListPhysicalInterfaces()
	if err != nil {
		t.Fatalf("ListPhysicalInterfaces: %v", err)
	}

	for _, ifc := range ifaces {
		if ifc.Name == "lo" || ifc.Name == "Loopback" {
			t.Errorf("loopback interface should not be returned: %s", ifc.Name)
		}
	}
}

func TestGetPublicIP_ReturnsValidIPOrEmpty(t *testing.T) {
	// This test may fail if offline - that's expected behavior
	ip := GetPublicIP(5 * time.Second)

	if ip == "" {
		t.Log("GetPublicIP returned empty (offline or timeout) - this is acceptable")
		return
	}

	// If we got an IP, it should be valid and non-private
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("GetPublicIP returned invalid IP: %s", ip)
		return
	}

	// Public IPs should not be loopback or link-local
	if parsed.IsLoopback() {
		t.Errorf("GetPublicIP returned loopback IP: %s", ip)
	}
	if parsed.IsLinkLocalUnicast() {
		t.Errorf("GetPublicIP returned link-local IP: %s", ip)
	}

	t.Logf("GetPublicIP detected: %s", ip)
}
