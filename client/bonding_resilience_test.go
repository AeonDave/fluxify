package main

import (
	"net"
	"reflect"
	"testing"
)

type testIfaceProvider struct {
	ifaces []net.Interface
	err    error
}

func (t testIfaceProvider) Interfaces() ([]net.Interface, error) {
	if t.err != nil {
		return nil, t.err
	}
	return t.ifaces, nil
}

func TestSanitizeIfacesAllowDown(t *testing.T) {
	old := ifaceProvider
	ifaceProvider = testIfaceProvider{ifaces: []net.Interface{
		{Name: "eth0", MTU: 1500, Flags: net.FlagUp},
		{Name: "wlan0", MTU: 1400},
	}}
	t.Cleanup(func() { ifaceProvider = old })

	got := sanitizeIfaces([]string{"eth0", "wlan0"}, true)
	want := []string{"eth0", "wlan0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestSanitizeIfacesDropDownWhenNotAllowed(t *testing.T) {
	old := ifaceProvider
	ifaceProvider = testIfaceProvider{ifaces: []net.Interface{
		{Name: "eth0", MTU: 1500, Flags: net.FlagUp},
		{Name: "wlan0", MTU: 1400},
	}}
	t.Cleanup(func() { ifaceProvider = old })

	got := sanitizeIfaces([]string{"eth0", "wlan0"}, false)
	want := []string{"eth0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestCloseConnIsIdempotent(t *testing.T) {
	pc := testPath("eth0", 1)
	pc.closeConn("test")
	pc.closeConn("test") // no conn set: must not panic
	if pc.currentConn() != nil {
		t.Fatal("expected nil conn after close")
	}
}
