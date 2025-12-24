//go:build linux
// +build linux

package common

// SetInterfaceDNS is a no-op on Linux in this build.
func SetInterfaceDNS(iface string, dns4 []string, dns6 []string) error {
	return nil
}

// ClearInterfaceDNS is a no-op on Linux in this build.
func ClearInterfaceDNS(iface string) error {
	return nil
}
