//go:build linux
// +build linux

package common

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

// ListenUDPBound creates an unconnected UDP socket bound to localIP and, when
// iface is non-empty, to the interface itself (SO_BINDTODEVICE) so the kernel
// restricts route lookup and egress to that device. network must be "udp4" or
// "udp6". Suitable as the underlying socket for a QUIC transport.
func ListenUDPBound(network string, localIP net.IP, iface string) (*net.UDPConn, error) {
	var lc net.ListenConfig
	if iface != "" {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	addr := ":0"
	if localIP != nil {
		addr = net.JoinHostPort(localIP.String(), "0")
	}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// EnsurePolicyRouting installs per-interface policy routing (Linux only). Best-effort, idempotent-ish.
// It adds a dedicated table and rule for source IP.
func EnsurePolicyRouting(tableID int, srcCIDR, gw, dev string) error {
	// ip route replace table <id> default via <gw> dev <dev> src <src>
	cmds := [][]string{
		{"ip", "route", "replace", "table", fmt.Sprint(tableID), srcCIDR, "dev", dev},
		{"ip", "route", "replace", "table", fmt.Sprint(tableID), "default", "via", gw, "dev", dev},
		{"ip", "rule", "replace", "from", srcCIDR, "table", fmt.Sprint(tableID)},
	}
	for _, c := range cmds {
		if err := RunPrivileged(c[0], c[1:]...); err != nil {
			return fmt.Errorf("policy route failed %v: %w", c, err)
		}
	}
	return nil
}

// GetDefaultRoute returns the first default route line along with parsed via/dev (Linux only).
// If no default route is found, via/dev are empty.
func GetDefaultRoute() (line, via, dev string, err error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", "", "", nil
	}
	line = strings.TrimSpace(lines[0])
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" {
			via = fields[i+1]
		}
		if fields[i] == "dev" {
			dev = fields[i+1]
		}
	}
	return line, via, dev, nil
}

// ReplaceDefaultRoute replaces the default route using the full route fields (Linux only).
// Example: line "default via 192.168.1.1 dev eth0".
func ReplaceDefaultRoute(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return fmt.Errorf("empty route line")
	}
	args := append([]string{"route", "replace"}, strings.Fields(line)...)
	return RunPrivileged("ip", args...)
}

// SetDefaultRouteDev replaces the default route to point to the given device (Linux only).
func SetDefaultRouteDev(dev string) error {
	if dev == "" {
		return fmt.Errorf("device required")
	}
	return RunPrivileged("ip", "route", "replace", "default", "dev", dev)
}

// SetDefaultRouteDevWithGateway replaces the default route via gateway on the given device (Linux only).
func SetDefaultRouteDevWithGateway(dev, gateway string) error {
	if dev == "" {
		return fmt.Errorf("device required")
	}
	if gateway == "" {
		return RunPrivileged("ip", "route", "replace", "default", "dev", dev)
	}
	return RunPrivileged("ip", "route", "replace", "default", "via", gateway, "dev", dev)
}

// GetDefaultRoute6 returns the IPv6 default route line along with via/dev (Linux only).
// If no default route is found, via/dev are empty.
func GetDefaultRoute6() (line, via, dev string, err error) {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return "", "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", "", "", nil
	}
	line = strings.TrimSpace(lines[0])
	fields := strings.Fields(line)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" {
			via = fields[i+1]
		}
		if fields[i] == "dev" {
			dev = fields[i+1]
		}
	}
	return line, via, dev, nil
}

// ReplaceDefaultRoute6 replaces the IPv6 default route using the full route fields (Linux only).
func ReplaceDefaultRoute6(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return fmt.Errorf("empty route line")
	}
	args := append([]string{"-6", "route", "replace"}, strings.Fields(line)...)
	return RunPrivileged("ip", args...)
}

// SetDefaultRouteDev6 replaces the IPv6 default route to point to the given device (Linux only).
func SetDefaultRouteDev6(dev string) error {
	if dev == "" {
		return fmt.Errorf("device required")
	}
	return RunPrivileged("ip", "-6", "route", "replace", "default", "dev", dev)
}

// EnsureHostRoute6 ensures a host route via the given gateway/device (Linux only).
func EnsureHostRoute6(ip, via, dev string) error {
	if ip == "" || dev == "" {
		return fmt.Errorf("ip and dev required")
	}
	args := []string{"-6", "route", "replace", ip, "dev", dev}
	if via != "" {
		args = []string{"-6", "route", "replace", ip, "via", via, "dev", dev}
	}
	return RunPrivileged("ip", args...)
}

// AddHostRoute6 adds a host route via the given gateway/device (Linux only).
func AddHostRoute6(ip, via, dev string) error {
	return EnsureHostRoute6(ip, via, dev)
}

// DeleteHostRoute6 removes an IPv6 host route if present (best-effort, Linux only).
func DeleteHostRoute6(ip string) error {
	if ip == "" {
		return nil
	}
	return RunPrivileged("ip", "-6", "route", "del", ip)
}

// EnsureHostRoute ensures a host route via the given gateway/device (Linux only).
func EnsureHostRoute(ip, via, dev string) error {
	if ip == "" || dev == "" {
		return fmt.Errorf("ip and dev required")
	}
	args := []string{"route", "replace", ip, "dev", dev}
	if via != "" {
		args = []string{"route", "replace", ip, "via", via, "dev", dev}
	}
	return RunPrivileged("ip", args...)
}

// AddHostRoute adds a host route via the given gateway/device (Linux only).
func AddHostRoute(ip, via, dev string) error {
	return EnsureHostRoute(ip, via, dev)
}

// AddHostRouteMetric installs a host route with an explicit metric so multiple
// routes to the same destination (one per uplink) can coexist (Linux only).
func AddHostRouteMetric(ip, via, dev string, metric int) error {
	if ip == "" || dev == "" {
		return fmt.Errorf("ip and dev required")
	}
	args := []string{"route", "replace", ip, "dev", dev, "metric", fmt.Sprint(metric)}
	if via != "" {
		args = []string{"route", "replace", ip, "via", via, "dev", dev, "metric", fmt.Sprint(metric)}
	}
	return RunPrivileged("ip", args...)
}

// DeleteHostRoutes removes every route to the given host (all metrics/uplinks).
func DeleteHostRoutes(ip string) error {
	if ip == "" {
		return nil
	}
	return RunPrivileged("ip", "route", "flush", ip)
}

// DeleteHostRoute removes a host route if present (best-effort, Linux only).
func DeleteHostRoute(ip string) error {
	if ip == "" {
		return nil
	}
	return RunPrivileged("ip", "route", "del", ip)
}
