//go:build windows
// +build windows

package common

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	// Winsock socket options for binding to an interface.
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// NewBoundUDPDialer binds optionally to a local IP and/or interface using Windows-specific socket options.
// iface binding uses IP_UNICAST_IF / IPV6_UNICAST_IF; localIP is respected for both IPv4/IPv6.
func NewBoundUDPDialer(iface, localIP string) (*net.Dialer, error) {
	d := &net.Dialer{}
	if localIP != "" {
		la, err := net.ResolveUDPAddr("udp", net.JoinHostPort(localIP, "0"))
		if err != nil {
			return nil, err
		}
		d.LocalAddr = la
	}
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, err
		}
		if ifi.Index == 0 {
			return nil, fmt.Errorf("interface %s has zero index", iface)
		}
		idx := uint32(ifi.Index)
		d.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				switch {
				case strings.HasPrefix(network, "udp4"):
					// IP_UNICAST_IF expects network byte order.
					_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(hToNL(idx)))
				case strings.HasPrefix(network, "udp6"):
					_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, int(idx))
				}
			})
		}
	}
	return d, nil
}

// EnsurePolicyRouting is not available on Windows; return nil to keep behavior no-op unless implemented in the future.
func EnsurePolicyRouting(tableID int, srcCIDR, gw, dev string) error { return nil }

func GetDefaultRoute() (line, via, dev string, err error) {
	out, err := exec.Command("route", "print", "-4").Output()
	if err != nil {
		return "", "", "", err
	}
	rows := parseRoutePrint(string(out))
	for _, r := range rows {
		if r.destination == "0.0.0.0" && r.netmask == "0.0.0.0" {
			devName, _ := interfaceNameForIP(r.ifaceIP)
			return r.raw, r.gateway, devName, nil
		}
	}
	return "", "", "", nil
}

func ReplaceDefaultRoute(line string) error {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return fmt.Errorf("invalid route line: %q", line)
	}
	gateway := fields[2]
	ifaceIP := fields[3]
	metric := fields[4]
	dev, err := interfaceNameForIP(ifaceIP)
	if err != nil {
		return fmt.Errorf("resolve interface for IP %s: %w", ifaceIP, err)
	}
	return setDefaultRoute(gateway, dev, metric)
}

func SetDefaultRouteDev(dev string) error {
	if strings.TrimSpace(dev) == "" {
		return nil
	}
	// Try using interface's first IPv4 as gateway if none provided.
	ifaceIP, _ := interfaceIPv4(dev)
	gw := "0.0.0.0"
	if ifaceIP != nil {
		gw = ifaceIP.String()
	}
	return setDefaultRoute(gw, dev, "1")
}

func setDefaultRoute(gateway, dev, metric string) error {
	if dev == "" {
		return fmt.Errorf("device required")
	}
	if metric == "" {
		metric = "1"
	}
	if err := exec.Command("route", "delete", "0.0.0.0").Run(); err != nil {
		// ignore failure; route may not exist
	}
	ifIdx, err := interfaceIndex(dev)
	if err != nil {
		return err
	}
	args := []string{"add", "0.0.0.0", "mask", "0.0.0.0", gateway, "if", strconv.Itoa(ifIdx), "metric", metric}
	if err := exec.Command("route", args...).Run(); err != nil {
		return fmt.Errorf("route add default: %w", err)
	}
	return nil
}

func GetDefaultRoute6() (line, via, dev string, err error) {
	out, err := exec.Command("netsh", "interface", "ipv6", "show", "route").Output()
	if err != nil {
		return "", "", "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if !strings.Contains(l, "::/0") {
			continue
		}
		fields := strings.Fields(l)
		if len(fields) < 4 {
			continue
		}
		// Format example: Publish Type Met Prefix Idx Gateway
		prefix := fields[len(fields)-3]
		if prefix != "::/0" {
			continue
		}
		ifaceIdxStr := fields[len(fields)-2]
		gateway := fields[len(fields)-1]
		ifaceIdx, _ := strconv.Atoi(ifaceIdxStr)
		devName, _ := interfaceNameByIndex(ifaceIdx)
		return l, gateway, devName, nil
	}
	return "", "", "", nil
}

func ReplaceDefaultRoute6(line string) error {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return fmt.Errorf("invalid ipv6 route line: %q", line)
	}
	gateway := fields[len(fields)-1]
	ifaceIdxStr := fields[len(fields)-2]
	ifaceIdx, err := strconv.Atoi(ifaceIdxStr)
	if err != nil {
		return err
	}
	dev, err := interfaceNameByIndex(ifaceIdx)
	if err != nil {
		return err
	}
	return setDefaultRoute6(gateway, dev)
}

func SetDefaultRouteDev6(dev string) error {
	if strings.TrimSpace(dev) == "" {
		return nil
	}
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	gw := "::"
	return setDefaultRoute6(gw, iface.Name)
}

func setDefaultRoute6(gateway, dev string) error {
	if dev == "" {
		return fmt.Errorf("device required")
	}
	// Delete existing default
	_ = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", dev).Run()
	args := []string{"interface", "ipv6", "add", "route", "::/0", dev, gateway, "store=active"}
	if err := exec.Command("netsh", args...).Run(); err != nil {
		return fmt.Errorf("netsh add ipv6 default: %w", err)
	}
	return nil
}

func EnsureHostRoute6(ip, via, dev string) error {
	if ip == "" || dev == "" {
		return nil
	}
	if via == "" {
		via = "::"
	}
	_ = exec.Command("netsh", "interface", "ipv6", "delete", "route", ip, dev).Run()
	return exec.Command("netsh", "interface", "ipv6", "add", "route", ip, dev, via, "store=active").Run()
}

func DeleteHostRoute6(ip string) error {
	if ip == "" {
		return nil
	}
	return exec.Command("netsh", "interface", "ipv6", "delete", "route", ip, "all").Run()
}

func EnsureHostRoute(ip, via, dev string) error {
	if ip == "" || dev == "" {
		return nil
	}
	ifIdx, err := interfaceIndex(dev)
	if err != nil {
		return err
	}
	if via == "" {
		if ip4, _ := interfaceIPv4(dev); ip4 != nil {
			via = ip4.String()
		} else {
			via = "0.0.0.0"
		}
	}
	_ = exec.Command("route", "delete", ip).Run()
	args := []string{"add", ip, "mask", "255.255.255.255", via, "if", strconv.Itoa(ifIdx), "metric", "1"}
	return exec.Command("route", args...).Run()
}

func DeleteHostRoute(ip string) error {
	if ip == "" {
		return nil
	}
	return exec.Command("route", "delete", ip).Run()
}

// IsLinux reports whether the current GOOS is linux (always false on Windows).
func IsLinux() bool { return false }

// Helpers

type routeRow struct {
	destination string
	netmask     string
	gateway     string
	ifaceIP     string
	metric      string
	raw         string
}

func parseRoutePrint(out string) []routeRow {
	var rows []routeRow
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		f := strings.Fields(strings.TrimSpace(l))
		if len(f) < 5 {
			continue
		}
		// Expect IPv4 route row: Destination, Netmask, Gateway, Interface, Metric
		rows = append(rows, routeRow{
			destination: f[0],
			netmask:     f[1],
			gateway:     f[2],
			ifaceIP:     f[3],
			metric:      f[4],
			raw:         strings.Join(f[:5], " "),
		})
	}
	return rows
}

func interfaceNameForIP(ip string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("empty ip")
	}
	target := net.ParseIP(ip)
	if target == nil {
		return "", fmt.Errorf("invalid ip: %s", ip)
	}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ipn.IP.Equal(target) {
					return ifc.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("interface for ip %s not found", ip)
}

func interfaceNameByIndex(idx int) (string, error) {
	ifc, err := net.InterfaceByIndex(idx)
	if err != nil {
		return "", err
	}
	return ifc.Name, nil
}

func interfaceIndex(name string) (int, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifc.Index, nil
}

func interfaceIPv4(name string) (net.IP, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return ipn.IP.To4(), nil
		}
	}
	return nil, fmt.Errorf("no ipv4 on %s", name)
}

func hToNL(v uint32) uint32 {
	return (v&0xff)<<24 | (v&0xff00)<<8 | (v&0xff0000)>>8 | (v >> 24)
}
