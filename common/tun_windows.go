//go:build windows
// +build windows

package common

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type TUNConfig struct {
	IfaceName   string
	CIDR        string
	MTU         int
	GatewayCIDR string
	IPv6CIDR    string
	IPv6Gateway string
}

// ConfigureTUN brings up the TUN interface with IP/MTU using netsh commands on Windows.
func ConfigureTUN(cfg TUNConfig) error {
	if cfg.IfaceName == "" {
		return fmt.Errorf("iface required")
	}

	commands := [][]string{}

	if cfg.CIDR != "" {
		ip, mask, err := parseCIDR(cfg.CIDR)
		if err != nil {
			return err
		}
		commands = append(commands, []string{"interface", "ip", "set", "address", fmt.Sprintf("name=%s", cfg.IfaceName), "source=static", "addr=" + ip, "mask=" + mask, "gateway=none"})
	}
	if cfg.IPv6CIDR != "" {
		commands = append(commands, []string{"interface", "ipv6", "set", "address", cfg.IfaceName, cfg.IPv6CIDR})
	}
	if cfg.MTU > 0 {
		commands = append(commands, []string{"interface", "ipv4", "set", "subinterface", cfg.IfaceName, fmt.Sprintf("mtu=%d", cfg.MTU), "store=persistent"})
	}
	if cfg.GatewayCIDR != "" {
		commands = append(commands, []string{"interface", "ip", "add", "route", cfg.GatewayCIDR, cfg.IfaceName, "0.0.0.0"})
	}
	if cfg.IPv6Gateway != "" {
		commands = append(commands, []string{"interface", "ipv6", "add", "route", cfg.IPv6Gateway, cfg.IfaceName, "::"})
	}

	for _, cmd := range commands {
		if err := runNetsh(cmd); err != nil {
			return err
		}
	}
	if cfg.CIDR != "" {
		if err := ensureInterfaceIPv4(cfg.IfaceName, cfg.CIDR); err != nil {
			return err
		}
	}
	return nil
}

func runNetsh(args []string) error {
	cmd := exec.Command("netsh", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh %v failed: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseCIDR(cidr string) (ip string, mask string, err error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid cidr: %s", cidr)
	}
	prefixIP := net.ParseIP(parts[0])
	if prefixIP == nil {
		return "", "", fmt.Errorf("invalid ip in cidr: %s", cidr)
	}
	_, n, e := net.ParseCIDR(cidr)
	if e != nil {
		return "", "", e
	}
	ip = prefixIP.String()
	mask = net.IP(n.Mask).String()
	return ip, mask, nil
}

func ensureInterfaceIPv4(iface, cidr string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil || ip == nil {
		return fmt.Errorf("invalid cidr: %s", cidr)
	}
	ipStr := ip.String()
	if hasInterfaceIPv4(iface, ipStr) {
		return nil
	}
	if err := forceInterfaceIPv4(iface, ipStr, cidr); err != nil {
		return fmt.Errorf("set interface ip: %w", err)
	}
	if hasInterfaceIPv4(iface, ipStr) {
		return nil
	}
	return fmt.Errorf("interface %s ip mismatch (expected %s)", iface, ipStr)
}

func hasInterfaceIPv4(iface, ip string) bool {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return false
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil && v4.String() == ip {
				return true
			}
		}
	}
	return false
}

func forceInterfaceIPv4(iface, ip, cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	prefixLen, _ := ipnet.Mask.Size()
	cmd := fmt.Sprintf(`$if='%s'; `+
		`Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -ErrorAction SilentlyContinue | `+
		`Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; `+
		`New-NetIPAddress -InterfaceAlias $if -IPAddress %s -PrefixLength %d -Type Unicast -ErrorAction Stop | Out-Null`, iface, ip, prefixLen)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell ip config failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
