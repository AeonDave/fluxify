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
