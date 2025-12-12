//go:build linux
// +build linux

package common

import (
	"fmt"
	"log"
	"runtime"
)

type TUNConfig struct {
	IfaceName   string
	CIDR        string
	MTU         int
	GatewayCIDR string // optional for server
	IPv6CIDR    string
	IPv6Gateway string
}

// ConfigureTUN brings up the TUN interface with IP/MTU. Linux only; Windows/mac not supported in this minimal pass.
func ConfigureTUN(cfg TUNConfig) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("only linux tun config implemented in this prototype")
	}
	commands := [][]string{
		{"ip", "addr", "flush", "dev", cfg.IfaceName},
	}
	if cfg.CIDR != "" {
		commands = append(commands, []string{"ip", "addr", "add", cfg.CIDR, "dev", cfg.IfaceName})
	}
	if cfg.IPv6CIDR != "" {
		commands = append(commands, []string{"ip", "-6", "addr", "add", cfg.IPv6CIDR, "dev", cfg.IfaceName})
	}
	commands = append(commands,
		[]string{"ip", "link", "set", "dev", cfg.IfaceName, "up"},
		[]string{"ip", "link", "set", "dev", cfg.IfaceName, "mtu", fmt.Sprintf("%d", cfg.MTU)},
	)
	if cfg.GatewayCIDR != "" {
		commands = append(commands, []string{"ip", "route", "replace", cfg.GatewayCIDR, "dev", cfg.IfaceName})
	}
	if cfg.IPv6Gateway != "" {
		commands = append(commands, []string{"ip", "-6", "route", "replace", cfg.IPv6Gateway, "dev", cfg.IfaceName})
	}
	for _, cmd := range commands {
		out, err := RunPrivilegedCombined(cmd[0], cmd[1:]...)
		if err != nil {
			return fmt.Errorf("cmd %v failed: %v (%s)", cmd, err, string(out))
		}
		log.Printf("tun: executed %v", cmd)
	}
	return nil
}
