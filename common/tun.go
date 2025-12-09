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
}

// ConfigureTUN brings up the TUN interface with IP/MTU. Linux only; Windows/mac not supported in this minimal pass.
func ConfigureTUN(cfg TUNConfig) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("only linux tun config implemented in this prototype")
	}
	commands := [][]string{
		{"ip", "addr", "flush", "dev", cfg.IfaceName},
		{"ip", "addr", "add", cfg.CIDR, "dev", cfg.IfaceName},
		{"ip", "link", "set", "dev", cfg.IfaceName, "up"},
		{"ip", "link", "set", "dev", cfg.IfaceName, "mtu", fmt.Sprintf("%d", cfg.MTU)},
	}
	if cfg.GatewayCIDR != "" {
		commands = append(commands, []string{"ip", "route", "replace", cfg.GatewayCIDR, "dev", cfg.IfaceName})
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
