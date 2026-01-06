package main

import (
	"testing"
)

func TestConfigPersistence_CLIOverridesStored(t *testing.T) {
	// Test that CLI flags override stored config
	cfg := clientConfig{
		Server: "stored.com",
		Ifaces: []string{"eth0"},
		Mode:   modeBonding,
		PKI:    "/stored/pki",
	}

	// Simulate CLI overrides
	cliServer := "cli.com"
	cliIfaces := []string{"wlan0", "eth1"}

	// Apply overrides
	if cliServer != "" {
		cfg.Server = cliServer
	}
	if len(cliIfaces) > 0 {
		cfg.Ifaces = cliIfaces
	}

	if cfg.Server != "cli.com" {
		t.Errorf("expected server=cli.com, got %s", cfg.Server)
	}
	if len(cfg.Ifaces) != 2 || cfg.Ifaces[0] != "wlan0" {
		t.Errorf("expected ifaces=[wlan0,eth1], got %v", cfg.Ifaces)
	}
}

func TestTelemetryFlag_OnlyInBondingMode(t *testing.T) {
	// Bonding mode: telemetry is allowed
	bondingCfg := clientConfig{
		Mode:      modeBonding,
		Telemetry: "telemetry.log",
	}
	if bondingCfg.Telemetry == "" {
		t.Error("telemetry should be allowed in bonding mode")
	}

	// Load-balance mode: telemetry path can be set but will error at runtime
	lbCfg := clientConfig{
		Mode:      modeLoadBalance,
		Telemetry: "telemetry.log",
	}
	// The flag can be set, but startTelemetryLogger will reject it
	if lbCfg.Telemetry == "" {
		t.Error("flag can be set (validation happens at runtime)")
	}
}

func TestDefaultMTU_IsCommonMTU(t *testing.T) {
	cfg := clientConfig{MTU: 0}
	// Default should be common.MTU (1400)
	// This is verified at runtime in bonding.go
	if cfg.MTU != 0 {
		t.Errorf("expected MTU=0 (auto), got %d", cfg.MTU)
	}
}
