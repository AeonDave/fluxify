//go:build linux
// +build linux

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// cmdRunner abstracts exec.Command for testability.
type cmdRunner interface {
	Run(name string, args ...string) error
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// ipt supports checking and applying rules idempotently.
type ipt struct {
	r cmdRunner
}

func newIpt(r cmdRunner) *ipt {
	if r == nil {
		r = execRunner{}
	}
	return &ipt{r: r}
}

func (i *ipt) ensureRule(tool string, table string, chain string, ruleArgs []string) error {
	// iptables -t <table> -C <chain> <ruleArgs...>
	check := append([]string{"-t", table, "-C", chain}, ruleArgs...)
	if err := i.r.Run(tool, check...); err == nil {
		return nil
	}
	// iptables -t <table> -A <chain> <ruleArgs...>
	add := append([]string{"-t", table, "-A", chain}, ruleArgs...)
	return i.r.Run(tool, add...)
}

type mssClampMode int

const (
	mssClampOff mssClampMode = iota
	mssClampPMTU
	mssClampFixed
)

type mssClampConfig struct {
	mode  mssClampMode
	fixed int
}

func parseMSSClampFlag(v string) (mssClampConfig, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "off" || v == "0" {
		return mssClampConfig{mode: mssClampOff}, nil
	}
	if v == "pmtu" || v == "clamp" || v == "clamp-mss-to-pmtu" {
		return mssClampConfig{mode: mssClampPMTU}, nil
	}
	if strings.HasPrefix(v, "fixed:") {
		var n int
		_, err := fmt.Sscanf(v, "fixed:%d", &n)
		if err != nil || n < 500 || n > 9000 {
			return mssClampConfig{}, fmt.Errorf("invalid fixed mss value: %q", v)
		}
		return mssClampConfig{mode: mssClampFixed, fixed: n}, nil
	}
	// Back-compat: if it's just a number treat as fixed.
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
		if n < 500 || n > 9000 {
			return mssClampConfig{}, fmt.Errorf("invalid mss value: %d", n)
		}
		return mssClampConfig{mode: mssClampFixed, fixed: n}, nil
	}
	return mssClampConfig{}, fmt.Errorf("invalid -mss-clamp value: %q (expected off|pmtu|fixed:N)", v)
}

func (c mssClampConfig) enabled() bool {
	return c.mode != mssClampOff
}

// ensureMSSClampRules ensures MSS clamping for TCP SYN traversing the TUN.
//
// We apply both directions to cover traffic entering/leaving the VPN.
// Note: we keep it simple (single tun device name).
func ensureMSSClampRules(r cmdRunner, tun string, cfg mssClampConfig) error {
	if !cfg.enabled() || tun == "" {
		return nil
	}
	i := newIpt(r)

	// For IPv4 use iptables; for IPv6 use ip6tables.
	if err := ensureMSSClampRulesTool(i, "iptables", tun, cfg); err != nil {
		return err
	}
	if err := ensureMSSClampRulesTool(i, "ip6tables", tun, cfg); err != nil {
		return err
	}
	return nil
}

func ensureMSSClampRulesTool(i *ipt, tool string, tun string, cfg mssClampConfig) error {
	// mangle/POSTROUTING for packets leaving tun
	ruleOut := []string{"-o", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS"}
	// mangle/FORWARD for packets entering tun
	ruleIn := []string{"-i", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS"}

	switch cfg.mode {
	case mssClampPMTU:
		ruleOut = append(ruleOut, "--clamp-mss-to-pmtu")
		ruleIn = append(ruleIn, "--clamp-mss-to-pmtu")
	case mssClampFixed:
		ruleOut = append(ruleOut, "--set-mss", fmt.Sprint(cfg.fixed))
		ruleIn = append(ruleIn, "--set-mss", fmt.Sprint(cfg.fixed))
	default:
		return nil
	}

	// Best-effort: if tool missing, just return error from runner.
	if err := i.ensureRule(tool, "mangle", "POSTROUTING", ruleOut); err != nil {
		return err
	}
	if err := i.ensureRule(tool, "mangle", "FORWARD", ruleIn); err != nil {
		return err
	}
	return nil
}
