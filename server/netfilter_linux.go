//go:build linux
// +build linux

package main

import (
	"fmt"
)

// Minimal netfilter/sysctl helpers to keep the linux server buildable.
// These are best-effort and assume the process runs with sufficient privileges.

func ensureNatRule(r cmdRunner) error {
	i := newIpt(r)
	// Masquerade VPN subnet.
	rule := []string{"-s", "10.8.0.0/24", "-j", "MASQUERADE"}
	return i.ensureRule("iptables", "nat", "POSTROUTING", rule)
}

func ensureNatRule6(r cmdRunner) error {
	i := newIpt(r)
	// Masquerade IPv6 VPN prefix (best-effort).
	rule := []string{"-s", "fd00:8:0::/64", "-j", "MASQUERADE"}
	return i.ensureRule("ip6tables", "nat", "POSTROUTING", rule)
}

func ensureForwardRules(r cmdRunner, tun string) error {
	if tun == "" {
		return nil
	}
	i := newIpt(r)
	// Allow established back.
	if err := i.ensureRule("iptables", "filter", "FORWARD", []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return err
	}
	// Allow forwarding from tun.
	return i.ensureRule("iptables", "filter", "FORWARD", []string{"-i", tun, "-j", "ACCEPT"})
}

func ensureForwardRules6(r cmdRunner, tun string) error {
	if tun == "" {
		return nil
	}
	i := newIpt(r)
	if err := i.ensureRule("ip6tables", "filter", "FORWARD", []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return err
	}
	return i.ensureRule("ip6tables", "filter", "FORWARD", []string{"-i", tun, "-j", "ACCEPT"})
}

func enableForwarding(r cmdRunner) error {
	if r == nil {
		r = execRunner{}
	}
	// Best-effort sysctl calls.
	if err := r.Run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("ipv4 ip_forward: %w", err)
	}
	_ = r.Run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	return nil
}
