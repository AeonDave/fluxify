//go:build linux
// +build linux

package platform

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Runner mirrors the command runner used by the client.
type Runner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	OutputSafe(name string, args ...string) ([]byte, error)
}

// Uplink describes per-interface routing info.
type Uplink struct {
	Iface  string
	Gw     string
	Gw6    string
	Alive4 bool
	Alive6 bool
}

func GatewayForIface(r Runner, iface string) (string, error) {
	log.Printf("GatewayForIface(%s): checking...", iface)
	out, err := r.OutputSafe("ip", "route", "get", "8.8.8.8", "oif", iface)
	if err != nil {
		log.Printf("GatewayForIface(%s): ip route get failed: %v", iface, err)
		return "", err
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" {
			gw := fields[i+1]
			log.Printf("GatewayForIface(%s): found gw %s", iface, gw)
			return gw, nil
		}
	}
	log.Printf("GatewayForIface(%s): no 'via' field in output", iface)
	return "", nil
}

func GatewayForIface6(r Runner, iface string) (string, error) {
	log.Printf("GatewayForIface6(%s): checking...", iface)
	out, err := r.OutputSafe("ip", "-6", "route", "get", "2001:4860:4860::8888", "oif", iface)
	if err != nil {
		log.Printf("GatewayForIface6(%s): ip route get failed: %v", iface, err)
		return "", err
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" {
			gw := fields[i+1]
			log.Printf("GatewayForIface6(%s): found gw %s", iface, gw)
			return gw, nil
		}
	}
	log.Printf("GatewayForIface6(%s): no 'via' field in output", iface)
	return "", nil
}

func InstallMultipathDefault(r Runner, uplinks []Uplink) error {
	log.Printf("InstallMultipathDefault: preparing routes...")
	args := []string{"route", "replace", "default", "scope", "global"}
	for _, u := range uplinks {
		if !u.Alive4 || u.Gw == "" {
			continue
		}
		args = append(args, "nexthop", "via", u.Gw, "dev", u.Iface, "weight", "1")
	}
	if len(args) == 5 { // no nexthops added
		log.Printf("InstallMultipathDefault: no alive uplinks")
		return fmt.Errorf("no alive uplinks to install")
	}
	log.Printf("InstallMultipathDefault: running ip %s", strings.Join(args, " "))
	if err := r.Run("ip", args...); err != nil {
		log.Printf("InstallMultipathDefault: failed: %v", err)
		return err
	}
	return nil
}

func InstallMultipathDefault6(r Runner, uplinks []Uplink) error {
	log.Printf("InstallMultipathDefault6: preparing routes...")
	args := []string{"-6", "route", "replace", "default"}
	for _, u := range uplinks {
		if !u.Alive6 || u.Gw6 == "" {
			continue
		}
		args = append(args, "nexthop", "via", u.Gw6, "dev", u.Iface, "weight", "1")
	}
	if len(args) == 4 {
		log.Printf("InstallMultipathDefault6: no alive ipv6 uplinks")
		return fmt.Errorf("no alive ipv6 uplinks to install")
	}
	log.Printf("InstallMultipathDefault6: running ip %s", strings.Join(args, " "))
	if err := r.Run("ip", args...); err != nil {
		log.Printf("InstallMultipathDefault6: failed: %v", err)
		return err
	}
	return nil
}

func AddMasqueradeRules(r Runner, uplinks []Uplink) error {
	for _, u := range uplinks {
		if err := r.Run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", u.Iface, "-j", "MASQUERADE"); err != nil {
			log.Printf("AddMasqueradeRules: failed for %s: %v", u.Iface, err)
			return fmt.Errorf("iptables add %s: %w", u.Iface, err)
		}
	}
	return nil
}

func AddMasqueradeRules6(r Runner, uplinks []Uplink) error {
	for _, u := range uplinks {
		if u.Gw6 == "" {
			continue
		}
		if err := r.Run("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-o", u.Iface, "-j", "MASQUERADE"); err != nil {
			log.Printf("AddMasqueradeRules6: failed for %s: %v", u.Iface, err)
			return fmt.Errorf("ip6tables add %s: %w", u.Iface, err)
		}
	}
	return nil
}

func RemoveMasqueradeRules(r Runner, uplinks []Uplink) error {
	for _, u := range uplinks {
		_ = r.Run("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", u.Iface, "-j", "MASQUERADE")
	}
	return nil
}

func RemoveMasqueradeRules6(r Runner, uplinks []Uplink) error {
	for _, u := range uplinks {
		if u.Gw6 == "" {
			continue
		}
		_ = r.Run("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-o", u.Iface, "-j", "MASQUERADE")
	}
	return nil
}

func ReadInterfaceBytes(iface string) (rx, tx uint64, err error) {
	read := func(path string) (uint64, error) {
		b, e := os.ReadFile(path)
		if e != nil {
			return 0, e
		}
		v, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if e != nil {
			return 0, e
		}
		return v, nil
	}
	rx, err = read(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", iface))
	if err != nil {
		return
	}
	tx, err = read(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface))
	return
}

func PingIfaceV4(r Runner, iface string) error {
	return r.Run("ping", "-c", "1", "-W", "1", "-I", iface, "1.1.1.1")
}

func PingIfaceV6(r Runner, iface string) error {
	return r.Run("ping", "-6", "-c", "1", "-W", "1", "-I", iface, "2606:4700:4700::1111")
}
