//go:build windows
// +build windows

package platform

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

type Runner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	OutputSafe(name string, args ...string) ([]byte, error)
}

type Uplink struct {
	Iface  string
	Gw     string
	Gw6    string
	Alive4 bool
	Alive6 bool
}

func GatewayForIface(r Runner, iface string) (string, error) {
	vvlogf("GatewayForIface(%s): checking gateway...", iface)
	if gw, err := gatewayViaPowerShell(r, iface, false); err == nil && gw != "" {
		vvlogf("GatewayForIface(%s): found via PowerShell: %s", iface, gw)
		return gw, nil
	} else {
		vvlogf("GatewayForIface(%s): PowerShell failed/empty (err=%v), falling back to route print", iface, err)
	}
	ifaceIP, err := getInterfaceIP(iface, false)
	if err != nil {
		return "", err
	}
	out, err := r.OutputSafe("route", "print", "-4")
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		if f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && f[3] == ifaceIP.String() {
			vvlogf("GatewayForIface(%s): found via route print: %s", iface, f[2])
			return f[2], nil
		}
	}
	vvlogf("GatewayForIface(%s): no default gateway found in route print for IP %s", iface, ifaceIP)
	return "", nil
}

func GatewayForIface6(r Runner, iface string) (string, error) {
	if gw, err := gatewayViaPowerShell(r, iface, true); err == nil && gw != "" {
		return gw, nil
	}
	idx, err := interfaceIndex(iface)
	if err != nil {
		return "", err
	}
	out, err := r.OutputSafe("netsh", "interface", "ipv6", "show", "route")
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if !strings.Contains(l, "::/0") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		gw := f[len(f)-1]
		ifaceIdxStr := f[len(f)-2]
		ifaceIdx, _ := strconv.Atoi(ifaceIdxStr)
		if ifaceIdx == idx {
			return gw, nil
		}
	}
	return "", nil
}

func InstallMultipathDefault(r Runner, uplinks []Uplink) error {
	added := 0
	vlogf("InstallMultipathDefault: deleting 0.0.0.0")
	_ = r.Run("route", "delete", "0.0.0.0")
	for _, u := range uplinks {
		if !u.Alive4 || u.Gw == "" {
			continue
		}
		ifIdx, err := interfaceIndex(u.Iface)
		if err != nil {
			vlogf("InstallMultipathDefault: iface index error for %s: %v", u.Iface, err)
			return err
		}
		args := []string{"add", "0.0.0.0", "mask", "0.0.0.0", u.Gw, "if", strconv.Itoa(ifIdx), "metric", "1"}
		if err := r.Run("route", args...); err != nil {
			vlogf("InstallMultipathDefault: route add failed for %s (GW %s): %v", u.Iface, u.Gw, err)
			return err
		}
		added++
	}
	if added == 0 {
		return fmt.Errorf("no alive uplinks to install")
	}
	vlogf("InstallMultipathDefault: installed %d routes", added)
	return nil
}

func InstallMultipathDefault6(r Runner, uplinks []Uplink) error {
	added := 0
	for _, u := range uplinks {
		if !u.Alive6 || u.Gw6 == "" {
			continue
		}
		_ = r.Run("netsh", "interface", "ipv6", "delete", "route", "::/0", u.Iface)
		if err := r.Run("netsh", "interface", "ipv6", "add", "route", "::/0", u.Iface, u.Gw6, "store=active"); err != nil {
			return err
		}
		added++
	}
	if added == 0 {
		return fmt.Errorf("no alive ipv6 uplinks to install")
	}
	return nil
}

func AddMasqueradeRules(r Runner, uplinks []Uplink) error  { return nil }
func AddMasqueradeRules6(r Runner, uplinks []Uplink) error { return nil }
func RemoveMasqueradeRules(r Runner, uplinks []Uplink) error {
	return nil
}
func RemoveMasqueradeRules6(r Runner, uplinks []Uplink) error {
	return nil
}

func ReadInterfaceBytes(iface string) (rx, tx uint64, err error) {
	idx, err := interfaceIndex(iface)
	if err != nil {
		return 0, 0, err
	}
	row := windows.MibIfRow{Index: uint32(idx)}
	if err := windows.GetIfEntry(&row); err != nil {
		return 0, 0, err
	}
	return uint64(row.InOctets), uint64(row.OutOctets), nil
}

func PingIfaceV4(r Runner, iface string) (time.Duration, error) {
	ip, err := getInterfaceIP(iface, false)
	if err != nil {
		return 0, err
	}
	out, err := r.OutputSafe("ping", "-n", "1", "-w", "1000", "-S", ip.String(), "1.1.1.1")
	if err != nil {
		return 0, err
	}
	return parsePingRTT(string(out)), nil
}

func PingIfaceV6(r Runner, iface string) (time.Duration, error) {
	ip, err := getInterfaceIP(iface, true)
	if err != nil {
		return 0, err
	}
	out, err := r.OutputSafe("ping", "-6", "-n", "1", "-w", "1000", "-S", ip.String(), "2606:4700:4700::1111")
	if err != nil {
		return 0, err
	}
	return parsePingRTT(string(out)), nil
}

func parsePingRTT(out string) time.Duration {
	if out == "" {
		return 0
	}
	if idx := strings.Index(out, "time="); idx != -1 {
		rest := out[idx+len("time="):]
		return parsePingMillis(rest)
	}
	if idx := strings.Index(out, "Average = "); idx != -1 {
		rest := out[idx+len("Average = "):]
		return parsePingMillis(rest)
	}
	return 0
}

func parsePingMillis(s string) time.Duration {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	if idx := strings.Index(s, "ms"); idx != -1 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return time.Duration(val * float64(time.Millisecond))
}

func gatewayViaPowerShell(r Runner, iface string, ipv6 bool) (string, error) {
	dest := "0.0.0.0/0"
	if ipv6 {
		dest = "::/0"
	}
	cmd := fmt.Sprintf(`$r=Get-NetRoute -InterfaceAlias '%s' -DestinationPrefix '%s' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1; if ($r) { $r.NextHop }`, iface, dest)
	out, err := r.OutputSafe("powershell", "-NoProfile", "-Command", cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func interfaceIndex(name string) (int, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifc.Index, nil
}

func getInterfaceIP(name string, ipv6 bool) (net.IP, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	var fallback net.IP
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			ip := ipnet.IP
			if ipv6 {
				if ip.To4() != nil {
					continue
				}
				if !ip.IsLinkLocalUnicast() {
					return ip, nil
				}
				if fallback == nil {
					fallback = ip
				}
			} else {
				if v4 := ip.To4(); v4 != nil {
					return v4, nil
				}
			}
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("no ip found for iface %s", name)
}
