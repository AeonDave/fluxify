//go:build windows
// +build windows

package common

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// SetInterfaceDNS sets DNS servers on a Windows interface.
func SetInterfaceDNS(iface string, dns4 []string, dns6 []string) error {
	if strings.TrimSpace(iface) == "" {
		return nil
	}
	var errs []string
	if len(dns4) > 0 {
		if err := runNetsh([]string{"interface", "ip", "set", "dns", "name=" + iface, "static", dns4[0]}); err != nil {
			errs = append(errs, err.Error())
		}
		for i := 1; i < len(dns4); i++ {
			idx := fmt.Sprintf("index=%d", i+1)
			if err := runNetsh([]string{"interface", "ip", "add", "dns", "name=" + iface, dns4[i], idx}); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(dns6) > 0 {
		if err := runNetsh([]string{"interface", "ipv6", "set", "dnsservers", iface, "static", dns6[0]}); err != nil {
			errs = append(errs, err.Error())
		}
		for i := 1; i < len(dns6); i++ {
			idx := fmt.Sprintf("index=%d", i+1)
			if err := runNetsh([]string{"interface", "ipv6", "add", "dnsservers", iface, dns6[i], idx}); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("set dns: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ClearInterfaceDNS removes DNS servers from a Windows interface.
func ClearInterfaceDNS(iface string) error {
	if strings.TrimSpace(iface) == "" {
		return nil
	}
	_ = runNetsh([]string{"interface", "ip", "delete", "dns", "name=" + iface, "all"})
	_ = runNetsh([]string{"interface", "ipv6", "delete", "dnsservers", iface, "all"})
	return nil
}

// GetInterfaceDNS returns IPv4/IPv6 DNS servers for a Windows interface.
func GetInterfaceDNS(iface string) ([]string, []string, error) {
	if strings.TrimSpace(iface) == "" {
		return nil, nil, nil
	}
	dns4, err4 := getInterfaceDNSFamily(iface, "IPv4")
	dns6, err6 := getInterfaceDNSFamily(iface, "IPv6")
	if err4 != nil && err6 != nil {
		return nil, nil, fmt.Errorf("dns query failed: %v; %v", err4, err6)
	}
	return dns4, dns6, nil
}

func getInterfaceDNSFamily(iface, family string) ([]string, error) {
	cmd := fmt.Sprintf(`$r=Get-DnsClientServerAddress -InterfaceAlias '%s' -AddressFamily %s -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses; if ($r) { $r -join "," }`, iface, family)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", cmd).Output()
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	var servers []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			servers = append(servers, ip.String())
		}
	}
	return servers, nil
}
