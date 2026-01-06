//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"fluxify/common"
)

func main() {
	port := flag.Int("port", 8000, "QUIC data port")
	ctrl := flag.Int("ctrl", 8443, "TLS control port")
	iface := flag.String("iface", "", "TUN interface name")
	pkiDir := flag.String("pki", "./pki", "PKI directory")
	regen := flag.Bool("regen", false, "Regenerate CA and server certs")
	hosts := flag.String("hosts", "", "Server SANs (comma-separated, auto-detect if empty)")
	tuiMode := flag.Bool("tui", false, "Start certificate management TUI")
	rsize := flag.Int("reorder-buffer-size", 128, "Inbound reorder buffer size")
	rflush := flag.Duration("reorder-flush-timeout", 50*time.Millisecond, "Reorder flush timeout")
	mssClamp := flag.String("mss-clamp", "off", "TCP MSS clamp (off|pmtu|fixed:N)")
	metricsEvery := flag.Duration("metrics-every", 0, "Periodic metrics logging interval (0 to disable)")
	verbose := flag.Bool("v", false, "Enable verbose output")

	flag.Parse()

	pki := common.DefaultPKI(*pkiDir)

	sanList := detectOrParseSANs(*hosts, *verbose)

	if *tuiMode {
		runServerTUI(pki, sanList, *port, *ctrl, *iface, *verbose)
		return
	}

	if err := common.EnsureBasePKI(pki, sanList, *regen); err != nil {
		log.Fatalf("PKI error: %v", err)
	}

	mssCfg, err := parseMSSClampFlag(*mssClamp)
	if err != nil {
		log.Fatalf("invalid -mss-clamp: %v", err)
	}

	srv := NewServer(*port, *ctrl, *iface, pki, *verbose, *rsize, *rflush)
	srv.mssClamp = mssCfg
	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	if *metricsEvery > 0 {
		go srv.metricsLoop(*metricsEvery)
	}

	fmt.Printf("Fluxify server running (data:%d, control:%d)\n", *port, *ctrl)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\nShutting down...")
}

func detectOrParseSANs(hostsFlag string, verbose bool) []string {
	if hostsFlag != "" {
		sans := strings.Split(hostsFlag, ",")
		if verbose {
			log.Printf("[DEBUG] Using explicit SANs from -hosts flag: %v", sans)
		}
		return sans
	}

	// Collect local interface IPs
	localIPs, err := common.GetLocalIPs()
	if err != nil && verbose {
		log.Printf("[DEBUG] Failed to detect local IPs: %v", err)
	}

	// Try to fetch public IP (for servers behind NAT)
	if verbose {
		log.Printf("[DEBUG] Fetching public IP from ipify.org...")
	}
	publicIP := common.GetPublicIP(3 * time.Second)
	if publicIP != "" && verbose {
		log.Printf("[DEBUG] Public IP detected: %s", publicIP)
	} else if verbose {
		log.Printf("[DEBUG] Could not detect public IP (offline or behind restrictive firewall)")
	}

	// Build SAN list: public IP first (if available), then local IPs, then localhost
	seen := make(map[string]bool)
	var sans []string

	// Add public IP first (most important for external clients)
	if publicIP != "" && !seen[publicIP] {
		sans = append(sans, publicIP)
		seen[publicIP] = true
	}

	// Add local IPs (for LAN clients)
	for _, ip := range localIPs {
		if !seen[ip] {
			sans = append(sans, ip)
			seen[ip] = true
		}
	}

	// Always include localhost
	if !seen["localhost"] {
		sans = append(sans, "localhost")
	}

	if len(sans) == 0 {
		sans = []string{"127.0.0.1", "localhost"}
		if verbose {
			log.Printf("[DEBUG] No IPs detected, using fallback: %v", sans)
		}
	} else if verbose {
		log.Printf("[DEBUG] Auto-detected SANs: %v", sans)
	}

	return sans
}
