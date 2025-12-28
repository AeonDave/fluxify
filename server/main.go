//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"fluxify/common"
)

func main() {
	port := flag.Int("port", 8000, "UDP data port")
	ctrlPort := flag.Int("ctrl", 8443, "TLS control port")
	ifaceName := flag.String("iface", "", "TUN interface name (optional)")
	pkiDir := flag.String("pki", "./pki", "PKI directory")
	reorderSize := flag.Int("reorder-buffer-size", defaultReorderBufferSize, "reorder buffer max packets")
	reorderTimeout := flag.Duration("reorder-flush-timeout", defaultReorderFlushTimeout, "reorder buffer flush timeout (e.g. 50ms)")
	mssClamp := flag.String("mss-clamp", "off", "TCP MSS clamp for traffic traversing TUN: off|pmtu|fixed:N")
	tuiMode := flag.Bool("tui", false, "run server with TUI for cert management")
	regen := flag.Bool("regen", false, "regenerate CA/server certs on start")
	hosts := flag.String("hosts", "127.0.0.1,localhost", "comma-separated SANs for server cert")
	verbose := flag.Bool("v", false, "enable verbose debug logging")
	metricsEvery := flag.Duration("metrics-every", 0, "log per-session metrics every interval (0 to disable)")
	flag.Parse()

	setServerReorderConfig(*reorderSize, *reorderTimeout)

	if !common.IsRoot() {
		log.Fatalf("run the server with sudo/root on linux for TUN/NAT setup")
	}

	pki := common.DefaultPKI(*pkiDir)
	hostList := splitCSV(*hosts)
	hostsProvided := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == "hosts" {
			hostsProvided = true
		}
	})
	if len(hostList) == 0 {
		hostList = []string{"127.0.0.1", "localhost"}
	}
	if !hostsProvided {
		if publicIP, err := fetchPublicIP(); err == nil && publicIP != "" {
			hostList = addHostIfMissing(hostList, publicIP)
		} else if err != nil {
			log.Printf("warning: failed to fetch public IP for cert SANs: %v", err)
		}
	}
	if err := common.EnsureBasePKI(pki, hostList, *regen); err != nil {
		log.Fatalf("pki init error: %v", err)
	}

	if *tuiMode {
		runServerTUI(pki, hostList, *port, *ctrlPort, *ifaceName)
		return
	}

	mssCfg, err := parseMSSClampFlag(*mssClamp)
	if err != nil {
		log.Fatalf("invalid -mss-clamp: %v", err)
	}

	srv := NewServer(*port, *ctrlPort, *ifaceName, pki, *verbose)
	if err := srv.Start(); err != nil {
		log.Fatalf("server start error: %v", err)
	}
	// Optional: MSS clamp to avoid PMTUD/fragmentation throughput collapse.
	if err := ensureMSSClampRules(nil, srv.tun.Name(), mssCfg); err != nil {
		log.Printf("warning: mss clamp setup failed: %v", err)
	}
	if *metricsEvery > 0 {
		go srv.metricsLoop(*metricsEvery)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	<-sigc
	log.Println("Shutting down...")
}

// splitCSV splits a comma-separated string into trimmed, non-empty parts.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func addHostIfMissing(hosts []string, host string) []string {
	for _, h := range hosts {
		if strings.EqualFold(h, host) {
			return hosts
		}
	}
	return append(hosts, host)
}

func fetchPublicIP() (string, error) {
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ipify http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid ipify response: %q", ip)
	}
	return ip, nil
}
