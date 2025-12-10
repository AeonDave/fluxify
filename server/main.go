package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"fluxify/common"
)

func main() {
	port := flag.Int("port", 8000, "UDP data port")
	ctrlPort := flag.Int("ctrl", 8443, "TLS control port")
	ifaceName := flag.String("iface", "", "TUN interface name (optional)")
	pkiDir := flag.String("pki", "./pki", "PKI directory")
	tuiMode := flag.Bool("tui", false, "run server with TUI for cert management")
	regen := flag.Bool("regen", false, "regenerate CA/server certs on start")
	hosts := flag.String("hosts", "127.0.0.1,localhost", "comma-separated SANs for server cert")
	verbose := flag.Bool("v", false, "enable verbose debug logging")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Println("Run as root for TUN/NAT setup")
	}

	pki := common.DefaultPKI(*pkiDir)
	hostList := splitCSV(*hosts)
	if len(hostList) == 0 {
		hostList = []string{"127.0.0.1", "localhost"}
	}
	if err := common.EnsureBasePKI(pki, hostList, *regen); err != nil {
		log.Fatalf("pki init error: %v", err)
	}

	if *tuiMode {
		runServerTUI(pki, hostList, *port, *ctrlPort, *ifaceName)
		return
	}

	srv := NewServer(*port, *ctrlPort, *ifaceName, pki, *verbose)
	if err := srv.Start(); err != nil {
		log.Fatalf("server start error: %v", err)
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
