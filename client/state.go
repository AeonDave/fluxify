package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rivo/tview"
	"github.com/songgao/water"
)

const (
	modeBonding     = "bonding"
	modeLoadBalance = "load-balance"
	controlTimeout  = 10 * time.Second
)

type clientConn struct {
	udp       *net.UDPConn
	addr      *net.UDPAddr
	iface     string
	alive     atomic.Bool
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	rttNano   atomic.Int64
	mu        sync.Mutex
}

type clientState struct {
	serverUDP   *net.UDPAddr
	sessionID   uint32
	sessionKey  []byte
	conns       []*clientConn
	connMu      sync.RWMutex
	nextSeqSend atomic.Uint32
	nextConnRR  atomic.Uint32
	tun         *water.Interface
	mode        string
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	revertRoute func()
	statsView   *tview.TextView // for dynamic updates
}

type clientConfig struct {
	Server        string
	Ifaces        []string
	IPs           []string
	Conns         int
	Mode          string
	PKI           string
	Client        string
	Ctrl          int
	PolicyRouting bool
	Gateways      []string
}

type storedConfig struct {
	Server string   `json:"server"`
	Mode   string   `json:"mode"`
	Ifaces []string `json:"ifaces"`
	Client string   `json:"client"`
	PKI    string   `json:"pki"`
	Ctrl   int      `json:"ctrl"`
}

func fmtBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	kb := float64(b) / unit
	if kb < unit {
		return fmt.Sprintf("%.1f KB", kb)
	}
	mb := kb / unit
	if mb < unit {
		return fmt.Sprintf("%.1f MB", mb)
	}
	gb := mb / unit
	if gb < unit {
		return fmt.Sprintf("%.2f GB", gb)
	}
	return fmt.Sprintf("%.2f TB", gb/unit)
}

// pickIndex picks element i modulo len(list) or empty string.
func pickIndex(list []string, i int) string {
	if len(list) == 0 {
		return ""
	}
	return list[i%len(list)]
}
