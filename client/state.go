package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/rivo/tview"

	"fluxify/client/platform"
)

const (
	modeBonding     = "bonding"
	modeLoadBalance = "load-balance"
	controlTimeout  = 10 * time.Second
)

type clientConn struct {
	// MP-QUIC connection (replaces udp)
	quicConn   *quic.Conn
	packetConn net.PacketConn
	addr       string // server address as string
	iface      string
	localIP    string
	alive      atomic.Bool
	ifaceUp    atomic.Bool
	bytesSent  atomic.Uint64
	bytesRecv  atomic.Uint64
	rttNano    atomic.Int64
	jitterNano atomic.Int64
	hbSent     atomic.Uint64
	hbRecv     atomic.Uint64
	lastRecv   atomic.Int64
	lastConn   atomic.Int64
	mu         sync.Mutex
}

type clientState struct {
	serverAddr   string // server address for QUIC connection
	sessionID    uint32
	clientIP     string
	clientIPv6   string
	conns        []*clientConn
	connMu       sync.RWMutex
	nextSeqSend  atomic.Uint32
	nextConnRR   atomic.Uint32
	tun          platform.TunDevice
	tunWriteCh   chan []byte
	mode         string
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	revertRoute  func()
	revertDNS    func()
	ifaceDNS     []ifaceDNSBackup
	statsView    *tview.TextView // for dynamic updates
	ctrlAddr     string
	cfg          clientConfig
	sessMu       sync.RWMutex
	serverAlive  atomic.Bool
	reconnectOn  atomic.Bool
	ipv6Enabled  bool
	rateMu       sync.Mutex
	rateByConn   map[*clientConn]*ifaceRate
	mpController *quic.DefaultMultipathController // MP-QUIC path controller

	// Inbound reorder (server -> client) for packet-level striping.
	inReorder      *reorderBuffer
	stopInReorder  chan struct{}
	inReorderStats struct {
		packetsBuffered  atomic.Uint64
		packetsReordered atomic.Uint64
		packetsDropped   atomic.Uint64
		flushes          atomic.Uint64
		maxDepth         atomic.Uint32
	}
}

type clientConfig struct {
	Server              string
	Ifaces              []string
	IPs                 []string
	Mode                string
	PKI                 string
	Cert                string
	Telemetry           string
	Ctrl                int
	DNS4                []string
	DNS6                []string
	ReorderBufferSize   int
	ReorderFlushTimeout time.Duration
	MTU                 int  // 0 = use default (common.MTU), >0 = override
	ProbePMTUD          bool // if true, probe PMTUD at startup and warn if fails
}

type storedConfig struct {
	Server string   `json:"server"`
	Mode   string   `json:"mode"`
	Ifaces []string `json:"ifaces"`
	Cert   string   `json:"cert,omitempty"`
	Client string   `json:"client,omitempty"`
	PKI    string   `json:"pki"`
	Ctrl   int      `json:"ctrl"`
}

type ifaceRate struct {
	lastTx  uint64
	lastRx  uint64
	lastAt  time.Time
	rateTxK float64
	rateRxK float64
}

type lossStats struct {
	percent float64
	ok      bool
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

func lossPercent(sent, recv uint64) lossStats {
	if sent < 3 {
		return lossStats{percent: 0, ok: false}
	}
	if recv > sent {
		recv = sent
	}
	return lossStats{percent: float64(sent-recv) * 100 / float64(sent), ok: true}
}

func stabilityScore(lossPct, jitterMs, rttMs float64) float64 {
	score := 100.0
	score -= lossPct * 1.2
	score -= jitterMs * 0.5
	score -= rttMs * 0.1
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// GetMPPathStats returns MP-QUIC path statistics if the controller is set.
func (c *clientState) GetMPPathStats() map[quic.PathID]quic.PathStatistics {
	if c.mpController == nil {
		return nil
	}
	return c.mpController.GetStatistics()
}

// pickIndex picks element i modulo len(list) or empty string.
func pickIndex(list []string, i int) string {
	if len(list) == 0 {
		return ""
	}
	return list[i%len(list)]
}
