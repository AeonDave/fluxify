package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

const (
	modeBonding     = "bonding"
	modeLoadBalance = "load-balance"
	controlTimeout  = 10 * time.Second

	// sendQueueLen is the per-path backlog (packets). Combined with the QUIC
	// datagram queue it bounds the queueing delay the scheduler can build up
	// on a single path.
	sendQueueLen = 256
	// tunQueueLen is the inbound TUN write queue (packets).
	tunQueueLen = 512
	// statsInterval is how often per-path rate/RTT estimates are refreshed.
	statsInterval = 100 * time.Millisecond
	// heartbeatEvery is the per-path heartbeat period (liveness + RTT/jitter).
	heartbeatEvery = 2 * time.Second
)

// pathConn is one bonded uplink: a dedicated QUIC connection over a UDP
// socket bound to a single physical interface. The connection inside comes
// and goes (redials); the pathConn itself lives for the whole session.
type pathConn struct {
	iface   string
	localIP string // optional explicit source IP ("" = auto-discover)

	mu   sync.Mutex
	conn *quic.Conn
	udp  *net.UDPConn

	// sendCh carries ready-to-send datagrams (pooled buffers). The path
	// sender drains it at whatever rate the QUIC congestion controller
	// allows; its occupancy is the backlog the scheduler keys on.
	sendCh chan []byte
	queued atomic.Int64 // bytes accepted but not yet handed to QUIC

	rate    *common.RateEstimator
	rttNano atomic.Int64 // smoothed RTT from QUIC connection stats

	alive      atomic.Bool
	bytesSent  atomic.Uint64
	bytesRecv  atomic.Uint64
	hbSent     atomic.Uint64
	hbRecv     atomic.Uint64
	lastHbRTT  atomic.Int64 // last heartbeat RTT sample (jitter input)
	jitterNano atomic.Int64
	lastRecv   atomic.Int64 // unix nanos of last inbound datagram
}

func newPathConn(iface, localIP string) *pathConn {
	return &pathConn{
		iface:   iface,
		localIP: localIP,
		sendCh:  make(chan []byte, sendQueueLen),
		rate:    common.NewRateEstimator(common.DefaultInitialRateBps, common.DefaultRateTau),
	}
}

func (p *pathConn) currentConn() *quic.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn
}

func (p *pathConn) setConn(conn *quic.Conn, udp *net.UDPConn) {
	p.mu.Lock()
	p.conn = conn
	p.udp = udp
	p.mu.Unlock()
}

// closeConn tears down the current QUIC connection and socket (if any),
// unblocking the receive loop so the path lifecycle can redial.
func (p *pathConn) closeConn(reason string) {
	p.mu.Lock()
	conn, udp := p.conn, p.udp
	p.conn, p.udp = nil, nil
	p.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, reason)
	}
	if udp != nil {
		_ = udp.Close()
	}
}

// metrics snapshots the scheduler inputs for this path.
func (p *pathConn) metrics() common.PathMetrics {
	return common.PathMetrics{
		QueuedBytes: p.queued.Load(),
		RateBps:     p.rate.Rate(),
		RTT:         time.Duration(p.rttNano.Load()),
		Alive:       p.alive.Load(),
	}
}

type clientState struct {
	serverAddr string
	sessionID  uint32
	clientIP   string
	clientIPv6 string

	paths   []*pathConn // fixed at startup, one per selected interface
	nextSeq atomic.Uint32

	tun        platform.TunDevice
	tunWriteCh chan []byte
	mode       string
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	revertRoute func()
	revertDNS   func()
	ifaceDNS    []ifaceDNSBackup

	statsView *tview.TextView // for dynamic TUI updates
	ctrlAddr  string
	cfg       clientConfig
	sessMu    sync.RWMutex

	serverAlive atomic.Bool
	reconnectOn atomic.Bool
	ipv6Enabled bool

	rateMu     sync.Mutex
	rateByPath map[*pathConn]*ifaceRate

	// Inbound reorder (server -> client) for packet-level striping.
	inReorder *common.ReorderBuffer
	tunDrops  atomic.Uint64 // packets dropped because the TUN write queue was full
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
