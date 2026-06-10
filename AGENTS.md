# AGENTS.md

## Setup commands
- Install dependencies: `go mod tidy`
- Build server: `go build -o server-bin ./server` (Linux-only build tag)
- Build client: `go build -o client-bin ./client`
- Run client tests: `go test ./client/...`
- Run common tests: `go test ./common/...`
- Run all tests: `go test ./...` (server package is Linux-only; on other platforms it matches no test files)

## Windows resources
- The client embeds an icon + manifest via `client/rsrc_windows_*.syso` and shows a system tray icon (fyne.io/systray, `client/tray_windows.go`); `-no-tray` disables it.
- Regenerate icons with `go run ./scripts/genicon` (writes `client/assets/*.ico`), then rebuild the syso files with `go run github.com/akavel/rsrc@latest -ico client/assets/fluxify.ico -manifest client/fluxify.manifest -arch <amd64|arm64> -o client/rsrc_windows_<arch>.syso`.
- The manifest stays `asInvoker` (no UAC auto-elevation): elevation is checked at runtime and tests must keep running unelevated.

## Operational notes
- Client and server must be started with admin/sudo privileges; do not add runtime elevation prompts.
- Client debug log (`client_debug.log`) is written only when `-v` is enabled.
- Client telemetry log: use `-telemetry=<file>` to write per-path stats every 5s (timestamped JSON snapshots with aggregate metrics, reorder buffer stats, and per-path telemetry).

## Bonding (important)
- Architecture: **one vanilla quic-go connection per uplink interface**, with per-packet striping done by fluxify itself (no multipath QUIC extension).
- Sockets are bound per interface: Linux `SO_BINDTODEVICE`, Windows `IP_UNICAST_IF` (`common.ListenUDPBound`).
- Scheduler (`common.PickPath`): earliest estimated delivery time = `(backlog + packet) / max(rate, floor) + RTT/2`. Idle traffic stays on the lowest-RTT path; under load packets spread proportionally to measured capacity. The same scheduler stripes the downlink on the server across a session's connections (demuxed by `SessionID` in the dataplane header).
- Rate estimation (`common.RateEstimator`): EWMA of delivered bytes, fed by the fact that quic-go's `SendDatagram` blocks when the path's congestion window is saturated (per-path sender goroutines drain bounded queues).
- Reorder buffers (`common.ReorderBuffer`, default 512 packets / 50ms flush) restore the global `SeqNum` ordering on both sides.
- Per-path RTT comes from `Conn.ConnectionStats()`; heartbeats (2s per path) provide liveness, jitter and loss metrics. If every path stays silent for 20s the client renegotiates the session via the control plane.

## Code style
- Go 1.24+ required
- Standard Go formatting with `go fmt`
- Error handling with explicit error returns
- Context usage for cancellation and timeouts
- Atomic operations for concurrent counters
- Single-letter variables for loops and short-lived variables
- Proper logging with log package

## Project Architecture

### Core Components
- **Server** (Linux only): QUIC datagram VPN server with mTLS control plane, per-session downlink striping and reorder buffer
- **Client** (Linux + Windows): bonding (striping) and load-balance modes, TUI, telemetry
- **Common**: dataplane framing, striping scheduler, rate estimator, reorder buffer, PKI, netutils, TUN config

### Key Features
- Per-packet striping over N QUIC connections (RFC 9221 datagrams, TLS 1.3)
- mTLS control plane for authentication and IP assignment
- TUN interfaces for IP traffic (bonding mode), IPv4 + IPv6
- Reorder buffers for cross-path ordering
- Heartbeat-based path monitoring and automatic session renegotiation
- Text User Interface (TUI) for certificate management and live path metrics

### Testing
- Unit tests cover protocol serialization, scheduler, rate estimator, reorder buffer
- Integration tests for control plane, load balancing, and striping over real QUIC connections on loopback
- Network utility tests (non-destructive on non-Linux)
- PKI generation and TLS configuration tests

### Security
- Certificate-based client authentication (mTLS control plane, client certs on the QUIC data plane)
- Proper PKI hierarchy with CA management
- Secure credential storage in user config directory
