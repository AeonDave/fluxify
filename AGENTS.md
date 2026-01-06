# AGENTS.md

## Setup commands
- Install dependencies: `go mod tidy`
- Build server: `go build -o server ./server` (Linux only build-tag)
- Build client: `go build -o client ./client`
- Run server tests: `go test ./...` (server is in root package with linux build tags; `./server/...` may match no packages)
- Run client tests: `go test ./client/...`
- Run all tests: `go test ./...`
- Run common tests: `go test ./common/...`

## Operational notes
- Client and server must be started with admin/sudo privileges; do not add runtime elevation prompts.
- Client debug log (`client_debug.log`) is written only when `-v` is enabled.
- Client telemetry log: use `-telemetry=<file>` to write MP-QUIC path stats every 5s (timestamped JSON snapshots with aggregate metrics, reorder buffer stats, and per-path telemetry).

## Bonding (important)
- Architecture: **MP-QUIC single-conn multipath** (one QUIC connection with multiple paths).
- Uses `github.com/AeonDave/mp-quic-go` with LowLatencyScheduler and OLIA congestion control.
- MultiSocketManager creates UDP sockets bound to each selected interface (Linux `SO_BINDTODEVICE`).
- MP-QUIC handles path selection internally based on RTT, congestion window, and packet loss.
- Reorder buffers (128 packets, 50ms flush timeout) are hardcoded and optimal for MP-QUIC.
- No tuning flags: compression sample size, reorder buffer settings are optimized internally.

## Code style
- Go 1.24+ required
- Standard Go formatting with `go fmt`
- Error handling with explicit error returns
- Context usage for cancellation and timeouts
- Atomic operations for concurrent counters
- Functional patterns with interfaces where appropriate
- Single-letter variables for loops and short-lived variables
- Proper logging with log package

## Project Architecture

### Core Components
- **Server**: MP-QUIC multipath VPN server with mTLS control plane and QUIC data plane
- **Client**: MP-QUIC multipath VPN client supporting bonding and load-balance modes
- **Common**: Shared utilities for crypto, protocol, networking, and PKI

### Key Features
- MP-QUIC single-conn multipath architecture with LowLatencyScheduler and OLIA
- QUIC datagrams (RFC 9221) with TLS 1.3 encryption/integrity for data plane
- mTLS control plane for authentication
- Optional gzip compression
- TUN interfaces for IP traffic (bonding mode)
- MultiSocketManager for per-interface UDP socket binding
- Reorder buffers for handling out-of-order datagrams
- Heartbeat-based path monitoring
- Text User Interface (TUI) for certificate management and telemetry display

### Testing
- Unit tests cover protocol serialization, crypto, compression
- Integration tests for control plane and load balancing
- Network utility tests (non-destructive on non-Linux)
- PKI generation and TLS configuration tests

### Security
- Certificate-based client authentication
- Session-based encryption keys
- Proper PKI hierarchy with CA management
- Secure credential storage in user config directory
