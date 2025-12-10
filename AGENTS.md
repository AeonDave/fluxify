# AGENTS.md

## Setup commands
- Install dependencies: `go mod tidy`
- Build server: `go build -o server ./server`
- Build client: `go build -o client ./client`
- Run server tests: `go test ./server/...`
- Run client tests: `go test ./client/...`
- Run all tests: `go test ./...`
- Run common tests: `go test ./common/...`

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
- **Server**: Multipath VPN server with mTLS control plane and UDP data plane
- **Client**: Multipath VPN client supporting bonding and load-balance modes
- **Common**: Shared utilities for crypto, protocol, networking, and PKI

### Key Features
- AES-256-GCM encryption for data plane
- mTLS control plane for authentication
- Optional gzip compression
- TUN interfaces for IP traffic (bonding mode)
- Multipath routing with RTT-based scheduling
- Heartbeat-based connection monitoring
- Text User Interface (TUI) for certificate management

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