# Fluxify - Multi-Path VPN Tunnel

Fluxify is a Go-based VPN that enables bonding/load-balancing across multiple network interfaces using UDP multipath with TLS control channel and AES-GCM encrypted data plane.

## Architecture

### Three-Component Design
- **`client/`**: Client with TUI for connecting via multiple interfaces (bonding or load-balance modes)
- **`server/`**: Server with TUI for PKI/certificate management, assigns IPs from 10.8.0.0/24
- **`common/`**: Shared protocol, crypto, PKI, TUN, and network utilities

### Data Flow
1. Client establishes TLS control session → receives SessionID, SessionKey, UDP port, assigned IP
2. Client spawns N UDP connections (optionally bound to specific interfaces/IPs via `SO_BINDTODEVICE`)
3. All data-plane packets are AES-256-GCM encrypted with session key, header used as AAD
4. Server multiplexes packets across client connections, tracks per-connection RTT via heartbeats
5. TUN interfaces handle IP packet forwarding; server sets up NAT for outbound traffic

### Bonding vs Load-Balance Modes
- **Bonding**: Round-robin across all alive connections (client sends on all paths sequentially), server-backed via mTLS control and UDP data plane
- **Load-balance (local/serverless)**: Client-only mode that creates a local TUN, discovers gateways per selected interface (`ip route get`), installs per-uplink MASQUERADE + multipath default route, and health-checks with ping to drop/add nexthops dynamically. No server required; TUI disables the server field and marks interfaces without gateways as unselectable.
- Server always sends on lowest RTT connection (`sendToSession` in `server/main.go`)

## Key Protocols & Conventions

### Packet Structure (`common/protocol.go`)
- Fixed 22-byte header: `Version|Type|SessionID|SeqNum|Length|Reserved[10]`
- Types: `PacketIP` (1), `PacketHeartbeat` (2), `PacketHandshake` (3), `PacketControl` (4)
- `Reserved[0]` byte: compression flag (0=none, 1=gzip)
- Encryption: header + nonce(12) + ciphertext, with header as GCM AAD

### PKI Management (`common/pki.go`)
- CA/server/client certs stored in `./pki/` (or `~/.config/fluxify/pki/`)
- Client certs: `pki/clients/<name>.pem` and `<name>-key.pem`
- Server TUI (`-tui` flag) allows interactive client cert generation with validation
- Mutual TLS on control channel (port 8443); client CN must match `ControlRequest.ClientName`

### TUN Device Configuration (`common/tun.go`)
- Linux-only implementation via `songgao/water` library
- Server: `10.8.0.1/24`, clients assigned `10.8.0.2+`
- MTU fixed at 1400 bytes (see `common.MTU`)
- Client replaces default route to tunnel via TUN, preserves host route to server IP

### Policy Routing (`common/netutils.go`)
- Optional per-interface routing tables for true multi-path egress (Linux only)
- Client flag: `-policy-routing` with `-gws <gw1>,<gw2>` matching interface order
- Uses `ip rule from <src> table <id>` and `SO_BINDTODEVICE` socket binding

### Local Load-Balancer Routing (`client/load_balancer.go`)
- TUN at `10.9.0.1/24`, flips default route to TUN after MASQUERADE + multipath route are installed
- Gateways auto-discovered; MASQUERADE per interface; multipath updated on health changes
- Cleanup restores previous default route and removes MASQUERADE rules

## Development Workflows

### Building & Running
```bash
# Build both binaries
go build -o server/server ./server
go build -o client/client ./client

# Server with cert management TUI
sudo ./server/server -tui -pki ./pki

# Client interactive mode (requires root for TUN)
sudo ./client/client -pki ./pki -client mydevice

# Client with specific interfaces
sudo ./client/client -server myserver.com -ifaces eth0,wlan0 -client laptop
```

### Testing
- Standard Go tests: `go test ./...` (no special runners)
- Integration tests: `*_integration_test.go` files test TLS control flow end-to-end
- Key tests: crypto roundtrip (`common/crypto_test.go`), PKI generation (`common/pki_test.go`), protocol marshal/unmarshal (`common/protocol_test.go`)

### Configuration Persistence
- Client stores config in `~/.config/fluxify/config.json` (or `~/.fluxify/`)
- Fields: `server`, `mode`, `ifaces`, `client`, `pki`, `ctrl` (see `storedConfig` in `client/main.go`)
- TUI auto-saves on successful connection start

## Critical Implementation Details

### Atomic Operations for Connection State
- `clientConn` and `serverConn` use `atomic.Bool` for `alive`, `atomic.Uint64` for byte counters
- RTT stored as `atomic.Int64` (nanoseconds) to avoid locking in hot path
- Access pattern: read RTT atomically in `pickBestConn`, write in heartbeat handler

### Sequence Numbers & Reordering
- `nextSeqSend` incremented atomically per packet (`state.nextSeqSend.Add(1)`)
- No reordering implemented in current version (TODO in `server/main.go:208`)
- Heartbeat echoes original `SeqNum` for RTT calculation

### Compression (`common/compress.go`)
- Optional gzip with `BestSpeed` level, applied per-packet if beneficial
- Decompression has hard limit (`maxOut`) to prevent zip bombs
- Header `Reserved[0]` signals compression type to receiver

### TUI Framework (`rivo/tview`)
- Both client and server use `tview.Application` with mouse support
- Client: interface selection list, mode dropdown, start/stop buttons with connection stats
- Server: client cert list, regenerate CA/server, delete clients (no restart required)

## Gotchas & Known Limitations

1. **Linux-only**: TUN/policy routing/SO_BINDTODEVICE not implemented for Windows/macOS
2. **Requires root**: TUN device creation and route manipulation need CAP_NET_ADMIN
3. **No automatic reconnect**: Lost control session requires manual restart
4. **Fixed IP allocation**: Server increments from 10.8.0.2, no DHCP or persistence (resets on server restart)
5. **Certificate CN must match client flag**: Server rejects mismatched `-client` name vs cert CN

## Common Tasks

- **Add new packet type**: Update `common/protocol.go` constants, add handler in both `client/main.go:readLoop` and `server/main.go:handlePacket`
- **Change network range**: Edit `server/main.go` TUN CIDR and `assignClientIP` logic
- **Adjust MTU**: Modify `common.MTU` constant (ensure < physical interface MTU - overhead)
- **Debug connection issues**: Check `alive` flags, RTT values in TUI stats; verify `SO_BINDTODEVICE` interface names match system
