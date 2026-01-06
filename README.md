```

██╗ ██╗  ███████╗██╗     ██╗   ██╗██╗  ██╗██╗███████╗██╗   ██╗██╗  
╚██╗╚██╗ ██╔════╝██║     ██║   ██║╚██╗██╔╝██║██╔════╝╚██╗ ██╔╝╚██╗ 
 ╚██╗╚██╗█████╗  ██║     ██║   ██║ ╚███╔╝ ██║█████╗   ╚████╔╝  ╚██╗
 ██╔╝██╔╝██╔══╝  ██║     ██║   ██║ ██╔██╗ ██║██╔══╝    ╚██╔╝   ██╔╝
██╔╝██╔╝ ██║     ███████╗╚██████╔╝██╔╝ ██╗██║██║        ██║   ██╔╝ 
╚═╝ ╚═╝  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  

```

Fluxify is a multipath VPN that bonds or load-balances multiple WAN interfaces. It uses a **QUIC (mp-quic-go) data plane** with QUIC datagrams, an mTLS control plane for session negotiation + IP assignment, optional gzip compression, and TUN interfaces on client and server to carry full IP traffic (IPv4 and IPv6) in bonding mode. In load-balance mode the client installs a multipath default route directly over selected gateways (no client TUN).

## Architecture

```text
          [User Application]
                   │
                   ▼ (Standard IP Traffic)
           [OS TCP/IP Stack]
                   │
                   ▼
       [TUN Interface: tun0]
        IP: 10.8.0.2 (IPv4)
        IP: fd00:8:0::2 (IPv6)
                   │
                   ▼
           [Fluxify Client]
      (Go, QUIC TLS 1.3, Gzip)
                   │
                   ▼ (QUIC Multipath Datagrams)
      ┌────────────┼────────────┐
   [WiFi]       [4G/5G]     [Ethernet]
      │            │            │
      └────────────┼────────────┘
                   │
                   ▼ (Public Internet)
           [Fluxify Server]
      (Go, QUIC TLS 1.3, Gzip)
                   │
                   ▼
       [TUN Interface: tun0]
        IP: 10.8.0.1 (IPv4)
        IP: fd00:8:0::1 (IPv6)
                   │
                   ▼ (NAT + Forwarding)
              [Internet]
```

- **Control plane (TLS/mTLS):** Client connects to the server control port, authenticates with a client certificate, and receives a per-session `SessionID`, data port, and assigned TUN IPs (10.8.0.x for IPv4, fd00:8:0::x for IPv6). Certificates are issued by the server’s CA.
- **Data plane (QUIC):** Encrypted QUIC datagrams carry the IP packets. QUIC provides TLS 1.3 encryption / integrity and (with mp-quic-go) multipath congestion control and scheduling. Fluxify adds only a minimal `DataPlaneHeader` for session demux (`SessionID`), debugging (`SeqNum`) and gzip flag.
- **TUN interfaces:** In bonding mode client and server create TUN devices; IP traffic is injected/extracted at the IP layer. Server performs NAT (MASQUERADE) for 10.8.0.0/24 (IPv4) and fd00:8:0::/64 (IPv6) toward the Internet. Load-balance mode does not use a client TUN.
- **Multipath architecture (bonding):**
  - **Single-conn multipath:** Uses MP-QUIC (`github.com/AeonDave/mp-quic-go`) with **one QUIC connection** per client session.
  - **MultiSocketManager:** Manages UDP sockets bound to each selected interface/IP (Linux `SO_BINDTODEVICE`).
  - **LowLatencyScheduler:** MP-QUIC's internal scheduler selects the best path per datagram based on RTT, congestion window, and loss.
  - **OLIA congestion control:** Coupled congestion control enables true single-flow aggregation on links with similar RTT.
  - **Reorder buffer:** Client and server maintain per-session reorder buffers to handle out-of-order datagrams from multiple paths.
- **Interface binding:** Each UDP socket created by MultiSocketManager is bound to a specific interface/IP (Linux `SO_BINDTODEVICE`).
- **Routing flip on start (bonding):** Installs a host route to the server via the existing default and replaces the default route to point to the TUN. On stop, restores the previous default route and removes the host route.
- **Routing (load-balance):** Installs per-uplink MASQUERADE rules and a multipath default route over discovered gateways; no TUN is created. Supports both IPv4 and IPv6 gateways.
- **Compression:** Best-effort gzip on payloads when it reduces size, signaled in the header.
- **Persistence:** Client settings are stored as JSON under `~/.fluxify`. PKI defaults to the same flat directory: place `ca.pem` and either a bundle `<name>.bundle`/`<name>.pem` or `<name>.pem` + `<name>-key.pem` directly in `~/.fluxify`.

## Building

Requires Go 1.24+ and root/admin privileges for TUN and iptables on Linux.

```bash
go build -o server ./server
go build -o client ./client
```

## Server

### Flags

- `-port` (int, default 8000): QUIC data port.
- `-ctrl` (int, default 8443): TLS control port (mTLS).
- `-iface` (string): Optional TUN interface name.
- `-pki` (string, default `./pki`): PKI directory (contains `ca.pem`, `server.pem`, `server-key.pem`, and `clients/`).
- `-regen` (bool): Regenerate CA and server certificates at start.
- `-hosts` (string): Comma-separated SANs for the server certificate. **Auto-detects public IP (via ipify.org) + local IPs if empty** (recommended for production).
- `-tui` (bool): Launch certificate-management TUI instead of starting the data/control plane.
- `-reorder-buffer-size` (int, default 128): Max packets in reorder buffer (inbound).
- `-reorder-flush-timeout` (duration, default 50ms): Flush timeout for reorder buffer.
- `-mss-clamp` (string, default `off`): TCP MSS clamp for traffic traversing TUN. Values: `off` | `pmtu` | `fixed:N`.
- `-metrics-every` (duration, default `0`): Periodically log per-session metrics (reorder + per-connection RTT/bytes). `0` disables.

### Behavior

- On first start, ensures CA/server certs exist (or regenerates with `-regen`).
- Assigns client IPs starting from 10.8.0.2/24 (IPv4) and fd00:8:0::2/64 (IPv6).
- Listens on QUIC `-port` for data-plane datagrams; listens on TCP `-ctrl` for mTLS control.
- Installs NAT MASQUERADE for 10.8.0.0/24 (IPv4) and fd00:8:0::/64 (IPv6) if missing (Linux).
- Data-plane packets are QUIC datagrams; MP-QUIC’s internal scheduler selects the path per datagram based on RTT, congestion window and loss.
- Client and server reorder inbound datagrams by `SeqNum` (QUIC datagrams are unordered by design).
- Gzip is applied when beneficial.

### Server TUI (`-tui`)

- Mouse-enabled certificate manager only (no data/control plane).
- Actions bar: regenerate CA/server (destructive, deletes client certs), create new client cert with timestamped filename (also maintains canonical `<name>.pem`), refresh list, quit.
- Lists existing client certificates and shows PKI paths.

## Client

### Modes

- **Bonding (server-backed):** MP-QUIC single-conn multipath for bandwidth aggregation. Requires server control connection and a client bundle (.pem with cert+key). One QUIC connection with multiple paths (via MultiSocketManager) is opened. Start requires at least two selected interfaces and a non-empty server; uses a TUN at 10.8.0.x/24 and fd00:8:0::x/64.
- **Load-balance (local/serverless):** No server or TUN. Discovers gateways per selected interface via `ip route get`, installs per-uplink MASQUERADE and a multipath default route; requires at least two interfaces with gateways. The TUI disables the server field and marks interfaces without gateways in red/unselectable. Supports IPv4 and IPv6 gateways.

### Flags (CLI)

- `-server` (string): Server host:port for control; if port omitted, `-ctrl` is used.
- `-ifaces` (string): Comma-separated interface names to bind QUIC sockets (UDP underlay, Linux `SO_BINDTODEVICE`).
- `-ips` (string): Comma-separated source IPs matching interfaces (optional).
- `-pki` (string, default `~/.fluxify`): PKI directory containing CA and client cert/key in flat files.
- `-cert` (string): Path to client bundle (.pem/.bundle with cert+key); if omitted, auto-detects a single bundle in `-pki`.
- `-ctrl` (int, default 8443): Control-plane TLS port if not specified in `-server`.
- `-mtu` (int, default 0): TUN MTU override (0=auto/default 1400). Use e.g. 1280, 1350 if you experience throughput issues.
- `-probe-pmtud` (bool): Probe path MTU at startup and warn if the default MTU may cause blackhole. Auto-reduces MTU if probe fails.
- `-v` (bool): Enable verbose logs (interface scan, gateways, routes) and write `client_debug.log`.
- `-telemetry` (string): Write MP-QUIC path telemetry to file (timestamped JSON snapshots every 5s, e.g. `telemetry.log`). Useful for debugging and performance analysis.
- `-b` (bool): Force bonding mode (headless/scripted).
- `-l` (bool): Force load-balance mode (headless/scripted).

### Configuration Persistence & CLI Override

The client saves configuration (server, interfaces, mode, PKI, ctrl port) to `~/.config/fluxify/config.json` when started from the TUI or when running headless with `-b`/`-l`.

**Behavior**:
- **No flags**: Launches TUI with stored config as defaults (if available).
- **With `-b` or `-l`**: Runs in headless mode using stored config + CLI flag overrides.
  - CLI flags **always override** stored values.
  - Unspecified flags use values from stored config.
  
**Examples**:
```bash
# First run via TUI: configure and save server=myserver.com, ifaces=eth0,wlan0
sudo ./client

# Headless bonding with saved config
sudo ./client -b  # uses saved server and interfaces

# Override server, keep saved interfaces
sudo ./client -b -server otherserver.com

# Override interfaces, keep saved server
sudo ./client -b -ifaces eth1,wlan1

# Full override
sudo ./client -b -server new.com -ifaces eth0,eth1 -ctrl 9000
```

### Client TUI

- Mouse-enabled UI with mode switch (bonding/load-balance), server input (disabled in load-balance), and filtered interface list (hides loopback/virtual; interfaces without a gateway are shown in red and cannot be selected).
- Start enabled only when: at least two interfaces are selected, and for bonding the server is set and a client cert/key exists in the PKI dir.
- Bonding start: saves config, negotiates session via mTLS control, configures TUN with assigned IPs (IPv4+IPv6), adds host route to server via original default, flips default route to TUN, dials multipath QUIC, and begins encrypted data forwarding.
- Load-balance start: discovers gateways (IPv4/IPv6), installs per-uplink MASQUERADE and a multipath default route (no TUN); a health monitor pings per uplink to drop/add nexthops dynamically.
- On Stop: tears down QUIC/TUN, removes MASQUERADE rules, replaces the previous default route, and (for bonding) removes the host route.
- Config is saved in the user config dir as JSON and reused on next launch.
- Usage panel shows per-interface share, rates, loss, jitter, and a stability score; summary lines include aggregate rates and gain.
- Status warns when multiple selected interfaces report the same external IP (same upstream network, limited benefit).

### Certificates

- Obtain client cert/key from the server (generated via TUI or headless) and place them directly under the client PKI dir (flat layout): either a bundle `<name>.bundle`/`<name>.pem` containing cert+key or `<name>.pem` + `<name>-key.pem`, plus `ca.pem`.
- Ensure the server certificate SANs include the hostname/IP used by the client; otherwise, TLS validation will fail.
- CLI can point to a bundle explicitly via `-cert`; if omitted, the client auto-detects a single bundle in `-pki`.

Notes on PKI layout and server vs client:

- The server maintains a PKI tree (default `./pki`) and can store multiple client certs; the server TUI and tooling manage multiple client entries.
- The client expects a simple, flat PKI directory (`~/.fluxify`) with ca+cert+key bundle.
- If you pass `-pki` on the client CLI, that explicit value takes precedence over stored config.

## Operational Notes

- Client and server must be started with elevated privileges; no automatic relaunch/elevation is performed.
  - Linux: run with `sudo` (e.g., `sudo ./client`, `sudo ./server`).
  - Windows: run as Administrator (UAC prompt at launch).
- The data plane uses QUIC datagrams; TLS 1.3 provides encryption and integrity.
- Bonding mode uses MP-QUIC single-conn multipath architecture with LowLatencyScheduler and OLIA congestion control.
- Heartbeats run every 2s to update RTT for scheduling.
- Compression is opportunistic; large incompressible payloads are sent uncompressed.

## Troubleshooting

### Throughput is very low (MTU/PMTUD)

If you see unexpectedly low throughput (e.g. a few Mbps) especially over mixed paths (Wi‑Fi + 5G), it can be caused by **PMTUD blackholes** or fragmentation issues.

Recommended mitigation on the server (Linux):

```bash
sudo ./server ... -mss-clamp=pmtu
```

Or a fixed conservative MSS:

```bash
sudo ./server ... -mss-clamp=fixed:1360
```

### Bonding feels unstable / TCP is slow

Use the client TUI "Bonding Metrics" panel or enable telemetry logging (`-telemetry=telemetry.log`) to analyze:
- MP-QUIC Path Stats: per-path RTT, congestion window, bytes/packets sent/lost.
- Aggregate statistics: total TX/RX, heartbeat loss.
- Inbound reorder (server->client): `bufferedEvents`, `reorderedEvents`, `drops`, `flushes`, `maxDepth`.

The MP-QUIC LowLatencyScheduler automatically selects the best path. If you experience issues, check the telemetry for high packet loss or RTT variance.

> Note
>
> With highly asymmetric links (e.g. ETH 20–40ms vs 5G hotspot 150–300ms), MP-QUIC's LowLatencyScheduler will favor the best path for single-flow traffic while still providing failover and multi-flow aggregation. True single-flow bandwidth aggregation across very different RTT paths requires similar link characteristics.

### Telemetry Logging

Enable detailed MP-QUIC telemetry for debugging and analysis:

```bash
./client ... -telemetry=telemetry.log
```

Writes timestamped JSON snapshots every 5 seconds with:
- **Aggregate metrics**: total TX/RX bytes, active paths, heartbeat loss, server status
- **Reorder buffer stats**: buffered/reordered/dropped packets, flush count, max depth
- **MP-QUIC per-path telemetry**: path ID, local/remote addresses, RTT, congestion window, bytes in flight, packets sent/lost, loss percentage

Example output:
```json
{"timestamp":"2024-01-15T10:30:45Z","aggregate":{"tx_bytes":12345678,"rx_bytes":23456789,"active_paths":2,"hb_sent":150,"hb_recv":148,"hb_loss_pct":1.33,"server_alive":true},"reorder":{"buffered":0,"reordered":12,"dropped":0,"flushes":5,"max_depth":3},"mp_paths":[{"path_id":0,"local":"192.168.1.100:54321","remote":"203.0.113.1:8444","rtt_ms":25,"cwnd":131072,"in_flight":8192,"bytes_sent":6172839,"packets_sent":4567,"packets_lost":12,"loss_pct":0.26},{"path_id":1,"local":"10.0.0.50:54322","remote":"203.0.113.1:8444","rtt_ms":45,"cwnd":98304,"in_flight":4096,"bytes_sent":6172839,"packets_sent":4012,"packets_lost":8,"loss_pct":0.20}]}
```


## Usage Workflows

### Interactive Mode (TUI)

Best for first-time setup and configuration:

```bash
# Launch TUI with no config
sudo ./client

# TUI remembers previous settings
sudo ./client  # loads saved config as defaults
```

In the TUI:
1. Select mode (bonding/load-balance)
2. Enter server address (bonding only)
3. Select 2+ interfaces
4. Press Start

Config is automatically saved to `~/.config/fluxify/config.json`.

### Headless Mode (CLI)

For scripting, automation, or systemd services:

```bash
# First time: specify all options
sudo ./client -b -server myserver.com:8443 -ifaces eth0,wlan0 -cert ~/.fluxify/client.pem

# Subsequent runs: reuse saved config
sudo ./client -b  # uses saved server, interfaces, etc.

# Override specific values
sudo ./client -b -server backup.com  # new server, saved interfaces
sudo ./client -b -ifaces eth1,wlan1  # new interfaces, saved server

# Load balancing (no server needed)
sudo ./client -l -ifaces eth0,wlan0,5g0
```

**Priority**: CLI flags > saved config > defaults

### Debugging with Telemetry

```bash
# Verbose logs + telemetry
sudo ./client -b -v -telemetry=debug.log

# Analyze telemetry
cat debug.log | jq '.mp_paths[] | {path: .path_id, rtt: .rtt_ms, loss: .loss_pct}'
```

## Quickstart (single client)

1. **Server PKI and run:**

   ```bash
   # Auto-detect local IPs (recommended)
   sudo ./server -port 8000 -ctrl 8443 -pki /path/to/pki
   
   # Or specify explicit IPs/hostnames
   sudo ./server -port 8000 -ctrl 8443 -hosts "192.168.1.100,vpn.example.com" -pki /path/to/pki
   ```

   Generate a client cert (TUI `-tui` or headless helper) for CN `alice`.
2. **Client PKI (flat layout):** Copy `ca.pem`, `alice.pem`, and `alice-key.pem` (or a single bundle `alice.pem` with cert+key) into `~/.fluxify/`.
3. **Client run (TUI recommended):**

   ```bash
   sudo ./client -server SERVER_IP:8443 -cert ~/.fluxify/alice.pem -pki ~/.fluxify
   ```

   In the TUI, select mode (bonding/load-balance), pick at least two interfaces, ensure server is set for bonding, then Start.

   For debugging with telemetry logging:
   
   ```bash
   sudo ./client -server SERVER_IP:8443 -cert ~/.fluxify/alice.pem -pki ~/.fluxify -v -telemetry=telemetry.log
   ```

4. **Routing:**

   - Bonding: default route is flipped to the TUN while running and restored on stop; the host route to the server is added automatically.
   - Load-balance: multipath default route + MASQUERADE per uplink; no TUN.

## Testing

- Unit tests cover dataplane framing, compression, control-plane marshalling, PKI generation/TLS config, netutils helpers (non-destructive on non-Linux), client/server schedulers, heartbeat handling, control-plane integrations, and load-balancer routing helpers (gateway parsing, multipath arg build, health-monitor route refresh via fake runner).
- Run all tests:

```bash
go test ./...
```

Note: server code is **Linux build-tagged**; `go test ./server/...` may match no packages. Prefer:

```bash
go test ./...
```

### E2E Testing & Diagnostics

**End-to-End Bonding Test** (`scripts/test_bonding_e2e.sh`):
- Simulates multiple WAN links with different characteristics using `tc/netem` (delay, jitter, loss, bandwidth)
- Runs baseline throughput tests per interface and bonded tests with `iperf3`
- Generates comparison reports to verify bandwidth aggregation
- Requires: Linux server with root, `tc`, `iperf3`

```bash
# Server side
sudo ./scripts/test_bonding_e2e.sh --server --netem

# Client side
sudo ./scripts/test_bonding_e2e.sh --client SERVER_IP --ifaces eth0,wlan0 --duration 30
```

**Diagnostic Collection** (`scripts/diagnose.sh`):
- Collects comprehensive system info (OS, CPU, memory, network buffers)
- Reports interface details (state, IP, MTU, gateway, driver, speed)
- Tests connectivity (DNS, TCP, ICMP, PMTUD)
- Dumps routing tables and firewall rules
- Provides performance recommendations

```bash
sudo ./scripts/diagnose.sh --server SERVER_IP --full --output /tmp/report.txt
```

**Client TUI Diagnostics**:
- Use the "DIAG" button in the client TUI for interactive diagnostics
- Reports: system info, interface status, server connectivity, certificate verification, TLS handshake, PMTUD probe, routing dump, performance recommendations

