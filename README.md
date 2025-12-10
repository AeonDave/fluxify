```

██╗ ██╗  ███████╗██╗     ██╗   ██╗██╗  ██╗██╗███████╗██╗   ██╗██╗  
╚██╗╚██╗ ██╔════╝██║     ██║   ██║╚██╗██╔╝██║██╔════╝╚██╗ ██╔╝╚██╗ 
 ╚██╗╚██╗█████╗  ██║     ██║   ██║ ╚███╔╝ ██║█████╗   ╚████╔╝  ╚██╗
 ██╔╝██╔╝██╔══╝  ██║     ██║   ██║ ██╔██╗ ██║██╔══╝    ╚██╔╝   ██╔╝
██╔╝██╔╝ ██║     ███████╗╚██████╔╝██╔╝ ██╗██║██║        ██║   ██╔╝ 
╚═╝ ╚═╝  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  

```

Fluxify is a multipath VPN that bonds or load-balances multiple WAN interfaces. It uses a UDP data plane with per-session AES-256-GCM encryption, an mTLS control plane for session/key negotiation, optional gzip compression, and TUN interfaces on client and server to carry full IP traffic (IPv4 and IPv6) in bonding mode. In load-balance mode the client installs a multipath default route directly over selected gateways (no client TUN).

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
      (Go, AES-256-GCM, Gzip)
                   │
                   ▼ (Encrypted UDP Multiplexing)
      ┌────────────┼────────────┐
   [WiFi]       [4G/5G]     [Ethernet]
      │            │            │
      └────────────┼────────────┘
                   │
                   ▼ (Public Internet)
           [Fluxify Server]
      (Go, AES-256-GCM, Gzip)
                   │
                   ▼
       [TUN Interface: tun0]
        IP: 10.8.0.1 (IPv4)
        IP: fd00:8:0::1 (IPv6)
                   │
                   ▼ (NAT + Forwarding)
              [Internet]
```

- **Control plane (TLS/mTLS):** Client connects to the server control port, authenticates with a client certificate, and receives a per-session `SessionID`, `SessionKey` (AES-256), UDP port, and assigned TUN IPs (10.8.0.x for IPv4, fd00:8:0::x for IPv6). Certificates are issued by the server’s CA.
- **Data plane (UDP):** Encrypted packets carry a compact 22-byte header (version, type, session ID, seq, length, reserved). Payloads are AES-GCM encrypted with the header as AAD. Optional gzip compression is flagged in `Reserved[0]`.
- **TUN interfaces:** In bonding mode client and server create TUN devices; IP traffic is injected/extracted at the IP layer. Server performs NAT (MASQUERADE) for 10.8.0.0/24 (IPv4) and fd00:8:0::/64 (IPv6) toward the Internet. Load-balance mode does not use a client TUN.
- **Multipath scheduling:** Client uplink supports two modes: bonding (round-robin over alive links) and load-balance (lowest RTT). Server downlink picks the lowest-RTT alive path per session. Heartbeats measure RTT.
- **Interface binding:** Each UDP connection can bind to a specific interface/IP (Linux `SO_BINDTODEVICE`). Policy-routing helper exists but is not auto-applied; manual multi-WAN routing may be required.
- **Routing flip on start (bonding):** Installs a host route to the server via the existing default and replaces the default route to point to the TUN. On stop, restores the previous default route and removes the host route.
- **Routing (load-balance):** Installs per-uplink MASQUERADE rules and a multipath default route over discovered gateways; no TUN is created. Supports both IPv4 and IPv6 gateways.
- **Compression:** Best-effort gzip on payloads when it reduces size, signaled in the header.
- **Persistence:** Client settings are stored as JSON under `~/.fluxify`. PKI defaults to the same flat directory: place `ca.pem` and either a bundle `<name>.pem` or `<name>.pem` + `<name>-key.pem` directly in `~/.fluxify`.

## Building

Requires Go 1.24+ and root/admin privileges for TUN and iptables on Linux.

```bash
go build -o server ./server
go build -o client ./client
```

## Server

### Flags

- `-port` (int, default 8000): UDP data port.
- `-ctrl` (int, default 8443): TLS control port (mTLS).
- `-iface` (string): Optional TUN interface name.
- `-pki` (string, default `./pki`): PKI directory (contains `ca.pem`, `server.pem`, `server-key.pem`, and `clients/`).
- `-regen` (bool): Regenerate CA and server certificates at start.
- `-hosts` (string, default `127.0.0.1,localhost`): Comma-separated SANs for the server certificate.
- `-tui` (bool): Launch certificate-management TUI instead of starting the data/control plane.

### Behavior

- On first start, ensures CA/server certs exist (or regenerates with `-regen`).
- Assigns client IPs starting from 10.8.0.2/24 (IPv4) and fd00:8:0::2/64 (IPv6).
- Listens on UDP `-port` for encrypted data-plane traffic; listens on TCP `-ctrl` for mTLS control.
- Installs NAT MASQUERADE for 10.8.0.0/24 (IPv4) and fd00:8:0::/64 (IPv6) if missing (Linux).
- Downlink scheduling picks the lowest-RTT alive connection per session; gzip is applied when beneficial.

### Server TUI (`-tui`)

- Mouse-enabled certificate manager only (no data/control plane).
- Actions bar: regenerate CA/server (destructive, deletes client certs), create new client cert with timestamped filename (also maintains canonical `<name>.pem`), refresh list, quit.
- Lists existing client certificates and shows PKI paths.

## Client

### Modes

- **Bonding (server-backed):** Round-robin over alive links; requires server control connection and client certificate (CN set via `-client` or TUI). Start requires at least two selected interfaces and a non-empty server; uses a TUN at 10.8.0.x/24 and fd00:8:0::x/64.
- **Load-balance (local/serverless):** No server or TUN. Discovers gateways per selected interface via `ip route get`, installs per-uplink MASQUERADE and a multipath default route; requires at least two interfaces with gateways. The TUI disables the server field and marks interfaces without gateways in red/unselectable. Supports IPv4 and IPv6 gateways.

### Flags (CLI)

- `-server` (string): Server host:port for control; if port omitted, `-ctrl` is used.
- `-ifaces` (string): Comma-separated interface names to bind UDP sockets (Linux `SO_BINDTODEVICE`).
- `-ips` (string): Comma-separated source IPs matching interfaces (optional).
- `-conns` (int, default 2): Number of parallel UDP connections.
- `-pki` (string, default `~/.fluxify`): PKI directory containing CA and client cert/key in flat files.
- `-client` (string): Client certificate name (CN); required for bonding.
- `-ctrl` (int, default 8443): Control-plane TLS port if not specified in `-server`.
- `-b` (bool): Force bonding mode (headless/scripted).
- `-l` (bool): Force load-balance mode (headless/scripted).
- `-policy-routing` (bool): Placeholder flag; policy routing helper exists but is not auto-applied.
- `-gws` (string): Comma-separated gateways matching ifaces/IPs (for future policy routing).

### Client TUI

- Mouse-enabled UI with mode switch (bonding/load-balance), server input (disabled in load-balance), and filtered interface list (hides loopback/virtual; interfaces without a gateway are shown in red and cannot be selected).
- Start enabled only when: at least two interfaces are selected, and for bonding the server is set and a client cert/key exists in the PKI dir.
- Bonding start: saves config, negotiates session via mTLS control, configures TUN with assigned IPs (IPv4+IPv6), adds host route to server via original default, flips default route to TUN, dials multipath UDP, and begins encrypted data forwarding.
- Load-balance start: discovers gateways (IPv4/IPv6), installs per-uplink MASQUERADE and a multipath default route (no TUN); a health monitor pings per uplink to drop/add nexthops dynamically.
- On Stop: tears down UDP/TUN, removes MASQUERADE rules, replaces the previous default route, and (for bonding) removes the host route.
- Config is saved in the user config dir as JSON and reused on next launch.

### Certificates

- Obtain client cert/key from the server (generated via TUI or headless) and place them directly under the client PKI dir (flat layout): either a bundle `<name>.pem` containing cert+key or `<name>.pem` + `<name>-key.pem`, plus `ca.pem`.
- Ensure the server certificate SANs include the hostname/IP used by the client; otherwise, TLS validation will fail.

Notes on PKI layout and server vs client:

- The server maintains a PKI tree (default `./pki`) and can store multiple client certs; the server TUI and tooling manage multiple client entries.
- The client expects a simple, flat PKI directory (`~/.fluxify`) with ca+cert+key bundle.
- If you pass `-pki` on the client CLI, that explicit value takes precedence and will not be overwritten by any stored config when the client is relaunched under elevation.

## Operational Notes

- Linux will prompt for elevation (sudo) when configuring routes/TUN/iptables if not already root.
  - Elevation flow: when you start the client without flags the TUI runs unprivileged. If you click Start for bonding and root privileges are required, the TUI will suspend and the client will relaunch via `pkexec`/`sudo` to perform privileged actions. The elevated process will return to the TUI (auto-start mode) so you continue to see stats in the UI — the client no longer forces a terminal-only CLI mode after elevation.
- The data plane is UDP; TCP-over-UDP avoids TCP-over-TCP head-of-line issues. AES-GCM protects both header integrity (as AAD) and payload confidentiality.
- No reorder buffer is implemented; higher-layer TCP handles reordering. Heartbeats run every 2s to update RTT for scheduling.
- Compression is opportunistic; large incompressible payloads are sent uncompressed.
- Policy routing: helper functions exist (`EnsurePolicyRouting`) but are not invoked automatically; configure per-WAN routing manually if needed to force egress per interface.

## Quickstart (single client)

1. **Server PKI and run:**

   ```bash
   sudo ./server -port 8000 -ctrl 8443 -hosts "SERVER_IP" -pki /path/to/pki
   ```

   Generate a client cert (TUI `-tui` or headless helper) for CN `alice`.
2. **Client PKI (flat layout):** Copy `ca.pem`, `alice.pem`, and `alice-key.pem` (or a single bundle `alice.pem` with cert+key) into `~/.fluxify/`.
3. **Client run (TUI recommended):**

   ```bash
   ./client -server SERVER_IP:8443 -client alice -pki ~/.fluxify -conns 2
   ```

   In the TUI, select mode (bonding/load-balance), pick at least two interfaces, ensure server is set for bonding, then Start.
4. **Routing:**

   - Bonding: default route is flipped to the TUN while running and restored on stop; the host route to the server is added automatically.
   - Load-balance: multipath default route + MASQUERADE per uplink; no TUN.

## Testing

- Unit tests cover protocol serialization, crypto, compression, control-plane marshalling, PKI generation/TLS config, netutils helpers (non-destructive on non-Linux), client/server schedulers, heartbeat handling, control-plane integrations, and load-balancer routing helpers (gateway parsing, multipath arg build, health-monitor route refresh via fake runner).
- Run all tests:

```bash
go test ./...
```

If the repository contains a `server/pki` directory created by a root-run server, the Go toolchain may hit permission errors when expanding `./...`. In that case run package-specific tests, which avoid that folder:

```bash
go test ./common ./client ./server
```
