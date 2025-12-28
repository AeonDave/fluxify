#!/bin/bash
# Fluxify Diagnostic Script
# Collects system information, network state, and bonding metrics
# for troubleshooting performance issues.
#
# Usage: sudo ./diagnose.sh [options]
#   -o, --output FILE  Output file (default: stdout + /tmp/fluxify_diag_TIMESTAMP.txt)
#   -s, --server HOST  Server to test connectivity (optional)
#   -f, --full         Full diagnostics (slower, includes external IP checks)
#   -v, --verbose      Verbose output
#   -h, --help         Show this help

set -e

# Configuration
OUTPUT_FILE=""
SERVER_HOST=""
FULL_DIAG=false
VERBOSE=false
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEFAULT_OUTPUT="/tmp/fluxify_diag_${TIMESTAMP}.txt"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

header() {
    echo ""
    echo -e "${CYAN}=== $1 ===${NC}"
    echo ""
}

subheader() {
    echo -e "${BLUE}--- $1 ---${NC}"
}

ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

info() {
    echo -e "[INFO] $1"
}

show_help() {
    head -15 "$0" | tail -9
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -s|--server)
            SERVER_HOST="$2"
            shift 2
            ;;
        -f|--full)
            FULL_DIAG=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Output handling
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="$DEFAULT_OUTPUT"
fi

# Tee output to both stdout and file
exec > >(tee -a "$OUTPUT_FILE") 2>&1

echo "Fluxify Diagnostic Report"
echo "Generated: $(date)"
echo "Output: $OUTPUT_FILE"
echo "========================================"

# System Information
header "System Information"

subheader "OS"
if [ -f /etc/os-release ]; then
    cat /etc/os-release | grep -E "^(NAME|VERSION|ID)="
elif [ -f /etc/lsb-release ]; then
    cat /etc/lsb-release
else
    uname -a
fi

subheader "Kernel"
uname -r
sysctl -n net.core.rmem_max net.core.wmem_max 2>/dev/null || true

subheader "CPU"
grep -c processor /proc/cpuinfo 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "Unknown"
grep "model name" /proc/cpuinfo 2>/dev/null | head -1 || true

subheader "Memory"
free -h 2>/dev/null || vm_stat 2>/dev/null || true

# Network Interfaces
header "Network Interfaces"

subheader "Interface List"
ip -br link show 2>/dev/null || ifconfig -a 2>/dev/null

subheader "Interface Details"
for iface in $(ip -br link show 2>/dev/null | awk '{print $1}' | tr -d ':'); do
    echo ""
    echo "Interface: $iface"
    
    # State
    STATE=$(ip link show "$iface" 2>/dev/null | grep -oP '(?<=state )\w+' || echo "unknown")
    if [ "$STATE" = "UP" ]; then
        ok "State: $STATE"
    else
        warn "State: $STATE"
    fi
    
    # IPv4
    IPV4=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+/\d+' | head -1)
    if [ -n "$IPV4" ]; then
        info "IPv4: $IPV4"
    else
        info "IPv4: none"
    fi
    
    # IPv6
    IPV6=$(ip -6 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet6\s)[^/]+' | grep -v "^fe80" | head -1)
    if [ -n "$IPV6" ]; then
        info "IPv6: $IPV6"
    else
        info "IPv6: none (link-local only)"
    fi
    
    # MTU
    MTU=$(ip link show "$iface" 2>/dev/null | grep -oP '(?<=mtu )\d+' || echo "unknown")
    info "MTU: $MTU"
    
    # Gateway (for non-loopback)
    if [[ "$iface" != "lo" ]]; then
        GW=$(ip route show dev "$iface" 2>/dev/null | grep default | awk '{print $3}' | head -1)
        if [ -n "$GW" ]; then
            ok "Gateway: $GW"
        else
            warn "Gateway: none"
        fi
    fi
    
    # Driver
    DRIVER=$(ethtool -i "$iface" 2>/dev/null | grep driver | awk '{print $2}' || echo "unknown")
    info "Driver: $DRIVER"
    
    # Speed (for ethernet)
    SPEED=$(ethtool "$iface" 2>/dev/null | grep "Speed:" | awk '{print $2}' || echo "unknown")
    if [ "$SPEED" != "unknown" ] && [ "$SPEED" != "" ]; then
        info "Speed: $SPEED"
    fi
done

# Routing
header "Routing"

subheader "IPv4 Default Route"
ip -4 route show default 2>/dev/null || route -n 2>/dev/null | grep "^0.0.0.0"

subheader "IPv4 Route Table"
ip -4 route show 2>/dev/null | head -20

subheader "IPv6 Default Route"
ip -6 route show default 2>/dev/null || true

subheader "Routing Rules"
ip rule show 2>/dev/null || true

# DNS
header "DNS Configuration"

subheader "resolv.conf"
cat /etc/resolv.conf 2>/dev/null || true

subheader "systemd-resolved (if active)"
resolvectl status 2>/dev/null | head -20 || true

# Firewall/NAT
header "Firewall & NAT"

subheader "iptables NAT"
iptables -t nat -L -n -v 2>/dev/null | head -30 || warn "Cannot read iptables (not root?)"

subheader "ip6tables NAT"
ip6tables -t nat -L -n -v 2>/dev/null | head -20 || true

subheader "nftables"
nft list ruleset 2>/dev/null | head -30 || true

# TUN/TAP
header "TUN/TAP Interfaces"

subheader "TUN devices"
ls -la /dev/net/tun 2>/dev/null || warn "/dev/net/tun not found"
ip link show type tun 2>/dev/null || true

subheader "Fluxify TUN (tun0)"
if ip link show tun0 &>/dev/null; then
    ok "tun0 exists"
    ip addr show tun0
else
    info "tun0 not present (fluxify not running?)"
fi

# Connectivity Tests
header "Connectivity Tests"

if [ -n "$SERVER_HOST" ]; then
    subheader "Server Connectivity: $SERVER_HOST"
    
    # Parse host:port
    HOST=$(echo "$SERVER_HOST" | cut -d: -f1)
    PORT=$(echo "$SERVER_HOST" | cut -d: -f2 -s)
    [ -z "$PORT" ] && PORT=8443
    
    # DNS resolution
    echo "DNS Resolution:"
    if host "$HOST" &>/dev/null; then
        host "$HOST" | head -3
        ok "DNS resolution successful"
    elif dig +short "$HOST" &>/dev/null; then
        dig +short "$HOST"
        ok "DNS resolution successful"
    else
        warn "DNS resolution failed"
    fi
    
    # TCP connectivity
    echo ""
    echo "TCP Connectivity to $HOST:$PORT:"
    if nc -z -w 5 "$HOST" "$PORT" 2>/dev/null; then
        ok "TCP port $PORT reachable"
    elif timeout 5 bash -c "echo >/dev/tcp/$HOST/$PORT" 2>/dev/null; then
        ok "TCP port $PORT reachable"
    else
        fail "TCP port $PORT unreachable"
    fi
    
    # Ping
    echo ""
    echo "ICMP Ping:"
    if ping -c 3 -W 2 "$HOST" &>/dev/null; then
        ping -c 3 -W 2 "$HOST" 2>&1 | tail -3
        ok "ICMP reachable"
    else
        warn "ICMP unreachable (may be blocked)"
    fi
    
    # MTU probe
    echo ""
    echo "Path MTU Probe:"
    for mtu in 1500 1400 1350 1300 1280 1200; do
        if ping -c 1 -W 2 -M do -s $((mtu - 28)) "$HOST" &>/dev/null; then
            ok "MTU $mtu: OK"
            break
        else
            warn "MTU $mtu: blocked/fragmented"
        fi
    done
fi

# External IP (full diagnostics only)
if [ "$FULL_DIAG" = true ]; then
    subheader "External IP Detection"
    
    for iface in $(ip -br link show 2>/dev/null | awk '$2=="UP" {print $1}' | tr -d ':'); do
        IP=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
        if [ -z "$IP" ]; then
            continue
        fi
        
        # Skip loopback and virtual
        case "$iface" in
            lo|docker*|veth*|br-*|tun*|tap*)
                continue
                ;;
        esac
        
        echo -n "$iface ($IP): "
        EXT_IP=$(curl -s --interface "$IP" --max-time 5 https://api.ipify.org 2>/dev/null || echo "failed")
        if [ "$EXT_IP" != "failed" ] && [ -n "$EXT_IP" ]; then
            ok "External IP: $EXT_IP"
        else
            warn "Could not determine external IP"
        fi
    done
fi

# Fluxify Process Check
header "Fluxify Status"

subheader "Server Process"
if pgrep -f "fluxify.*server" > /dev/null; then
    ok "Server running"
    ps aux | grep -E "fluxify.*server" | grep -v grep
else
    info "Server not running"
fi

subheader "Client Process"
if pgrep -f "fluxify.*client" > /dev/null; then
    ok "Client running"
    ps aux | grep -E "fluxify.*client" | grep -v grep
else
    info "Client not running"
fi

# Fluxify Logs
subheader "Recent Logs"
if [ -f "./client_debug.log" ]; then
    echo "Client debug log (last 30 lines):"
    tail -30 ./client_debug.log 2>/dev/null || true
fi

if [ -f "./server_debug.log" ]; then
    echo ""
    echo "Server debug log (last 30 lines):"
    tail -30 ./server_debug.log 2>/dev/null || true
fi

# UDP Socket Stats
header "Socket Statistics"

subheader "UDP Sockets"
ss -ulnp 2>/dev/null | grep -E "fluxify|8000|8443" || info "No fluxify UDP sockets found"

subheader "TCP Sockets"
ss -tlnp 2>/dev/null | grep -E "fluxify|8443" || info "No fluxify TCP sockets found"

# Network Buffers
header "Kernel Network Settings"

subheader "Socket Buffers"
sysctl net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default 2>/dev/null || true

subheader "TCP Settings"
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_window_scaling net.ipv4.tcp_timestamps 2>/dev/null || true

subheader "IP Forwarding"
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding 2>/dev/null || true

# Performance Hints
header "Performance Recommendations"

# Check rmem_max
RMEM=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
if [ "$RMEM" -lt 26214400 ]; then
    warn "net.core.rmem_max=$RMEM is low. Recommend: sudo sysctl -w net.core.rmem_max=26214400"
else
    ok "net.core.rmem_max=$RMEM"
fi

# Check wmem_max
WMEM=$(sysctl -n net.core.wmem_max 2>/dev/null || echo "0")
if [ "$WMEM" -lt 26214400 ]; then
    warn "net.core.wmem_max=$WMEM is low. Recommend: sudo sysctl -w net.core.wmem_max=26214400"
else
    ok "net.core.wmem_max=$WMEM"
fi

# Check IP forwarding (server)
FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
if [ "$FWD" = "0" ]; then
    warn "IP forwarding disabled. Server needs: sudo sysctl -w net.ipv4.ip_forward=1"
else
    ok "IP forwarding enabled"
fi

# Check TUN device
if [ ! -c /dev/net/tun ]; then
    warn "/dev/net/tun missing. Load module: sudo modprobe tun"
else
    ok "/dev/net/tun exists"
fi

# Summary
header "Summary"

echo "Diagnostic report saved to: $OUTPUT_FILE"
echo ""
echo "To share this report, run:"
echo "  cat $OUTPUT_FILE | curl -F 'file=@-' https://0x0.st"
echo ""
echo "For real-time monitoring, use:"
echo "  watch -n1 'ss -ulnp | grep fluxify; ip route show default'"