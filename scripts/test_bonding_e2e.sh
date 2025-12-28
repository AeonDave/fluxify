#!/bin/bash
# Fluxify E2E Bonding Test Script
# This script simulates multiple WAN links with different characteristics
# using tc/netem and runs throughput tests with iperf3.
#
# Requirements:
# - Linux server with root privileges
# - tc (iproute2), iperf3, curl installed
# - Fluxify server and client binaries
#
# Usage: sudo ./test_bonding_e2e.sh [options]
#   -s, --server       Run as server (default)
#   -c, --client HOST  Run as client, connect to HOST
#   -i, --ifaces       Comma-separated interfaces (default: eth0,wlan0)
#   -d, --duration     Test duration in seconds (default: 30)
#   -p, --pki          PKI directory (default: ./pki)
#   --netem            Apply netem simulation (default: false)
#   --cleanup          Remove netem rules and exit
#   -v, --verbose      Verbose output
#   -h, --help         Show this help

set -e

# Default configuration
MODE="server"
SERVER_HOST=""
IFACES="eth0,wlan0"
DURATION=30
PKI_DIR="./pki"
APPLY_NETEM=false
CLEANUP_ONLY=false
VERBOSE=false
FLUXIFY_PORT=8000
FLUXIFY_CTRL=8443
IPERF_PORT=5201

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[$(date '+%H:%M:%S')] DEBUG:${NC} $1"
    fi
}

show_help() {
    head -25 "$0" | tail -17
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--server)
            MODE="server"
            shift
            ;;
        -c|--client)
            MODE="client"
            SERVER_HOST="$2"
            shift 2
            ;;
        -i|--ifaces)
            IFACES="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -p|--pki)
            PKI_DIR="$2"
            shift 2
            ;;
        --netem)
            APPLY_NETEM=true
            shift
            ;;
        --cleanup)
            CLEANUP_ONLY=true
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
            error "Unknown option: $1"
            ;;
    esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root"
fi

# Check dependencies
check_deps() {
    local missing=()
    for cmd in tc iperf3 ip; do
        if ! command -v $cmd &> /dev/null; then
            missing+=($cmd)
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        error "Missing dependencies: ${missing[*]}"
    fi
}

# Convert comma-separated ifaces to array
IFS=',' read -ra IFACE_ARRAY <<< "$IFACES"

# Netem profiles: simulate different link characteristics
# Format: delay_ms jitter_ms loss_pct rate_mbit
declare -A NETEM_PROFILES=(
    ["eth0"]="10 1 0 1000"      # Low latency ethernet: 10ms, 1ms jitter, 0% loss, 1Gbps
    ["wlan0"]="30 15 0.5 100"   # WiFi: 30ms, 15ms jitter, 0.5% loss, 100Mbps
    ["wwan0"]="60 40 1 50"      # 4G/5G: 60ms, 40ms jitter, 1% loss, 50Mbps
    ["default"]="20 5 0.1 200"  # Default profile
)

apply_netem() {
    local iface=$1
    local profile=${NETEM_PROFILES[$iface]:-${NETEM_PROFILES["default"]}}
    read -r delay jitter loss rate <<< "$profile"
    
    log "Applying netem to $iface: delay=${delay}ms jitter=${jitter}ms loss=${loss}% rate=${rate}Mbit"
    
    # Clear existing qdisc
    tc qdisc del dev "$iface" root 2>/dev/null || true
    
    # Apply netem
    tc qdisc add dev "$iface" root handle 1: netem \
        delay "${delay}ms" "${jitter}ms" distribution normal \
        loss "${loss}%" \
        rate "${rate}mbit"
    
    debug "  tc qdisc show dev $iface: $(tc qdisc show dev "$iface")"
}

cleanup_netem() {
    log "Cleaning up netem rules..."
    for iface in "${IFACE_ARRAY[@]}"; do
        tc qdisc del dev "$iface" root 2>/dev/null || true
        debug "  Removed qdisc from $iface"
    done
}

# Cleanup on exit
cleanup() {
    log "Cleaning up..."
    cleanup_netem
    # Kill background processes
    pkill -f "fluxify.*test" 2>/dev/null || true
    pkill -f "iperf3.*-s" 2>/dev/null || true
}

trap cleanup EXIT

if [ "$CLEANUP_ONLY" = true ]; then
    cleanup_netem
    log "Cleanup complete."
    exit 0
fi

check_deps

# Apply netem if requested
if [ "$APPLY_NETEM" = true ]; then
    log "Setting up network emulation..."
    for iface in "${IFACE_ARRAY[@]}"; do
        if ip link show "$iface" &>/dev/null; then
            apply_netem "$iface"
        else
            warn "Interface $iface not found, skipping netem"
        fi
    done
fi

run_server_tests() {
    log "=== Running Server-Side Tests ==="
    
    # Check if fluxify server is running
    if ! pgrep -f "fluxify.*server" > /dev/null; then
        log "Starting Fluxify server..."
        ./server -port $FLUXIFY_PORT -ctrl $FLUXIFY_CTRL -pki "$PKI_DIR" &
        sleep 2
    fi
    
    # Start iperf3 server
    log "Starting iperf3 server on port $IPERF_PORT..."
    iperf3 -s -p $IPERF_PORT -D
    sleep 1
    
    log "Server ready. Waiting for client tests..."
    log "Press Ctrl+C to stop."
    
    # Wait indefinitely
    while true; do
        sleep 10
        # Show current connections
        if [ "$VERBOSE" = true ]; then
            ss -tulpn | grep -E "$FLUXIFY_PORT|$FLUXIFY_CTRL|$IPERF_PORT" || true
        fi
    done
}

run_client_tests() {
    if [ -z "$SERVER_HOST" ]; then
        error "Server host not specified. Use -c HOST"
    fi
    
    log "=== Running Client-Side Tests ==="
    log "Server: $SERVER_HOST"
    log "Interfaces: $IFACES"
    log "Duration: ${DURATION}s"
    
    # Build iface args
    IFACE_ARGS=""
    for iface in "${IFACE_ARRAY[@]}"; do
        if [ -n "$IFACE_ARGS" ]; then
            IFACE_ARGS="$IFACE_ARGS,$iface"
        else
            IFACE_ARGS="$iface"
        fi
    done
    
    log "--- Baseline Tests (single interface) ---"
    for iface in "${IFACE_ARRAY[@]}"; do
        log "Testing $iface alone..."
        
        # Get interface IP
        IFACE_IP=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [ -z "$IFACE_IP" ]; then
            warn "$iface has no IPv4 address, skipping"
            continue
        fi
        
        debug "  Interface IP: $IFACE_IP"
        
        # Direct iperf3 through interface
        log "  iperf3 through $iface ($IFACE_IP)..."
        iperf3 -c "$SERVER_HOST" -p $IPERF_PORT -B "$IFACE_IP" -t 10 --json > "/tmp/iperf_${iface}.json" 2>&1 || true
        
        # Extract results
        if [ -f "/tmp/iperf_${iface}.json" ]; then
            DL=$(jq -r '.end.sum_received.bits_per_second // 0' "/tmp/iperf_${iface}.json" 2>/dev/null)
            UL=$(jq -r '.end.sum_sent.bits_per_second // 0' "/tmp/iperf_${iface}.json" 2>/dev/null)
            DL_MBPS=$(echo "scale=2; $DL / 1000000" | bc 2>/dev/null || echo "N/A")
            UL_MBPS=$(echo "scale=2; $UL / 1000000" | bc 2>/dev/null || echo "N/A")
            log "  $iface: Download=${DL_MBPS}Mbps Upload=${UL_MBPS}Mbps"
        else
            warn "  $iface: iperf3 failed"
        fi
    done
    
    log "--- Bonding Test ---"
    log "Starting Fluxify client in bonding mode..."
    
    # Start fluxify client
    ./client -server "$SERVER_HOST:$FLUXIFY_CTRL" -ifaces "$IFACE_ARGS" -pki "$PKI_DIR" -b -v &
    CLIENT_PID=$!
    sleep 5
    
    # Verify TUN is up
    if ip link show tun0 &>/dev/null; then
        log "  TUN interface is up"
        TUN_IP=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        debug "  TUN IP: $TUN_IP"
    else
        warn "  TUN interface not found"
    fi
    
    log "Running iperf3 through bonded connection..."
    iperf3 -c "$SERVER_HOST" -p $IPERF_PORT -t "$DURATION" --json > /tmp/iperf_bonding.json 2>&1 || true
    
    if [ -f "/tmp/iperf_bonding.json" ]; then
        DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/iperf_bonding.json 2>/dev/null)
        UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/iperf_bonding.json 2>/dev/null)
        DL_MBPS=$(echo "scale=2; $DL / 1000000" | bc 2>/dev/null || echo "N/A")
        UL_MBPS=$(echo "scale=2; $UL / 1000000" | bc 2>/dev/null || echo "N/A")
        log "  Bonding: Download=${DL_MBPS}Mbps Upload=${UL_MBPS}Mbps"
    else
        warn "  Bonding iperf3 failed"
    fi
    
    # Stop client
    kill $CLIENT_PID 2>/dev/null || true
    wait $CLIENT_PID 2>/dev/null || true
    
    log "--- Generating Report ---"
    generate_report
}

generate_report() {
    REPORT_FILE="/tmp/fluxify_test_report_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "=========================================="
        echo "Fluxify E2E Test Report"
        echo "Date: $(date)"
        echo "=========================================="
        echo ""
        echo "Configuration:"
        echo "  Server: $SERVER_HOST"
        echo "  Interfaces: $IFACES"
        echo "  Netem: $APPLY_NETEM"
        echo "  Duration: ${DURATION}s"
        echo ""
        echo "Results:"
        echo "--------"
        
        for iface in "${IFACE_ARRAY[@]}"; do
            if [ -f "/tmp/iperf_${iface}.json" ]; then
                DL=$(jq -r '.end.sum_received.bits_per_second // 0' "/tmp/iperf_${iface}.json" 2>/dev/null)
                UL=$(jq -r '.end.sum_sent.bits_per_second // 0' "/tmp/iperf_${iface}.json" 2>/dev/null)
                DL_MBPS=$(echo "scale=2; $DL / 1000000" | bc 2>/dev/null || echo "N/A")
                UL_MBPS=$(echo "scale=2; $UL / 1000000" | bc 2>/dev/null || echo "N/A")
                echo "  $iface: DL=${DL_MBPS}Mbps UL=${UL_MBPS}Mbps"
            fi
        done
        
        if [ -f "/tmp/iperf_bonding.json" ]; then
            DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/iperf_bonding.json 2>/dev/null)
            UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/iperf_bonding.json 2>/dev/null)
            DL_MBPS=$(echo "scale=2; $DL / 1000000" | bc 2>/dev/null || echo "N/A")
            UL_MBPS=$(echo "scale=2; $UL / 1000000" | bc 2>/dev/null || echo "N/A")
            echo "  BONDING: DL=${DL_MBPS}Mbps UL=${UL_MBPS}Mbps"
        fi
        
        echo ""
        echo "=========================================="
    } > "$REPORT_FILE"
    
    log "Report saved to: $REPORT_FILE"
    cat "$REPORT_FILE"
}

# Main
case $MODE in
    server)
        run_server_tests
        ;;
    client)
        run_client_tests
        ;;
    *)
        error "Unknown mode: $MODE"
        ;;
esac