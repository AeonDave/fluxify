package common

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PMTUDResult holds the result of a PMTUD probe.
type PMTUDResult struct {
	Success    bool          // true if probe succeeded
	TestedMTU  int           // the MTU size tested
	SuggestMTU int           // suggested MTU if probe failed
	RTT        time.Duration // round-trip time if successful
	Error      string        // error message if probe failed
	IPv6       bool          // whether IPv6 was used
}

// DefaultProbeMTUs are common MTU sizes to test in order of preference.
var DefaultProbeMTUs = []int{1400, 1350, 1300, 1280, 1200}

// ProbePMTUD sends ICMP echo with Don't Fragment (DF) flag to test path MTU.
// It probes the given MTU size (payload = mtu - headers).
// For IPv4: IP header (20) + ICMP header (8) = 28 bytes overhead
// For IPv6: IP header (40) + ICMPv6 header (8) = 48 bytes overhead
func ProbePMTUD(host string, mtu int, timeout time.Duration) PMTUDResult {
	result := PMTUDResult{TestedMTU: mtu}

	// Resolve host to determine IPv4 vs IPv6
	ip := net.ParseIP(host)
	if ip == nil {
		// Try resolving hostname
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			result.Error = fmt.Sprintf("cannot resolve host: %v", err)
			return result
		}
		ip = addrs[0]
	}

	isIPv6 := ip.To4() == nil
	result.IPv6 = isIPv6

	// Calculate ping payload size
	// IPv4: mtu - 20 (IP) - 8 (ICMP) = mtu - 28
	// IPv6: mtu - 40 (IP) - 8 (ICMPv6) = mtu - 48
	var payloadSize int
	if isIPv6 {
		payloadSize = mtu - 48
	} else {
		payloadSize = mtu - 28
	}

	if payloadSize < 0 {
		result.Error = fmt.Sprintf("MTU %d too small for headers", mtu)
		return result
	}

	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		if isIPv6 {
			// Linux ping6 with -M do (don't fragment)
			cmd = exec.Command("ping", "-6", "-c", "1", "-W", strconv.Itoa(timeoutSec),
				"-M", "do", "-s", strconv.Itoa(payloadSize), host)
		} else {
			// Linux ping with -M do (don't fragment)
			cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutSec),
				"-M", "do", "-s", strconv.Itoa(payloadSize), host)
		}
	case "windows":
		// Windows ping with -f (don't fragment) flag
		// Note: Windows ping -l sets payload size, -f sets DF bit
		// Windows doesn't have native IPv6 DF control in ping, but we try anyway
		cmd = exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutSec*1000),
			"-f", "-l", strconv.Itoa(payloadSize), host)
	case "darwin":
		if isIPv6 {
			cmd = exec.Command("ping6", "-c", "1", "-D", "-s", strconv.Itoa(payloadSize), host)
		} else {
			// macOS ping with -D (don't fragment)
			cmd = exec.Command("ping", "-c", "1", "-t", strconv.Itoa(timeoutSec),
				"-D", "-s", strconv.Itoa(payloadSize), host)
		}
	default:
		result.Error = "unsupported OS for PMTUD probe"
		return result
	}

	start := time.Now()
	out, err := cmd.CombinedOutput()
	result.RTT = time.Since(start)

	if err != nil {
		outStr := strings.ToLower(string(out))
		// Check for fragmentation needed / packet too big messages
		if strings.Contains(outStr, "frag needed") ||
			strings.Contains(outStr, "message too long") ||
			strings.Contains(outStr, "packet too big") ||
			strings.Contains(outStr, "mtu") ||
			strings.Contains(outStr, "fragmentation needed") ||
			strings.Contains(outStr, "needs to be fragmented") {
			result.Error = "packet too big (fragmentation needed)"
		} else if strings.Contains(outStr, "timeout") ||
			strings.Contains(outStr, "timed out") ||
			strings.Contains(outStr, "unreachable") {
			result.Error = "host unreachable or timeout"
		} else {
			result.Error = fmt.Sprintf("ping failed: %v", err)
		}
		// Suggest a smaller MTU
		result.SuggestMTU = suggestSmallerMTU(mtu)
		return result
	}

	result.Success = true
	// Parse RTT from output if possible (for more accurate timing)
	if rtt := parseRTTFromPing(string(out)); rtt > 0 {
		result.RTT = rtt
	}
	return result
}

// AutoProbePMTUD tries multiple MTU sizes and returns the largest working one.
func AutoProbePMTUD(host string, timeout time.Duration) (int, PMTUDResult) {
	for _, mtu := range DefaultProbeMTUs {
		result := ProbePMTUD(host, mtu, timeout)
		if result.Success {
			return mtu, result
		}
	}
	// All failed, return minimum MTU with the last result
	lastResult := ProbePMTUD(host, 1280, timeout)
	return 1280, lastResult
}

func suggestSmallerMTU(currentMTU int) int {
	for _, mtu := range DefaultProbeMTUs {
		if mtu < currentMTU {
			return mtu
		}
	}
	return 1280 // minimum MTU for IPv6
}

func parseRTTFromPing(output string) time.Duration {
	// Try to parse RTT from ping output
	// Linux: time=X.XX ms
	// Windows: time=Xms or time<Xms
	// macOS: time=X.XX ms
	output = strings.ToLower(output)

	// Look for "time=X" or "time<X"
	idx := strings.Index(output, "time=")
	if idx < 0 {
		idx = strings.Index(output, "time<")
	}
	if idx < 0 {
		return 0
	}

	// Extract number after time=
	start := idx + 5
	end := start
	for end < len(output) && (output[end] == '.' || (output[end] >= '0' && output[end] <= '9')) {
		end++
	}
	if end <= start {
		return 0
	}

	numStr := output[start:end]
	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}

	// Check unit (ms or s)
	unit := strings.TrimSpace(output[end:])
	if strings.HasPrefix(unit, "ms") {
		return time.Duration(val * float64(time.Millisecond))
	}
	// Assume ms if no unit found
	return time.Duration(val * float64(time.Millisecond))
}

// FormatPMTUDResult formats the result for display.
func FormatPMTUDResult(r PMTUDResult) string {
	if r.Success {
		proto := "IPv4"
		if r.IPv6 {
			proto = "IPv6"
		}
		return fmt.Sprintf("PMTUD OK: MTU %d works (%s, RTT %v)", r.TestedMTU, proto, r.RTT.Round(time.Millisecond))
	}
	if r.SuggestMTU > 0 {
		return fmt.Sprintf("PMTUD FAIL: MTU %d too large (%s), suggest %d", r.TestedMTU, r.Error, r.SuggestMTU)
	}
	return fmt.Sprintf("PMTUD FAIL: MTU %d (%s)", r.TestedMTU, r.Error)
}
