package common

import (
	"io"
	"log"
	"net"
	"net/http"
	"os/user"
	"strings"
	"time"
)

var verboseEnabled bool

func EnableVerbose() { verboseEnabled = true }

func VLogf(f string, v ...interface{}) {
	if verboseEnabled {
		log.Printf(f, v...)
	}
}

func ClampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~") {
		u, _ := user.Current()
		if u != nil {
			return strings.Replace(p, "~", u.HomeDir, 1)
		}
	}
	return p
}

func IsIPPacket(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	ver := pkt[0] >> 4
	return ver == 4 || ver == 6
}

type NetInterface struct {
	Name string
	MTU  int
}

func ListPhysicalInterfaces() ([]NetInterface, error) {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	res := []NetInterface{}
	for _, i := range ifcs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		res = append(res, NetInterface{Name: i.Name, MTU: i.MTU})
	}
	return res, nil
}

func GetLocalIPs() ([]string, error) {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, ifc := range ifcs {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.IsLoopback() {
				continue
			}
			if ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ipnet.IP.String())
		}
	}
	return ips, nil
}

// GetPublicIP fetches the public IP address using ipify.org API.
// Returns empty string if detection fails (offline, timeout, behind restrictive firewall).
func GetPublicIP(timeout time.Duration) string {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

type LossStats struct {
	Percent float64
	Ok      bool
}

func LossPercent(sent, recv uint64) LossStats {
	if sent < 3 {
		return LossStats{Percent: 0, Ok: false}
	}
	if recv > sent {
		recv = sent
	}
	return LossStats{Percent: float64(sent-recv) * 100 / float64(sent), Ok: true}
}

func StabilityScore(lossPct, jitterMs, rttMs float64) float64 {
	score := 100.0 - lossPct*1.2 - jitterMs*0.5 - rttMs*0.1
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
