package common

import (
	"encoding/binary"
	"errors"
	"time"
)

const (
	MaxPacketSize = 1500
	MTU           = 1400
)

// HeartbeatPayload carries a monotonic nanosecond timestamp for RTT.
type HeartbeatPayload struct {
	SendTime int64 // unix nano
}

func (p HeartbeatPayload) Marshal() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(p.SendTime))
	return buf
}

func (p *HeartbeatPayload) Unmarshal(b []byte) error {
	if len(b) < 8 {
		return errors.New("heartbeat payload too short")
	}
	p.SendTime = int64(binary.BigEndian.Uint64(b))
	return nil
}

func NowMonoNano() int64 {
	return time.Now().UnixNano()
}

func CalcRTT(ns int64) time.Duration {
	return time.Duration(time.Now().UnixNano() - ns)
}
