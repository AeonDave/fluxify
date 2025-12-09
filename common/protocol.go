package common

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	ProtoVersion  = 1
	MaxPacketSize = 1500
	MTU           = 1400

	PacketIP        = 1
	PacketHeartbeat = 2
	PacketHandshake = 3
	PacketControl   = 4
)

// PacketHeader is a compact, fixed-size header with no padding.
// We marshal/unmarshal manually to avoid struct padding ambiguity.
type PacketHeader struct {
	Version   uint8
	Type      uint8
	SessionID uint32
	SeqNum    uint32
	Length    uint16
	Reserved  [10]byte
}

const HeaderSize = 1 + 1 + 4 + 4 + 2 + 10 // 22 bytes

func (h *PacketHeader) Marshal() ([]byte, error) {
	buf := make([]byte, HeaderSize)
	buf[0] = h.Version
	buf[1] = h.Type
	binary.BigEndian.PutUint32(buf[2:], h.SessionID)
	binary.BigEndian.PutUint32(buf[6:], h.SeqNum)
	binary.BigEndian.PutUint16(buf[10:], h.Length)
	copy(buf[12:], h.Reserved[:])
	return buf, nil
}

func (h *PacketHeader) Unmarshal(data []byte) error {
	if len(data) < HeaderSize {
		return fmt.Errorf("header too short: %d", len(data))
	}
	h.Version = data[0]
	h.Type = data[1]
	h.SessionID = binary.BigEndian.Uint32(data[2:])
	h.SeqNum = binary.BigEndian.Uint32(data[6:])
	h.Length = binary.BigEndian.Uint16(data[10:])
	copy(h.Reserved[:], data[12:])
	return nil
}

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

// SerializePacket builds header+payload.
func SerializePacket(h PacketHeader, payload []byte) ([]byte, error) {
	if int(h.Length) != len(payload) {
		return nil, fmt.Errorf("length mismatch: header %d payload %d", h.Length, len(payload))
	}
	hdr, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, HeaderSize+len(payload)))
	buf.Write(hdr)
	buf.Write(payload)
	return buf.Bytes(), nil
}

// ParsePacket reads header then payload from a reader-like buffer.
func ParsePacket(data []byte) (PacketHeader, []byte, error) {
	var h PacketHeader
	if len(data) < HeaderSize {
		return h, nil, fmt.Errorf("packet too short: %d", len(data))
	}
	if err := h.Unmarshal(data[:HeaderSize]); err != nil {
		return h, nil, err
	}
	if len(data) < HeaderSize+int(h.Length) {
		return h, nil, fmt.Errorf("payload missing: have %d need %d", len(data), HeaderSize+int(h.Length))
	}
	return h, data[HeaderSize : HeaderSize+int(h.Length)], nil
}
