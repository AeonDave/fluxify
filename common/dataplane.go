package common

import (
	"encoding/binary"
	"errors"
)

// DataPlaneHeader is a lightweight framing header for QUIC DATAGRAM payloads.
//
// With QUIC, encryption / integrity / replay protection are already provided
// by the transport (TLS 1.3), therefore we do NOT include any AEAD metadata.
//
// We still keep a compact header to:
// - demultiplex sessions on the server (multi-user)
// - support optional gzip compression flag
// - keep SeqNum for debugging/metrics (QUIC already reorders streams; datagrams are unordered)
//
// Layout (network byte order):
//
//	[0]    Version (1 byte)
//	[1]    Type    (1 byte)
//	[2:6]  SessionID (uint32)
//	[6:10] SeqNum    (uint32)
//	[10]   Flags     (1 byte)  (bit0: gzip)
//
// Total: 11 bytes
const (
	DataPlaneVersion  = 1
	DataPlaneHdrSize  = 11
	DPTypeIP          = 1
	DPTypeHeartbeat   = 2
	DPTypeHandshake   = 3 // optional / keepalive
	DPFlagCompression = 1 << 0
)

type DataPlaneHeader struct {
	Version   uint8
	Type      uint8
	SessionID uint32
	SeqNum    uint32
	Flags     uint8
}

func DataPlaneTypeName(t uint8) string {
	switch t {
	case DPTypeIP:
		return "IP"
	case DPTypeHeartbeat:
		return "Heartbeat"
	case DPTypeHandshake:
		return "Handshake"
	default:
		return "Unknown"
	}
}

func (h *DataPlaneHeader) MarshalTo(dst []byte) ([]byte, error) {
	if cap(dst) < DataPlaneHdrSize {
		dst = make([]byte, DataPlaneHdrSize)
	}
	b := dst[:DataPlaneHdrSize]
	b[0] = h.Version
	b[1] = h.Type
	binary.BigEndian.PutUint32(b[2:6], h.SessionID)
	binary.BigEndian.PutUint32(b[6:10], h.SeqNum)
	b[10] = h.Flags
	return b, nil
}

func (h *DataPlaneHeader) Unmarshal(b []byte) error {
	if len(b) < DataPlaneHdrSize {
		return errors.New("dataplane: short header")
	}
	h.Version = b[0]
	h.Type = b[1]
	h.SessionID = binary.BigEndian.Uint32(b[2:6])
	h.SeqNum = binary.BigEndian.Uint32(b[6:10])
	h.Flags = b[10]
	return nil
}

// BuildDataPlaneDatagram returns header||payload. Payload is not encrypted here.
func BuildDataPlaneDatagram(dst []byte, h DataPlaneHeader, payload []byte) ([]byte, error) {
	hdr, err := h.MarshalTo(dst)
	if err != nil {
		return nil, err
	}
	if cap(hdr) < DataPlaneHdrSize+len(payload) {
		buf := make([]byte, DataPlaneHdrSize+len(payload))
		copy(buf, hdr)
		copy(buf[DataPlaneHdrSize:], payload)
		return buf, nil
	}
	out := hdr[:DataPlaneHdrSize+len(payload)]
	copy(out[DataPlaneHdrSize:], payload)
	return out, nil
}

func ParseDataPlaneDatagram(b []byte) (DataPlaneHeader, []byte, error) {
	var h DataPlaneHeader
	if err := h.Unmarshal(b); err != nil {
		return h, nil, err
	}
	return h, b[DataPlaneHdrSize:], nil
}
