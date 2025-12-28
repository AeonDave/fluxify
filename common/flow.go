package common

import (
	"encoding/binary"
	"hash/fnv"
	"net"
)

// FlowKey is a stable hash for an L3/L4 flow (5-tuple).
// It is used to keep packets of the same flow on the same path
// to avoid TCP throughput collapse due to reordering.
type FlowKey uint64

// FlowKeyFromIPPacket extracts a 5-tuple flow key from an IP packet.
// Supports IPv4/IPv6 and TCP/UDP. For other protocols, it falls back to
// a stable L3 hash (src/dst + proto).
func FlowKeyFromIPPacket(pkt []byte) (FlowKey, bool) {
	if len(pkt) < 1 {
		return 0, false
	}
	ver := pkt[0] >> 4
	switch ver {
	case 4:
		return flowKeyV4(pkt)
	case 6:
		return flowKeyV6(pkt)
	default:
		return 0, false
	}
}

func flowKeyV4(pkt []byte) (FlowKey, bool) {
	if len(pkt) < 20 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0, false
	}
	proto := pkt[9]
	src := net.IP(pkt[12:16])
	dst := net.IP(pkt[16:20])
	return hashTuple(src, dst, proto, pkt[ihl:])
}

func flowKeyV6(pkt []byte) (FlowKey, bool) {
	if len(pkt) < 40 {
		return 0, false
	}
	proto := pkt[6] // NextHeader
	src := net.IP(pkt[8:24])
	dst := net.IP(pkt[24:40])
	return hashTuple(src, dst, proto, pkt[40:])
}

func hashTuple(src, dst net.IP, proto byte, l4 []byte) (FlowKey, bool) {
	var sport, dport uint16
	if (proto == 6 || proto == 17) && len(l4) >= 4 { // TCP/UDP
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
	}

	h := fnv.New64a()
	_, _ = h.Write([]byte{proto})
	_, _ = h.Write(src)
	_, _ = h.Write(dst)
	var b [4]byte
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	_, _ = h.Write(b[:])
	return FlowKey(h.Sum64()), true
}
