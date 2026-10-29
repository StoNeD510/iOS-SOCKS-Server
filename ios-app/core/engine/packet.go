package engine

import (
	"encoding/binary"
	"net/netip"
)

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// ipPacket is a minimal parsed view of an IPv4/IPv6 packet coming from a client.
type ipPacket struct {
	version  int
	proto    int
	src, dst netip.Addr
	payload  []byte // transport header + data
	fragment bool   // IPv4 packet that is a fragment (MF set or offset != 0)
}

func parseIP(b []byte) (p ipPacket, ok bool) {
	if len(b) < 1 {
		return p, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || total < ihl || total > len(b) {
			return p, false
		}
		flagsFrag := binary.BigEndian.Uint16(b[6:8])
		p.version = 4
		p.proto = int(b[9])
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.payload = b[ihl:total]
		p.fragment = flagsFrag&0x2000 != 0 || flagsFrag&0x1fff != 0
		return p, true
	case 6:
		if len(b) < 40 {
			return p, false
		}
		plen := int(binary.BigEndian.Uint16(b[4:6]))
		if 40+plen > len(b) {
			return p, false
		}
		p.version = 6
		p.proto = int(b[6]) // extension headers are not walked; non-UDP/TCP goes to gVisor
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		p.payload = b[40 : 40+plen]
		return p, true
	}
	return p, false
}

// checksum folds a ones'-complement sum.
func csumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func csumFinish(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudoSum(src, dst netip.Addr, proto int, length int) uint32 {
	var sum uint32
	s := src.AsSlice()
	d := dst.AsSlice()
	sum = csumAdd(sum, s)
	sum = csumAdd(sum, d)
	if src.Is4() {
		sum += uint32(proto)
		sum += uint32(length)
	} else {
		sum += uint32(length>>16) + uint32(length&0xffff)
		sum += uint32(proto)
	}
	return sum
}

// buildIP wraps a transport payload (with its header already filled, checksum
// field zeroed if a checksum is to be computed by the caller) into an IP packet.
func buildIP(src, dst netip.Addr, proto int, transport []byte) []byte {
	if src.Is4() {
		pkt := make([]byte, 20+len(transport))
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		pkt[8] = 64 // TTL
		pkt[9] = byte(proto)
		copy(pkt[12:16], src.AsSlice())
		copy(pkt[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(pkt[10:12], csumFinish(csumAdd(0, pkt[:20])))
		copy(pkt[20:], transport)
		return pkt
	}
	pkt := make([]byte, 40+len(transport))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(transport)))
	pkt[6] = byte(proto)
	pkt[7] = 64 // hop limit
	copy(pkt[8:24], src.AsSlice())
	copy(pkt[24:40], dst.AsSlice())
	copy(pkt[40:], transport)
	return pkt
}

// buildUDP builds a full IP+UDP packet from src to dst carrying data.
func buildUDP(src, dst netip.AddrPort, data []byte) []byte {
	u := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], data)
	sum := pseudoSum(src.Addr(), dst.Addr(), protoUDP, len(u))
	c := csumFinish(csumAdd(sum, u))
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], c)
	return buildIP(src.Addr(), dst.Addr(), protoUDP, u)
}

// buildICMPEchoReply builds an IPv4 ICMP echo reply.
func buildICMPEchoReply(src, dst netip.Addr, id, seq uint16, data []byte) []byte {
	m := make([]byte, 8+len(data))
	m[0] = 0 // echo reply
	binary.BigEndian.PutUint16(m[4:6], id)
	binary.BigEndian.PutUint16(m[6:8], seq)
	copy(m[8:], data)
	binary.BigEndian.PutUint16(m[2:4], csumFinish(csumAdd(0, m)))
	return buildIP(src, dst, protoICMP, m)
}
