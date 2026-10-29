package engine

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpIdleTimeout = 3 * time.Minute // generous for games
	maxUDPFlows    = 4096
)

// udpFlow is one client source address:port. It owns unconnected phone-side
// sockets, so any remote can reply (endpoint-independent / "full cone"
// mapping), which is what console/PC games want for a good NAT type.
type udpFlow struct {
	nat    *udpNAT
	client netip.AddrPort

	mu           sync.Mutex
	conn4, conn6 *net.UDPConn
	closed       bool
	last         atomic.Int64
}

type udpNAT struct {
	s     *Server
	mu    sync.Mutex
	flows map[netip.AddrPort]*udpFlow
}

func newUDPNAT(s *Server) *udpNAT {
	return &udpNAT{s: s, flows: map[netip.AddrPort]*udpFlow{}}
}

func dropDestination(a netip.Addr) bool {
	if a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsLoopback() {
		return true
	}
	if a.Is4() {
		b := a.As4()
		if b == [4]byte{255, 255, 255, 255} || b[3] == 255 && (b[0] == 10 || b[0] == 172 || b[0] == 192) {
			return true // broadcasts (SSDP/NetBIOS chatter from Windows)
		}
	}
	return false
}

func (n *udpNAT) handle(p ipPacket) {
	u := p.payload
	if len(u) < 8 {
		return
	}
	ulen := int(binary.BigEndian.Uint16(u[4:6]))
	if ulen < 8 || ulen > len(u) {
		ulen = len(u)
	}
	data := u[8:ulen]
	client := netip.AddrPortFrom(p.src, binary.BigEndian.Uint16(u[0:2]))
	dst := netip.AddrPortFrom(p.dst, binary.BigEndian.Uint16(u[2:4]))

	if dst.Addr() == n.s.gateway {
		if dst.Port() == 53 {
			n.s.dnsQuery(client, dst, append([]byte(nil), data...))
		}
		return
	}
	if dropDestination(dst.Addr()) {
		return
	}
	f := n.get(client)
	if f == nil {
		return
	}
	f.send(dst, data)
}

func (n *udpNAT) get(client netip.AddrPort) *udpFlow {
	n.mu.Lock()
	defer n.mu.Unlock()
	if f, ok := n.flows[client]; ok {
		return f
	}
	if len(n.flows) >= maxUDPFlows {
		return nil
	}
	f := &udpFlow{nat: n, client: client}
	f.last.Store(time.Now().UnixNano())
	n.flows[client] = f
	return f
}

func (n *udpNAT) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.flows)
}

func (n *udpNAT) reap(all bool) {
	cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()
	n.mu.Lock()
	var dead []*udpFlow
	for k, f := range n.flows {
		if all || f.last.Load() < cutoff {
			dead = append(dead, f)
			delete(n.flows, k)
		}
	}
	n.mu.Unlock()
	for _, f := range dead {
		f.close()
	}
}

func (f *udpFlow) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	if f.conn4 != nil {
		f.conn4.Close()
	}
	if f.conn6 != nil {
		f.conn6.Close()
	}
}

func (f *udpFlow) socket(v6 bool) *net.UDPConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	c := &f.conn4
	if v6 {
		c = &f.conn6
	}
	if *c == nil {
		conn, err := f.nat.s.egress.ListenUDP(v6)
		if err != nil {
			f.nat.s.log.Printf("udp: socket for %s: %v", f.client, err)
			return nil
		}
		*c = conn
		go f.readLoop(conn)
	}
	return *c
}

func (f *udpFlow) send(dst netip.AddrPort, data []byte) {
	f.last.Store(time.Now().UnixNano())
	s := f.nat.s
	if dst.Addr().Is4() {
		if c := f.socket(false); c != nil {
			_, err := c.WriteToUDPAddrPort(data, dst)
			if err == nil {
				s.bytesUp.Add(int64(len(data)))
				return
			}
			if !isUnreachable(err) {
				return
			}
		}
		// IPv6-only cellular without CLAT: go via NAT64.
		v6, ok := s.egress.synth(dst.Addr())
		if !ok {
			return
		}
		dst = netip.AddrPortFrom(v6, dst.Port())
	}
	if c := f.socket(true); c != nil {
		if _, err := c.WriteToUDPAddrPort(data, dst); err == nil {
			s.bytesUp.Add(int64(len(data)))
		}
	}
}

func (f *udpFlow) readLoop(c *net.UDPConn) {
	s := f.nat.s
	buf := make([]byte, 65535)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		src := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if src.Addr().Is6() && f.client.Addr().Is4() {
			v4, ok := s.egress.unsynth(src.Addr())
			if !ok {
				continue
			}
			src = netip.AddrPortFrom(v4, src.Port())
		} else if src.Addr().Is4() != f.client.Addr().Is4() {
			continue
		}
		f.last.Store(time.Now().UnixNano())
		s.bytesDown.Add(int64(n))
		s.dev.send(buildUDP(src, f.client, buf[:n]))
	}
}

// dnsQuery answers DNS sent to the tunnel gateway (10.66.66.1) by relaying
// it to the configured upstream resolvers from the phone.
func (s *Server) dnsQuery(client, gw netip.AddrPort, q []byte) {
	select {
	case s.dnsSem <- struct{}{}:
	default:
		return // too many in flight; client will retry
	}
	go func() {
		defer func() { <-s.dnsSem }()
		for _, up := range s.dnsUpstreams {
			resp, err := s.udpExchange(up, q, 2500*time.Millisecond)
			if err == nil {
				s.dev.send(buildUDP(gw, client, resp))
				return
			}
		}
	}()
}

func (s *Server) udpExchange(up netip.AddrPort, q []byte, timeout time.Duration) ([]byte, error) {
	target := up
	c, err := s.egress.ListenUDP(up.Addr().Is6())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err = c.WriteToUDPAddrPort(q, target); err != nil {
		if !up.Addr().Is4() || !isUnreachable(err) {
			return nil, err
		}
		v6, ok := s.egress.synth(up.Addr())
		if !ok {
			return nil, err
		}
		c.Close()
		if c, err = s.egress.ListenUDP(true); err != nil {
			return nil, err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(timeout))
		target = netip.AddrPortFrom(v6, up.Port())
		if _, err = c.WriteToUDPAddrPort(q, target); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, 65535)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return nil, err
		}
		if from.Addr().Unmap() == target.Addr() && from.Port() == target.Port() {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}
