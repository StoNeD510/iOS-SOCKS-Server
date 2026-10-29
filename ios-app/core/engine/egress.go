package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// egress opens the phone-side sockets that carry client traffic to the
// internet. Because these sockets belong to this app, the carrier sees
// ordinary phone traffic on the cellular IP, not hotspot traffic.
type egress struct {
	bindCellular bool
	log          *ringLog

	mu      sync.RWMutex
	ifIndex int    // interface to pin sockets to (0 = default route)
	ifName  string // for display/logging
	vpn     bool

	natMu        sync.Mutex
	nat64        netip.Prefix // /96, zero if none
	nat64Checked time.Time
}

func newEgress(bindCellular bool, log *ringLog) *egress {
	e := &egress{bindCellular: bindCellular, log: log, nat64Checked: time.Now()}
	e.refresh()
	go e.discoverNAT64() // learn the prefix up front, off the packet path
	return e
}

// refresh re-reads interfaces. With a VPN active on the phone we follow the
// default route so traffic goes through the VPN (same behaviour as socks5.py).
func (e *egress) refresh() NetInfo {
	ni := DetectNetInfo()
	idx, name := 0, ""
	if e.bindCellular && !ni.VPNActive && ni.CellularIdx > 0 {
		idx, name = ni.CellularIdx, ni.CellularIf
	}
	e.mu.Lock()
	changed := idx != e.ifIndex || ni.VPNActive != e.vpn
	e.ifIndex, e.ifName, e.vpn = idx, name, ni.VPNActive
	e.mu.Unlock()
	if changed {
		switch {
		case ni.VPNActive:
			e.log.Printf("egress: VPN %s active on phone, using default route (through VPN)", ni.VPNIf)
		case idx > 0:
			e.log.Printf("egress: pinned to cellular %s (%s)", name, ni.CellularIP)
		default:
			e.log.Printf("egress: using phone's default route")
		}
	}
	return ni
}

func (e *egress) boundIndex() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ifIndex
}

func (e *egress) dialer(ifIndex int) *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return bindSocket(network, c, ifIndex)
		},
	}
}

func isUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)
}

// DialTCP connects to dst from the phone. Fallbacks, in order:
// IPv4 unreachable -> NAT64-synthesized IPv6 (IPv6-only carriers without CLAT);
// pinned interface unreachable -> default route.
func (e *egress) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	idx := e.boundIndex()
	try := func(ifIndex int) (net.Conn, error) {
		d := e.dialer(ifIndex)
		network := "tcp6"
		if dst.Addr().Is4() {
			network = "tcp4"
		}
		c, err := d.DialContext(ctx, network, dst.String())
		if err == nil || !dst.Addr().Is4() || !isUnreachable(err) {
			return c, err
		}
		if v6, ok := e.synth(dst.Addr()); ok {
			return d.DialContext(ctx, "tcp6", netip.AddrPortFrom(v6, dst.Port()).String())
		}
		return c, err
	}
	c, err := try(idx)
	if err != nil && idx > 0 && isUnreachable(err) {
		c, err = try(0)
	}
	return c, err
}

// ListenUDP opens an unconnected UDP socket for one client flow.
func (e *egress) ListenUDP(v6 bool) (*net.UDPConn, error) {
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	idx := e.boundIndex()
	lc := net.ListenConfig{Control: func(n, a string, c syscall.RawConn) error { return bindSocket(n, c, idx) }}
	pc, err := lc.ListenPacket(context.Background(), network, ":0")
	if err != nil && idx > 0 {
		pc, err = net.ListenPacket(network, ":0")
	}
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// synth maps an IPv4 address into the carrier's NAT64 prefix (RFC 7050).
func (e *egress) synth(v4 netip.Addr) (netip.Addr, bool) {
	p := e.nat64Prefix()
	if !p.IsValid() {
		return netip.Addr{}, false
	}
	b := p.Addr().As16()
	a := v4.As4()
	copy(b[12:], a[:])
	return netip.AddrFrom16(b), true
}

// unsynth reverses synth for addresses inside the NAT64 prefix.
func (e *egress) unsynth(v6 netip.Addr) (netip.Addr, bool) {
	e.natMu.Lock()
	p := e.nat64
	e.natMu.Unlock()
	if !p.IsValid() || !v6.Is6() || !p.Contains(v6) {
		return netip.Addr{}, false
	}
	b := v6.As16()
	return netip.AddrFrom4([4]byte(b[12:16])), true
}

// nat64Prefix never blocks: it returns what is known now and, if nothing is
// known, starts a background lookup (it is called from the packet path).
func (e *egress) nat64Prefix() netip.Prefix {
	e.natMu.Lock()
	defer e.natMu.Unlock()
	if !e.nat64.IsValid() && time.Since(e.nat64Checked) >= 2*time.Minute {
		e.nat64Checked = time.Now()
		go e.discoverNAT64()
	}
	return e.nat64
}

func (e *egress) discoverNAT64() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", "ipv4only.arpa")
	if err != nil {
		return
	}
	for _, ip := range ips {
		b := ip.As16()
		if b[12] == 192 && b[13] == 0 && b[14] == 0 && (b[15] == 170 || b[15] == 171) {
			p := netip.PrefixFrom(ip, 96).Masked()
			e.natMu.Lock()
			e.nat64 = p
			e.natMu.Unlock()
			e.log.Printf("egress: NAT64 prefix %s", p)
			return
		}
	}
}
