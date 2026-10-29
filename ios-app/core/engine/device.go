package engine

import (
	"fmt"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// interceptor gets first look at every packet a client sends. It returns true
// if it consumed the packet (UDP, ICMP echo); everything else goes to gVisor.
type interceptor func(pkt []byte) bool

// netDev is the "TUN device" wireguard-go reads/writes. Instead of a kernel
// interface it feeds a userspace TCP/IP stack (for TCP) and our own UDP/ICMP
// NAT, all of which terminate on sockets owned by this app.
type netDev struct {
	ep           *channel.Endpoint
	stack        *stack.Stack
	notifyHandle *channel.NotificationHandle
	events       chan tun.Event
	out          chan []byte
	done         chan struct{}
	closeOnce    sync.Once
	mtu          int
	intercept    interceptor
}

func newNetDev(mtu int, gateway netip.Addr) (*netDev, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false,
	})
	d := &netDev{
		ep:     channel.New(1024, uint32(mtu), ""),
		stack:  s,
		events: make(chan tun.Event, 4),
		out:    make(chan []byte, 1024),
		done:   make(chan struct{}),
		mtu:    mtu,
	}

	// TCP tuning: SACK, large auto-tuned windows (cellular has big BDP).
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mod)

	d.notifyHandle = d.ep.AddNotify(d)
	if err := s.CreateNIC(1, d.ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}
	// Accept packets for ANY destination and reply as that destination:
	// this is what makes the stack act as a transparent proxy.
	if err := s.SetPromiscuousMode(1, true); err != nil {
		return nil, fmt.Errorf("promiscuous: %v", err)
	}
	if err := s.SetSpoofing(1, true); err != nil {
		return nil, fmt.Errorf("spoofing: %v", err)
	}
	if gateway.IsValid() {
		s.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(gateway.AsSlice()).WithPrefix(),
		}, stack.AddressProperties{})
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	d.events <- tun.EventUp
	return d, nil
}

// send queues a packet towards the WireGuard side (i.e. back to a client).
func (d *netDev) send(p []byte) {
	select {
	case d.out <- p:
	case <-d.done:
	}
}

// WriteNotify is called by gVisor when it has a packet for a client.
func (d *netDev) WriteNotify() {
	pkt := d.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	b := view.ToSlice()
	view.Release()
	d.send(b)
}

func (d *netDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var p []byte
	select {
	case p = <-d.out:
	case <-d.done:
		return 0, os.ErrClosed
	}
	n := 0
	for {
		sizes[n] = copy(bufs[n][offset:], p)
		n++
		if n == len(bufs) {
			return n, nil
		}
		select {
		case p = <-d.out:
		default:
			return n, nil
		}
	}
}

func (d *netDev) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		if d.intercept != nil && d.intercept(pkt) {
			continue
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		switch pkt[0] >> 4 {
		case 4:
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
		case 6:
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pb)
		}
		pb.DecRef()
	}
	return len(bufs), nil
}

func (d *netDev) File() *os.File           { return nil }
func (d *netDev) MTU() (int, error)        { return d.mtu, nil }
func (d *netDev) Name() (string, error)    { return "hotspotwg", nil }
func (d *netDev) Events() <-chan tun.Event { return d.events }
func (d *netDev) BatchSize() int           { return 16 }

func (d *netDev) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		d.stack.RemoveNIC(1)
		d.stack.Close()
		d.ep.RemoveNotify(d.notifyHandle)
		d.ep.Close()
		close(d.events)
	})
	return nil
}
