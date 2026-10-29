package engine

import (
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// pinger forwards IPv4 echo requests (ping) using the unprivileged
// datagram-ICMP sockets iOS allows, so `ping` from the laptop measures the
// real cellular path instead of being faked.
type pingKey struct {
	client, dst netip.Addr
	id          uint16
}

type pingFlow struct {
	key  pingKey
	myID uint16
	conn *icmp.PacketConn
	last atomic.Int64
}

type pinger struct {
	s      *Server
	mu     sync.Mutex
	flows  map[pingKey]*pingFlow
	nextID atomic.Uint32
	failed atomic.Bool
}

func newPinger(s *Server) *pinger { return &pinger{s: s, flows: map[pingKey]*pingFlow{}} }

func (pg *pinger) handle(p ipPacket) {
	m := p.payload
	if p.fragment || len(m) < 8 || m[0] != 8 || m[1] != 0 { // only echo request
		return
	}
	id := binary.BigEndian.Uint16(m[4:6])
	seq := binary.BigEndian.Uint16(m[6:8])
	data := m[8:]

	if p.dst == pg.s.gateway {
		pg.s.dev.send(buildICMPEchoReply(p.dst, p.src, id, seq, data))
		return
	}
	if dropDestination(p.dst) {
		return
	}
	f := pg.get(pingKey{p.src, p.dst, id})
	if f == nil {
		return
	}
	f.last.Store(time.Now().UnixNano())
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: int(f.myID), Seq: int(seq), Data: data}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	f.conn.WriteTo(b, &net.UDPAddr{IP: p.dst.AsSlice()})
}

func (pg *pinger) get(k pingKey) *pingFlow {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	if f, ok := pg.flows[k]; ok {
		return f
	}
	if len(pg.flows) > 256 || pg.failed.Load() {
		return nil
	}
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		pg.failed.Store(true)
		pg.s.log.Printf("ping: ICMP sockets unavailable (%v); pings will time out", err)
		return nil
	}
	id := uint16(pg.nextID.Add(1)%0xfffe + 1)
	f := &pingFlow{key: k, myID: id, conn: conn}
	f.last.Store(time.Now().UnixNano())
	pg.flows[k] = f
	go pg.readLoop(f)
	return f
}

func (pg *pinger) readLoop(f *pingFlow) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := f.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := peer.(*net.UDPAddr)
		if !ok {
			continue
		}
		from, ok := netip.AddrFromSlice(ua.IP)
		if !ok || from.Unmap() != f.key.dst {
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// Linux rewrites the ID to the socket's port; Darwin keeps ours.
		if runtime.GOOS != "linux" && uint16(echo.ID) != f.myID {
			continue
		}
		f.last.Store(time.Now().UnixNano())
		pg.s.dev.send(buildICMPEchoReply(f.key.dst, f.key.client, f.key.id, uint16(echo.Seq), echo.Data))
	}
}

func (pg *pinger) reap(all bool) {
	cutoff := time.Now().Add(-time.Minute).UnixNano()
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for k, f := range pg.flows {
		if all || f.last.Load() < cutoff {
			f.conn.Close()
			delete(pg.flows, k)
		}
	}
}
