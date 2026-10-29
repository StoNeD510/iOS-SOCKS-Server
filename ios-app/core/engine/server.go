package engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type PeerConfig struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`            // base64
	PrivateKey string `json:"private_key,omitempty"` // base64; only used to serve the client .conf
	Address    string `json:"address"`               // e.g. 10.66.66.2
}

type Config struct {
	PrivateKey   string       `json:"private_key"` // server key, base64
	ListenPort   int          `json:"listen_port"`
	Gateway      string       `json:"gateway"` // tunnel-side address of the phone, default 10.66.66.1
	MTU          int          `json:"mtu"`
	BindCellular bool         `json:"bind_cellular"`
	DNS          []string     `json:"dns"`      // upstream resolvers, default 1.1.1.1, 8.8.8.8
	WebPort      int          `json:"web_port"` // config download page; 0 = off
	Peers        []PeerConfig `json:"peers"`
}

func (c *Config) applyDefaults() {
	if c.ListenPort == 0 {
		c.ListenPort = 51820
	}
	if c.Gateway == "" {
		c.Gateway = "10.66.66.1"
	}
	if c.MTU == 0 {
		c.MTU = 1420
	}
	if len(c.DNS) == 0 {
		c.DNS = []string{"1.1.1.1", "8.8.8.8"}
	}
}

type Server struct {
	cfg     Config
	cfgMu   sync.RWMutex
	log     *ringLog
	dev     *netDev
	wg      *device.Device
	egress  *egress
	udp     *udpNAT
	ping    *pinger
	web     *webServer
	gateway netip.Addr

	dnsUpstreams []netip.AddrPort
	dnsSem       chan struct{}

	started   time.Time
	netInfo   atomic.Pointer[NetInfo]
	tcpActive atomic.Int64
	tcpTotal  atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
}

func keyToHex(b64 string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(k) != 32 {
		return "", fmt.Errorf("invalid key %q", b64)
	}
	return hex.EncodeToString(k), nil
}

func hexToKey(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func Start(cfg Config, log *ringLog) (*Server, error) {
	cfg.applyDefaults()
	gw, err := netip.ParseAddr(cfg.Gateway)
	if err != nil || !gw.Is4() {
		return nil, fmt.Errorf("bad gateway %q", cfg.Gateway)
	}
	s := &Server{cfg: cfg, log: log, gateway: gw, dnsSem: make(chan struct{}, 256), started: time.Now()}
	for _, d := range cfg.DNS {
		d = strings.TrimSpace(d)
		if ap, err := netip.ParseAddrPort(d); err == nil {
			s.dnsUpstreams = append(s.dnsUpstreams, ap)
		} else if a, err := netip.ParseAddr(d); err == nil {
			s.dnsUpstreams = append(s.dnsUpstreams, netip.AddrPortFrom(a, 53))
		}
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.egress = newEgress(cfg.BindCellular, log)
	ni := s.egress.refresh()
	s.netInfo.Store(&ni)

	s.dev, err = newNetDev(cfg.MTU, gw)
	if err != nil {
		return nil, err
	}
	s.udp = newUDPNAT(s)
	s.ping = newPinger(s)
	s.dev.intercept = s.intercept

	fwd := tcp.NewForwarder(s.dev.stack, 0, 1024, s.handleTCP)
	s.dev.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log.Printf("wg: "+f, a...) },
	}
	s.wg = device.NewDevice(s.dev, conn.NewDefaultBind(), logger)

	ipc, err := s.ipcConfig(cfg)
	if err != nil {
		s.wg.Close()
		return nil, err
	}
	if err := s.wg.IpcSet(ipc); err != nil {
		s.wg.Close()
		return nil, fmt.Errorf("configure wireguard: %w", err)
	}
	if err := s.wg.Up(); err != nil {
		s.wg.Close()
		return nil, fmt.Errorf("listen on UDP %d: %w", cfg.ListenPort, err)
	}
	log.Printf("WireGuard listening on UDP %d, %d device(s) configured", cfg.ListenPort, len(cfg.Peers))
	if ni.HotspotIP != "" {
		log.Printf("hotspot address %s", ni.HotspotIP)
	} else {
		log.Printf("Personal Hotspot not detected yet (clients will use 172.20.10.1)")
	}

	if cfg.WebPort > 0 {
		s.web, err = startWeb(s, cfg.WebPort)
		if err != nil {
			log.Printf("config page: %v", err)
		} else {
			log.Printf("config page on port %d", cfg.WebPort)
		}
	}
	go s.housekeeping()
	return s, nil
}

func (s *Server) ipcConfig(cfg Config) (string, error) {
	priv, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("server private key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", priv, cfg.ListenPort)
	b.WriteString(peersIPC(cfg.Peers, s.log))
	return b.String(), nil
}

func peersIPC(peers []PeerConfig, log *ringLog) string {
	var b strings.Builder
	for _, p := range peers {
		pub, err := keyToHex(p.PublicKey)
		if err != nil {
			log.Printf("skipping device %q: bad public key", p.Name)
			continue
		}
		addr, err := netip.ParseAddr(p.Address)
		if err != nil {
			log.Printf("skipping device %q: bad address %q", p.Name, p.Address)
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\nallowed_ip=%s\n", pub, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return b.String()
}

// SetPeers swaps the device list without dropping connected clients.
// Only peers that were added, removed or re-addressed are touched, so
// existing sessions keep their keys.
func (s *Server) SetPeers(peers []PeerConfig) error {
	old := map[string]string{}
	for _, p := range s.Config().Peers {
		old[p.PublicKey] = p.Address
	}
	var b strings.Builder
	keep := map[string]bool{}
	for _, p := range peers {
		keep[p.PublicKey] = true
		if addr, ok := old[p.PublicKey]; ok && addr == p.Address {
			continue
		}
		ipc := peersIPC([]PeerConfig{p}, s.log)
		if ipc == "" {
			continue
		}
		b.WriteString(strings.Replace(ipc, "\nallowed_ip=", "\nreplace_allowed_ips=true\nallowed_ip=", 1))
	}
	for pub := range old {
		if !keep[pub] {
			if h, err := keyToHex(pub); err == nil {
				fmt.Fprintf(&b, "public_key=%s\nremove=true\n", h)
			}
		}
	}
	if b.Len() > 0 {
		if err := s.wg.IpcSet(b.String()); err != nil {
			return err
		}
	}
	s.cfgMu.Lock()
	s.cfg.Peers = peers
	s.cfgMu.Unlock()
	s.log.Printf("device list updated (%d)", len(peers))
	return nil
}

func (s *Server) Config() Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

func (s *Server) Stop() {
	s.cancel()
	if s.web != nil {
		s.web.close()
	}
	s.wg.Close() // closes the netDev too
	s.udp.reap(true)
	s.ping.reap(true)
	s.log.Printf("stopped")
}

func (s *Server) housekeeping() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			ni := s.egress.refresh()
			s.netInfo.Store(&ni)
			s.udp.reap(false)
			s.ping.reap(false)
		}
	}
}

func (s *Server) intercept(pkt []byte) bool {
	p, ok := parseIP(pkt)
	if !ok {
		return true
	}
	switch p.proto {
	case protoUDP:
		if !p.fragment {
			s.udp.handle(p)
		}
		return true
	case protoICMP:
		if p.version == 4 {
			s.ping.handle(p)
		}
		return true
	}
	return false
}

// handleTCP is called (in its own goroutine) for every new client TCP
// connection. We connect out from the phone first, then accept the client's
// handshake, so unreachable hosts get a clean RST.
func (s *Server) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	dst := netip.AddrPortFrom(dstIP.Unmap(), id.LocalPort)

	var out net.Conn
	var err error
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	switch {
	case dst.Addr() == s.gateway && dst.Port() == 53 && len(s.dnsUpstreams) > 0:
		out, err = s.egress.DialTCP(ctx, s.dnsUpstreams[0])
	case dst.Addr() == s.gateway:
		out, err = (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", dst.Port()))
	case dropDestination(dst.Addr()):
		err = errors.New("blocked destination")
	default:
		out, err = s.egress.DialTCP(ctx, dst)
	}
	cancel()
	if err != nil {
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		out.Close()
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(60 * time.Second)
	ep.SetSockOpt(&idle)
	intv := tcpip.KeepaliveIntervalOption(30 * time.Second)
	ep.SetSockOpt(&intv)
	in := gonet.NewTCPConn(&wq, ep)

	s.tcpActive.Add(1)
	s.tcpTotal.Add(1)
	defer s.tcpActive.Add(-1)

	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(out, in)
		s.bytesUp.Add(n)
		if tc, ok := out.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(in, out)
		s.bytesDown.Add(n)
		in.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	// Give the other direction a moment to drain after a half-close.
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
	case <-s.ctx.Done():
	}
	in.Close()
	out.Close()
}

type PeerStatus struct {
	Name          string `json:"name"`
	PublicKey     string `json:"public_key"`
	Address       string `json:"address"`
	Endpoint      string `json:"endpoint"`
	LastHandshake int64  `json:"last_handshake"` // unix seconds, 0 = never
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}

type Status struct {
	Running    bool         `json:"running"`
	ListenPort int          `json:"listen_port"`
	Net        NetInfo      `json:"net"`
	EgressIf   string       `json:"egress_if"`
	TCPActive  int64        `json:"tcp_active"`
	TCPTotal   int64        `json:"tcp_total"`
	UDPFlows   int          `json:"udp_flows"`
	BytesUp    int64        `json:"bytes_up"`
	BytesDown  int64        `json:"bytes_down"`
	Uptime     int64        `json:"uptime"`
	Peers      []PeerStatus `json:"peers"`
}

func (s *Server) Status() Status {
	cfg := s.Config()
	st := Status{
		Running:    true,
		ListenPort: cfg.ListenPort,
		TCPActive:  s.tcpActive.Load(),
		TCPTotal:   s.tcpTotal.Load(),
		UDPFlows:   s.udp.count(),
		BytesUp:    s.bytesUp.Load(),
		BytesDown:  s.bytesDown.Load(),
		Uptime:     int64(time.Since(s.started).Seconds()),
	}
	if ni := s.netInfo.Load(); ni != nil {
		st.Net = *ni
	}
	s.egress.mu.RLock()
	st.EgressIf = s.egress.ifName
	if st.EgressIf == "" {
		st.EgressIf = "default route"
	}
	s.egress.mu.RUnlock()

	live := map[string]*PeerStatus{}
	if ipc, err := s.wg.IpcGet(); err == nil {
		var cur *PeerStatus
		sc := bufio.NewScanner(strings.NewReader(ipc))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			switch k {
			case "public_key":
				cur = &PeerStatus{PublicKey: hexToKey(v)}
				live[cur.PublicKey] = cur
			case "endpoint":
				if cur != nil {
					cur.Endpoint = v
				}
			case "last_handshake_time_sec":
				if cur != nil {
					cur.LastHandshake, _ = strconv.ParseInt(v, 10, 64)
				}
			case "rx_bytes":
				if cur != nil {
					cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
				}
			case "tx_bytes":
				if cur != nil {
					cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
				}
			}
		}
	}
	for _, p := range cfg.Peers {
		ps := PeerStatus{Name: p.Name, PublicKey: p.PublicKey, Address: p.Address}
		if l, ok := live[p.PublicKey]; ok {
			ps.Endpoint, ps.LastHandshake, ps.RxBytes, ps.TxBytes = l.Endpoint, l.LastHandshake, l.RxBytes, l.TxBytes
		}
		st.Peers = append(st.Peers, ps)
	}
	return st
}

// ClientConfig renders the wg-quick style config a client device imports.
func ClientConfig(peerPrivateKey, peerAddress, serverPublicKey, endpointHost string, port int, gateway string, mtu int) string {
	if gateway == "" {
		gateway = "10.66.66.1"
	}
	if mtu == 0 {
		mtu = 1420
	}
	if port == 0 {
		port = 51820
	}
	if endpointHost == "" {
		endpointHost = "172.20.10.1"
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s
PersistentKeepalive = 25
`, peerPrivateKey, peerAddress, gateway, mtu, serverPublicKey, net.JoinHostPort(endpointHost, strconv.Itoa(port)))
}
