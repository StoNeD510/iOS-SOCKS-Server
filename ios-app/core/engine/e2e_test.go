package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// hostIP returns a non-loopback IPv4 of this machine (stand-in for "the internet").
func hostIP(t *testing.T) netip.Addr {
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		for _, a := range ifaceAddrs(ifc) {
			if a.Is4() && !a.IsLinkLocalUnicast() {
				return a
			}
		}
	}
	t.Skip("no non-loopback IPv4")
	return netip.Addr{}
}

// fakeDNS answers every A query with 203.0.113.7.
func fakeDNS(t *testing.T, ip netip.Addr) netip.AddrPort {
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}})
			}
			out, _ := b.Finish()
			pc.WriteTo(out, from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestEndToEnd(t *testing.T) {
	host := hostIP(t)
	log := NewLog(200)
	log.SetEcho(func(s string) { t.Log(s) })

	serverPriv, _ := GenerateKey()
	serverPub, _ := PublicKey(serverPriv)
	clientPriv, _ := GenerateKey()
	clientPub, _ := PublicKey(clientPriv)
	dns := fakeDNS(t, host)

	srv, err := Start(Config{
		PrivateKey: serverPriv,
		ListenPort: 51999,
		DNS:        []string{dns.String()},
		WebPort:    18080,
		Peers:      []PeerConfig{{Name: "laptop", PublicKey: clientPub, PrivateKey: clientPriv, Address: "10.66.66.2"}},
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Client: a real WireGuard peer with its own userspace stack.
	ctun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.66.2")},
		[]netip.Addr{netip.MustParseAddr("10.66.66.1")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	cdev := device.NewDevice(ctun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client "))
	defer cdev.Close()
	ch, _ := keyToHex(clientPriv)
	sh, _ := keyToHex(serverPub)
	if err := cdev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:51999\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n", ch, sh)); err != nil {
		t.Fatal(err)
	}
	cdev.Up()

	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}, Timeout: 20 * time.Second}

	t.Run("tcp_large_download", func(t *testing.T) {
		blob := make([]byte, 24<<20)
		rand.Read(blob)
		want := sha256.Sum256(blob)
		ln, _ := net.Listen("tcp4", net.JoinHostPort(host.String(), "0"))
		defer ln.Close()
		go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				n, _ := io.Copy(io.Discard, r.Body)
				fmt.Fprint(w, n)
				return
			}
			w.Write(blob)
		}))
		start := time.Now()
		resp, err := client.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || sha256.Sum256(got) != want {
			t.Fatalf("download mismatch: %d bytes err=%v", len(got), err)
		}
		t.Logf("download 24MB in %v (%.0f Mbit/s)", time.Since(start), float64(len(got))*8/time.Since(start).Seconds()/1e6)
		// upload
		resp, err = client.Post("http://"+ln.Addr().String()+"/", "application/octet-stream", bytes.NewReader(blob[:8<<20]))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != fmt.Sprint(8<<20) {
			t.Fatalf("upload got %s", b)
		}
	})

	t.Run("tcp_refused_gets_rst", func(t *testing.T) {
		ln, _ := net.Listen("tcp4", net.JoinHostPort(host.String(), "0"))
		addr := ln.Addr().String()
		ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		start := time.Now()
		_, err := tnet.DialContext(ctx, "tcp", addr)
		if err == nil {
			t.Fatal("expected failure")
		}
		if time.Since(start) > 3*time.Second {
			t.Fatalf("refused took %v (should be fast RST)", time.Since(start))
		}
	})

	t.Run("udp_full_cone", func(t *testing.T) {
		// Echo server; additionally a *second* socket replies to the client's
		// observed address, which only works with endpoint-independent mapping.
		a, _ := net.ListenPacket("udp4", net.JoinHostPort(host.String(), "0"))
		b, _ := net.ListenPacket("udp4", net.JoinHostPort(host.String(), "0"))
		defer a.Close()
		defer b.Close()
		go func() {
			buf := make([]byte, 2000)
			for {
				n, from, err := a.ReadFrom(buf)
				if err != nil {
					return
				}
				a.WriteTo(buf[:n], from)
				b.WriteTo(append([]byte("other:"), buf[:n]...), from)
			}
		}()
		uc, err := tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 66, 66, 2), Port: 40000})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		dst := a.LocalAddr().(*net.UDPAddr)
		got := map[string]bool{}
		for i := 0; i < 5 && len(got) < 2; i++ {
			uc.WriteTo([]byte("hello"), dst)
			uc.SetReadDeadline(time.Now().Add(time.Second))
			for {
				buf := make([]byte, 2000)
				n, _, err := uc.ReadFrom(buf)
				if err != nil {
					break
				}
				got[string(buf[:n])] = true
			}
		}
		if !got["hello"] || !got["other:hello"] {
			t.Fatalf("got %v", got)
		}
		// 1400-byte datagram (typical game/QUIC size)
		big := bytes.Repeat([]byte{7}, 1300)
		uc.WriteTo(big, dst)
		uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2000)
		n, _, err := uc.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], big) {
			t.Fatalf("big datagram: n=%d err=%v", n, err)
		}
	})

	t.Run("dns_via_gateway", func(t *testing.T) {
		addrs, err := tnet.LookupHost("example.test")
		if err != nil || len(addrs) == 0 || addrs[0] != "203.0.113.7" {
			t.Fatalf("lookup: %v %v", addrs, err)
		}
	})

	t.Run("ping_gateway", func(t *testing.T) {
		pc, err := tnet.DialPingAddr(netip.Addr{}, netip.MustParseAddr("10.66.66.1"))
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		msg := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'h', 'i'}
		pc.Write(msg)
		pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 100)
		n, err := pc.Read(buf)
		if err != nil || n < 8 || buf[0] != 0 {
			t.Fatalf("ping reply: %x %v", buf[:n], err)
		}
	})

	t.Run("config_page_through_tunnel", func(t *testing.T) {
		resp, err := client.Get("http://10.66.66.1:18080/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "/conf/0/laptop.conf") {
			t.Fatalf("index: %s", body)
		}
		resp, err = client.Get("http://10.66.66.1:18080/conf/0/laptop.conf")
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "PublicKey = "+serverPub) || !strings.Contains(string(body), "AllowedIPs = 0.0.0.0/0") {
			t.Fatalf("conf: %s", body)
		}
		t.Logf("served config:\n%s", body)
	})

	t.Run("status", func(t *testing.T) {
		st := srv.Status()
		if len(st.Peers) != 1 || st.Peers[0].LastHandshake == 0 || st.Peers[0].RxBytes == 0 {
			t.Fatalf("status %+v", st)
		}
		t.Logf("status: tcp_total=%d udp_flows=%d up=%d down=%d peer=%+v", st.TCPTotal, st.UDPFlows, st.BytesUp, st.BytesDown, st.Peers[0])
	})

	t.Run("set_peers_live", func(t *testing.T) {
		p2priv, _ := GenerateKey()
		p2pub, _ := PublicKey(p2priv)
		peers := append(srv.Config().Peers, PeerConfig{Name: "ipad", PublicKey: p2pub, PrivateKey: p2priv, Address: "10.66.66.3"})
		if err := srv.SetPeers(peers); err != nil {
			t.Fatal(err)
		}
		// existing client must keep working
		addrs, err := tnet.LookupHost("still.works")
		if err != nil || len(addrs) == 0 {
			t.Fatalf("after SetPeers: %v %v", addrs, err)
		}
	})
}

func TestSetPeersRemove(t *testing.T) {
	log := NewLog(50)
	sp, _ := GenerateKey()
	a, _ := GenerateKey()
	ap, _ := PublicKey(a)
	b, _ := GenerateKey()
	bp, _ := PublicKey(b)
	srv, err := Start(Config{PrivateKey: sp, ListenPort: 51998, Peers: []PeerConfig{{Name: "a", PublicKey: ap, Address: "10.66.66.2"}, {Name: "b", PublicKey: bp, Address: "10.66.66.3"}}}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	if err := srv.SetPeers([]PeerConfig{{Name: "b", PublicKey: bp, Address: "10.66.66.3"}}); err != nil {
		t.Fatal(err)
	}
	ipc, _ := srv.wg.IpcGet()
	if strings.Count(ipc, "public_key=") != 1 {
		t.Fatalf("expected 1 peer:\n%s", ipc)
	}
}
