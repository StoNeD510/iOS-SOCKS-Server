package engine

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// NetInfo describes the phone's interfaces as relevant to the server.
type NetInfo struct {
	HotspotIP   string `json:"hotspot_ip"`  // bridge100 address clients reach us on
	CellularIf  string `json:"cellular_if"` // e.g. pdp_ip0
	CellularIP  string `json:"cellular_ip"` // address on that interface
	CellularIdx int    `json:"-"`
	WiFiIP      string `json:"wifi_ip"`    // en0 address, if associated to a network
	VPNActive   bool   `json:"vpn_active"` // a utun/ipsec tunnel with an IPv4 address exists
	VPNIf       string `json:"vpn_if"`
	DefaultIf   string `json:"default_if"` // interface iOS routes internet traffic through
}

// routeSource returns the local address the OS would use to reach dst,
// without sending anything (a connected UDP socket just picks a route).
func routeSource(dst string) (netip.Addr, bool) {
	c, err := net.Dial("udp", dst)
	if err != nil {
		return netip.Addr{}, false
	}
	defer c.Close()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func ifaceAddrs(ifc net.Interface) []netip.Addr {
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

func firstUsable(addrs []netip.Addr, want4 bool) (netip.Addr, bool) {
	for _, a := range addrs {
		if a.IsLinkLocalUnicast() || a.IsLoopback() {
			continue
		}
		if want4 && a.Is4() {
			return a, true
		}
		if !want4 && a.Is6() && a.IsGlobalUnicast() {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// DetectNetInfo inspects the interfaces the same way socks5.py does:
// bridge* = Personal Hotspot, pdp_ip* = cellular, utun*/ipsec* with IPv4 = VPN.
func DetectNetInfo() NetInfo {
	var ni NetInfo
	ifs, err := net.Interfaces()
	if err != nil {
		return ni
	}
	sort.Slice(ifs, func(i, j int) bool { return ifs[i].Name < ifs[j].Name })
	var srcs []netip.Addr
	if a, ok := routeSource("1.1.1.1:53"); ok {
		srcs = append(srcs, a)
	}
	if a, ok := routeSource("[2606:4700:4700::1111]:53"); ok {
		srcs = append(srcs, a)
	}
	type cell struct {
		name string
		idx  int
		ip   netip.Addr
	}
	var cells []cell
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs := ifaceAddrs(ifc)
		name := ifc.Name
		for _, a := range addrs {
			for _, src := range srcs {
				if a == src && ni.DefaultIf == "" {
					ni.DefaultIf = name
				}
			}
		}
		switch {
		case strings.HasPrefix(name, "bridge"):
			if a, ok := firstUsable(addrs, true); ok && ni.HotspotIP == "" {
				ni.HotspotIP = a.String()
			}
		case strings.HasPrefix(name, "pdp_ip"):
			if a, ok := firstUsable(addrs, true); ok {
				cells = append(cells, cell{name, ifc.Index, a})
			} else if a, ok := firstUsable(addrs, false); ok {
				cells = append(cells, cell{name, ifc.Index, a})
			}
		case name == "en0":
			if a, ok := firstUsable(addrs, true); ok {
				ni.WiFiIP = a.String()
			}
		}
	}
	// A VPN only counts if iOS actually routes internet traffic through it.
	// Carriers create ipsec*/utun* tunnels with IPv4 addresses for VoLTE and
	// Wi-Fi Calling; those are not VPNs and must not disable cellular pinning.
	for _, p := range []string{"utun", "ipsec", "ppp"} {
		if strings.HasPrefix(ni.DefaultIf, p) {
			ni.VPNActive, ni.VPNIf = true, ni.DefaultIf
		}
	}
	// Prefer the cellular interface iOS itself uses for internet traffic;
	// other pdp_ip interfaces are often carrier-only (IMS/voice, MMS).
	pick := -1
	for i, c := range cells {
		if c.name == ni.DefaultIf {
			pick = i
			break
		}
	}
	if pick < 0 {
		for i, c := range cells {
			if c.ip.Is4() {
				pick = i
				break
			}
		}
	}
	if pick < 0 && len(cells) > 0 {
		pick = 0
	}
	if pick >= 0 {
		ni.CellularIf, ni.CellularIP, ni.CellularIdx = cells[pick].name, cells[pick].ip.String(), cells[pick].idx
	}
	return ni
}
