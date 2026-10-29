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
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs := ifaceAddrs(ifc)
		name := ifc.Name
		switch {
		case strings.HasPrefix(name, "bridge"):
			if a, ok := firstUsable(addrs, true); ok && ni.HotspotIP == "" {
				ni.HotspotIP = a.String()
			}
		case strings.HasPrefix(name, "pdp_ip"):
			if ni.CellularIf != "" {
				continue
			}
			if a, ok := firstUsable(addrs, true); ok {
				ni.CellularIf, ni.CellularIP, ni.CellularIdx = name, a.String(), ifc.Index
			} else if a, ok := firstUsable(addrs, false); ok {
				ni.CellularIf, ni.CellularIP, ni.CellularIdx = name, a.String(), ifc.Index
			}
		case name == "en0":
			if a, ok := firstUsable(addrs, true); ok {
				ni.WiFiIP = a.String()
			}
		case strings.HasPrefix(name, "utun"), strings.HasPrefix(name, "ipsec"):
			if a, ok := firstUsable(addrs, true); ok && !ni.VPNActive {
				_ = a
				ni.VPNActive, ni.VPNIf = true, name
			}
		}
	}
	return ni
}
