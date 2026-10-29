package engine

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// webServer serves http://<hotspot-ip>:<port>/ with a download link per
// device, so a laptop can grab its WireGuard config without AirDrop.
type webServer struct {
	srv *http.Server
}

func startWeb(s *Server, port int) (*webServer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.webIndex)
	mux.HandleFunc("/conf/", s.webConf)
	w := &webServer{srv: &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}}
	go w.srv.Serve(ln)
	return w, nil
}

func (w *webServer) close() { w.srv.Close() }

// endpointHost picks the address the client should use as its WireGuard
// endpoint: whatever address it reached this page on, unless that was the
// in-tunnel gateway, in which case the hotspot address.
func (s *Server) endpointHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(host); err == nil && a != s.gateway && !a.IsLoopback() {
		return a.String()
	}
	if ni := s.netInfo.Load(); ni != nil && ni.HotspotIP != "" {
		return ni.HotspotIP
	}
	return "172.20.10.1"
}

func (s *Server) webIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cfg := s.Config()
	var rows strings.Builder
	for i, p := range cfg.Peers {
		if p.PrivateKey == "" {
			continue
		}
		fmt.Fprintf(&rows, `<li><a href="/conf/%d/%s.conf">%s</a> <span>%s</span></li>`,
			i, safeName(p.Name), html.EscapeString(p.Name), html.EscapeString(p.Address))
	}
	if rows.Len() == 0 {
		rows.WriteString("<li>No devices yet. Add one in the app.</li>")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hotspot WireGuard</title><style>
body{font:16px -apple-system,Segoe UI,sans-serif;max-width:560px;margin:2em auto;padding:0 16px;color:#222}
li{margin:.6em 0}a{font-weight:600}span{color:#888;margin-left:.5em}ol li{margin:.3em 0}
</style></head><body><h1>Hotspot WireGuard</h1>
<p>Download the config for <b>this</b> device:</p><ul>%s</ul>
<h3>Windows</h3><ol><li>Install WireGuard from wireguard.com (one time).</li>
<li>WireGuard &rarr; <i>Import tunnel(s) from file</i> &rarr; pick the .conf.</li>
<li>Click <i>Activate</i> whenever you're on the hotspot.</li></ol>
<p>Endpoint used: %s:%d</p></body></html>`, rows.String(), html.EscapeString(s.endpointHost(r)), cfg.ListenPort)
}

func safeName(n string) string {
	var b strings.Builder
	for _, c := range n {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			b.WriteRune(c)
		} else if c == ' ' {
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "device"
	}
	return b.String()
}

func (s *Server) webConf(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/conf/"), "/")
	idx, err := strconv.Atoi(parts[0])
	cfg := s.Config()
	if err != nil || idx < 0 || idx >= len(cfg.Peers) || cfg.Peers[idx].PrivateKey == "" {
		http.NotFound(w, r)
		return
	}
	p := cfg.Peers[idx]
	serverPub, err := PublicKey(cfg.PrivateKey)
	if err != nil {
		http.Error(w, "server key error", 500)
		return
	}
	conf := ClientConfig(p.PrivateKey, p.Address, serverPub, s.endpointHost(r), cfg.ListenPort, cfg.Gateway, cfg.MTU)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, safeName(p.Name)))
	w.Write([]byte(conf))
}
