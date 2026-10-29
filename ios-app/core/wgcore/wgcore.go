// Package wgcore is the gomobile-facing API used by the iOS app.
// Everything is plain functions over strings so the Swift side stays simple:
// in Swift these appear as WgcoreStart(_:_:), WgcoreStatusJSON(), etc.
package wgcore

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/StoNeD510/iOS-SOCKS-Server/ios-app/core/engine"
)

var (
	mu  sync.Mutex
	srv *engine.Server
	log = engine.NewLog(400)
)

// Start launches the server from a JSON engine.Config. Stops any running one.
func Start(configJSON string) error {
	var cfg engine.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return errors.New("bad config: " + err.Error())
	}
	mu.Lock()
	defer mu.Unlock()
	if srv != nil {
		srv.Stop()
		srv = nil
	}
	s, err := engine.Start(cfg, log)
	if err != nil {
		log.Printf("start failed: %v", err)
		return err
	}
	srv = s
	return nil
}

// Stop shuts the server down (no-op if not running).
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if srv != nil {
		srv.Stop()
		srv = nil
	}
}

// Running reports whether the server is up.
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return srv != nil
}

// SetPeers replaces the device list (JSON array of engine.PeerConfig)
// on the running server without disconnecting anyone.
func SetPeers(peersJSON string) error {
	var peers []engine.PeerConfig
	if err := json.Unmarshal([]byte(peersJSON), &peers); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.SetPeers(peers)
}

// StatusJSON returns engine.Status as JSON (or {"running":false,...}).
func StatusJSON() string {
	mu.Lock()
	s := srv
	mu.Unlock()
	var st engine.Status
	if s != nil {
		st = s.Status()
	} else {
		st.Net = engine.DetectNetInfo()
	}
	b, _ := json.Marshal(st)
	return string(b)
}

// NetInfoJSON reports hotspot/cellular/VPN interface state.
func NetInfoJSON() string {
	b, _ := json.Marshal(engine.DetectNetInfo())
	return string(b)
}

// Logs returns recent log lines, newest last.
func Logs() string { return log.Tail() }

// GeneratePrivateKey returns a new base64 WireGuard private key.
func GeneratePrivateKey() string {
	k, err := engine.GenerateKey()
	if err != nil {
		return ""
	}
	return k
}

// PublicKey derives a base64 public key ("" if the private key is invalid).
func PublicKey(privateKey string) string {
	p, err := engine.PublicKey(privateKey)
	if err != nil {
		return ""
	}
	return p
}

// ClientConfig renders the .conf a client device imports.
func ClientConfig(peerPrivateKey, peerAddress, serverPublicKey, endpointHost string, port int, gateway string, mtu int) string {
	return engine.ClientConfig(peerPrivateKey, peerAddress, serverPublicKey, endpointHost, port, gateway, mtu)
}
