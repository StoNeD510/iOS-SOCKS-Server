package engine

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenerateKey returns a new WireGuard private key (base64).
func GenerateKey() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// PublicKey derives the base64 public key from a base64 private key.
func PublicKey(priv string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(k) != 32 {
		return "", errors.New("invalid private key")
	}
	pub, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
