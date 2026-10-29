//go:build darwin

package engine

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindSocket pins an outbound socket to a specific interface (e.g. pdp_ip0,
// the cellular data interface) using IP_BOUND_IF / IPV6_BOUND_IF.
func bindSocket(network string, c syscall.RawConn, ifIndex int) error {
	if ifIndex <= 0 {
		return nil
	}
	var serr error
	err := c.Control(func(fd uintptr) {
		if strings.HasSuffix(network, "6") {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifIndex)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifIndex)
		}
	})
	if err != nil {
		return err
	}
	return serr
}
