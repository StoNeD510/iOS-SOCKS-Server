//go:build !darwin

package engine

import "syscall"

// bindSocket is a no-op off Apple platforms (used for tests on Linux).
func bindSocket(network string, c syscall.RawConn, ifIndex int) error { return nil }
