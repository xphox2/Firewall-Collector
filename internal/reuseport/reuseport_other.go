//go:build !linux

package reuseport

import "syscall"

// Supported reports whether SO_REUSEPORT is available on this platform. It is
// false everywhere except Linux; callers fall back to a single socket.
const Supported = false

// control is a no-op on platforms without SO_REUSEPORT, so a single socket still
// opens normally. Attempting to open more than one socket on the same address
// here would fail at bind — callers must gate N>1 on Supported.
func control(network, address string, c syscall.RawConn) error { return nil }
