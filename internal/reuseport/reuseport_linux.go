//go:build linux

package reuseport

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Supported reports whether SO_REUSEPORT is available on this platform.
const Supported = true

// control sets SO_REUSEPORT on the socket fd before bind, so multiple sockets
// may share the same address and the kernel spreads datagrams across them.
func control(network, address string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
