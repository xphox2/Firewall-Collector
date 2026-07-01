// Package reuseport opens UDP sockets with SO_REUSEPORT so multiple sockets can
// bind the same address and the kernel load-balances incoming datagrams across
// them — letting a receiver run N reader goroutines (one per socket) on N cores
// instead of draining one socket on one core.
//
// The sockopt is Linux/BSD-only. On unsupported platforms (e.g. the Windows dev
// box) Supported is false and the Control hook is a no-op, so a single socket
// still opens normally — the collector runs, just without multi-socket scaling.
// The production collector runs in a Linux container, where it is supported.
package reuseport

import (
	"context"
	"fmt"
	"log"
	"net"
)

// Workers clamps a requested receive-worker count to what this platform can
// honor: at least 1, and greater than 1 only when SO_REUSEPORT is available
// (otherwise a second socket on the same port fails to bind). label names the
// receiver in the downgrade log line.
func Workers(requested int, label string) int {
	if requested < 1 {
		return 1
	}
	if requested > 1 && !Supported {
		log.Printf("[%s] %d workers requested but SO_REUSEPORT is unsupported on this platform; using 1", label, requested)
		return 1
	}
	return requested
}

// Listen opens a UDP socket bound to address with SO_REUSEPORT set (where
// supported). Opening it once is harmless; open it N times with the same address
// to fan a listener across N sockets. Returns the concrete *net.UDPConn.
func Listen(network, address string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: control}
	pc, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("reuseport: %s is not a UDP connection", address)
	}
	return uc, nil
}
