package reuseport

import (
	"net"
	"testing"
	"time"
)

// TestListenRoundTrip verifies a reuseport socket opens and receives a datagram
// on every platform (single-socket path works regardless of SO_REUSEPORT).
func TestListenRoundTrip(t *testing.T) {
	c, err := Listen("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer c.Close()

	dst := c.LocalAddr().(*net.UDPAddr)
	sender, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("got %q, want %q", buf[:n], "ping")
	}
}

// TestListenShared pins the core property: on a platform WITH SO_REUSEPORT two
// sockets can bind the same concrete address; WITHOUT it, the second bind fails
// (so callers must gate N>1 workers on Supported).
func TestListenShared(t *testing.T) {
	c1, err := Listen("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer c1.Close()
	addr := c1.LocalAddr().String()

	c2, err := Listen("udp", addr)
	if Supported {
		if err != nil {
			t.Fatalf("SO_REUSEPORT supported but second bind to %s failed: %v", addr, err)
		}
		_ = c2.Close()
	} else {
		if err == nil {
			_ = c2.Close()
			t.Fatalf("SO_REUSEPORT unsupported but second bind to %s unexpectedly succeeded", addr)
		}
	}
}
