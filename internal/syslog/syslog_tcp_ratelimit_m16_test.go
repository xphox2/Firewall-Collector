package syslog

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/ratelimit"
	"firewall-collector/internal/relay"
)

// TestSyslogTCP_RateLimited_M16 pins the 2026-07-01 audit M16 fix: the TCP
// syslog path must enforce the same per-source rate limit as UDP. A single
// source streaming past its budget on one connection must have its excess
// lines dropped (and counted) rather than forwarded unthrottled.
func TestSyslogTCP_RateLimited_M16(t *testing.T) {
	rx := NewSyslogReceiver("127.0.0.1", 0)
	// Tiny budget: 5/sec, burst 5 — the 6th line in a burst is dropped.
	lim := ratelimit.New(ratelimit.Config{PerSourceRate: 5, PerSourceBurst: 5, GlobalRate: 1e9, GlobalBurst: 1e9})
	var drops int64
	rx.SetRateLimiter(lim, func() { atomic.AddInt64(&drops, 1) })

	var forwarded int64
	if err := rx.Start(func(*relay.SyslogMessage) { atomic.AddInt64(&forwarded, 1) }); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer rx.Stop()

	addr := rx.listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send 20 valid RFC5424 lines in one write — well over the burst of 5.
	const n = 20
	var payload []byte
	for i := 0; i < n; i++ {
		payload = append(payload, []byte(fmt.Sprintf("<13>1 2026-07-01T00:00:0%dZ host app - - - msg%d\n", i%10, i))...)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Give the handler goroutine time to process.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&forwarded)+atomic.LoadInt64(&drops) >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	fwd := atomic.LoadInt64(&forwarded)
	drp := atomic.LoadInt64(&drops)
	if fwd > 6 {
		t.Errorf("forwarded = %d, want <= burst (~5) — the TCP path is not rate limited", fwd)
	}
	if drp == 0 {
		t.Error("no drops recorded — the rate limiter never engaged on the TCP path")
	}
	if fwd+drp != n {
		t.Errorf("forwarded(%d) + dropped(%d) = %d, want %d (every line accounted for)", fwd, drp, fwd+drp, n)
	}
}

// TestSyslogTCP_ConnectionCap_M16 pins the concurrent-connection cap: beyond
// the cap, new connections are refused (closed immediately) instead of
// letting an attacker exhaust memory/FDs with idle-but-open connections.
func TestSyslogTCP_ConnectionCap_M16(t *testing.T) {
	// Shrink the cap via a receiver whose semaphore we size down.
	rx := NewSyslogReceiver("127.0.0.1", 0)
	rx.connSem = make(chan struct{}, 2) // cap = 2 for the test
	if err := rx.Start(func(*relay.SyslogMessage) {}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer rx.Stop()

	addr := rx.listener.Addr().String()
	// Two long-lived connections that don't send a newline occupy both slots.
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	// Wait for both handler goroutines to claim their semaphore slots.
	time.Sleep(200 * time.Millisecond)

	// A third connection must be accepted-then-immediately-closed by the server.
	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial third: %v", err)
	}
	defer third.Close()
	third.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, rerr := third.Read(buf)
	if rerr == nil {
		t.Error("third connection over the cap should have been closed by the server (read returned no error)")
	}
}
