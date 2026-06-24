package syslog

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// TestHandleConnection_MultiLineFraming_M6 is the regression for the 2026-06-23
// audit M6 finding: the TCP framing now forward-scans the read buffer with an
// advancing offset and compacts the tail once, instead of resetting + rewriting
// the remaining bytes on every newline (O(n²) per read). This pins the behavior
// the rewrite must preserve: many newline-delimited lines in a single Read are
// all parsed, and a trailing partial line carries over to the next Read.
func TestHandleConnection_MultiLineFraming_M6(t *testing.T) {
	var received atomic.Int32
	rcv := NewSyslogReceiver("127.0.0.1", 0)
	if err := rcv.Start(func(*relay.SyslogMessage) { received.Add(1) }); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rcv.Stop() })

	port := rcv.listener.Addr().(*net.TCPAddr).Port
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	const tmpl = "<13>1 2025-04-10T05:01:53.000000-07:00 h a p m - - msg%d\n"
	// Three complete lines + a partial (no trailing newline) in ONE write.
	first := fmt.Sprintf(tmpl, 1) + fmt.Sprintf(tmpl, 2) + fmt.Sprintf(tmpl, 3) +
		"<13>1 2025-04-10T05:01:53.000000-07:00 h a p m - - partial"
	if _, err := conn.Write([]byte(first)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	waitForCount(t, &received, 3)
	if n := received.Load(); n != 3 {
		t.Fatalf("after first write: handler called %d times, want 3 (all newline-delimited lines parsed)", n)
	}

	// Completing the partial line must produce the 4th message (tail carried over).
	if _, err := conn.Write([]byte("rest\n")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	waitForCount(t, &received, 4)
	if n := received.Load(); n != 4 {
		t.Errorf("after completing partial line: handler called %d times, want 4 (carry-over)", n)
	}
}

func waitForCount(t *testing.T, c *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.Load() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
