package tftp

import (
	"bytes"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestTFTPReceiveTransfer_SizeCapEnforced is the AUDIT-050 size-cap test.
// receiveTransfer must reject WRQ payloads larger than maxTransferSize (2 MB)
// before they exhaust collector memory. We drive blocks directly into a
// session socket (skipping the full WRQ dance) so the test is fast and
// focused on the cap logic.
func TestTFTPReceiveTransfer_SizeCapEnforced(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 500 * time.Millisecond})

	sessionConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("session ListenUDP: %v", err)
	}
	defer sessionConn.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	defer clientConn.Close()

	sessionAddr := sessionConn.LocalAddr().(*net.UDPAddr)
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	type result struct {
		data []byte
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		d, rerr := server.receiveTransfer(sessionConn, clientAddr)
		resCh <- result{d, rerr}
	}()

	chunk := bytes.Repeat([]byte{'X'}, blockSize)
	ackBuf := make([]byte, 16)
	overallDeadline := time.Now().Add(30 * time.Second)

	// We expect the cap to bite around block 4097 (4096 * 512 == 2 MB exactly,
	// the 4097th would push past). Cap iterations at 5000 to detect a broken
	// implementation that never enforces the limit.
	const safetyLimit = 5000

	for block := uint16(1); block <= safetyLimit; block++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				t.Fatalf("receiveTransfer returned nil error after %d blocks; want size-cap error", block-1)
			}
			if !strings.Contains(res.err.Error(), "exceeds") {
				t.Errorf("expected size-cap error containing %q, got: %v", "exceeds", res.err)
			}
			return
		default:
		}

		if time.Now().After(overallDeadline) {
			t.Fatalf("test timed out at block %d (cap should have triggered earlier)", block)
		}

		pkt := make([]byte, 4+blockSize)
		pkt[1] = byte(opDATA)
		pkt[2] = byte(block >> 8)
		pkt[3] = byte(block & 0xff)
		copy(pkt[4:], chunk)
		if _, werr := clientConn.WriteToUDP(pkt, sessionAddr); werr != nil {
			t.Fatalf("write DATA %d: %v", block, werr)
		}

		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, rerr := clientConn.ReadFromUDP(ackBuf)
		if rerr != nil {
			// ACK didn't arrive — server may have hit the cap and exited.
			select {
			case res := <-resCh:
				if res.err == nil {
					t.Fatalf("receiveTransfer returned nil after block %d; want size-cap error", block)
				}
				if !strings.Contains(res.err.Error(), "exceeds") {
					t.Errorf("expected size-cap error, got: %v", res.err)
				}
				return
			case <-time.After(2 * time.Second):
				t.Fatalf("ACK %d not received (%v) and receiveTransfer did not return", block, rerr)
			}
		}
		if n < 4 {
			t.Fatalf("ACK %d: short reply (%d bytes)", block, n)
		}
		opcode := uint16(ackBuf[0])<<8 | uint16(ackBuf[1])
		if opcode != opACK {
			t.Fatalf("expected ACK for block %d, got opcode %d", block, opcode)
		}
		ackBlock := uint16(ackBuf[2])<<8 | uint16(ackBuf[3])
		if ackBlock != block {
			t.Fatalf("expected ACK block %d, got %d", block, ackBlock)
		}
	}

	t.Fatalf("sent %d full blocks (~%d KB) without hitting the 2 MB cap",
		safetyLimit, (safetyLimit*blockSize)/1024)
}

// TestTFTPHandleWRQ_SourceIPBlocked is the AUDIT-050 allowlist deny test.
// A WRQ from a source IP not in the allowlist must be refused before any
// session socket is allocated and before the write handler is called.
func TestTFTPHandleWRQ_SourceIPBlocked(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 1 * time.Second})
	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer server.Shutdown()

	var handlerCalled int32
	server.SetWriteHandler(func(filename string, data []byte, addr net.Addr) error {
		atomic.StoreInt32(&handlerCalled, 1)
		return nil
	})
	// RFC 5737 TEST-NET-1 — never matches a real loopback peer.
	server.SetAllowedSourceIPs([]string{"192.0.2.1"})

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.WriteToUDP(buildWRQ("fgt_42_config"), serverAddr); err != nil {
		t.Fatalf("write WRQ: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	n, sender, err := clientConn.ReadFromUDP(buf)
	if err == nil {
		// Server replied — must be ERROR (code 2 access violation), never ACK.
		if n < 4 {
			t.Fatalf("short reply (%d bytes)", n)
		}
		opcode := uint16(buf[0])<<8 | uint16(buf[1])
		if opcode == opACK {
			t.Fatal("server sent ACK to blocked source IP — allowlist bypassed")
		}
		if opcode != opERROR {
			t.Fatalf("expected ERROR (opcode 5), got opcode %d", opcode)
		}
		errCode := uint16(buf[2])<<8 | uint16(buf[3])
		if errCode != 2 {
			t.Errorf("expected ERROR code 2 (Access violation), got %d", errCode)
		}
		// ERROR must come from the listen socket — we never allocated a session.
		if sender.Port != serverAddr.Port {
			t.Errorf("expected reply from listen port %d, got %d", serverAddr.Port, sender.Port)
		}
	} else {
		// Silent drop is also defensible. Either way, the handler must not fire.
		t.Logf("no reply received (acceptable): %v", err)
	}

	// Grace window in case a buggy implementation queues the handler late.
	time.Sleep(150 * time.Millisecond)
	if atomic.LoadInt32(&handlerCalled) != 0 {
		t.Fatal("write handler was invoked for a blocked source IP")
	}
}

// TestTFTPHandleWRQ_SourceIPAllowed confirms a peer in the allowlist
// completes the full WRQ end-to-end (regression guard so the allowlist
// check does not break the happy path).
func TestTFTPHandleWRQ_SourceIPAllowed(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 2 * time.Second})
	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer server.Shutdown()

	handlerHit := make(chan struct{})
	server.SetWriteHandler(func(filename string, data []byte, addr net.Addr) error {
		close(handlerHit)
		return nil
	})
	server.SetAllowedSourceIPs([]string{"127.0.0.1"})

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)
	if err := runWRQ(t, serverAddr, "fgt_42_config", []byte("hello world")); err != nil {
		t.Fatalf("runWRQ: %v", err)
	}

	select {
	case <-handlerHit:
	case <-time.After(2 * time.Second):
		t.Fatal("write handler not invoked despite source IP being in allowlist")
	}
}

// TestTFTPHandleWRQ_AllowlistEmpty_DeniesAll confirms that an explicitly
// empty (non-nil) allowlist is interpreted as "deny everyone" — distinct
// from the nil default which means "no policy, allow all".
func TestTFTPHandleWRQ_AllowlistEmpty_DeniesAll(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 1 * time.Second})
	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer server.Shutdown()

	var handlerCalled int32
	server.SetWriteHandler(func(filename string, data []byte, addr net.Addr) error {
		atomic.StoreInt32(&handlerCalled, 1)
		return nil
	})
	server.SetAllowedSourceIPs([]string{})

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.WriteToUDP(buildWRQ("fgt_42_config"), serverAddr); err != nil {
		t.Fatalf("write WRQ: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	if n, _, err := clientConn.ReadFromUDP(buf); err == nil && n >= 4 {
		if uint16(buf[0])<<8|uint16(buf[1]) == opACK {
			t.Fatal("empty allowlist accepted a WRQ (should deny all)")
		}
	}

	time.Sleep(150 * time.Millisecond)
	if atomic.LoadInt32(&handlerCalled) != 0 {
		t.Fatal("write handler ran despite empty allowlist")
	}
}

// TestTFTPHandleWRQ_RateLimitRefused is the AUDIT-050 rate-limit test.
// After one accepted WRQ from a source IP, a second WRQ from the same IP
// within minWRQInterval must be refused — without allocating a session
// socket and without invoking the write handler a second time.
func TestTFTPHandleWRQ_RateLimitRefused(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 1 * time.Second})
	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer server.Shutdown()

	server.SetWriteHandler(func(filename string, data []byte, addr net.Addr) error {
		return nil
	})
	server.SetMinWRQInterval(60 * time.Second)

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)

	// WRQ #1 — fresh client socket, accepted, ACK 0 from a fresh session TID.
	client1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client1 ListenUDP: %v", err)
	}
	defer client1.Close()

	if _, err := client1.WriteToUDP(buildWRQ("fgt_42_config"), serverAddr); err != nil {
		t.Fatalf("WRQ #1 write: %v", err)
	}
	client1.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	n, sender1, err := client1.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("WRQ #1 read ACK 0: %v", err)
	}
	if n < 4 || buf[1] != byte(opACK) {
		t.Fatalf("WRQ #1: expected ACK opcode, got %d", buf[1])
	}
	if sender1.Port == serverAddr.Port {
		t.Fatalf("WRQ #1: expected ACK from ephemeral TID, got listen port %d", sender1.Port)
	}

	// WRQ #2 from a DIFFERENT ephemeral port (same source IP 127.0.0.1)
	// within the 60s window — must be refused.
	client2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client2 ListenUDP: %v", err)
	}
	defer client2.Close()

	if _, err := client2.WriteToUDP(buildWRQ("fgt_42_config"), serverAddr); err != nil {
		t.Fatalf("WRQ #2 write: %v", err)
	}
	client2.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, sender2, err := client2.ReadFromUDP(buf)
	if err != nil {
		// Silent drop also acceptable; the key check is that no session was set up.
		t.Logf("WRQ #2: no reply (acceptable rate-limit behavior)")
		return
	}
	if n < 4 {
		t.Fatalf("WRQ #2: short reply %d bytes", n)
	}
	opcode := uint16(buf[0])<<8 | uint16(buf[1])
	if opcode == opACK {
		t.Fatal("WRQ #2: server sent ACK despite rate limit")
	}
	if opcode != opERROR {
		t.Errorf("WRQ #2: expected ERROR (opcode 5), got %d", opcode)
	}
	// Rate-limit denial replies from the listen socket — no session was allocated.
	if sender2.Port != serverAddr.Port {
		t.Errorf("WRQ #2: expected reply from listen port %d, got %d (session allocated despite limit)",
			serverAddr.Port, sender2.Port)
	}
}

// TestTFTPHandleWRQ_RateLimitDisabledByDefault confirms that, without an
// explicit SetMinWRQInterval call, two WRQs from the same source IP in
// quick succession both succeed — preserving the pre-AUDIT-050 behavior
// for callers that have not opted in.
func TestTFTPHandleWRQ_RateLimitDisabledByDefault(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 2 * time.Second})
	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer server.Shutdown()

	var hitCount int32
	server.SetWriteHandler(func(filename string, data []byte, addr net.Addr) error {
		atomic.AddInt32(&hitCount, 1)
		return nil
	})
	// Deliberately do NOT call SetMinWRQInterval.

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)
	if err := runWRQ(t, serverAddr, "fgt_a_config", []byte("hello")); err != nil {
		t.Fatalf("WRQ #1: %v", err)
	}
	if err := runWRQ(t, serverAddr, "fgt_b_config", []byte("world")); err != nil {
		t.Fatalf("WRQ #2: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&hitCount) == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("expected 2 handler invocations (rate limit off by default), got %d",
		atomic.LoadInt32(&hitCount))
}

// TestTFTPSetAllowedSourceIPs_NormalizesIPv4Mapped exercises the
// net.ParseIP(...).String() normalization that lets callers pass either
// dotted-quad or IPv4-mapped IPv6 forms.
func TestTFTPSetAllowedSourceIPs_NormalizesIPv4Mapped(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 1 * time.Second})
	server.SetAllowedSourceIPs([]string{"::ffff:127.0.0.1"})

	if !server.isSourceAllowed(net.ParseIP("127.0.0.1")) {
		t.Errorf("expected 127.0.0.1 to be allowed when allowlist contains ::ffff:127.0.0.1")
	}
	if server.isSourceAllowed(net.ParseIP("127.0.0.2")) {
		t.Errorf("expected 127.0.0.2 NOT to match an allowlist of ::ffff:127.0.0.1")
	}
}

// TestTFTPSetAllowedSourceIPs_NilSemantics verifies the nil / empty / set
// tri-state of the allowlist API:
//   - nil   -> no policy (allow all). Backward compatible default.
//   - [...] -> only listed IPs.
//   - nil again -> reset to allow-all.
func TestTFTPSetAllowedSourceIPs_NilSemantics(t *testing.T) {
	server := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 1 * time.Second})

	if !server.isSourceAllowed(net.ParseIP("127.0.0.1")) {
		t.Error("default (nil allowlist) should allow all peers")
	}
	if !server.isSourceAllowed(net.ParseIP("10.20.30.40")) {
		t.Error("default (nil allowlist) should allow 10.20.30.40 too")
	}

	server.SetAllowedSourceIPs([]string{"192.0.2.1"})
	if server.isSourceAllowed(net.ParseIP("127.0.0.1")) {
		t.Error("after SetAllowedSourceIPs([192.0.2.1]) 127.0.0.1 should be blocked")
	}
	if !server.isSourceAllowed(net.ParseIP("192.0.2.1")) {
		t.Error("after SetAllowedSourceIPs([192.0.2.1]) 192.0.2.1 should be allowed")
	}

	server.SetAllowedSourceIPs(nil)
	if !server.isSourceAllowed(net.ParseIP("127.0.0.1")) {
		t.Error("after SetAllowedSourceIPs(nil) the policy should be cleared (allow all)")
	}
}
