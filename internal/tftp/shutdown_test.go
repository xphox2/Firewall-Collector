package tftp

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestServer_Shutdown_WaitsForRealWriteHandler drives the REAL handleWRQ path
// (a full WRQ transfer) with a slow write handler and asserts Shutdown blocks
// until that in-flight handler finishes. AUDIT-306: handleWRQ spawned the
// writeHandler callback (SendConfigRevision in prod) in a goroutine WITHOUT
// s.wg.Add(1), so Shutdown's s.wg.Wait() could return while a config revision
// was still being sent — losing it on shutdown. The handler sleeps longer than
// serve()'s 1s read-deadline exit latency, so on a reverted fix Shutdown
// returns (after serve exits) before the handler completes and this fails.
func TestServer_Shutdown_WaitsForRealWriteHandler(t *testing.T) {
	s := NewServer(&Config{Addr: "127.0.0.1:0", Timeout: 2 * time.Second})
	if err := s.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}

	handlerStarted := make(chan struct{})
	var handlerCompleted atomic.Bool
	s.SetWriteHandler(func(filename string, data []byte, addr net.Addr) error {
		close(handlerStarted)
		time.Sleep(2 * time.Second) // slow callback: config revision in flight
		handlerCompleted.Store(true)
		return nil
	})

	serverAddr := s.conn.LocalAddr().(*net.UDPAddr)
	if err := runWRQ(t, serverAddr, "fgt_42_config", []byte("hello world")); err != nil {
		t.Fatalf("runWRQ: %v", err)
	}

	select {
	case <-handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("write handler never started after a completed WRQ")
	}

	shutdownReturned := make(chan struct{})
	go func() {
		_ = s.Shutdown()
		close(shutdownReturned)
	}()

	select {
	case <-shutdownReturned:
		if !handlerCompleted.Load() {
			t.Fatal("Shutdown returned before the in-flight writeHandler completed (AUDIT-306: inner goroutine not tracked on s.wg)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return")
	}
}

// TestServer_Shutdown_WaitsForInFlightHandler verifies that Shutdown
// blocks while a tracked handler is in flight, then returns once the
// handler is released. Before AUDIT-053, the listener launched handler
// goroutines with `go s.handleWRQ(...)` and `go s.handleRRQ(...)` but
// never incremented s.wg, so `s.wg.Wait()` in Shutdown returned
// immediately — in-flight transfers were abandoned on shutdown.
func TestServer_Shutdown_WaitsForInFlightHandler(t *testing.T) {
	s := NewServer(&Config{
		Addr:    "127.0.0.1:0",
		Timeout: 100 * time.Millisecond,
	})
	if err := s.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}

	// Simulate an in-flight handler by incrementing the server's WG.
	// This is the same counter Shutdown waits on; the real production
	// path is `s.wg.Add(1)` at the top of handleWRQ/handleRRQ.
	s.wg.Add(1)

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- s.Shutdown() }()

	// Shutdown must still be running.
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned too early: err=%v", err)
	case <-time.After(100 * time.Millisecond):
		// Good - Shutdown is blocked on s.wg.
	}

	// Release the simulated in-flight work.
	s.wg.Done()

	// Shutdown must now return.
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Errorf("Shutdown returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after wg.Done()")
	}
}

// TestServer_Shutdown_Idempotent verifies that calling Shutdown twice
// does not panic. The first call sets running=false and closes stopCh;
// the second short-circuits at the `if !s.running` guard. This
// mirrors the Collector.stop() sync.Once fix at the package boundary.
func TestServer_Shutdown_Idempotent(t *testing.T) {
	s := NewServer(&Config{
		Addr:    "127.0.0.1:0",
		Timeout: 100 * time.Millisecond,
	})
	if err := s.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("first Shutdown returned err: %v", err)
	}
	// Second call must be a no-op, not a double-close panic.
	if err := s.Shutdown(); err != nil {
		t.Errorf("second Shutdown returned err: %v", err)
	}
}
