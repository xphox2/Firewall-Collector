package tftp

import (
	"testing"
	"time"
)

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
