package main

import (
	"sync"
	"testing"
	"time"
)

// TestCollectorStop_Idempotent verifies that calling stop() more than once
// does not panic. Before AUDIT-053, the second call would panic on
// `close(c.stopChan)` because the channel was already closed.
func TestCollectorStop_Idempotent(t *testing.T) {
	c := &Collector{
		stopChan: make(chan struct{}),
	}
	// First stop should close the channel.
	c.stop()
	// Second stop must be a no-op (sync.Once).
	c.stop()
	// Third, fourth, fifth — all no-ops.
	for i := 0; i < 3; i++ {
		c.stop()
	}
	// Channel is closed (and not double-closed, which would have panicked
	// in the un-fixed code).
	select {
	case <-c.stopChan:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("stopChan should be closed after first stop()")
	}
}

// TestCollectorStop_WaitsForSSHPolls verifies that stop() blocks until
// tracked SSH poll goroutines complete. Before AUDIT-053, sshPollWg did
// not exist; SSH goroutines could outlive stop() for up to 10 minutes
// (commandTimeout × 6 commands).
func TestCollectorStop_WaitsForSSHPolls(t *testing.T) {
	// Speed up the bounded-wait fallback for this test.
	prevTimeout := shutdownDrainTimeout
	shutdownDrainTimeout = 5 * time.Second
	defer func() { shutdownDrainTimeout = prevTimeout }()

	c := &Collector{
		stopChan: make(chan struct{}),
	}
	c.sshPollWg.Add(1)

	stopped := make(chan struct{})
	go func() {
		c.stop()
		close(stopped)
	}()

	// stop() should be blocked on the sshPollWg.
	select {
	case <-stopped:
		t.Fatal("stop() returned before sshPollWg was released")
	case <-time.After(100 * time.Millisecond):
		// Good - still waiting
	}

	// Release the WG. stop() should now return.
	c.sshPollWg.Done()

	select {
	case <-stopped:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return after sshPollWg was released")
	}
}

// TestCollectorStop_WaitsForPollWg is the SNMP counterpart of the SSH test.
// pollWg was already tracked before AUDIT-053, but the fix now also runs
// stop() through sync.Once, so the test ensures that path still works.
func TestCollectorStop_WaitsForPollWg(t *testing.T) {
	prevTimeout := shutdownDrainTimeout
	shutdownDrainTimeout = 5 * time.Second
	defer func() { shutdownDrainTimeout = prevTimeout }()

	c := &Collector{
		stopChan: make(chan struct{}),
	}
	c.pollWg.Add(1)

	stopped := make(chan struct{})
	go func() {
		c.stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("stop() returned before pollWg was released")
	case <-time.After(100 * time.Millisecond):
	}

	c.pollWg.Done()

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return after pollWg was released")
	}
}

// TestCollectorStop_BoundedWaitWhenStuck verifies the bounded-wait fallback:
// if a goroutine is stuck past shutdownDrainTimeout, stop() logs a warning
// and proceeds with shutdown instead of hanging forever. Uses a short
// override so the test runs in <1s.
func TestCollectorStop_BoundedWaitWhenStuck(t *testing.T) {
	prevTimeout := shutdownDrainTimeout
	shutdownDrainTimeout = 100 * time.Millisecond
	defer func() { shutdownDrainTimeout = prevTimeout }()

	c := &Collector{
		stopChan: make(chan struct{}),
	}
	// sshPollWg will never be released — simulates a stuck SSH session.
	c.sshPollWg.Add(1)
	defer c.sshPollWg.Done() // release after stop() returns

	start := time.Now()
	c.stop()
	elapsed := time.Since(start)

	// Must have waited approximately shutdownDrainTimeout (allow generous slack).
	if elapsed < 50*time.Millisecond {
		t.Fatalf("stop() returned too fast (%v); expected ~%v wait", elapsed, shutdownDrainTimeout)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("stop() took too long (%v); expected ~%v wait", elapsed, shutdownDrainTimeout)
	}
}

// TestCollectorStop_ConcurrentCalls exercises the case where multiple
// goroutines (e.g. the signal handler AND the metrics server's graceful
// shutdown) try to stop the collector at the same time. All but the first
// must be no-ops.
func TestCollectorStop_ConcurrentCalls(t *testing.T) {
	c := &Collector{
		stopChan: make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.stop()
		}()
	}
	wg.Wait()
}
