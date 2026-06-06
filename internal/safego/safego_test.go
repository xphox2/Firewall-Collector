package safego

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withCapturedLog runs fn with the package's logf swapped for one that
// captures output into a buffer. Waits for `expected` log calls to complete
// before returning the buffer's contents, so the test never reads while a
// goroutine is still writing. The buffer is protected by a mutex because
// Go's race detector doesn't infer happens-before from the atomic counter
// alone — a concurrent goroutine could still be inside Fprintf when the
// test calls String, even if the counter has already incremented. The
// mutex makes the write/read pair serializable.
func withCapturedLog(t *testing.T, expected int, fn func()) string {
	t.Helper()
	var (
		mu      sync.Mutex
		buf     bytes.Buffer
		counter int32
	)
	saved := logf
	logf = func(format string, args ...interface{}) {
		atomic.AddInt32(&counter, 1)
		mu.Lock()
		fmt.Fprintf(&buf, format, args...)
		mu.Unlock()
	}
	defer func() { logf = saved }()
	fn()
	waitForCount(t, &counter, int32(expected), 2*time.Second)
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	return out
}

// withCountingLogf swaps the package's logf for one that increments an
// atomic counter on every call. Returns the counter pointer and a restore
// function. Necessary for tests where the panic is recovered in a goroutine
// that has no other signal to the test (wg.Wait() can return before the
// recover completes).
func withCountingLogf() (*int32, func()) {
	var counter int32
	saved := logf
	logf = func(format string, args ...interface{}) {
		atomic.AddInt32(&counter, 1)
	}
	return &counter, func() { logf = saved }
}

func waitForCount(t *testing.T, counter *int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for atomic.LoadInt32(counter) < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for count %d, got %d", want, atomic.LoadInt32(counter))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGo_NormalReturn_NoLog(t *testing.T) {
	counter, restore := withCountingLogf()
	defer restore()
	var wg sync.WaitGroup
	wg.Add(1)
	Go("normal", func() { defer wg.Done() })
	wg.Wait()
	if got := atomic.LoadInt32(counter); got != 0 {
		t.Errorf("expected no log output, got %d calls", got)
	}
}

func TestGo_PanicCaught_ProcessSurvives(t *testing.T) {
	var ran int32
	out := withCapturedLog(t, 1, func() {
		var wg sync.WaitGroup
		wg.Add(2)
		Go("panicker", func() {
			defer wg.Done()
			atomic.StoreInt32(&ran, 1)
			panic("boom")
		})
		Go("survivor", func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&ran, 1)
		})
		wg.Wait()
	})

	if got := atomic.LoadInt32(&ran); got != 2 {
		t.Fatalf("expected both goroutines to run, ran=%d", got)
	}
	if !strings.Contains(out, "PANIC in panicker") {
		t.Errorf("log should mention 'PANIC in panicker', got: %q", out)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("log should contain the panic value, got: %q", out)
	}
	if !strings.Contains(out, "goroutine") {
		t.Errorf("log should include a stack trace, got: %q", out)
	}
}

func TestGo_ManyConcurrentPanics_AllCaught(t *testing.T) {
	const n = 100
	counter, restore := withCountingLogf()
	defer restore()
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		Go("concurrent", func() {
			defer wg.Done()
			panic("concurrent boom")
		})
	}
	wg.Wait()
	waitForCount(t, counter, n, 2*time.Second)
}

func TestGo_DefersStillRun(t *testing.T) {
	var ran int32
	withCapturedLog(t, 1, func() {
		var wg sync.WaitGroup
		wg.Add(1)
		Go("defer-check", func() {
			defer wg.Done()
			defer func() { atomic.StoreInt32(&ran, 1) }()
			panic("after defer")
		})
		wg.Wait()
	})
	if got := atomic.LoadInt32(&ran); got != 1 {
		t.Errorf("expected defer to run, ran=%d", got)
	}
}

func TestAfterFunc_PanicCaught(t *testing.T) {
	counter, restore := withCountingLogf()
	defer restore()
	timer := AfterFunc(10*time.Millisecond, "debouncer", func() {
		panic("timer boom")
	})
	waitForCount(t, counter, 1, 2*time.Second)
	_ = timer.Stop()
}

func TestAfterFunc_NameAppearsInLog(t *testing.T) {
	out := withCapturedLog(t, 1, func() {
		timer := AfterFunc(time.Millisecond, "named-timer", func() {
			panic("named-boom")
		})
		// Wait for the timer to fire. The new withCapturedLog
		// will block on the expected-count, so we don't need
		// a separate sleep here.
		_ = timer
	})
	for _, want := range []string{"PANIC in timer:named-timer", "named-boom", "goroutine"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q; got: %q", want, out)
		}
	}
}

func TestAfterFunc_ReturnsUsableTimer(t *testing.T) {
	timer := AfterFunc(time.Hour, "never-fires", func() {})
	if timer == nil {
		t.Fatal("AfterFunc returned nil")
	}
	if !timer.Stop() {
		t.Fatal("Stop on unexpired timer should return true")
	}
}

func TestRecoverPanic_NilNoOp(t *testing.T) {
	counter, restore := withCountingLogf()
	defer restore()
	recoverPanic("noop")
	if got := atomic.LoadInt32(counter); got != 0 {
		t.Errorf("recoverPanic with no panic should not log, got %d calls", got)
	}
}

func TestGo_NameAppearsInLog(t *testing.T) {
	// Confirms the `name` argument is included in the formatted output, since
	// it's the only handle for an operator to identify which goroutine died.
	out := withCapturedLog(t, 1, func() {
		var wg sync.WaitGroup
		wg.Add(1)
		Go("specific-name-xyz", func() {
			defer wg.Done()
			panic("see-name")
		})
		wg.Wait()
	})
	for _, want := range []string{"specific-name-xyz", "see-name", "goroutine"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q; got: %q", want, out)
		}
	}
}

func TestGo_HighConcurrencyNoDeadlock(t *testing.T) {
	// A panic in the recover path should not deadlock the wrapping goroutine
	// (would happen if recoverPanic itself panicked). Spawn many to exercise.
	const n = 1000
	counter, restore := withCountingLogf()
	defer restore()
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		Go("deadlock-test", func() {
			defer wg.Done()
			panic(fmt.Sprintf("boom-%d", i))
		})
	}
	wg.Wait()
	waitForCount(t, counter, n, 5*time.Second)
}
