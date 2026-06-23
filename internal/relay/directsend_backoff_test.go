package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/relay/queue"
)

// TestDoDirectSend_BackoffUsesExpBackoff pins that the retry-with-backoff
// loop in doDirectSend uses the extracted expBackoff helper (1s, 2s, 4s
// for attempts 0, 1, 2) rather than the previous hardcoded 2s sleep. The
// audit found that 1.2.127 extracted the helper for sendBatch and
// sendOneRevisionWithRetry but missed this third call site; this test
// fails if a future refactor regresses back to a constant sleep.
//
// Wall-clock is real: the test takes ~3s (1s + 2s of expBackoff sleeps
// between the 3 attempts). Tolerance is loose because Go scheduler +
// HTTP RTT can add tens of milliseconds.
func TestDoDirectSend_BackoffUsesExpBackoff(t *testing.T) {
	var (
		callTimes []time.Time
		callMu    sync.Mutex
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callMu.Lock()
		callTimes = append(callTimes, time.Now())
		callMu.Unlock()
		// Drain the body so the connection can be reused.
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	open := func(name string) *queue.SpilloverQueue {
		q, err := queue.Open(queue.Config{
			Path:   filepath.Join(dir, name+".bolt"),
			Bucket: name,
			MaxMem: maxQueueSize,
		})
		if err != nil {
			t.Fatalf("open %s queue: %v", name, err)
		}
		t.Cleanup(func() { _ = q.Close() })
		return q
	}
	c := &Client{
		Config: Config{
			ServerURL:       srv.URL,
			RegistrationKey: "test-key",
		},
		httpClient:    srv.Client(),
		trapQueue:     open("traps"),
		pingQueue:     open("pings"),
		syslogQueue:   open("syslog"),
		flowQueue:     open("flows"),
		revisionQueue: open("revisions"),
	}
	c.probeID = 42
	c.approved.Store(true)
	c.stopChan = make(chan struct{})
	c.done = make(chan struct{})

	start := time.Now()
	err := c.SendSystemStatuses([]SystemStatus{{Hostname: "test", Timestamp: time.Now()}})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on persistent 500, got nil")
	}
	callMu.Lock()
	calls := append([]time.Time(nil), callTimes...)
	callMu.Unlock()

	if got := len(calls); got != 3 {
		t.Fatalf("server call count = %d, want 3 (initial + 2 retries)", got)
	}

	// Gap between call 0 and call 1 must be ~expBackoff(0) = 1s.
	// Gap between call 1 and call 2 must be ~expBackoff(1) = 2s.
	gap1 := calls[1].Sub(calls[0])
	gap2 := calls[2].Sub(calls[1])
	totalGap := gap1 + gap2

	// Tolerances: lower bound is the helper value minus 50ms scheduler
	// slop; upper bound is generous to allow CI jitter.
	const slack = 100 * time.Millisecond
	if gap1 < 1*time.Second-slack {
		t.Errorf("gap[0->1] = %v, want ~1s (expBackoff(0)); doDirectSend may have regressed to a constant sleep", gap1)
	}
	if gap1 > 1*time.Second+2*time.Second {
		t.Errorf("gap[0->1] = %v, suspiciously long for expBackoff(0)=1s", gap1)
	}
	if gap2 < 2*time.Second-slack {
		t.Errorf("gap[1->2] = %v, want ~2s (expBackoff(1)); doDirectSend may have regressed to a constant sleep", gap2)
	}
	if gap2 > 2*time.Second+2*time.Second {
		t.Errorf("gap[1->2] = %v, suspiciously long for expBackoff(1)=2s", gap2)
	}

	// Sanity: total wall-clock should be ~3s (1s + 2s) plus a bit of
	// HTTP RTT. The audit's old behavior was ~4s (2s + 2s); if we
	// regress back to constant 2s, this assertion fires too.
	if elapsed < 3*time.Second-slack {
		t.Errorf("total elapsed = %v, want ~3s (expBackoff(0)+expBackoff(1)); constant 2s sleep would yield ~4s", elapsed)
	}
	if elapsed > 3*time.Second+3*time.Second {
		t.Errorf("total elapsed = %v, suspiciously long", elapsed)
	}

	// And: total wall-clock should be NOTICEABLY less than the old
	// constant-2s behavior (4s + RTT). If this test ever measures ~4s,
	// the helper application was reverted.
	if totalGap > 3500*time.Millisecond {
		t.Errorf("retry gaps total = %v, want ~3s; a regression to constant 2s sleep would yield ~4s", totalGap)
	}
}

// TestDoDirectSend_SuccessOnFirstTry_SkipsBackoff sanity-checks that
// the helper is NOT called when the first attempt succeeds. Cheap,
// non-flaky, pins the success path.
func TestDoDirectSend_SuccessOnFirstTry_SkipsBackoff(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	open := func(name string) *queue.SpilloverQueue {
		q, _ := queue.Open(queue.Config{Path: filepath.Join(dir, name+".bolt"), Bucket: name, MaxMem: maxQueueSize})
		t.Cleanup(func() { _ = q.Close() })
		return q
	}
	c := &Client{
		Config:         Config{ServerURL: srv.URL, RegistrationKey: "test-key"},
		httpClient:     srv.Client(),
		trapQueue:      open("traps"),
		pingQueue:      open("pings"),
		syslogQueue:    open("syslog"),
		flowQueue:      open("flows"),
		revisionQueue:  open("revisions"),
	}
	c.probeID = 42
	c.approved.Store(true)
	c.stopChan = make(chan struct{})
	c.done = make(chan struct{})

	start := time.Now()
	if err := c.SendSystemStatuses([]SystemStatus{{Hostname: "test", Timestamp: time.Now()}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("success-path elapsed = %v, want <500ms (no backoff should fire)", elapsed)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("call count = %d, want 1", got)
	}
}