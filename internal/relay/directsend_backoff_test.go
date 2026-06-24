package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/relay/queue"
)

// TestDoDirectSend_SingleAttemptThenBuffers pins the H9 (v1.2.132) contract:
// doDirectSend makes exactly ONE live attempt and, on a transient failure,
// buffers the payload to the metric spillover queue instead of burning multiple
// seconds of inline expBackoff per metric per device. Durability now comes from
// the queue (drained on recovery, survives restart), not inline retries — so a
// server outage must NOT block the poll loop with multi-second sleeps. This test
// fails if a future change reintroduces the inline retry loop.
func TestDoDirectSend_SingleAttemptThenBuffers(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError) // persistent 500 (transient)
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
		metricQueue:   open("metrics"),
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
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("server call count = %d, want 1 (single attempt; no inline retry loop)", got)
	}
	// No multi-second inline backoff: the call returns promptly and buffers.
	if elapsed > 1*time.Second {
		t.Errorf("elapsed = %v, want <1s (inline expBackoff retries must be gone)", elapsed)
	}
	if d := c.metricQueue.Depth(); d != 1 {
		t.Errorf("metric queue depth = %d, want 1 (failed send must be buffered, not dropped)", d)
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
		Config:        Config{ServerURL: srv.URL, RegistrationKey: "test-key"},
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
