package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"firewall-collector/internal/relay/queue"
)

// newMetricQueueClient builds a Client with only the metric spillover queue
// opened in t.TempDir(), wired to an httptest server. QueueDiskPath is left
// empty so doDirectSend's ensureQueues() call is a no-op that preserves this
// pre-opened queue.
func newMetricQueueClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	dir := t.TempDir()
	q, err := queue.Open(queue.Config{
		Path:   filepath.Join(dir, "metrics.bolt"),
		Bucket: "metrics",
		MaxMem: maxQueueSize,
	})
	if err != nil {
		t.Fatalf("open metric queue: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	c := &Client{
		Config:      Config{ServerURL: srv.URL, RegistrationKey: "test-key"},
		httpClient:  srv.Client(),
		metricQueue: q,
	}
	c.probeID = 42
	c.approved.Store(true)
	return c
}

// TestDoDirectSend_BuffersOnOutage_AndDrainsOnRecovery is the H9 regression:
// a failed primary-metric send must be buffered (not dropped), then re-sent to
// its correct endpoint when the server recovers.
func TestDoDirectSend_BuffersOnOutage_AndDrainsOnRecovery(t *testing.T) {
	var up atomic.Bool
	var gotPath atomic.Value
	var gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 — transient
			return
		}
		body, _ := io.ReadAll(r.Body)
		gotPath.Store(r.URL.Path)
		gotBody.Store(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newMetricQueueClient(t, srv)

	// Outage: the live send fails and must be buffered, not dropped.
	up.Store(false)
	if err := c.SendSystemStatuses([]SystemStatus{{DeviceID: 7}}); err == nil {
		t.Fatal("expected an error when the server is down")
	}
	if d := c.metricQueue.Depth(); d != 1 {
		t.Fatalf("metric queue depth = %d, want 1 (outage send must be buffered)", d)
	}

	// Recovery: the drain re-sends to the right endpoint and empties the queue.
	up.Store(true)
	c.drainMetricQueue(100)
	if d := c.metricQueue.Depth(); d != 0 {
		t.Fatalf("metric queue depth = %d after drain, want 0", d)
	}
	if p, _ := gotPath.Load().(string); p != "/api/probes/42/system-status" {
		t.Errorf("recovered POST path = %q, want /api/probes/42/system-status", p)
	}
	if b, _ := gotBody.Load().(string); b == "" {
		t.Error("recovered POST had empty body")
	}
}

// TestDoDirectSend_PermanentRejection_NotBuffered verifies a permanent 4xx is
// dropped (and NOT queued), so a malformed batch can never wedge the queue.
func TestDoDirectSend_PermanentRejection_NotBuffered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400 — permanent
	}))
	defer srv.Close()

	c := newMetricQueueClient(t, srv)
	if err := c.SendInterfaceStats([]InterfaceStats{{DeviceID: 1}}); err == nil {
		t.Fatal("expected an error on a 400 response")
	}
	if d := c.metricQueue.Depth(); d != 0 {
		t.Errorf("metric queue depth = %d, want 0 (permanent rejection must not be buffered)", d)
	}
}

// TestDrainMetricQueue_RequeuesOnStillDown verifies that if the server is still
// unreachable during a drain, the buffered item is requeued (not lost).
func TestDrainMetricQueue_RequeuesOnStillDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newMetricQueueClient(t, srv)
	// Buffer one item (send fails -> buffered).
	_ = c.SendVPNStatuses([]VPNStatus{{DeviceID: 3}})
	if d := c.metricQueue.Depth(); d != 1 {
		t.Fatalf("setup: depth = %d, want 1", d)
	}
	// Drain while still down: item must be requeued, not dropped.
	c.drainMetricQueue(100)
	if d := c.metricQueue.Depth(); d != 1 {
		t.Errorf("depth = %d after failed drain, want 1 (item must be requeued)", d)
	}
}
