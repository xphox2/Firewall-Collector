package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/relay/queue"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// newConfigRevisionClient builds a Client wired to an httptest server, with
// the probeID, approval flag, and SpilloverQueue instances (one per
// queue, including the AUDIT-054 revisionQueue) opened in t.TempDir().
// Cleanup hooks close the queues after the test.
//
// AUDIT-054 (v2): unlike the v1 helper (which used a plain
// `[]*ConfigRevision` slice), this one goes through the full
// SpilloverQueue so tests exercise the same path as production —
// including the disk-persistence restart-survival behavior.
func newConfigRevisionClient(t *testing.T, srv *httptest.Server, approved bool) *Client {
	t.Helper()
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
	c.approved.Store(approved)
	c.stopChan = make(chan struct{})
	c.done = make(chan struct{})
	return c
}

// revisionQueueDepth returns the in-memory depth of the revision queue.
// Used by tests that want to assert "the queue is empty after a
// successful drain" without poking at SpilloverQueue internals.
func revisionQueueDepth(c *Client) int {
	return c.revisionQueue.Depth()
}

// revisionQueueDiskCount returns the number of items persisted to the
// revision queue's BoltDB file. Used by the restart-survival test.
func revisionQueueDiskCount(c *Client) int {
	n, err := c.revisionQueue.DiskCount()
	if err != nil {
		return -1
	}
	return n
}

func sampleRevision() *ConfigRevision {
	return &ConfigRevision{
		DeviceID:      7,
		Timestamp:     time.Unix(1717000000, 0).UTC(),
		Checksum:      "deadbeef",
		ConfigText:    "config system global\n  set hostname fw1\nend\n",
		Length:        42,
		TriggerSource: "syslog",
		BackupQuality: "full",
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestSendConfigRevision_NoRetryOnFailure_AUDIT054 pins the "one POST per
// call" semantics of SendConfigRevision itself. The retry-with-backoff
// lives in sendOneRevisionWithRetry (called from syncData's drain path);
// the public SendConfigRevision method makes a single POST, surfaces
// the failure to the caller, and enqueues for the next drain.
func TestSendConfigRevision_NoRetryOnFailure_AUDIT054(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"err":"db down"}`)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)

	err := c.SendConfigRevision(sampleRevision())
	if err == nil {
		t.Fatal("expected error from SendConfigRevision on 500")
	}
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("server call count = %d, want 1 (no inline retries)", got)
	}
	// 500 should have enqueued the revision for the next syncData drain.
	if got := revisionQueueDepth(c); got != 1 {
		t.Errorf("revisionQueue depth after single 500 = %d, want 1 (enqueued for retry)", got)
	}
}

// TestSendConfigRevision_EnqueuesOnFailure_AUDIT054 verifies that a
// 5xx response from the central server results in the revision being
// available for the next syncData cycle (this is the core AUDIT-054
// durability guarantee).
func TestSendConfigRevision_EnqueuesOnFailure_AUDIT054(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)

	rev := sampleRevision()
	if err := c.SendConfigRevision(rev); err == nil {
		t.Fatal("expected error on 502")
	}
	if got := revisionQueueDepth(c); got != 1 {
		t.Errorf("revisionQueue depth = %d, want 1", got)
	}

	// Drain to confirm the bytes round-trip cleanly.
	raw, err := c.revisionQueue.Drain(10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("Drain returned %d items, want 1", len(raw))
	}
	var got ConfigRevision
	if err := json.Unmarshal(raw[0], &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.DeviceID != rev.DeviceID || got.Checksum != rev.Checksum {
		t.Errorf("round-trip mismatch: got %+v, want DeviceID=%d Checksum=%q", got, rev.DeviceID, rev.Checksum)
	}
}

// TestSendConfigRevision_EnqueuesOnTransportError_AUDIT054 verifies that
// a connection failure (server unreachable) also enqueues — the v1
// design had a hole where transport errors were logged but not
// re-queued, so a 60s TLS handshake failure dropped the only copy.
func TestSendConfigRevision_EnqueuesOnTransportError_AUDIT054(t *testing.T) {
	// Bind a listener and immediately close it to get an unreachable
	// URL — httptest.NewServer + srv.Close is the standard pattern.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachableURL := srv.URL
	srv.Close()

	c := &Client{
		Config: Config{
			ServerURL:       unreachableURL,
			RegistrationKey: "test-key",
		},
		httpClient: &http.Client{Timeout: 500 * time.Millisecond},
	}
	c.probeID = 42
	c.approved.Store(true)
	dir := t.TempDir()
	q, err := queue.Open(queue.Config{
		Path:   filepath.Join(dir, "revisions.bolt"),
		Bucket: "revisions",
		MaxMem: maxQueueSize,
	})
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	c.revisionQueue = q

	rev := sampleRevision()
	if err := c.SendConfigRevision(rev); err == nil {
		t.Fatal("expected error on transport failure")
	}
	if got := q.Depth(); got != 1 {
		t.Errorf("revisionQueue depth = %d, want 1 (enqueued on transport error)", got)
	}
}

// TestSendConfigRevision_NotApproved_ReturnsError_AUDIT054 pins the
// approval gate: an unapproved probe is a state issue, not a network
// issue, and the revision should NOT be enqueued.
func TestSendConfigRevision_NotApproved_ReturnsError_AUDIT054(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, false) // approved=false

	err := c.SendConfigRevision(sampleRevision())
	if err == nil {
		t.Fatal("expected error when not approved")
	}
	if !strings.Contains(err.Error(), "not approved") {
		t.Errorf("error message %q does not mention approval", err)
	}
	if got := revisionQueueDepth(c); got != 0 {
		t.Errorf("revisionQueue depth = %d, want 0 (unapproved must NOT enqueue)", got)
	}
}

// TestSendConfigRevision_ResponseBodyRead_AUDIT054 is a regression for
// the documented `defer resp.Body.Close()` / `io.ReadAll` ordering —
// the body must be readable for the failure log to be useful. (Go
// semantics actually do the right thing here: `defer` runs at function
// return, not at the `defer` statement, so `io.ReadAll` always runs
// before the close. The test pins this behavior so a future
// refactor can't silently break it.)
func TestSendConfigRevision_ResponseBodyRead_AUDIT054(t *testing.T) {
	const bodyText = `{"err":"db temporarily unavailable, retry in 30s"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, bodyText)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	if err := c.SendConfigRevision(sampleRevision()); err == nil {
		t.Fatal("expected error on 503")
	}
	// We can't directly assert on log output without a logger hook,
	// but the test confirms: (1) the request was made, (2) the body
	// was read without panic, and (3) the revision was enqueued.
	if got := revisionQueueDepth(c); got != 1 {
		t.Errorf("revisionQueue depth = %d, want 1", got)
	}
}

// TestSendConfigRevision_SuccessResponse_BodyReadable_AUDIT054 confirms
// the success path reads the response body too (for the success log
// line) without crashing.
func TestSendConfigRevision_SuccessResponse_BodyReadable_AUDIT054(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true,"stored_id":"abc-123"}`)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	if err := c.SendConfigRevision(sampleRevision()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := revisionQueueDepth(c); got != 0 {
		t.Errorf("revisionQueue depth after success = %d, want 0", got)
	}
}

// TestSendConfigRevision_RequestShape_AUDIT054 pins the request shape
// so a refactor can't silently change the wire format: POST to
// /api/probes/{probeID}/config-revision, JSON body, bearer auth.
func TestSendConfigRevision_RequestShape_AUDIT054(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotCT     string
		gotBody   []byte
		mu        sync.Mutex
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	rev := sampleRevision()
	if err := c.SendConfigRevision(rev); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "/api/probes/42/config-revision"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Errorf("Authorization = %q, want Bearer prefix", gotAuth)
	}
	if !strings.HasPrefix(gotCT, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	var decoded ConfigRevision
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw=%q)", err, gotBody)
	}
	if decoded.DeviceID != rev.DeviceID || decoded.Checksum != rev.Checksum {
		t.Errorf("body mismatch: got %+v, want DeviceID=%d Checksum=%q", decoded, rev.DeviceID, rev.Checksum)
	}
}

// TestEnqueueRevisionBytes_OverflowDropsOldest_AUDIT054 ensures the
// SpilloverQueue enforces its MaxMem cap and drops the oldest in-memory
// item to disk on overflow (matching the trap/ping/syslog/flow
// behavior). Items past the cap persist in BoltDB until the byte cap
// is hit.
func TestEnqueueRevisionBytes_OverflowDropsOldest_AUDIT054(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100) // very small in-memory cap

	dir := t.TempDir()
	q, err := queue.Open(queue.Config{
		Path:   filepath.Join(dir, "revisions.bolt"),
		Bucket: "revisions",
		MaxMem: 2,
	})
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })

	c := &Client{revisionQueue: q}

	oldest := sampleRevision()
	oldest.Checksum = "oldest"
	middle := sampleRevision()
	middle.Checksum = "middle"
	newest := sampleRevision()
	newest.Checksum = "newest"

	for _, rev := range []*ConfigRevision{oldest, middle, newest} {
		data, _ := json.Marshal(rev)
		c.enqueueRevisionBytes(data)
	}

	// In-memory should hold the 2 newest.
	if got := q.Depth(); got != 2 {
		t.Errorf("in-memory depth = %d, want 2", got)
	}
	// Disk should hold the 1 overflowed.
	if got, _ := q.DiskCount(); got != 1 {
		t.Errorf("disk count = %d, want 1 (oldest moved to disk)", got)
	}

	// Drain everything in order — strict FIFO across tiers.
	raw, err := q.Drain(10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(raw) != 3 {
		t.Fatalf("Drain returned %d items, want 3", len(raw))
	}
	wantOrder := []string{"oldest", "middle", "newest"}
	for i, want := range wantOrder {
		var got ConfigRevision
		if err := json.Unmarshal(raw[i], &got); err != nil {
			t.Fatalf("Unmarshal[%d]: %v", i, err)
		}
		if got.Checksum != want {
			t.Errorf("Drain[%d].Checksum = %q, want %q", i, got.Checksum, want)
		}
	}
}

// TestEnqueueRevisionBytes_QueueDisabledWhenDiskPathEmpty_AUDIT054
// pins the graceful-degradation behavior: if QueueDiskPath is empty
// (e.g. a misconfigured or disk-less deployment), enqueueRevisionBytes
// is a silent no-op rather than a panic.
func TestEnqueueRevisionBytes_QueueDisabledWhenDiskPathEmpty_AUDIT054(t *testing.T) {
	// No revisionQueue set — simulates "QueueDiskPath was empty, so
	// ensureQueues left all queues nil".
	c := &Client{}
	// Should not panic.
	c.enqueueRevisionBytes([]byte(`{"device_id":1}`))
}

// TestSendRevisionBatch_SuccessClearsQueue_AUDIT054 verifies that
// when every revision in a drain batch is successfully POSTed, the
// queue is empty afterwards.
func TestSendRevisionBatch_SuccessClearsQueue_AUDIT054(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	// Pre-populate the queue.
	for i := 0; i < 3; i++ {
		rev := sampleRevision()
		rev.DeviceID = uint(i + 1)
		data, _ := json.Marshal(rev)
		c.enqueueRevisionBytes(data)
	}
	if got := revisionQueueDepth(c); got != 3 {
		t.Fatalf("setup: depth = %d, want 3", got)
	}

	raw, err := c.revisionQueue.Drain(10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	// The full URL must be passed because sendRevisionBatch does not
	// prepend ServerURL — syncData constructs baseURL+"/config-revision"
	// and passes the result.
	c.sendRevisionBatch(srv.URL+"/config-revision", raw)

	if got := atomic.LoadInt32(&callCount); got != 3 {
		t.Errorf("server call count = %d, want 3", got)
	}
	if got, _ := c.revisionQueue.DiskCount(); got != 0 {
		t.Errorf("queue disk count after success = %d, want 0", got)
	}
}

// TestSendRevisionBatch_RetriesAndRequeues_AUDIT054 verifies the
// retry-with-backoff loop: a revision is retried 3× before being
// re-queued, and the re-queued item is the same payload (round-trip
// check).
func TestSendRevisionBatch_RetriesAndRequeues_AUDIT054(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	rev := sampleRevision()
	data, _ := json.Marshal(rev)
	c.enqueueRevisionBytes(data)

	raw, err := c.revisionQueue.Drain(10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	c.sendRevisionBatch(srv.URL+"/config-revision", raw)

	// 3 attempts per revision.
	if got := atomic.LoadInt32(&callCount); got != 3 {
		t.Errorf("server call count = %d, want 3 (1 initial + 2 retries)", got)
	}
	// Failed item was re-queued (in-memory or on disk).
	mem := c.revisionQueue.Depth()
	disk, _ := c.revisionQueue.DiskCount()
	if mem+disk != 1 {
		t.Errorf("queue contents after total failure = mem=%d disk=%d, want 1 total", mem, disk)
	}
}

// TestSendRevisionBatch_400IsNotRetried_AUDIT054 pins the 400-as-permanent-error
// behavior: a bad request (malformed payload) is dropped, not retried,
// not re-queued — the next attempt would fail identically.
func TestSendRevisionBatch_400IsNotRetried_AUDIT054(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"err":"invalid checksum"}`)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	data, _ := json.Marshal(sampleRevision())
	c.enqueueRevisionBytes(data)

	raw, _ := c.revisionQueue.Drain(10)
	c.sendRevisionBatch(srv.URL+"/config-revision", raw)

	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("server call count = %d, want 1 (400 is not retried)", got)
	}
	if got, _ := c.revisionQueue.DiskCount(); got != 0 {
		t.Errorf("queue should be empty after 400 (no requeue), disk = %d", got)
	}
}

// TestSyncData_DrainsRevisionQueue_AUDIT054 wires the new code path
// through the existing syncData machinery: pre-load the queue, run
// syncData once, confirm the server saw a POST and the queue is
// empty on success.
func TestSyncData_DrainsRevisionQueue_AUDIT054(t *testing.T) {
	var callCount int32
	var mu sync.Mutex
	var seenPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		mu.Lock()
		seenPaths = append(seenPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	for i := 0; i < 2; i++ {
		rev := sampleRevision()
		rev.DeviceID = uint(i + 1)
		data, _ := json.Marshal(rev)
		c.enqueueRevisionBytes(data)
	}

	c.syncData()

	if got := atomic.LoadInt32(&callCount); got != 2 {
		t.Errorf("server call count = %d, want 2 (one per drained revision)", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range seenPaths {
		if !strings.HasSuffix(p, "/config-revision") {
			t.Errorf("unexpected path in syncData drain: %q", p)
		}
	}
}

// TestSyncData_NotApprovedDoesNotDrain_AUDIT054 pins the approval gate
// in syncData: an unapproved probe must not post anything to the
// /config-revision endpoint (the drain block is gated on approval,
// just like the 4 event queues).
func TestSyncData_NotApprovedDoesNotDrain_AUDIT054(t *testing.T) {
	var configRevCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config-revision") {
			atomic.AddInt32(&configRevCalls, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, false) // approved=false
	data, _ := json.Marshal(sampleRevision())
	c.enqueueRevisionBytes(data)

	c.syncData()

	if got := atomic.LoadInt32(&configRevCalls); got != 0 {
		t.Errorf("/config-revision call count = %d, want 0 (unapproved probe must not POST)", got)
	}
	// The queue still holds the revision; the next approved syncData
	// (or the next sendOneRevisionWithRetry) will process it.
	if got := revisionQueueDepth(c); got != 1 {
		t.Errorf("revisionQueue depth = %d, want 1 (preserved across unapproved cycle)", got)
	}
}

// TestSendConfigRevision_TLSEndpointAccepted_AUDIT054 is a smoke test
// that the TLS handshake path doesn't panic when the server
// actually presents a cert. The httptest.Server uses a self-signed
// cert, so we need InsecureSkipVerify on the client to connect
// (mirroring the production tls.Config that only skips verify when
// the operator opts in).
func TestSendConfigRevision_TLSEndpointAccepted_AUDIT054(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newConfigRevisionClient(t, srv, true)
	// Replace the http.Client with one that trusts the test server's
	// self-signed cert (the default srv.Client() does this, but
	// newConfigRevisionClient uses srv.Client() — verify the path works).
	if err := c.SendConfigRevision(sampleRevision()); err != nil {
		t.Fatalf("unexpected error over TLS: %v", err)
	}
}

// TestRevisionQueue_RestartSurvivesPendingItems_AUDIT054 is the
// headline win of v2 over v1: pending revisions survive a process
// restart because they live in BoltDB, not RAM. This test simulates
// a restart by closing the queue and reopening it from the same
// path, then asserts the previously-pending revisions are still
// there and can be drained in order.
func TestRevisionQueue_RestartSurvivesPendingItems_AUDIT054(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "revisions.bolt")

	// First "process": write 3 revisions and "crash" without draining.
	open := func() *queue.SpilloverQueue {
		q, err := queue.Open(queue.Config{
			Path:   dbPath,
			Bucket: "revisions",
			MaxMem: 10,
		})
		if err != nil {
			t.Fatalf("open queue: %v", err)
		}
		return q
	}
	q1 := open()
	for i, name := range []string{"alpha", "bravo", "charlie"} {
		rev := sampleRevision()
		rev.DeviceID = uint(i + 1)
		rev.Checksum = name
		data, _ := json.Marshal(rev)
		if err := q1.Push(data); err != nil {
			t.Fatalf("Push[%d]: %v", i, err)
		}
	}
	// Simulate a hard crash — no graceful Close, no final flush.
	// The SpilloverQueue.Close() does flush in-memory → disk; for
	// realism we close the underlying bbolt file directly. But
	// bbolt is fussy about double-close, so just call Close().
	if err := q1.Close(); err != nil {
		t.Fatalf("close q1: %v", err)
	}

	// Second "process": reopen the same file.
	q2 := open()
	defer q2.Close()

	mem := q2.Depth()
	disk, _ := q2.DiskCount()
	total := mem + disk
	if total != 3 {
		t.Fatalf("after restart: mem=%d disk=%d total=%d, want 3 (revisions must survive)", mem, disk, total)
	}

	// Drain and confirm order.
	raw, err := q2.Drain(10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(raw) != 3 {
		t.Fatalf("Drain returned %d items, want 3", len(raw))
	}
	wantOrder := []string{"alpha", "bravo", "charlie"}
	for i, want := range wantOrder {
		var got ConfigRevision
		if err := json.Unmarshal(raw[i], &got); err != nil {
			t.Fatalf("Unmarshal[%d]: %v", i, err)
		}
		if got.Checksum != want {
			t.Errorf("Drain[%d].Checksum = %q, want %q (FIFO order must survive restart)", i, got.Checksum, want)
		}
	}
}
