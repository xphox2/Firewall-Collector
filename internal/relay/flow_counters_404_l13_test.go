package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestSendBatch_FlowCounters404DropsNotDeapprove_L13 pins the 2026-07-01 audit
// L13 fix: a 404 on the schema-v2-only /flow-counters endpoint (a server rolled
// back to v1 no longer serves it) must be read as "endpoint unsupported — drop
// this batch" rather than "probe deleted". Pre-fix, sendBatch flipped
// approved=false and re-registered on that 404, so a buffered counter backlog
// flapped the probe's approval and forced a re-register on every sync.
func TestSendBatch_FlowCounters404DropsNotDeapprove_L13(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNotFound) // endpoint gone on a rolled-back server
	}))
	defer srv.Close()

	c := &Client{
		Config:     Config{ServerURL: srv.URL, RegistrationKey: "test-key"},
		httpClient: srv.Client(),
	}
	c.probeID = 42
	c.approved.Store(true)
	c.negotiatedSchema.Store(2)

	ok := c.sendBatch(srv.URL+"/flow-counters", "flow-counters", []map[string]any{{"if_index": 1}})

	if !ok {
		t.Error("sendBatch returned false — the batch would be requeued and 404 forever; want true (dropped)")
	}
	if !c.approved.Load() {
		t.Error("probe was deapproved on a /flow-counters 404 — that's the L13 approval flap")
	}
	if got := c.negotiatedSchema.Load(); got != 1 {
		t.Errorf("negotiatedSchema = %d, want 1 (downgrade recorded so counter sync stops)", got)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("server calls = %d, want 1 (no retry/re-register storm on the 404)", got)
	}
}

// TestSendBatch_CoreEndpoint404StillReregisters_L13 confirms the fix is scoped:
// a 404 on a CORE endpoint (e.g. /flows) still means "probe deleted" and must
// keep driving the deapprove + re-register path — otherwise a genuinely deleted
// probe would go unnoticed.
func TestSendBatch_CoreEndpoint404StillReregisters_L13(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Client{
		Config:     Config{ServerURL: srv.URL, RegistrationKey: "test-key"},
		httpClient: srv.Client(),
	}
	c.probeID = 42
	c.approved.Store(true)
	c.negotiatedSchema.Store(2)

	// tryReregister will hit the same 404 server and fail, so sendBatch returns
	// false — but the point is it took the deapprove path, not the drop path.
	_ = c.sendBatch(srv.URL+"/flows", "flows", []map[string]any{{"src": "1.1.1.1"}})

	if c.approved.Load() {
		t.Error("a /flows 404 must still deapprove the probe (real probe-deleted signal)")
	}
}
