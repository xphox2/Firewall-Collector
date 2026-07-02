package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestContentBatchID_DeterministicAndDistinct_M19 pins the M19 (2026-07-01
// audit) contract: batch ids are derived from the payload CONTENT, so an
// identical body always carries the identical id (stable across retries,
// sync-cycle requeues, and process restarts — the server dedupes a
// timed-out-but-committed batch whenever it comes back), while distinct
// payloads get distinct ids (every payload embeds collector-stamped
// timestamps, so distinct collections never collide).
func TestContentBatchID_DeterministicAndDistinct_M19(t *testing.T) {
	a1 := contentBatchID([]byte(`[{"m":"x","ts":"2026-07-01T00:00:01Z"}]`))
	a2 := contentBatchID([]byte(`[{"m":"x","ts":"2026-07-01T00:00:01Z"}]`))
	b := contentBatchID([]byte(`[{"m":"x","ts":"2026-07-01T00:00:02Z"}]`))
	if a1 == "" {
		t.Fatal("contentBatchID returned empty")
	}
	if a1 != a2 {
		t.Errorf("identical payloads got different ids (%s vs %s) — replay dedup would fail", a1, a2)
	}
	if a1 == b {
		t.Error("distinct payloads collided — dedup would wrongly drop real data")
	}
}

// TestSendBatch_StableBatchIDAcrossRetries_AUDIT042 is the crux of AUDIT-042:
// the X-Probe-Batch-ID must be IDENTICAL across a batch's retry attempts, so the
// server can recognise a retried batch and dedupe it. A per-attempt id would
// defeat dedup entirely.
func TestSendBatch_StableBatchIDAcrossRetries_AUDIT042(t *testing.T) {
	var mu sync.Mutex
	var ids []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ids = append(ids, r.Header.Get("X-Probe-Batch-ID"))
		n := len(ids)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // force exactly one retry
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{Config: Config{RegistrationKey: "test"}, httpClient: srv.Client()}
	if ok := c.sendBatch(srv.URL, "syslog", []map[string]string{{"m": "x"}}); !ok {
		t.Fatal("sendBatch returned false (expected success on retry)")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ids) < 2 {
		t.Fatalf("expected >=2 attempts (one retry), got %d", len(ids))
	}
	if strings.TrimSpace(ids[0]) == "" {
		t.Fatal("X-Probe-Batch-ID header was not sent")
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Errorf("attempt %d id %q != first attempt %q — batch id must be stable across retries", i+1, id, ids[0])
		}
	}
}
