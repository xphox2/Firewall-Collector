package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestNewBatchID_UniqueNonEmpty_AUDIT042 pins that batch ids are non-empty and
// effectively unique (collisions would weaken server-side dedup).
func TestNewBatchID_UniqueNonEmpty_AUDIT042(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := newBatchID()
		if id == "" {
			t.Fatal("newBatchID returned empty")
		}
		if seen[id] {
			t.Fatalf("duplicate batch id: %s", id)
		}
		seen[id] = true
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
