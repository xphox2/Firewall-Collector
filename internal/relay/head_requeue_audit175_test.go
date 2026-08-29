package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// Tests for the AUDIT-175 head-requeue + stop-drain fix and the AUDIT-213/214
// idempotency-key regression it narrows (full-size failed chunks replay
// byte-identically; partial-chunk regroups, overflow splits, and restarts
// remain the residual duplicate window).

// TestDrainAndSend_TransientFailureStopsDrain_NothingLost pins AUDIT-175: when
// the first chunk of a drain fails transiently (503 — server outage), the
// drain must STOP after requeuing the failed chunk plus the whole drained-but-
// unattempted tail to the queue head. Pre-fix, only the failed chunk was
// requeued and the tail of the drain was silently dropped — one syncData cycle
// during an outage collapsed an arbitrarily large disk spool to a single
// chunk.
func TestDrainAndSend_TransientFailureStopsDrain_NothingLost(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable) // outage: every send fails transiently
	}))
	defer srv.Close()

	c := newTestClient(t)
	c.Config = Config{ServerURL: srv.URL, RegistrationKey: "k", MaxBatchSize: 1}
	c.httpClient = srv.Client()

	const total = 6
	for i := 0; i < total; i++ {
		c.SendTrap(&TrapEvent{Message: string(rune('0' + i))})
	}

	// drainChunk 3 over 6 items: without the stop, the loop would Drain twice.
	drainAndSend(c, srv.URL+"/api/probes/42", 3, queueDrainSpec[TrapEvent]{
		queue: c.trapQueue, endpoint: "/traps", sendName: "traps",
		drainLabel: "traps", unmarshalLabel: "trap",
		noun: "traps", nounLong: "trap events",
	})

	// Chunk 0 (batch size 1) gets sendBatch's 3 in-call attempts; the drain
	// then stops — chunks 1-2 of the first Drain and the entire second Drain
	// must never be attempted.
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("server calls = %d, want 3 (only chunk 0's retries; the drain must stop on the transient failure)", got)
	}

	// Nothing lost: the failed chunk AND the unattempted tail were requeued,
	// and the second Drain never ran, so the queue still holds all 6 items —
	// in their original order (head-requeue preserves it).
	items, err := c.trapQueue.Drain(100)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(items) != total {
		t.Fatalf("queue holds %d items after the failed drain, want %d (the drained tail was lost)", len(items), total)
	}
	for i, raw := range items {
		var tr TrapEvent
		if err := json.Unmarshal(raw, &tr); err != nil {
			t.Fatalf("unmarshal[%d]: %v", i, err)
		}
		if want := string(rune('0' + i)); tr.Message != want {
			t.Errorf("post-requeue order[%d] = %q, want %q", i, tr.Message, want)
		}
	}
}

// TestRequeueRedrain_ReplaysIdenticalBatchID is the AUDIT-213/214 regression:
// a transiently-failed FULL-SIZE chunk, head-requeued and re-drained on the
// next sync, must replay with the IDENTICAL content-derived X-Probe-Batch-ID
// so the server's (probe_id, batch_id) dedup catches a committed-but-timed-out
// original. The fixture seeds FIVE items with drainChunk 3, so two items are
// still queued behind the failed chunk when the requeue lands: pre-fix, the
// tail requeue put [a b c] BEHIND [d e] and the next drain regrouped them
// ([d e a] + [b c]) under fresh keys the server could not dedup, inserting
// every row twice. (With an empty queue at requeue time, even a tail push
// happens to reproduce the original order, so that fixture cannot catch the
// bug.) The guarantee pinned here is for full-size chunks — a partial final
// chunk that gains newly-arrived neighbors, a memory-bound PushFront split,
// or a restart can still regroup: the duplicate window is narrowed, not
// closed.
func TestRequeueRedrain_ReplaysIdenticalBatchID(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	var mu sync.Mutex
	var downIDs, upIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Probe-Batch-ID")
		mu.Lock()
		if down.Load() {
			downIDs = append(downIDs, id)
		} else {
			upIDs = append(upIDs, id)
		}
		mu.Unlock()
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	c.Config = Config{ServerURL: srv.URL, RegistrationKey: "k", MaxBatchSize: 3}
	c.httpClient = srv.Client()

	spec := queueDrainSpec[TrapEvent]{
		queue: c.trapQueue, endpoint: "/traps", sendName: "traps",
		drainLabel: "traps", unmarshalLabel: "trap",
		noun: "traps", nounLong: "trap events",
	}

	// Seed 5 items; drainChunk 3. Sync 1 drains one full chunk [a b c] and
	// fails it transiently — d and e are still queued when the requeue lands.
	for _, m := range []string{"a", "b", "c", "d", "e"} {
		c.SendTrap(&TrapEvent{Message: m})
	}
	drainAndSend(c, srv.URL+"/api/probes/42", 3, spec)

	mu.Lock()
	if len(downIDs) == 0 {
		mu.Unlock()
		t.Fatal("no send attempts recorded during the outage")
	}
	failedID := downIDs[0]
	for i, id := range downIDs {
		if id != failedID {
			mu.Unlock()
			t.Fatalf("in-call retry %d used batch ID %q, want %q (content key must be attempt-stable)", i, id, failedID)
		}
	}
	mu.Unlock()

	// Sync 2: server recovered. The head-requeued run drains FIRST and
	// re-chunks from index 0, so chunk 0 is again exactly [a b c] —
	// byte-identical, identical key — with [d e] following as its own batch.
	down.Store(false)
	drainAndSend(c, srv.URL+"/api/probes/42", 3, spec)

	mu.Lock()
	defer mu.Unlock()
	if len(upIDs) != 2 {
		t.Fatalf("recovery sync sent %d batch(es), want 2 ([a b c] then [d e])", len(upIDs))
	}
	if upIDs[0] != failedID {
		t.Errorf("replayed batch ID = %q, want %q — the requeued chunk must replay under its original content key (AUDIT-213/214)", upIDs[0], failedID)
	}
	if upIDs[1] == failedID {
		t.Error("the new-items batch reused the failed batch's ID — distinct content must produce a distinct key")
	}
	if d := c.trapQueue.Depth(); d != 0 {
		t.Errorf("queue depth after recovery = %d, want 0", d)
	}
}
