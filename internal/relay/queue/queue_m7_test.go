package queue

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestQueue_M7_SyncIntervalDefault pins the 2026-06-23 audit M7 config: the DB
// is opened NoSync and fsyncs are throttled to SyncInterval, defaulting to 2s.
func TestQueue_M7_SyncIntervalDefault(t *testing.T) {
	q, err := Open(Config{Path: filepath.Join(t.TempDir(), "d.bolt"), Bucket: "d", MaxMem: 1})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer q.Close()
	if q.syncInterval != 2*time.Second {
		t.Errorf("default syncInterval = %v, want 2s", q.syncInterval)
	}

	q2, err := Open(Config{Path: filepath.Join(t.TempDir(), "c.bolt"), Bucket: "c", MaxMem: 1, SyncInterval: 250 * time.Millisecond})
	if err != nil {
		t.Fatalf("open custom: %v", err)
	}
	defer q2.Close()
	if q2.syncInterval != 250*time.Millisecond {
		t.Errorf("custom syncInterval = %v, want 250ms", q2.syncInterval)
	}
}

// TestQueue_M7_DurableAcrossClose_WithOverflow verifies that switching to NoSync
// did not weaken the restart guarantee: with items both spilled to disk and held
// in memory, a graceful Close (which now forces a final fsync) followed by a
// reopen replays every item in FIFO order. A long SyncInterval ensures the
// throttled in-Push sync does not fire for the later items, so the Close fsync is
// what carries them across.
func TestQueue_M7_DurableAcrossClose_WithOverflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m7.bolt")
	cfg := Config{Path: path, Bucket: "m7", MaxMem: 2, SyncInterval: time.Hour}

	q, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const n = 6 // MaxMem=2 → 4 spill to disk, 2 stay in memory
	for i := 0; i < n; i++ {
		if err := q.Push([]byte(fmt.Sprintf("item-%d", i))); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	q2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer q2.Close()

	got, err := q2.Drain(n + 5)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(got) != n {
		t.Fatalf("drained %d items, want %d (durability lost across Close)", len(got), n)
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("item-%d", i)
		if string(got[i]) != want {
			t.Errorf("item %d = %q, want %q (FIFO order broken across restart)", i, got[i], want)
		}
	}
}
