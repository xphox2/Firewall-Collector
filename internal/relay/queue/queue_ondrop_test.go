package queue

import (
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestOnDrop_FiresPerByteCapDrop verifies the AUDIT-210 OnDrop callback is
// invoked exactly once for every item the byte cap forces out of the spillover
// queue — the two q.dropped++ sites in appendToDisk. Without this the
// firewall_collector_queue_dropped_total metric stayed a permanent zero even
// while real spillover data was being lost.
func TestOnDrop_FiresPerByteCapDrop(t *testing.T) {
	var drops atomic.Int64
	q, err := Open(Config{
		Path:     filepath.Join(t.TempDir(), "drop.bolt"),
		Bucket:   "drop",
		MaxMem:   1,  // force each extra push to evict the oldest to disk
		MaxBytes: 10, // each item (8 + payload) is larger, so it is dropped
		OnDrop:   func() { drops.Add(1) },
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = q.Close() }()

	// First push lands in memory (MaxMem=1). Each subsequent push evicts the
	// prior oldest item to disk, where it exceeds MaxBytes and is dropped.
	const pushes = 5
	for i := 0; i < pushes; i++ {
		if err := q.Push([]byte("payload-larger-than-cap")); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}

	wantDrops := int64(pushes - 1) // the last push's item stays in memory
	if got := drops.Load(); got != wantDrops {
		t.Errorf("OnDrop fired %d times; want %d", got, wantDrops)
	}
	if got := q.Dropped(); got != uint64(wantDrops) {
		t.Errorf("Dropped()=%d; want %d (OnDrop count must match the internal counter)", got, wantDrops)
	}
}

// TestOnDrop_NilSafe verifies a queue with no OnDrop callback still drops
// cleanly (the nil hook must never be invoked).
func TestOnDrop_NilSafe(t *testing.T) {
	q, err := Open(Config{
		Path:     filepath.Join(t.TempDir(), "nil.bolt"),
		Bucket:   "nil",
		MaxMem:   1,
		MaxBytes: 10,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = q.Close() }()
	for i := 0; i < 3; i++ {
		if err := q.Push([]byte("payload-larger-than-cap")); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if got := q.Dropped(); got != 2 {
		t.Errorf("Dropped()=%d; want 2", got)
	}
}
