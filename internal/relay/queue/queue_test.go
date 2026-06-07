package queue

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func openTestQueue(t *testing.T, maxMem int, maxBytes int64) *SpilloverQueue {
	t.Helper()
	dir := t.TempDir()
	q, err := Open(Config{
		Path:     filepath.Join(dir, "test.bolt"),
		Bucket:   "test",
		MaxMem:   maxMem,
		MaxBytes: maxBytes,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

func itemBytes(i int) []byte {
	return []byte(fmt.Sprintf("item-%04d", i))
}

// ── Tests ────────────────────────────────────────────────────────────────────

// AUDIT-058: with MaxQueueSize=10 and 100 enqueues, 10 items live in memory
// and 90 spill to BoltDB. The overflow path must move the OLDEST in-memory
// item to disk, not the newest.
func TestQueue_SpillsToDisk_OnOverflow(t *testing.T) {
	q := openTestQueue(t, 10, 0)

	for i := 0; i < 100; i++ {
		if err := q.Push(itemBytes(i)); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}

	if got := q.Depth(); got != 10 {
		t.Errorf("Depth = %d, want 10", got)
	}
	disk, err := q.DiskCount()
	if err != nil {
		t.Fatalf("DiskCount: %v", err)
	}
	if disk != 90 {
		t.Errorf("DiskCount = %d, want 90", disk)
	}
}

// AUDIT-058: pre-populate BoltDB, close, reopen, assert the 90 spillover
// items are still drained in correct FIFO order. The in-memory slice must
// also be repopulated with the 10 newest items.
func TestQueue_ReplaysFromDisk_OnStartup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bolt")

	q, err := Open(Config{Path: path, Bucket: "test", MaxMem: 10})
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	for i := 0; i < 100; i++ {
		if err := q.Push(itemBytes(i)); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}
	if got := q.Depth(); got != 10 {
		t.Fatalf("pre-close Depth = %d, want 10", got)
	}
	if disk, _ := q.DiskCount(); disk != 90 {
		t.Fatalf("pre-close DiskCount = %d, want 90", disk)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen — replay should restore both tiers.
	q2, err := Open(Config{Path: path, Bucket: "test", MaxMem: 10})
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	defer q2.Close()

	if got := q2.Depth(); got != 10 {
		t.Errorf("post-replay Depth = %d, want 10", got)
	}
	if disk, _ := q2.DiskCount(); disk != 90 {
		t.Errorf("post-replay DiskCount = %d, want 90", disk)
	}

	// Drain everything and verify strict FIFO order across the two tiers.
	items, err := q2.Drain(100)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(items) != 100 {
		t.Fatalf("Drain returned %d items, want 100", len(items))
	}
	for i, it := range items {
		if want := string(itemBytes(i)); string(it) != want {
			t.Errorf("items[%d] = %q, want %q", i, it, want)
		}
	}
}

// AUDIT-058: overflow the queue by 10×, assert the BoltDB file stays
// bounded. bbolt reuses free pages, so the file should plateau well below
// "1 byte per item" even with a 10K-item workload.
func TestQueue_Compaction_OnRollover(t *testing.T) {
	const maxMem = 100
	q := openTestQueue(t, maxMem, 0)

	// Overflow the in-memory slice 100× (10K items total). Each item is
	// ~10 bytes + 8-byte key + bbolt page overhead.
	for i := 0; i < 10000; i++ {
		if err := q.Push(itemBytes(i)); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}

	// After 10K pushes, the on-disk tier holds ~9900 items.
	disk, err := q.DiskCount()
	if err != nil {
		t.Fatalf("DiskCount: %v", err)
	}
	if disk < 9000 {
		t.Errorf("DiskCount = %d, expected ~9900 (overflow 100× %d)", disk, maxMem)
	}

	// File size must stay bounded. 10K items × ~30 bytes raw ≈ 300 KB.
	// bbolt's 4KB pages will add overhead; give a generous 4 MB ceiling.
	size, err := q.DiskSize()
	if err != nil {
		t.Fatalf("DiskSize: %v", err)
	}
	const bound = 4 * 1024 * 1024
	if size > bound {
		t.Errorf("DiskSize = %d bytes, exceeds bound %d (file not bounded by eviction)", size, bound)
	}

	// Now drain 10K more and push 10K more — verify the file size does
	// not grow linearly with cumulative writes.
	before, _ := q.DiskSize()
	for i := 10000; i < 20000; i++ {
		if err := q.Push(itemBytes(i)); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}
	if _, err := q.Drain(10000); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	after, _ := q.DiskSize()
	if after > before+bound/2 {
		t.Errorf("file grew from %d to %d bytes after second 10K-cycle (free pages not reused)", before, after)
	}
}

// AUDIT-058: with MaxBytes set, fills the disk to its cap and asserts new
// items are dropped (counted as Dropped) rather than appended. The
// invariant is: in-memory + on-disk + dropped = total pushes.
func TestQueue_Cap_Respected(t *testing.T) {
	const cap = 2048
	q := openTestQueue(t, 10, cap)

	const total = 1000
	for i := 0; i < total; i++ {
		if err := q.Push(itemBytes(i)); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}

	depth := q.Depth()
	disk, _ := q.DiskCount()
	dropped := q.Dropped()

	if depth+disk+int(dropped) != total {
		t.Errorf("invariant broken: mem(%d) + disk(%d) + dropped(%d) != total(%d)",
			depth, disk, dropped, total)
	}
	if disk == 0 {
		t.Error("expected some items on disk; got 0")
	}
	if dropped == 0 {
		t.Error("expected drops after exceeding MaxBytes; got 0")
	}

	// TrackedSize should not exceed the cap by more than one item.
	tracked := q.TrackedSize()
	if tracked > cap+64 {
		t.Errorf("TrackedSize = %d, exceeds cap %d by more than 1 item", tracked, cap)
	}
}

// ── Additional correctness tests ──────────────────────────────────────────────

// Push then Drain then Push: items must be strictly ordered FIFO across
// multiple drain cycles.
func TestQueue_FIFO_Order(t *testing.T) {
	q := openTestQueue(t, 10, 0)

	for i := 0; i < 50; i++ {
		q.Push(itemBytes(i))
	}

	first, err := q.Drain(20)
	if err != nil {
		t.Fatalf("Drain #1: %v", err)
	}
	if len(first) != 20 {
		t.Fatalf("Drain #1 returned %d, want 20", len(first))
	}
	for i, it := range first {
		if want := string(itemBytes(i)); string(it) != want {
			t.Errorf("Drain #1[%d] = %q, want %q", i, it, want)
		}
	}

	second, err := q.Drain(30)
	if err != nil {
		t.Fatalf("Drain #2: %v", err)
	}
	for i, it := range second {
		want := string(itemBytes(i + 20))
		if string(it) != want {
			t.Errorf("Drain #2[%d] = %q, want %q", i, it, want)
		}
	}
}

// Open with a missing dir creates parent dirs.
func TestOpen_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "subdir", "q.bolt")
	q, err := Open(Config{Path: path, Bucket: "b", MaxMem: 5})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer q.Close()
	if err := q.Push(itemBytes(0)); err != nil {
		t.Fatalf("Push: %v", err)
	}
}

// Open rejects bad configs.
func TestOpen_ValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty path", Config{Bucket: "b", MaxMem: 1}},
		{"empty bucket", Config{Path: "x.bolt", MaxMem: 1}},
		{"zero MaxMem", Config{Path: "x.bolt", Bucket: "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(tc.cfg); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// Concurrent Pushes from many goroutines must not lose items or corrupt
// the in-memory slice.
func TestQueue_ConcurrentPushes(t *testing.T) {
	q := openTestQueue(t, 10000, 0)

	const goroutines = 20
	const perGoroutine = 100

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if err := q.Push(itemBytes(gid*perGoroutine + i)); err != nil {
					t.Errorf("Push: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if got := q.Depth() + mustDiskCount(t, q); got != goroutines*perGoroutine {
		t.Errorf("total items = %d, want %d", got, goroutines*perGoroutine)
	}
}

func mustDiskCount(t *testing.T, q *SpilloverQueue) int {
	t.Helper()
	n, err := q.DiskCount()
	if err != nil {
		t.Fatalf("DiskCount: %v", err)
	}
	return n
}

// Drain(0) and negative n return no items.
func TestQueue_DrainZeroOrNegative(t *testing.T) {
	q := openTestQueue(t, 5, 0)
	q.Push(itemBytes(0))
	q.Push(itemBytes(1))

	items, err := q.Drain(0)
	if err != nil {
		t.Fatalf("Drain(0): %v", err)
	}
	if len(items) != 0 {
		t.Errorf("Drain(0) returned %d items, want 0", len(items))
	}

	items, err = q.Drain(-5)
	if err != nil {
		t.Fatalf("Drain(-5): %v", err)
	}
	if len(items) != 0 {
		t.Errorf("Drain(-5) returned %d items, want 0", len(items))
	}
}

// Drain more than the queue holds: returns everything, leaves queue empty.
func TestQueue_DrainMoreThanAvailable(t *testing.T) {
	q := openTestQueue(t, 5, 0)
	for i := 0; i < 3; i++ {
		q.Push(itemBytes(i))
	}
	items, err := q.Drain(100)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(items) != 3 {
		t.Errorf("Drain returned %d, want 3", len(items))
	}
	if q.Depth() != 0 {
		t.Errorf("Depth after draining more than available = %d, want 0", q.Depth())
	}
}

// Push an item larger than MaxBytes alone: it is dropped because the
// disk cap cannot accommodate it even after evicting everything.
func TestQueue_OversizedItemDropped(t *testing.T) {
	q := openTestQueue(t, 1, 100)
	big := make([]byte, 200)
	if err := q.Push(big); err != nil {
		t.Fatalf("Push: %v", err)
	}
	// The in-memory slice still holds the big item (MaxMem is the
	// in-memory cap, not the disk cap).
	if q.Depth() != 1 {
		t.Errorf("Depth = %d, want 1 (in-memory still holds the big item)", q.Depth())
	}
	// Pushing a small item forces the big one to disk; it can't fit
	// (200 > 100), so it is dropped and counted.
	small := itemBytes(0)
	if err := q.Push(small); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if got := q.Dropped(); got != 1 {
		t.Errorf("Dropped = %d, want 1 (big item dropped — too large for disk cap)", got)
	}
	if disk, _ := q.DiskCount(); disk != 0 {
		t.Errorf("DiskCount = %d, want 0 (small item stays in memory, big was dropped)", disk)
	}
	if q.Depth() != 1 {
		t.Errorf("Depth = %d, want 1 (small item still in memory)", q.Depth())
	}
}
