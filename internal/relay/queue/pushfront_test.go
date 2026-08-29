package queue

import (
	"path/filepath"
	"testing"
)

// Tests for the AUDIT-175 front tier: PushFront prepends an ordered run to
// the queue's HEAD, Drain consumes the front tier first (then disk, then the
// in-memory tail), Depth counts front items, overflow falls back to the tail
// without losing anything, and Close flushes the front tier to disk FIRST so
// a restart replays it before the tail.

// PushFront'd runs drain FIRST, in their given order, ahead of both the disk
// overflow tier and the in-memory tail.
func TestQueue_PushFront_OrderAndDrainFrontFirst(t *testing.T) {
	q := openTestQueue(t, 3, 0)

	// Head-requeue a run while the queue is empty, then push new arrivals:
	// x overflows to disk once the in-memory bound (front + tail ≤ 3) is hit.
	if err := q.PushFront([][]byte{[]byte("a")}); err != nil {
		t.Fatalf("PushFront: %v", err)
	}
	for _, s := range []string{"x", "y", "z"} {
		if err := q.Push([]byte(s)); err != nil {
			t.Fatalf("Push %s: %v", s, err)
		}
	}
	if disk := mustDiskCount(t, q); disk != 1 {
		t.Fatalf("disk count = %d, want 1 (front counts toward the in-memory bound)", disk)
	}
	if got := q.Depth(); got != 3 {
		t.Errorf("Depth = %d, want 3 (front + tail)", got)
	}

	items, err := q.Drain(10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	want := []string{"a", "x", "y", "z"} // front, then disk overflow, then tail
	if len(items) != len(want) {
		t.Fatalf("drained %d items, want %d", len(items), len(want))
	}
	for i, w := range want {
		if string(items[i]) != w {
			t.Errorf("drained[%d] = %q, want %q (front tier must drain first)", i, items[i], w)
		}
	}
}

// A multi-item run keeps its order at the head even when newer items were
// pushed while it was out for delivery — the AUDIT-213/214 replay premise.
func TestQueue_PushFront_RunPrecedesNewerItems(t *testing.T) {
	q := openTestQueue(t, 10, 0)

	for i := 0; i < 5; i++ {
		if err := q.Push(itemBytes(i)); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}
	run, err := q.Drain(3)
	if err != nil || len(run) != 3 {
		t.Fatalf("Drain(3) = %d items, err %v; want 3", len(run), err)
	}
	// Delivery failed; a new item arrives before the requeue lands.
	if err := q.Push(itemBytes(5)); err != nil {
		t.Fatalf("Push new: %v", err)
	}
	if err := q.PushFront(run); err != nil {
		t.Fatalf("PushFront: %v", err)
	}

	items, err := q.Drain(100)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(items) != 6 {
		t.Fatalf("drained %d items, want 6", len(items))
	}
	for i, it := range items {
		if want := string(itemBytes(i)); string(it) != want {
			t.Errorf("drained[%d] = %q, want %q (requeued run must stay at the head, in order)", i, it, want)
		}
	}
}

// When the run doesn't fit within MaxMem (front + tail), the remainder falls
// back to a tail Push (spilling to disk as usual): out of order, never lost.
func TestQueue_PushFront_OverflowFallsBackToTail(t *testing.T) {
	q := openTestQueue(t, 3, 0)

	for _, s := range []string{"x", "y"} {
		if err := q.Push([]byte(s)); err != nil {
			t.Fatalf("Push %s: %v", s, err)
		}
	}
	// Room for one front item (3 - 0 - 2); b and c fall back to the tail.
	if err := q.PushFront([][]byte{[]byte("a"), []byte("b"), []byte("c")}); err != nil {
		t.Fatalf("PushFront: %v", err)
	}

	items, err := q.Drain(100)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(items) != 5 {
		t.Fatalf("drained %d items, want 5 (overflow must fall back to the tail, not drop)", len(items))
	}
	got := make(map[string]bool, len(items))
	for _, it := range items {
		got[string(it)] = true
	}
	for _, w := range []string{"a", "b", "c", "x", "y"} {
		if !got[w] {
			t.Errorf("item %q lost across a PushFront overflow", w)
		}
	}
	if string(items[0]) != "a" {
		t.Errorf("drained[0] = %q, want %q (the fitting prefix still holds the head)", items[0], "a")
	}
}

// Close flushes the front tier to disk BEFORE the tail, so a restart replays
// front items ahead of tail items (the byte-identical-replay guarantee for the
// held batch is traded away across a restart — duplicates possible, not loss).
func TestQueue_PushFront_CloseFlushesFrontFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "front.bolt")
	cfg := Config{Path: path, Bucket: "front", MaxMem: 10}

	q, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, s := range []string{"t1", "t2"} {
		if err := q.Push([]byte(s)); err != nil {
			t.Fatalf("Push %s: %v", s, err)
		}
	}
	if err := q.PushFront([][]byte{[]byte("h1"), []byte("h2")}); err != nil {
		t.Fatalf("PushFront: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	q2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer q2.Close()

	items, err := q2.Drain(100)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	want := []string{"h1", "h2", "t1", "t2"}
	if len(items) != len(want) {
		t.Fatalf("drained %d items after restart, want %d (front tier lost across Close)", len(items), len(want))
	}
	for i, w := range want {
		if string(items[i]) != w {
			t.Errorf("post-restart drained[%d] = %q, want %q (front must be flushed before the tail)", i, items[i], w)
		}
	}
}
