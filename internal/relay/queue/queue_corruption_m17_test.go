package queue

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpen_QuarantinesCorruptFile_M17 pins the 2026-07-01 audit M17 fix: a
// corrupt spool file (a real risk under the NoSync open mode on power loss)
// must not fail Open — pre-fix, that failure made the caller disable ALL SEVEN
// queues, so one power event silently removed all outage buffering until an
// operator manually deleted the file. Open now quarantines the unreadable file
// and recreates a fresh, working spool.
func TestOpen_QuarantinesCorruptFile_M17(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.bolt")

	// Write garbage where a valid bbolt file is expected — this is what a
	// torn/corrupt file looks like to bolt.Open (bad magic / meta pages).
	if err := os.WriteFile(path, []byte("this is not a bolt database, it is corrupt garbage"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	q, err := Open(Config{Path: path, Bucket: "flows", MaxMem: 10})
	if err != nil {
		t.Fatalf("Open must self-heal a corrupt file, got error: %v", err)
	}
	defer q.Close()

	// The fresh queue must be usable.
	if err := q.Push([]byte("after-recovery")); err != nil {
		t.Fatalf("push into recreated queue: %v", err)
	}
	items, err := q.Drain(1)
	if err != nil || len(items) != 1 || string(items[0]) != "after-recovery" {
		t.Fatalf("recreated queue not usable: items=%v err=%v", items, err)
	}

	// The corrupt original must have been quarantined, not deleted.
	entries, _ := os.ReadDir(dir)
	var quarantined bool
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".bolt" && len(e.Name()) > len("flows.bolt.corrupt-") {
			quarantined = true
		}
	}
	if !quarantined {
		t.Error("corrupt file was not quarantined (expected a flows.bolt.corrupt-<ts> sibling)")
	}
}

// TestQueue_BackgroundSyncDurable_M18 verifies the fsync moved to the
// background loop still makes committed items durable across a graceful
// Close/reopen (the audit moved db.Sync() off the hot q.mu path).
func TestQueue_BackgroundSyncDurable_M18(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m18.bolt")

	q, err := Open(Config{Path: path, Bucket: "m18", MaxMem: 2})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Push more than MaxMem so items overflow to disk.
	for i := 0; i < 10; i++ {
		if err := q.Push([]byte{byte('a' + i)}); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if err := q.Close(); err != nil { // Close does the final unconditional fsync
		t.Fatalf("close: %v", err)
	}

	q2, err := Open(Config{Path: path, Bucket: "m18", MaxMem: 2})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer q2.Close()
	items, err := q2.Drain(10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(items) != 10 {
		t.Errorf("recovered %d items, want 10 (background-synced + Close-fsynced items must survive)", len(items))
	}
}
