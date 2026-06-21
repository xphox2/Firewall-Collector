package main

import "testing"

// TestObservedHostKeys_RecordAndSnapshot verifies the collector keeps the latest
// observed SSH host-key fingerprint per device, ignores blanks, and hands the
// heartbeat a copy (not the live map).
func TestObservedHostKeys_RecordAndSnapshot(t *testing.T) {
	c := &Collector{}

	if snap := c.snapshotObservedHostKeys(); snap != nil {
		t.Errorf("empty snapshot = %v, want nil", snap)
	}

	// A blank fingerprint is ignored.
	c.recordObservedHostKey(1, "")
	if snap := c.snapshotObservedHostKeys(); snap != nil {
		t.Errorf("blank fingerprint must be ignored, got %v", snap)
	}

	c.recordObservedHostKey(1, "SHA256:aaa")
	c.recordObservedHostKey(2, "SHA256:bbb")
	c.recordObservedHostKey(1, "SHA256:ccc") // overwrite with the latest

	snap := c.snapshotObservedHostKeys()
	if snap[1] != "SHA256:ccc" || snap[2] != "SHA256:bbb" {
		t.Fatalf("snapshot = %v, want {1:SHA256:ccc, 2:SHA256:bbb}", snap)
	}

	// The snapshot must be a copy — mutating it must not affect the collector.
	snap[1] = "mutated"
	if c.snapshotObservedHostKeys()[1] != "SHA256:ccc" {
		t.Error("snapshot must be a copy of the live map")
	}
}
