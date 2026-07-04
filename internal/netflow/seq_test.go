package netflow

import (
	"fmt"
	"testing"
	"time"
)

// TestSeqTracker_VersionSemantics pins the per-version expected deltas
// (research §2.7): v5 += record count, v9 += 1 per packet, IPFIX += data
// records — and that a matching stream stays silent while a jump fires ONE
// seq_gap per occurrence.
func TestSeqTracker_VersionSemantics(t *testing.T) {
	t.Run("v5-records", func(t *testing.T) {
		tr := newSeqTracker()
		k := seqKey{"192.0.2.1", 0x0107, 5}
		if ev := tr.observe(k, 0, 10, 1000, true, true); ev != "" {
			t.Errorf("first sighting event = %q, want none", ev)
		}
		if ev := tr.observe(k, 10, 5, 2000, true, true); ev != "" {
			t.Errorf("in-sync event = %q, want none", ev)
		}
		// 15 expected; 40 arrives → 25 records lost, ONE gap event.
		if ev := tr.observe(k, 40, 3, 3000, true, true); ev != eventSeqGap {
			t.Errorf("gap event = %q, want %q", ev, eventSeqGap)
		}
		// Stream recovers from the new baseline.
		if ev := tr.observe(k, 43, 1, 4000, true, true); ev != "" {
			t.Errorf("post-gap resync event = %q, want none", ev)
		}
	})

	t.Run("v9-packets", func(t *testing.T) {
		tr := newSeqTracker()
		k := seqKey{"192.0.2.1", 3, 9}
		tr.observe(k, 100, 1, 1000, true, true)
		if ev := tr.observe(k, 101, 1, 2000, true, true); ev != "" {
			t.Errorf("in-sync event = %q", ev)
		}
		if ev := tr.observe(k, 105, 1, 3000, true, true); ev != eventSeqGap {
			t.Errorf("gap event = %q, want %q", ev, eventSeqGap)
		}
	})

	t.Run("ipfix-data-records", func(t *testing.T) {
		tr := newSeqTracker()
		k := seqKey{"192.0.2.1", 7, 10}
		tr.observe(k, 500, 12, 0, false, true)
		if ev := tr.observe(k, 512, 4, 0, false, true); ev != "" {
			t.Errorf("in-sync event = %q", ev)
		}
		if ev := tr.observe(k, 600, 1, 0, false, true); ev != eventSeqGap {
			t.Errorf("gap event = %q, want %q", ev, eventSeqGap)
		}
	})
}

// TestSeqTracker_DomainIsolation: sequence spaces are per (exporter, domain,
// version) — one VDOM's stream must not judge another's.
func TestSeqTracker_DomainIsolation(t *testing.T) {
	tr := newSeqTracker()
	a := seqKey{"192.0.2.1", 1, 9}
	b := seqKey{"192.0.2.1", 2, 9}
	tr.observe(a, 100, 1, 1000, true, true)
	// Domain 2 starting at a wildly different sequence is a FIRST sighting,
	// not a gap in domain 1's space.
	if ev := tr.observe(b, 9999, 1, 1000, true, true); ev != "" {
		t.Errorf("sibling-domain first sighting event = %q, want none", ev)
	}
	if ev := tr.observe(a, 101, 1, 2000, true, true); ev != "" {
		t.Errorf("domain 1 in-sync event = %q, want none", ev)
	}
}

// TestSeqTracker_Uint32Wrap: modular math across the 2^32 boundary is NOT a
// gap or a resync.
func TestSeqTracker_Uint32Wrap(t *testing.T) {
	tr := newSeqTracker()
	k := seqKey{"192.0.2.1", 0, 10}
	tr.observe(k, 0xFFFFFFFE, 3, 0, false, true) // next = 1 (wraps)
	if ev := tr.observe(k, 1, 2, 0, false, true); ev != "" {
		t.Errorf("wrap-boundary event = %q, want none (modular math)", ev)
	}
	if ev := tr.observe(k, 3, 1, 0, false, true); ev != "" {
		t.Errorf("post-wrap in-sync event = %q, want none", ev)
	}
}

// TestSeqTracker_RebootResync: an exporter reboot must resync, never count as
// loss — detected by a backward jump > 2^31 OR a sysUptime decrease.
func TestSeqTracker_RebootResync(t *testing.T) {
	// Backward jump (no uptime available — IPFIX).
	tr := newSeqTracker()
	k := seqKey{"192.0.2.1", 0, 10}
	tr.observe(k, 4000000000, 5, 0, false, true)
	if ev := tr.observe(k, 3, 1, 0, false, true); ev != eventSeqResync {
		t.Errorf("backward-jump event = %q, want %q", ev, eventSeqResync)
	}
	if ev := tr.observe(k, 4, 1, 0, false, true); ev != "" {
		t.Errorf("post-resync event = %q, want none", ev)
	}

	// sysUptime decrease (v9): even a small forward-looking seq mismatch after
	// a reboot is a resync, not a gap.
	tr2 := newSeqTracker()
	k2 := seqKey{"192.0.2.1", 0, 9}
	tr2.observe(k2, 100, 1, 500000, true, true)
	if ev := tr2.observe(k2, 150, 1, 3000, true, true); ev != eventSeqResync {
		t.Errorf("uptime-decrease event = %q, want %q", ev, eventSeqResync)
	}
}

// TestSeqTracker_UncountableSkipsJudgment: after a message whose record count
// is unknown (countable=false — IPFIX data-before-template), the next
// observation must not fire a gap off a guessed expectation.
func TestSeqTracker_UncountableSkipsJudgment(t *testing.T) {
	tr := newSeqTracker()
	k := seqKey{"192.0.2.1", 0, 10}
	tr.observe(k, 100, 2, 0, false, true)
	// This message decoded 0 of its unknown-many records.
	if ev := tr.observe(k, 102, 0, 0, false, false); ev != "" {
		t.Errorf("uncountable message event = %q, want none", ev)
	}
	// Whatever arrives next is a re-baseline, silently.
	if ev := tr.observe(k, 110, 1, 0, false, true); ev != "" {
		t.Errorf("post-uncountable event = %q, want silent resync", ev)
	}
	// And judgment resumes after the re-baseline.
	if ev := tr.observe(k, 115, 1, 0, false, true); ev != eventSeqGap {
		t.Errorf("resumed-judgment event = %q, want %q", ev, eventSeqGap)
	}
}

// TestSeqTracker_StateCap: the tracker refuses to grow past maxSeqStates
// (spoofing-source memory-DoS guard) without panicking or misbehaving.
func TestSeqTracker_StateCap(t *testing.T) {
	tr := newSeqTracker()
	for i := 0; i < maxSeqStates; i++ {
		tr.observe(seqKey{fmt.Sprintf("10.0.%d.%d", i/256, i%256), 0, 9}, 1, 1, 0, true, true)
	}
	if ev := tr.observe(seqKey{"192.0.2.99", 0, 9}, 1, 1, 0, true, true); ev != "" {
		t.Errorf("over-cap observe event = %q, want none (untracked)", ev)
	}
	if len(tr.states) != maxSeqStates {
		t.Errorf("states = %d, want capped at %d", len(tr.states), maxSeqStates)
	}
}

// TestParseV9_SeqGapEndToEnd wires the tracker through the real v9 parser:
// consecutive datagrams are silent, a skipped packet fires seq_gap, and the
// gap never touches FlowSample.Drops.
func TestParseV9_SeqGapEndToEnd(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	dgAt := func(seq uint32) []byte {
		hdr := v9HdrAt(now, 500000)
		hdr.seq = seq
		return buildV9(hdr, fset(0, 0, stdV9Template(256)), fset(256, 0, stdV9Record(100, 1, 490000, 440000)))
	}
	r.parseDatagram(dgAt(10), "192.0.2.1", now)
	r.parseDatagram(dgAt(11), "192.0.2.1", now)
	if ev := getEvents(); len(ev) != 0 {
		t.Fatalf("consecutive datagrams fired events: %v", ev)
	}
	r.parseDatagram(dgAt(13), "192.0.2.1", now) // one packet lost
	found := 0
	for _, e := range getEvents() {
		if e == eventSeqGap {
			found++
		}
	}
	if found != 1 {
		t.Errorf("seq_gap events = %d, want exactly 1", found)
	}
	for _, s := range getSamples() {
		if s.Drops != 0 {
			t.Errorf("sequence loss leaked into FlowSample.Drops = %d", s.Drops)
		}
	}
}

// TestParseV5_SeqTracking wires the tracker through the v5 parser: the header
// sequence advances by the RECORD count.
func TestParseV5_SeqTracking(t *testing.T) {
	now := time.Now()
	r, _, getEvents := newTestReceiver()

	dg := func(seq uint32, recs int) []byte {
		hdr := hdrAt(now, 100000)
		hdr.flowSeq = seq
		rr := make([]v5Record, recs)
		for i := range rr {
			rr[i] = v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1, first: 90000, last: 95000}
		}
		return buildV5(hdr, rr...)
	}
	r.parseDatagram(dg(0, 2), "192.0.2.1", now)
	r.parseDatagram(dg(2, 3), "192.0.2.1", now)
	if ev := getEvents(); len(ev) != 0 {
		t.Fatalf("in-sync v5 stream fired events: %v", ev)
	}
	r.parseDatagram(dg(9, 1), "192.0.2.1", now) // 4 records lost
	found := false
	for _, e := range getEvents() {
		if e == eventSeqGap {
			found = true
		}
	}
	if !found {
		t.Errorf("v5 record-count gap not detected: events=%v", getEvents())
	}
}
