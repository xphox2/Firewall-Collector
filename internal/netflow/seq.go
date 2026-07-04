package netflow

import "sync"

// Sequence-loss tracking (research §2.7): every flow protocol numbers its
// exports, but with VERSION-SPECIFIC semantics — v5 counts flow records, v9
// counts export packets, IPFIX counts data records (templates excluded). The
// tracker keys one expectation per (exporter IP, domain, version) because
// multi-VDOM/multi-ODID devices run independent sequence spaces behind one
// source IP — keying on the IP alone false-alarms on every such device.
//
// Gaps are surfaced as seq_gap parse events (a collector metric — "X% export
// loss from device Y"), NEVER as FlowSample.Drops: that field carries sFlow
// agent-drop semantics and the server does delta math on it.

// maxSeqStates bounds the tracker map. Without the source allowlist enabled a
// spoofing source could otherwise grow one entry per forged (IP, domain) pair
// — same memory-DoS rationale as the template-cache caps.
const maxSeqStates = 4096

// seqGapPlausibleLimit splits a nonzero modular delta into "loss" vs
// "renumbering". Modular uint32 math cannot tell a backward jump of J from a
// forward jump of 2^32−J — an exporter rebooting from sequence ~4e9 back to
// ~0 LOOKS like a ~295M-unit forward gap. 2^24 (~16.7M sequence units) is far
// beyond any plausible real loss between two consecutively-received datagrams
// (days of traffic), so anything bigger — including every backward jump,
// whose modular image is ≥ 2^31 — is treated as a reboot/renumber resync, not
// counted as loss (nfdump/libfixbuf posture: mismatch is never authoritative).
const seqGapPlausibleLimit = 1 << 24

// seqKey identifies one sequence space.
type seqKey struct {
	exporter string // UDP source IP
	domain   uint32 // v9 sourceID / IPFIX ODID / v5 engine_type<<8|engine_id
	version  uint8  // 5, 9, or 10 — versions never share a sequence counter
}

// seqState is the per-space expectation.
type seqState struct {
	next     uint32 // expected sequence value of the next datagram
	uptimeMs int64  // last seen header sysUptime (-1 = none seen / IPFIX)
	valid    bool   // next is trustworthy (false after init or an uncountable message)
}

// seqTracker holds every sequence space's state. All methods are
// goroutine-safe (SO_REUSEPORT workers feed it concurrently).
type seqTracker struct {
	mu     sync.Mutex
	states map[seqKey]*seqState
}

func newSeqTracker() *seqTracker {
	return &seqTracker{states: make(map[seqKey]*seqState)}
}

// observe feeds one datagram's header sequence plus the increment it
// represents (records for v5/IPFIX, always 1 for v9) and returns the parse
// event to emit: "" (in sync / first sighting), eventSeqGap (records were
// lost between the previous datagram and this one — ONE event per gap
// occurrence, not per missing record), or eventSeqResync (the exporter
// rebooted or renumbered; expectation reset, no loss counted).
//
// uptimeMs is the header sysUptime for v5/v9 (hasUptime true); IPFIX has no
// uptime (hasUptime false). countable=false means this message's own record
// count is unknown (e.g. an IPFIX data set arrived before its template), so
// the NEXT observation must not judge against a guess.
func (t *seqTracker) observe(k seqKey, seq, records uint32, uptimeMs int64, hasUptime, countable bool) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.states[k]
	if st == nil {
		if len(t.states) >= maxSeqStates {
			return "" // cap hit: stop tracking new spaces rather than growing unbounded
		}
		st = &seqState{uptimeMs: -1}
		t.states[k] = st
	}

	// delta is the modular uint32 distance from the expectation to what
	// arrived: 0 = in sync; a small positive value = that many sequence units
	// lost; anything implausibly large (see seqGapPlausibleLimit) = a
	// reboot/renumber. A sysUptime decrease is a reboot regardless of delta.
	delta := seq - st.next
	rebooted := hasUptime && st.uptimeMs >= 0 && uptimeMs < st.uptimeMs

	event := ""
	switch {
	case !st.valid || delta == 0:
		// No expectation yet, or exactly on schedule.
	case rebooted || delta >= seqGapPlausibleLimit:
		event = eventSeqResync
	default:
		event = eventSeqGap
	}

	if hasUptime {
		st.uptimeMs = uptimeMs
	}
	st.next = seq + records // modular wrap is the correct behavior
	st.valid = countable
	return event
}
