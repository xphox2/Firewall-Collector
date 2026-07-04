package netflow

import (
	"testing"
	"time"
)

// testCtx builds a recordContext for direct decoder-level tests (v9-flavored:
// sysUptime present).
func testCtx(now time.Time) recordContext {
	return recordContext{
		key:          exporterKey{exporter: "192.0.2.1", sourceID: 0},
		flowSource:   2,
		exportTimeMs: now.UnixMilli(),
		sysUptime:    500000,
		hasSysUptime: true,
		now:          now,
	}
}

// set is a test shorthand for a present optU64.
func set(v uint64) optU64 { return optU64{v: v, ok: true} }

// TestEmitDataRecord_CounterFallbackChain walks the research-§2.2 families at
// the unit level: 1/2 preferred; 23/24 as forward when 1/2 absent; 231-only
// (ASA) bytes land with packets 0; 85/86 without 1/2 skip the record with the
// total_counters_skipped event; 85/86 WITH 1/2 use 1/2 normally.
func TestEmitDataRecord_CounterFallbackChain(t *testing.T) {
	now := time.Now()
	addr := func(d *decodedRecord) {
		d.srcV4 = []byte{10, 0, 0, 1}
		d.dstV4 = []byte{10, 0, 0, 2}
	}

	cases := []struct {
		name       string
		build      func(*decodedRecord)
		wantN      int
		wantBytes  uint64
		wantPkts   uint64
		wantEvents []string
	}{
		{
			name:      "ie1-2-preferred",
			build:     func(d *decodedRecord) { addr(d); d.fwdBytes, d.fwdPackets = set(100), set(2) },
			wantN:     1,
			wantBytes: 100, wantPkts: 2,
		},
		{
			name:      "out-bytes-forward-fallback",
			build:     func(d *decodedRecord) { addr(d); d.outBytes, d.outPackets = set(300), set(3) },
			wantN:     1,
			wantBytes: 300, wantPkts: 3,
		},
		{
			name:      "asa-initiator-only-packets-zero",
			build:     func(d *decodedRecord) { addr(d); d.initOctets = set(5000) },
			wantN:     1,
			wantBytes: 5000, wantPkts: 0,
		},
		{
			name:       "totals-without-deltas-skipped",
			build:      func(d *decodedRecord) { addr(d); d.totalOctets, d.totalPkts = set(999999), set(1000) },
			wantN:      0,
			wantEvents: []string{eventTotalCountersSkipped},
		},
		{
			name: "totals-alongside-deltas-use-deltas",
			build: func(d *decodedRecord) {
				addr(d)
				d.totalOctets = set(999999)
				d.fwdBytes, d.fwdPackets = set(150), set(1)
			},
			wantN:     1,
			wantBytes: 150, wantPkts: 1,
		},
		{
			name:       "reverse-only-dropped",
			build:      func(d *decodedRecord) { addr(d); d.revPENBytes = set(500) },
			wantN:      0,
			wantEvents: []string{eventReverseOnlyDropped},
		},
		{
			name:      "zero-counter-firewall-event-emits",
			build:     func(d *decodedRecord) { addr(d); d.fwEvent = set(3) },
			wantN:     1,
			wantBytes: 0, wantPkts: 0,
		},
		{
			name:      "zero-counter-nat-event-emits",
			build:     func(d *decodedRecord) { addr(d); d.natEvent = set(1) },
			wantN:     1,
			wantBytes: 0, wantPkts: 0,
		},
		{
			name:  "no-counters-no-event-no-addrs-skipped",
			build: func(d *decodedRecord) { d.protocol = set(6); d.srcPort = set(1234) },
			wantN: 0,
		},
		{
			name:      "addresses-alone-emit-zero-bytes",
			build:     func(d *decodedRecord) { addr(d) },
			wantN:     1,
			wantBytes: 0, wantPkts: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, getSamples, getEvents := newTestReceiver()
			var dec decodedRecord
			tc.build(&dec)
			r.emitDataRecord(&dec, testCtx(now))

			got := getSamples()
			if len(got) != tc.wantN {
				t.Fatalf("emitted %d samples, want %d (events=%v)", len(got), tc.wantN, getEvents())
			}
			if tc.wantN == 1 && (got[0].Bytes != tc.wantBytes || got[0].Packets != tc.wantPkts) {
				t.Errorf("counters = %d/%d, want %d/%d", got[0].Bytes, got[0].Packets, tc.wantBytes, tc.wantPkts)
			}
			ev := getEvents()
			if len(ev) != len(tc.wantEvents) {
				t.Fatalf("events = %v, want %v", ev, tc.wantEvents)
			}
			for i := range tc.wantEvents {
				if ev[i] != tc.wantEvents[i] {
					t.Errorf("event[%d] = %q, want %q", i, ev[i], tc.wantEvents[i])
				}
			}
		})
	}
}

// TestEmitDataRecord_ReverseEmissionZeroSuppressed: FortiGate ships 23/24
// zero-filled for one-way sessions — a zero reverse counter must NOT emit a
// reverse row.
func TestEmitDataRecord_ReverseEmissionZeroSuppressed(t *testing.T) {
	now := time.Now()
	r, getSamples, _ := newTestReceiver()
	var dec decodedRecord
	dec.srcV4, dec.dstV4 = []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	dec.fwdBytes, dec.fwdPackets = set(100), set(1)
	dec.outBytes, dec.outPackets = set(0), set(0) // present but zero
	r.emitDataRecord(&dec, testCtx(now))

	if got := getSamples(); len(got) != 1 {
		t.Fatalf("zero reverse counters emitted %d samples, want 1", len(got))
	}
}

// TestResolveFlowTimes_PriorityChain pins the §2.5 priority order at the unit
// level with the pairs that the protocol-level tests don't already cover:
// 150/151 seconds, 158/159 delta-µs, and 323-alone (start inherits end).
func TestResolveFlowTimes_PriorityChain(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	ctx := testCtx(now)

	// 150/151 seconds pair.
	tf := timeFields{
		startSec: set(uint64(now.Add(-70 * time.Second).Unix())),
		endSec:   set(uint64(now.Add(-10 * time.Second).Unix())),
	}
	start, end := resolveFlowTimes(&tf, ctx)
	if !end.Equal(now.Add(-10*time.Second)) || end.Sub(start) != time.Minute {
		t.Errorf("150/151: %v..%v, want 60s ending -10s", start, end)
	}

	// 152/153 outrank 150/151.
	tf.startMilli = set(uint64(now.Add(-30 * time.Second).UnixMilli()))
	tf.endMilli = set(uint64(now.Add(-5 * time.Second).UnixMilli()))
	start, end = resolveFlowTimes(&tf, ctx)
	if !end.Equal(now.Add(-5*time.Second)) || end.Sub(start) != 25*time.Second {
		t.Errorf("152/153 priority: %v..%v", start, end)
	}

	// 158/159 delta-µs before export time.
	tf2 := timeFields{
		startDeltaUs: set(60_000_000), // 60 s before export
		endDeltaUs:   set(5_000_000),  // 5 s before export
	}
	start, end = resolveFlowTimes(&tf2, ctx)
	if !end.Equal(now.Add(-5*time.Second)) || end.Sub(start) != 55*time.Second {
		t.Errorf("158/159: %v..%v", start, end)
	}

	// 323 alone: start = end.
	tf3 := timeFields{obsMilli: set(uint64(now.Add(-3 * time.Second).UnixMilli()))}
	start, end = resolveFlowTimes(&tf3, ctx)
	if !end.Equal(now.Add(-3*time.Second)) || !start.Equal(end) {
		t.Errorf("323 alone: %v..%v, want equal at -3s", start, end)
	}

	// Start-only (21/22 hot path with only FIRST present): end inherits start.
	tf4 := timeFields{startUptime: set(440000)} // export − 60 s at sysUptime 500000
	start, end = resolveFlowTimes(&tf4, ctx)
	if !start.Equal(now.Add(-time.Minute)) || !end.Equal(start) {
		t.Errorf("start-only: %v..%v", start, end)
	}
}

// TestResolveFlowTimes_SkewClampPreservesDuration: a broken exporter clock
// (end hours off the receive time) falls back to the receive time, keeping a
// believable internal duration — the same contract as the v5 clamp.
func TestResolveFlowTimes_SkewClampPreservesDuration(t *testing.T) {
	now := time.Now()
	ctx := testCtx(now)
	skewed := now.Add(-3 * time.Hour)
	tf := timeFields{
		startMilli: set(uint64(skewed.Add(-50 * time.Second).UnixMilli())),
		endMilli:   set(uint64(skewed.UnixMilli())),
	}
	start, end := resolveFlowTimes(&tf, ctx)
	if !end.Equal(now) {
		t.Errorf("clamped end = %v, want receive time %v", end, now)
	}
	if end.Sub(start) != 50*time.Second {
		t.Errorf("duration = %v, want preserved 50s", end.Sub(start))
	}

	// Garbage duration (negative) collapses to a point at the receive time.
	tf2 := timeFields{
		startMilli: set(uint64(skewed.Add(time.Hour).UnixMilli())),
		endMilli:   set(uint64(skewed.UnixMilli())),
	}
	start, end = resolveFlowTimes(&tf2, ctx)
	if !end.Equal(now) || !start.Equal(now) {
		t.Errorf("garbage duration: %v..%v, want point at receive time", start, end)
	}
}

// TestNtpToMs pins the NTP-format conversion: epoch offset, fractional ms,
// the µs bottom-11-bit mask, and era-1 disambiguation.
func TestNtpToMs(t *testing.T) {
	exportSecs := int64(1780000000) // ~2026

	// 2026-ish time, 0.5 s fraction.
	unix := int64(1779999990)
	v := uint64(uint32(unix+ntpEpochOffset))<<32 | 0x80000000
	if got := ntpToMs(v, false, exportSecs); got != unix*1000+500 {
		t.Errorf("nano decode = %d, want %d", got, unix*1000+500)
	}

	// µs variant: the bottom 11 fraction bits are noise and must be masked.
	// frac 0x00418938 is exactly the 1 ms boundary (ceil(2^32/1000)): the nano
	// decode reads 1 ms, while the masked micro decode (0x00418000) reads 0 ms
	// — the ms result differing is what proves the mask is applied.
	vBoundary := uint64(uint32(unix+ntpEpochOffset))<<32 | 0x00418938
	if got := ntpToMs(vBoundary, false, exportSecs); got != unix*1000+1 {
		t.Errorf("nano boundary decode = %d, want %d", got, unix*1000+1)
	}
	if got := ntpToMs(vBoundary, true, exportSecs); got != unix*1000 {
		t.Errorf("micro mask decode = %d, want %d (bottom 11 bits masked)", got, unix*1000)
	}

	// Era 1: seconds word wrapped (post-2036 export time).
	exportSecs2040 := time.Date(2040, 3, 1, 12, 0, 0, 0, time.UTC).Unix()
	unix2040 := exportSecs2040 - 10
	wrapped := uint64(uint32(unix2040+ntpEpochOffset)) << 32 // zero fraction
	if got := ntpToMs(wrapped, false, exportSecs2040); got != unix2040*1000 {
		t.Errorf("era-1 decode = %d, want %d", got, unix2040*1000)
	}
}

// TestDecodeString pins the exporter-string extraction: NUL-padding stops the
// content, whitespace trims, and the length cap holds.
func TestDecodeString(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("dns\x00\x00\x00\x00"), "dns"},
		{[]byte("  web-browsing \x00junk"), "web-browsing"},
		{[]byte{}, ""},
		{[]byte("\x00hidden"), ""},
	}
	for _, tc := range cases {
		if got := decodeString(tc.in); got != tc.want {
			t.Errorf("decodeString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := make([]byte, 100)
	for i := range long {
		long[i] = 'A'
	}
	if got := decodeString(long); len(got) != maxAppNameLen {
		t.Errorf("cap: len = %d, want %d", len(got), maxAppNameLen)
	}
}
