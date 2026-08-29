package netflow

import (
	"runtime"
	"testing"
	"time"
)

// TestParseIPFIXFieldSpecs_HugeCountNoOverAlloc_AUDIT282 pins the AUDIT-282
// bound: parseIPFIXFieldSpecs must reject a wire-declared field count that
// cannot fit in the remaining bytes BEFORE the make([]templateField, 0, count).
// A crafted template record with fieldCount=0xFFFF and no field data would
// otherwise force a ~512 KB allocation from a ~24-byte datagram. The test
// measures bytes allocated per call: with the bound, ~0; on a reverted fix,
// ~512 KB (8 bytes/field × 65535).
func TestParseIPFIXFieldSpecs_HugeCountNoOverAlloc_AUDIT282(t *testing.T) {
	// off=4 (caller consumed tid+count), only the 4-byte record header remains —
	// so a declared count of 0xFFFF is unsatisfiable.
	rem := make([]byte, 4)
	const bogusCount = 0xFFFF

	if fields, _, ok := parseIPFIXFieldSpecs(rem, 4, bogusCount); ok {
		t.Fatalf("expected rejection of an out-of-bounds field count, got ok=true (%d fields)", len(fields))
	}

	const iters = 2000
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	sink := 0
	for i := 0; i < iters; i++ {
		f, _, _ := parseIPFIXFieldSpecs(rem, 4, bogusCount)
		sink += len(f)
	}
	runtime.ReadMemStats(&m1)
	if sink != 0 {
		t.Fatalf("rejected calls returned %d fields total; want 0", sink)
	}
	perCall := (m1.TotalAlloc - m0.TotalAlloc) / iters
	// ~512 KB pre-fix vs ~0 with the bound. 8 KB is a safe separating threshold.
	if perCall > 8*1024 {
		t.Fatalf("parseIPFIXFieldSpecs allocated ~%d bytes/call for a bogus 0xFFFF count — AUDIT-282 pre-make bound not enforced", perCall)
	}
}

// TestParseIPFIX_HugeFieldCountRejected_AUDIT282 drives the same bound through
// the real datagram parse path: an IPFIX template set whose only record claims
// 0xFFFF fields with no specs must be flagged malformed and register nothing,
// with no panic.
func TestParseIPFIX_HugeFieldCountRejected_AUDIT282(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	badRecord := u16be(u16be(nil, 256), 0xFFFF) // tid=256, fieldCount=0xFFFF, no specs
	dg := buildIPFIX(uint32(now.Unix()), 1, 7, fset(2, 0, badRecord))
	r.parseDatagram(dg, "192.0.2.1", now)

	sawMalformed := false
	for _, e := range getEvents() {
		if e == eventMalformed {
			sawMalformed = true
		}
	}
	if !sawMalformed {
		t.Errorf("expected eventMalformed for a 0xFFFF-fieldCount IPFIX template")
	}
	if n := r.caches.templates.len(); n != 0 {
		t.Errorf("bogus template registered (cache len=%d); want 0", n)
	}
	if got := getSamples(); len(got) != 0 {
		t.Errorf("bogus template produced %d samples; want 0", len(got))
	}
}

// TestParseV9_VarlenFieldQuarantined_AUDIT284 pins that a v9 template carrying a
// 0xFFFF-length field is quarantined. v9/NetFlow has no variable-length fields
// (RFC 3954); put() exempts 0xFFFF from its width cap for legitimate IPFIX
// varlen IEs, so a v9 template with it would slip through and decodeDataRecord
// would read it as a 1-byte varlen prefix, desyncing every field offset for the
// exporter. The template must never register and the data set must decode
// nothing. On a reverted fix the template registers (cache len 1) and this
// fails.
func TestParseV9_VarlenFieldQuarantined_AUDIT284(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	badTmpl := v9Template(256,
		tf(ieSourceIPv4Address, 4),
		tf(ieDestinationIPv4Address, varlenFieldLen), // 0xFFFF — illegal in v9
		tf(ieOctetDeltaCount, 4),
	)
	dataBody := []byte{10, 0, 0, 1, 10, 0, 0, 2, 3, 4} // referenced by set 256
	dg := buildV9(v9HdrAt(now, 500000), fset(0, 0, badTmpl), fset(256, 0, dataBody))
	r.parseDatagram(dg, "192.0.2.1", now)

	sawMalformed := false
	for _, e := range getEvents() {
		if e == eventMalformed {
			sawMalformed = true
		}
	}
	if !sawMalformed {
		t.Errorf("expected eventMalformed for the v9 0xFFFF template")
	}
	if n := r.caches.templates.len(); n != 0 {
		t.Errorf("v9 0xFFFF template registered (cache len=%d); want 0 (quarantined)", n)
	}
	if got := getSamples(); len(got) != 0 {
		t.Errorf("v9 0xFFFF template produced %d samples; want 0 (never decoded)", len(got))
	}
}

// TestParseV9OptionsVarlenFieldQuarantined_AUDIT284 is the options-template twin
// of the guard: a v9 OPTIONS template with a 0xFFFF field is quarantined too.
func TestParseV9OptionsVarlenFieldQuarantined_AUDIT284(t *testing.T) {
	now := time.Now()
	r, _, getEvents := newTestReceiver()

	// One scope field (4 bytes) + one option field with length 0xFFFF.
	badOpt := v9OptionsTemplate(256,
		[][]byte{tf(1, 4)},
		[][]byte{tf(ieOctetDeltaCount, varlenFieldLen)},
	)
	dg := buildV9(v9HdrAt(now, 500000), fset(1, 0, badOpt))
	r.parseDatagram(dg, "192.0.2.1", now)

	sawMalformed := false
	for _, e := range getEvents() {
		if e == eventMalformed {
			sawMalformed = true
		}
	}
	if !sawMalformed {
		t.Errorf("expected eventMalformed for the v9 0xFFFF options template")
	}
	if n := r.caches.templates.len(); n != 0 {
		t.Errorf("v9 0xFFFF options template registered (cache len=%d); want 0 (quarantined)", n)
	}
}
