package netflow

import (
	"strings"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// ---- IPFIX wire builders (fset/tf shared with the v9 suite — the 4-byte set
// header and IANA field specifier encode identically in both protocols).

// buildIPFIX assembles an IPFIX message with the header Length computed from
// the actual sets. Tests exercising length lies use buildIPFIXLen.
func buildIPFIX(exportSecs, seq, odid uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	return buildIPFIXLen(uint16(ipfixHeaderLen+len(body)), exportSecs, seq, odid, body)
}

// buildIPFIXLen assembles an IPFIX message with an explicit header Length.
func buildIPFIXLen(length uint16, exportSecs, seq, odid uint32, body []byte) []byte {
	d := u16be(nil, 10)
	d = u16be(d, length)
	d = u32be(d, exportSecs)
	d = u32be(d, seq)
	d = u32be(d, odid)
	return append(d, body...)
}

// etf encodes one enterprise field specifier: type with bit 15 set, length,
// then the 4-byte PEN (RFC 7011 §3.2).
func etf(pen uint32, typ, length uint16) []byte {
	b := u16be(nil, typ|ipfixEnterpriseBit)
	b = u16be(b, length)
	return u32be(b, pen)
}

// ipfixTemplate encodes one template record for set 2. Specs come from tf()
// (IANA) or etf() (enterprise) — each counts as ONE field regardless of the
// PEN's extra 4 bytes.
func ipfixTemplate(tid uint16, specs ...[]byte) []byte {
	b := u16be(nil, tid)
	b = u16be(b, uint16(len(specs)))
	for _, s := range specs {
		b = append(b, s...)
	}
	return b
}

// ipfixOptionsTemplate encodes one options template record for set 3 with the
// IPFIX FIELD-COUNT semantics: totalFieldCount + scopeFieldCount (counts, not
// bytes — the other side of the v9 corruption trap).
func ipfixOptionsTemplate(tid uint16, scopeCount int, specs ...[]byte) []byte {
	b := u16be(nil, tid)
	b = u16be(b, uint16(len(specs)))
	b = u16be(b, uint16(scopeCount))
	for _, s := range specs {
		b = append(b, s...)
	}
	return b
}

// ipfixWithdrawal encodes a template-withdrawal record (fieldCount 0;
// tid 2/3 = withdraw-all).
func ipfixWithdrawal(tid uint16) []byte {
	return u16be(u16be(nil, tid), 0)
}

// validIPFIXMessage builds a self-contained template+data message (used by
// the lifecycle test and the fuzz seeds).
func validIPFIXMessage(now time.Time) []byte {
	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4),
	)
	rec := append(append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 640)...), u32be(nil, 4)...)
	return buildIPFIX(uint32(now.Unix()), 1, 7, fset(2, 0, tmpl), fset(256, 0, rec))
}

// TestParseIPFIX_TemplateThenData is the happy path: template set + data set
// in one message → a FlowSource=3 sample, with flowEndMilliseconds (152/153)
// preferred over the lower-priority seconds pair carried alongside.
func TestParseIPFIX_TemplateThenData(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4),
		tf(ieFlowStartMilliseconds, 8), tf(ieFlowEndMilliseconds, 8),
		tf(ieFlowStartSeconds, 4), tf(ieFlowEndSeconds, 4),
	)
	endMs := now.Add(-10 * time.Second).UnixMilli()
	startMs := endMs - 50000
	rec := []byte{10, 0, 0, 1, 192, 0, 2, 50}
	rec = u16be(rec, 55000)
	rec = u16be(rec, 443)
	rec = append(rec, 6)
	rec = u32be(rec, 4200)
	rec = u32be(rec, 10)
	rec = u64beT(rec, uint64(startMs))
	rec = u64beT(rec, uint64(endMs))
	// Deliberately WRONG seconds pair — must lose to 152/153.
	rec = u32be(rec, uint32(now.Add(-time.Hour).Unix()))
	rec = u32be(rec, uint32(now.Add(-time.Hour).Unix()))

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 9, 3, fset(2, 0, tmpl), fset(256, 0, rec)), "203.0.113.5", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d (events=%v)", len(got), getEvents())
	}
	s := got[0]
	if s.FlowSource != relay.FlowSourceIPFIX {
		t.Errorf("FlowSource = %d, want %d", s.FlowSource, relay.FlowSourceIPFIX)
	}
	if s.SequenceNumber != 9 || s.SamplerAddress != "203.0.113.5" {
		t.Errorf("seq/sampler = %d/%q", s.SequenceNumber, s.SamplerAddress)
	}
	if s.Bytes != 4200 || s.Packets != 10 {
		t.Errorf("counters = %d/%d", s.Bytes, s.Packets)
	}
	if s.FlowEnd == nil || s.FlowEnd.UnixMilli() != endMs {
		t.Errorf("FlowEnd = %v, want ms-precision %d (152/153 must outrank 150/151)", s.FlowEnd, endMs)
	}
	if s.FlowStart == nil || s.FlowStart.UnixMilli() != startMs {
		t.Errorf("FlowStart = %v, want %d", s.FlowStart, startMs)
	}
}

// u64beT appends a big-endian uint64 (test helper; the parser side is
// length-agnostic via decodeBE).
func u64beT(buf []byte, v uint64) []byte {
	buf = u32be(buf, uint32(v>>32))
	return u32be(buf, uint32(v))
}

// TestParseIPFIX_HeaderLengthBounds pins the Length-field contract: bytes
// past the header Length are trailing garbage and ignored (no malformed, no
// phantom sets); a Length shorter than the fixed header is malformed; a
// Length LONGER than the datagram (truncation) still decodes the sets that
// arrived whole.
func TestParseIPFIX_HeaderLengthBounds(t *testing.T) {
	now := time.Now()

	// Trailing garbage beyond Length: ignored.
	r, getSamples, getEvents := newTestReceiver()
	msg := validIPFIXMessage(now)
	msg = append(msg, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x00, 0x04, 0x00) // junk that would misparse as a set
	r.parseDatagram(msg, "192.0.2.1", now)
	if got := getSamples(); len(got) != 1 {
		t.Fatalf("trailing garbage changed decoding: %d samples", len(got))
	}
	if ev := getEvents(); len(ev) != 0 {
		t.Errorf("trailing garbage events = %v, want none", ev)
	}

	// Length < fixed header size: malformed.
	r2, _, getEvents2 := newTestReceiver()
	r2.parseDatagram(buildIPFIXLen(8, uint32(now.Unix()), 1, 3, nil), "192.0.2.1", now)
	if ev := getEvents2(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("undersized length events = %v, want [%q]", ev, eventMalformed)
	}

	// Length > datagram (truncated in flight): the whole template set arrived,
	// the data set did not — template registers, ragged set aborts malformed.
	r3, getSamples3, getEvents3 := newTestReceiver()
	full := validIPFIXMessage(now)
	cut := append([]byte(nil), full[:len(full)-8]...) // cut mid-data-set, header Length still claims full
	r3.parseDatagram(cut, "192.0.2.1", now)
	if got := getSamples3(); len(got) != 0 {
		t.Fatalf("truncated data set emitted %d samples", len(got))
	}
	if ev := getEvents3(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("truncation events = %v, want [%q]", ev, eventMalformed)
	}
	// The template survived the truncated message — a follow-up data-only
	// message decodes.
	rec := append(append([]byte{10, 0, 0, 9, 10, 0, 0, 8}, u32be(nil, 77)...), u32be(nil, 1)...)
	r3.parseDatagram(buildIPFIX(uint32(now.Unix()), 2, 7, fset(256, 0, rec)), "192.0.2.1", now)
	if got := getSamples3(); len(got) != 1 || got[0].Bytes != 77 {
		t.Fatalf("template lost to truncation: samples=%v", got)
	}
}

// TestParseIPFIX_OptionsCountSemantics is the IPFIX side of THE corruption
// trap (research §2.6): set-3 options templates carry FIELD COUNTS. This
// template (total 2, scope 1) would misparse under v9 byte semantics (scope
// "2 bytes" is not even pair-aligned), so the correct rate landing in the
// sampler cache — and applying to a selectorId-bearing data record — proves
// the count path is in use.
func TestParseIPFIX_OptionsCountSemantics(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	optTmpl := ipfixOptionsTemplate(260, 1,
		tf(ieSelectorID, 4),             // scope: the sampler being described
		tf(ieSamplingPacketInterval, 4), // rate
	)
	optData := append(u32be(nil, 7), u32be(nil, 1000)...) // selector 7 → rate 1000

	dataTmpl := ipfixTemplate(257,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieOctetDeltaCount, 4), tf(ieSelectorID, 4),
	)
	rec := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 5)...)
	rec = append(rec, u32be(nil, 7)...) // references selector 7

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3,
		fset(3, 0, optTmpl),
		fset(260, 0, optData),
		fset(2, 0, dataTmpl),
		fset(257, 0, rec),
	), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample (options data must NOT emit), got %d (events=%v)", len(got), getEvents())
	}
	if got[0].SamplingRate != 1000 || got[0].Bytes != 5000 {
		t.Errorf("rate/bytes = %d/%d, want 1000/5000 — sampler table corrupted?", got[0].SamplingRate, got[0].Bytes)
	}
}

// TestParseIPFIX_SamplingIntervalSpacePair: with both 305 and 306 present the
// effective rate is (interval+space)/interval (PSAMP count-based sampling:
// 1 taken, 99 skipped → 1-in-100).
func TestParseIPFIX_SamplingIntervalSpacePair(t *testing.T) {
	now := time.Now()
	r, getSamples, _ := newTestReceiver()

	optTmpl := ipfixOptionsTemplate(261, 1,
		tf(ieSelectorID, 4),
		tf(ieSamplingPacketInterval, 4),
		tf(ieSamplingPacketSpace, 4),
	)
	optData := append(append(u32be(nil, 0), u32be(nil, 1)...), u32be(nil, 99)...)

	dataTmpl := ipfixTemplate(258, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4))
	rec := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 88)...)

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3,
		fset(3, 0, optTmpl), fset(261, 0, optData),
		fset(2, 0, dataTmpl), fset(258, 0, rec),
	), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	// The options record carried a selectorId scope of 0; the data record has
	// no selector reference, so the rate resolves via... the per-sampler entry
	// is keyed to ID 0 and skipped (no reference) — this test pins the DOMAIN
	// fallback NOT applying from a sampler-scoped option. See the assertion.
	if got[0].SamplingRate != 1 {
		t.Errorf("SamplingRate = %d, want 1 (sampler-scoped rate must not leak to unreferenced records)", got[0].SamplingRate)
	}

	// Now a record that DOES reference selector 0 gets the composed rate 100.
	dataTmpl2 := ipfixTemplate(259, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4), tf(ieSelectorID, 4))
	rec2 := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 88)...)
	rec2 = append(rec2, u32be(nil, 0)...)
	// seq 3: the first message carried TWO data records (the options data
	// record counts — RFC 7011 sequences count data records of every kind).
	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 3, 3,
		fset(2, 0, dataTmpl2), fset(259, 0, rec2),
	), "192.0.2.1", now)
	got = getSamples()
	if len(got) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(got))
	}
	if got[1].SamplingRate != 100 || got[1].Bytes != 8800 {
		t.Errorf("rate/bytes = %d/%d, want 100/8800 ((305+306)/305)", got[1].SamplingRate, got[1].Bytes)
	}
}

// TestParseIPFIX_VarlenBothEncodings: template length 0xFFFF → a 1-byte
// actual length in the data, with first byte 255 escaping to a 2-byte BE
// length (prefix excluded from the field length) — and the varlen field sits
// BEFORE the mapped fixed fields, so a mis-sized walk would corrupt every
// field that follows. (An opaque enterprise string is used because IPFIX
// element IDs are 15-bit — PAN's raw 56701 has bit 15 set and exists only in
// v9's full 16-bit type space; the v9 PAN fixture covers the AppName mapping.)
func TestParseIPFIX_VarlenBothEncodings(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := ipfixTemplate(256,
		etf(penPaloAlto, 1001, varlenFieldLen), // opaque vendor string, varlen
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieOctetDeltaCount, 4),
	)
	// Record 1: short-form varlen (len 3).
	rec1 := append([]byte{3}, []byte("dns")...)
	rec1 = append(rec1, 10, 0, 0, 1, 10, 0, 0, 2)
	rec1 = append(rec1, u32be(nil, 100)...)
	// Record 2: long-form varlen (255 escape + 2-byte BE length 300).
	long := strings.Repeat("A", 300)
	rec2 := append([]byte{255}, u16be(nil, 300)...)
	rec2 = append(rec2, []byte(long)...)
	rec2 = append(rec2, 10, 0, 0, 3, 10, 0, 0, 4)
	rec2 = append(rec2, u32be(nil, 200)...)

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3,
		fset(2, 0, tmpl), fset(256, 0, rec1, rec2),
	), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 2 {
		t.Fatalf("expected 2 samples, got %d (events=%v)", len(got), getEvents())
	}
	if got[0].SrcAddr != "10.0.0.1" || got[0].Bytes != 100 {
		t.Errorf("short-form: src=%q bytes=%d, want 10.0.0.1/100 (varlen walk desynced?)", got[0].SrcAddr, got[0].Bytes)
	}
	if got[1].SrcAddr != "10.0.0.3" || got[1].Bytes != 200 {
		t.Errorf("long-form: src=%q bytes=%d, want 10.0.0.3/200 (255-escape walk desynced?)", got[1].SrcAddr, got[1].Bytes)
	}
}

// TestParseIPFIX_TruncatedVarlen: a varlen length prefix pointing past the
// set end must drop the REMAINDER of the set with malformed — records already
// decoded stay.
func TestParseIPFIX_TruncatedVarlen(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4),
		etf(penPaloAlto, 1001, varlenFieldLen),
		tf(ieOctetDeltaCount, 4),
	)
	rec1 := []byte{10, 0, 0, 1}
	rec1 = append(rec1, 3)
	rec1 = append(rec1, []byte("web")...)
	rec1 = append(rec1, u32be(nil, 100)...)
	// Record 2 lies: varlen claims 200 bytes, only a handful remain. It must
	// be LONGER than minRecLen so the walk enters it (shorter would be legal
	// padding) — the lying length prefix is what trips the truncation guard.
	rec2 := []byte{10, 0, 0, 2, 200, 0xde, 0xad, 0xbe, 0xef, 0x01}

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3,
		fset(2, 0, tmpl), fset(256, 0, rec1, rec2),
	), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 || got[0].Bytes != 100 {
		t.Fatalf("expected only the intact first record, got %d samples", len(got))
	}
	if ev := getEvents(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("events = %v, want [%q]", ev, eventMalformed)
	}
}

// TestParseIPFIX_SonicWallEnterpriseSkip is the SonicWall-shaped fixture:
// PEN-8741 "IPFIX with extensions" AppFlow fields interleaved with standard
// IEs — enterprise fields skip by their template length, standard fields must
// land intact around them.
func TestParseIPFIX_SonicWallEnterpriseSkip(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4),
		etf(penSonicWall, 1001, 4), // opaque AppFlow field
		tf(ieDestinationIPv4Address, 4),
		etf(penSonicWall, 1002, 8), // opaque
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4),
	)
	rec := []byte{10, 0, 0, 1}
	rec = append(rec, 0xaa, 0xbb, 0xcc, 0xdd) // enterprise junk
	rec = append(rec, 192, 0, 2, 50)
	rec = append(rec, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88) // enterprise junk
	rec = u16be(rec, 55000)
	rec = u16be(rec, 443)
	rec = append(rec, 6)
	rec = u32be(rec, 4200)
	rec = u32be(rec, 10)

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3, fset(2, 0, tmpl), fset(256, 0, rec)), "192.0.2.44", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d (events=%v)", len(got), getEvents())
	}
	s := got[0]
	if s.SrcAddr != "10.0.0.1" || s.DstAddr != "192.0.2.50" || s.SrcPort != 55000 ||
		s.DstPort != 443 || s.Protocol != 6 || s.Bytes != 4200 || s.Packets != 10 {
		t.Errorf("standard fields corrupted by enterprise skip: %+v", s)
	}
}

// TestParseIPFIX_BiflowReversePEN pins RFC 5103 biflow: reverse-PEN-29305
// IE 1/2 emit a second mirrored row; a record with ONLY reverse counters is
// dropped with the reverse_only_dropped event.
func TestParseIPFIX_BiflowReversePEN(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4),
		etf(penReverse, ieOctetDeltaCount, 4), etf(penReverse, iePacketDeltaCount, 4),
	)
	rec := []byte{10, 0, 0, 1, 192, 0, 2, 50}
	rec = u16be(rec, 50000)
	rec = u16be(rec, 22)
	rec = append(rec, 6)
	rec = u32be(rec, 100)
	rec = u32be(rec, 1)
	rec = u32be(rec, 200) // reverse bytes
	rec = u32be(rec, 2)   // reverse packets

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3, fset(2, 0, tmpl), fset(256, 0, rec)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 2 {
		t.Fatalf("expected forward+reverse, got %d (events=%v)", len(got), getEvents())
	}
	fwd, rev := got[0], got[1]
	if fwd.Bytes != 100 || fwd.Packets != 1 || rev.Bytes != 200 || rev.Packets != 2 {
		t.Errorf("counters fwd %d/%d rev %d/%d, want 100/1 200/2", fwd.Bytes, fwd.Packets, rev.Bytes, rev.Packets)
	}
	if rev.SrcAddr != "192.0.2.50" || rev.DstAddr != "10.0.0.1" || rev.SrcPort != 22 || rev.DstPort != 50000 {
		t.Errorf("reverse tuple not mirrored: %s:%d -> %s:%d", rev.SrcAddr, rev.SrcPort, rev.DstAddr, rev.DstPort)
	}

	// Reverse-only record: dropped + event.
	tmpl2 := ipfixTemplate(257,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		etf(penReverse, ieOctetDeltaCount, 4),
	)
	rec2 := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 500)...)
	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 2, 3, fset(2, 0, tmpl2), fset(257, 0, rec2)), "192.0.2.1", now)
	if got := getSamples(); len(got) != 2 {
		t.Fatalf("reverse-only record emitted a sample: %d total", len(got))
	}
	found := false
	for _, e := range getEvents() {
		if e == eventReverseOnlyDropped {
			found = true
		}
	}
	if !found {
		t.Errorf("events = %v, want %q present", getEvents(), eventReverseOnlyDropped)
	}
}

// TestParseIPFIX_NTPTimestamps pins the 154/155 dateTimeMicroseconds decode:
// 64-bit NTP format (seconds since 1900 + 2^-32 fraction, bottom 11 fraction
// bits masked) — including the era-1 edge past 2036-02-07, disambiguated
// against the message export time.
func TestParseIPFIX_NTPTimestamps(t *testing.T) {
	cases := []struct {
		name string
		now  time.Time
	}{
		{"era0-present-day", time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)},
		{"era1-post-2036", time.Date(2040, 3, 1, 12, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := tc.now
			r, getSamples, getEvents := newTestReceiver()

			tmpl := ipfixTemplate(256,
				tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
				tf(ieOctetDeltaCount, 4),
				tf(ieFlowStartMicroseconds, 8), tf(ieFlowEndMicroseconds, 8),
			)
			end := now.Add(-10 * time.Second)
			start := end.Add(-50 * time.Second)
			// NTP encode: seconds word wraps modulo 2^32 (the era-1 edge), the
			// fraction encodes 500 ms as 0x80000000.
			ntp := func(t time.Time) uint64 {
				secs := uint64(uint32(t.Unix() + ntpEpochOffset))
				return secs<<32 | 0x80000000
			}
			rec := []byte{10, 0, 0, 1, 10, 0, 0, 2}
			rec = u32be(rec, 100)
			rec = u64beT(rec, ntp(start))
			rec = u64beT(rec, ntp(end))

			r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3, fset(2, 0, tmpl), fset(256, 0, rec)), "192.0.2.1", now)

			got := getSamples()
			if len(got) != 1 {
				t.Fatalf("expected 1 sample, got %d (events=%v)", len(got), getEvents())
			}
			s := got[0]
			wantEnd := end.Add(500 * time.Millisecond)
			if s.FlowEnd == nil || absDuration(s.FlowEnd.Sub(wantEnd)) > time.Millisecond {
				t.Errorf("FlowEnd = %v, want ~%v (NTP decode / era disambiguation)", s.FlowEnd, wantEnd)
			}
			if dur := s.FlowEnd.Sub(*s.FlowStart); dur != 50*time.Second {
				t.Errorf("duration = %v, want 50s", dur)
			}
		})
	}
}

// TestParseIPFIX_WithdrawalHandling pins RFC 7011 §8.1 over UDP: withdrawal
// records (fieldCount 0, incl. the tid-2/3 withdraw-alls) are parsed then
// ignored with an event — they must not corrupt set iteration (a template
// AFTER the withdrawal in the same set still registers) and must never
// register a zero-length template.
func TestParseIPFIX_WithdrawalHandling(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := ipfixTemplate(257, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4))
	rec := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 100)...)

	// One template set: withdrawal(256), withdraw-all(2), then a REAL template
	// 257 — iteration must reach it. Plus an options-set withdraw-all(3).
	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3,
		fset(2, 0, ipfixWithdrawal(256), ipfixWithdrawal(2), tmpl),
		fset(3, 0, ipfixWithdrawal(3)),
		fset(257, 0, rec),
	), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 || got[0].Bytes != 100 {
		t.Fatalf("template after withdrawal did not register: %d samples (events=%v)", len(got), getEvents())
	}
	withdrawals := 0
	for _, e := range getEvents() {
		if e == eventTemplateWithdrawal {
			withdrawals++
		}
	}
	if withdrawals != 3 {
		t.Errorf("withdrawal events = %d, want 3", withdrawals)
	}

	// The withdrawn ID must not have become a decodable (zero-length) template:
	// data for 256 is data-before-template, and MUST NOT hang the walk.
	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 2, 3, fset(256, 0, []byte{1, 2, 3, 4})), "192.0.2.1", now)
	found := false
	for _, e := range getEvents() {
		if e == eventDataNoTemplate {
			found = true
		}
	}
	if !found {
		t.Errorf("withdrawal registered a template for ID 256: events=%v", getEvents())
	}
}

// TestParseIPFIX_UptimeIEsIgnored: IPFIX has no sysUptime in its header, so
// uptime-relative IEs 21/22 are undecodable there — the flow falls back to
// the receive time instead of doing garbage math (research §2.5).
func TestParseIPFIX_UptimeIEsIgnored(t *testing.T) {
	now := time.Now()
	r, getSamples, _ := newTestReceiver()

	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieOctetDeltaCount, 4),
		tf(ieFlowEndSysUpTime, 4), tf(ieFlowStartSysUpTime, 4),
	)
	rec := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 100)...)
	rec = u32be(rec, 490000)
	rec = u32be(rec, 440000)

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3, fset(2, 0, tmpl), fset(256, 0, rec)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	if got[0].FlowEnd == nil || !got[0].FlowEnd.Equal(now) {
		t.Errorf("FlowEnd = %v, want receive time (21/22 must be ignored without a sysUptime)", got[0].FlowEnd)
	}
}

// TestParseIPFIX_StructuredDataSkipped: RFC 6313 structured-data IEs
// (291/292/293, varlen) are recognized-and-skipped by length — the mapped
// fields around them must land.
func TestParseIPFIX_StructuredDataSkipped(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4),
		tf(ieSubTemplateList, varlenFieldLen),
		tf(ieOctetDeltaCount, 4),
	)
	rec := []byte{10, 0, 0, 1}
	rec = append(rec, 5)                            // varlen: 5 bytes of opaque structured data
	rec = append(rec, 0x03, 0x01, 0x00, 0xff, 0xee) // semantic byte + inner junk
	rec = append(rec, u32be(nil, 4200)...)

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3, fset(2, 0, tmpl), fset(256, 0, rec)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d (events=%v)", len(got), getEvents())
	}
	if got[0].SrcAddr != "10.0.0.1" || got[0].Bytes != 4200 {
		t.Errorf("fields around structured data corrupted: %+v", got[0])
	}
}

// TestParseIPFIX_IPv6WinsAndPostNAT: IPv6 addresses (27/28) win over IPv4
// (8/12) when a template carries both, and the standard post-NAT tuple
// (225-228) maps.
func TestParseIPFIX_IPv6WinsAndPostNAT(t *testing.T) {
	now := time.Now()
	r, getSamples, _ := newTestReceiver()

	tmpl := ipfixTemplate(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceIPv6Address, 16), tf(ieDestinationIPv6Address, 16),
		tf(ieOctetDeltaCount, 4),
		tf(iePostNATSourceIPv4Address, 4), tf(iePostNATDestinationIPv4Addr, 4),
		tf(iePostNAPTSourceTransportPort, 2), tf(iePostNAPTDestTransportPort, 2),
	)
	v6src := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	v6dst := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	rec := []byte{10, 0, 0, 1, 10, 0, 0, 2}
	rec = append(rec, v6src...)
	rec = append(rec, v6dst...)
	rec = u32be(rec, 100)
	rec = append(rec, 198, 51, 100, 7)
	rec = append(rec, 203, 0, 113, 9)
	rec = u16be(rec, 40000)
	rec = u16be(rec, 8443)

	r.parseDatagram(buildIPFIX(uint32(now.Unix()), 1, 3, fset(2, 0, tmpl), fset(256, 0, rec)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	s := got[0]
	if s.SrcAddr != "2001:db8::1" || s.DstAddr != "2001:db8::2" {
		t.Errorf("addrs = %q -> %q, want the IPv6 pair to win", s.SrcAddr, s.DstAddr)
	}
	if s.PostNATSrcAddr != "198.51.100.7" || s.PostNATDstAddr != "203.0.113.9" ||
		s.PostNATSrcPort != 40000 || s.PostNATDstPort != 8443 {
		t.Errorf("post-NAT tuple = %s:%d -> %s:%d", s.PostNATSrcAddr, s.PostNATSrcPort, s.PostNATDstAddr, s.PostNATDstPort)
	}
}
