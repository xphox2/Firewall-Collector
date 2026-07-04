package netflow

import (
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// ---- v9 wire builders (shared with the fuzz seeds and, for fset/tf, the
// IPFIX suite — the 4-byte set header and type/length pair encode identically
// in both protocols).

// v9Hdr parameterizes the 20-byte NetFlow v9 header.
type v9Hdr struct {
	count     uint16 // sanity hint only — the parser must never trust it
	sysUptime uint32 // ms since exporter boot
	unixSecs  uint32
	seq       uint32
	sourceID  uint32
}

// v9HdrAt builds a v9 header whose export time is now and whose uptime is
// sysUptime — the "healthy exporter" baseline (v5's hdrAt analogue).
func v9HdrAt(now time.Time, sysUptime uint32) v9Hdr {
	return v9Hdr{sysUptime: sysUptime, unixSecs: uint32(now.Unix())}
}

// buildV9 assembles a v9 datagram from a header and pre-encoded flowsets.
func buildV9(hdr v9Hdr, flowsets ...[]byte) []byte {
	d := u16be(nil, 9)
	d = u16be(d, hdr.count)
	d = u32be(d, hdr.sysUptime)
	d = u32be(d, hdr.unixSecs)
	d = u32be(d, hdr.seq)
	d = u32be(d, hdr.sourceID)
	for _, fs := range flowsets {
		d = append(d, fs...)
	}
	return d
}

// fset wraps one or more record bodies in a (Flow)Set header with `pad`
// trailing zero bytes counted in the set length (4-byte-boundary padding).
func fset(id uint16, pad int, bodies ...[]byte) []byte {
	var body []byte
	for _, b := range bodies {
		body = append(body, b...)
	}
	d := u16be(nil, id)
	d = u16be(d, uint16(4+len(body)+pad))
	d = append(d, body...)
	return append(d, make([]byte, pad)...)
}

// tf encodes one type/length field specifier (v9 and IPFIX IANA form).
func tf(typ, length uint16) []byte {
	return u16be(u16be(nil, typ), length)
}

// v9Template encodes one template record for flowset 0.
func v9Template(tid uint16, fields ...[]byte) []byte {
	b := u16be(nil, tid)
	b = u16be(b, uint16(len(fields)))
	for _, f := range fields {
		b = append(b, f...)
	}
	return b
}

// v9OptionsTemplate encodes one options-template record for flowset 1 with
// the v9 BYTE-length semantics: scope/option lengths are len(pairs)*4 bytes.
func v9OptionsTemplate(tid uint16, scope, options [][]byte) []byte {
	b := u16be(nil, tid)
	b = u16be(b, uint16(len(scope)*4))
	b = u16be(b, uint16(len(options)*4))
	for _, f := range scope {
		b = append(b, f...)
	}
	for _, f := range options {
		b = append(b, f...)
	}
	return b
}

// stdV9Template is the generic RFC-clean data template used across tests:
// IPv4 5-tuple + counters + uptimes (the PAN/FortiGate-style hot path).
func stdV9Template(tid uint16) []byte {
	return v9Template(tid,
		tf(ieSourceIPv4Address, 4),
		tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2),
		tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieTCPControlBits, 1),
		tf(ieIPClassOfService, 1),
		tf(ieOctetDeltaCount, 4),
		tf(iePacketDeltaCount, 4),
		tf(ieIngressInterface, 4),
		tf(ieEgressInterface, 4),
		tf(ieBGPSourceASNumber, 2), // 2-byte AS — decodeBE is width-agnostic
		tf(ieBGPDestinationASNumber, 4),
		tf(ieVLANID, 2),
		tf(iePostVLANID, 2),
		tf(ieFlowEndSysUpTime, 4),
		tf(ieFlowStartSysUpTime, 4),
		tf(ieIPNextHopIPv4Address, 4),
		tf(ieFlowEndReason, 1),
	)
}

// stdV9Record encodes a record matching stdV9Template. last/first are
// sysUptime offsets (ms).
func stdV9Record(bytes, packets, last, first uint32) []byte {
	b := []byte{10, 0, 0, 1, 192, 0, 2, 50} // src, dst
	b = u16be(b, 55000)                     // src port
	b = u16be(b, 443)                       // dst port
	b = append(b, 6, 0x1b, 0xb8)            // proto, tcp_flags, tos
	b = u32be(b, bytes)
	b = u32be(b, packets)
	b = u32be(b, 3) // input ifindex
	b = u32be(b, 7) // output ifindex
	b = u16be(b, 64500)
	b = u32be(b, 64511)
	b = u16be(b, 100) // src vlan
	b = u16be(b, 200) // dst vlan
	b = u32be(b, last)
	b = u32be(b, first)
	b = append(b, 10, 0, 0, 254) // next hop
	b = append(b, 2)             // flow end reason: active timeout
	return b
}

// TestParseV9_TemplateThenData is the golden-bytes happy path: a template
// flowset followed by a data flowset in one datagram must yield a fully
// mapped FlowSource=2 sample, with 21/22 uptime-math timestamps.
func TestParseV9_TemplateThenData(t *testing.T) {
	now := time.Now()
	hdr := v9HdrAt(now, 500000)
	hdr.seq = 42
	hdr.sourceID = 3
	dg := buildV9(hdr,
		fset(0, 0, stdV9Template(256)),
		fset(256, 0, stdV9Record(4200, 10, 490000, 440000)),
	)

	r, getSamples, getEvents := newTestReceiver()
	r.parseDatagram(dg, "203.0.113.9", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d (events=%v)", len(got), getEvents())
	}
	s := got[0]
	if s.FlowSource != relay.FlowSourceNetFlowV9 {
		t.Errorf("FlowSource = %d, want %d", s.FlowSource, relay.FlowSourceNetFlowV9)
	}
	if s.SamplerAddress != "203.0.113.9" || s.SequenceNumber != 42 {
		t.Errorf("sampler/seq = %q/%d, want 203.0.113.9/42", s.SamplerAddress, s.SequenceNumber)
	}
	if s.SrcAddr != "10.0.0.1" || s.DstAddr != "192.0.2.50" {
		t.Errorf("addrs = %q -> %q", s.SrcAddr, s.DstAddr)
	}
	if s.SrcPort != 55000 || s.DstPort != 443 || s.Protocol != 6 {
		t.Errorf("tuple = %d->%d proto %d", s.SrcPort, s.DstPort, s.Protocol)
	}
	if s.TCPFlags != 0x1b || s.TOS != 0xb8 {
		t.Errorf("flags/tos = 0x%02x/0x%02x", s.TCPFlags, s.TOS)
	}
	if s.Bytes != 4200 || s.Packets != 10 || s.SamplingRate != 1 {
		t.Errorf("counters = %d/%d rate %d, want 4200/10 rate 1", s.Bytes, s.Packets, s.SamplingRate)
	}
	if s.InputIfIndex != 3 || s.OutputIfIndex != 7 {
		t.Errorf("ifindexes = %d/%d", s.InputIfIndex, s.OutputIfIndex)
	}
	if s.SrcAS != 64500 || s.DstAS != 64511 {
		t.Errorf("AS = %d/%d", s.SrcAS, s.DstAS)
	}
	if s.SrcVLAN != 100 || s.DstVLAN != 200 {
		t.Errorf("VLANs = %d/%d", s.SrcVLAN, s.DstVLAN)
	}
	if s.NextHop != "10.0.0.254" {
		t.Errorf("NextHop = %q", s.NextHop)
	}
	if s.FlowEndReason != 2 {
		t.Errorf("FlowEndReason = %d, want 2", s.FlowEndReason)
	}
	if s.Drops != 0 {
		t.Errorf("Drops = %d, want 0 (NetFlow never carries sFlow drop semantics)", s.Drops)
	}
	// 21/22 uptime math: end = export − (500000−490000) = export − 10 s. The
	// v9 header export time is SECOND-granular (no nsec word, unlike v5).
	wantEnd := time.Unix(now.Unix(), 0).Add(-10 * time.Second)
	if s.FlowEnd == nil || absDuration(s.FlowEnd.Sub(wantEnd)) > time.Millisecond {
		t.Errorf("FlowEnd = %v, want ~%v", s.FlowEnd, wantEnd)
	}
	if dur := s.FlowEnd.Sub(*s.FlowStart); dur != 50*time.Second {
		t.Errorf("duration = %v, want 50s", dur)
	}
	if !s.Timestamp.Equal(*s.FlowEnd) {
		t.Errorf("legacy Timestamp = %v, want = FlowEnd", s.Timestamp)
	}
	if ev := getEvents(); len(ev) != 0 {
		t.Errorf("unexpected events: %v", ev)
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// TestParseV9_DataBeforeTemplate pins the restart-normal ordering: a data set
// with no template is dropped with the data_before_template event (not an
// error log, not a crash), and once the template arrives the SAME data set
// decodes.
func TestParseV9_DataBeforeTemplate(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	hdr := v9HdrAt(now, 500000)
	hdr.seq = 1
	data := fset(256, 0, stdV9Record(100, 1, 490000, 440000))
	r.parseDatagram(buildV9(hdr, data), "192.0.2.1", now)
	if got := getSamples(); len(got) != 0 {
		t.Fatalf("data-before-template emitted %d samples", len(got))
	}
	if ev := getEvents(); len(ev) != 1 || ev[0] != eventDataNoTemplate {
		t.Fatalf("events = %v, want [%q]", ev, eventDataNoTemplate)
	}

	hdr.seq = 2
	r.parseDatagram(buildV9(hdr, fset(0, 0, stdV9Template(256))), "192.0.2.1", now)
	hdr.seq = 3
	r.parseDatagram(buildV9(hdr, data), "192.0.2.1", now)
	if got := getSamples(); len(got) != 1 {
		t.Fatalf("post-template decode: %d samples, want 1 (events=%v)", len(got), getEvents())
	}
}

// TestParseV9_TemplateRedefinitionMidStream pins the RFC 7011 §8.4 in-place
// replace end-to-end: after a redefinition swaps the src/dst field order,
// subsequent records must decode with the NEW layout.
func TestParseV9_TemplateRedefinitionMidStream(t *testing.T) {
	now := time.Now()
	r, getSamples, _ := newTestReceiver()

	tmplA := v9Template(256, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4))
	tmplB := v9Template(256, tf(ieDestinationIPv4Address, 4), tf(ieSourceIPv4Address, 4), tf(ieOctetDeltaCount, 4))
	rec := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 100)...)

	hdr := v9HdrAt(now, 100000)
	hdr.seq = 1
	r.parseDatagram(buildV9(hdr, fset(0, 0, tmplA), fset(256, 0, rec)), "192.0.2.1", now)
	hdr.seq = 2
	r.parseDatagram(buildV9(hdr, fset(0, 0, tmplB), fset(256, 0, rec)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(got))
	}
	if got[0].SrcAddr != "10.0.0.1" || got[0].DstAddr != "10.0.0.2" {
		t.Errorf("pre-redefinition sample: %q -> %q", got[0].SrcAddr, got[0].DstAddr)
	}
	if got[1].SrcAddr != "10.0.0.2" || got[1].DstAddr != "10.0.0.1" {
		t.Errorf("post-redefinition sample decoded with STALE layout: %q -> %q", got[1].SrcAddr, got[1].DstAddr)
	}
}

// TestParseV9_PaddingTail: trailing padding in a data flowset (remaining <
// minRecLen) must not become a phantom 0.0.0.0→0.0.0.0 flow.
func TestParseV9_PaddingTail(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := v9Template(256, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 2))
	rec := append(append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 100)...), u16be(nil, 1)...) // 14 bytes
	hdr := v9HdrAt(now, 100000)
	// 14-byte record + 2 bytes padding to the 4-byte boundary.
	r.parseDatagram(buildV9(hdr, fset(0, 0, tmpl), fset(256, 2, rec)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample (padding decoded as a record?), got %d (events=%v)", len(got), getEvents())
	}
	if got[0].SrcAddr != "10.0.0.1" {
		t.Errorf("sample = %q, want the real record", got[0].SrcAddr)
	}
}

// TestParseV9_CountFieldLies: the v9 header Count is ambiguous in the wild
// (records? flowsets?) — the walk goes by FlowSet lengths ONLY, so a lying
// count changes nothing: same samples, no malformed event.
func TestParseV9_CountFieldLies(t *testing.T) {
	now := time.Now()
	for _, count := range []uint16{0, 1, 2, 42, 65535} {
		r, getSamples, getEvents := newTestReceiver()
		hdr := v9HdrAt(now, 500000)
		hdr.count = count
		dg := buildV9(hdr,
			fset(0, 0, stdV9Template(256)),
			fset(256, 0, stdV9Record(100, 1, 490000, 440000), stdV9Record(200, 2, 490000, 440000)),
		)
		r.parseDatagram(dg, "192.0.2.1", now)
		if got := getSamples(); len(got) != 2 {
			t.Errorf("count=%d: %d samples, want 2", count, len(got))
		}
		if ev := getEvents(); len(ev) != 0 {
			t.Errorf("count=%d: events = %v, want none (count is a hint, not a contract)", count, ev)
		}
	}
}

// TestParseV9_FlowsetLengthTooSmall: a flowset length under 4 cannot cover its
// own header — the datagram is unrecoverable past that point (abort+malformed).
func TestParseV9_FlowsetLengthTooSmall(t *testing.T) {
	now := time.Now()
	for _, badLen := range []uint16{0, 1, 3} {
		r, getSamples, getEvents := newTestReceiver()
		dg := buildV9(v9HdrAt(now, 100000))
		dg = u16be(dg, 256)    // flowset ID
		dg = u16be(dg, badLen) // impossible length
		dg = append(dg, 0xde, 0xad, 0xbe, 0xef)
		r.parseDatagram(dg, "192.0.2.1", now)
		if got := getSamples(); len(got) != 0 {
			t.Errorf("len=%d: emitted %d samples from garbage", badLen, len(got))
		}
		if ev := getEvents(); len(ev) != 1 || ev[0] != eventMalformed {
			t.Errorf("len=%d: events = %v, want [%q]", badLen, ev, eventMalformed)
		}
	}
}

// TestParseV9_TruncatedFlowset: a flowset length pointing past the datagram
// end aborts with malformed (never reads adjacent memory).
func TestParseV9_TruncatedFlowset(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()
	dg := buildV9(v9HdrAt(now, 100000), fset(0, 0, stdV9Template(256)))
	dg = dg[:len(dg)-6] // cut mid-template
	r.parseDatagram(dg, "192.0.2.1", now)
	if got := getSamples(); len(got) != 0 {
		t.Fatalf("truncated flowset emitted %d samples", len(got))
	}
	if ev := getEvents(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("events = %v, want [%q]", ev, eventMalformed)
	}
}

// TestParseV9_OptionsByteSemantics is one side of THE corruption trap
// (research §2.6): v9 options templates carry scope/option lengths in BYTES.
// This template (scope 4 BYTES = one pair, options 8 BYTES = two pairs) would
// misparse under IPFIX count semantics ("4 total fields, scope count 8"), so
// a correct sampler rate landing proves the v9-bytes path is in use.
func TestParseV9_OptionsByteSemantics(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	optTmpl := v9OptionsTemplate(260,
		[][]byte{tf(1, 4)}, // scope: System(1), 4 bytes — v9 scope types are kinds, not IEs
		[][]byte{tf(ieSamplerID, 2), tf(ieSamplerRandomInterval, 4)},
	)
	// Options data record: scope value + samplerID 5 + rate 100 (10 bytes, pad 2).
	optData := append(append(u32be(nil, 0), u16be(nil, 5)...), u32be(nil, 100)...)

	// Data template referencing the sampler per record via IE 48.
	dataTmpl := v9Template(257,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4), tf(ieSamplerID, 2),
	)
	rec := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 88)...)
	rec = append(rec, u32be(nil, 1)...)
	rec = u16be(rec, 5) // sampler ID 5

	hdr := v9HdrAt(now, 100000)
	r.parseDatagram(buildV9(hdr,
		fset(1, 2, optTmpl),
		fset(260, 2, optData),
		fset(0, 0, dataTmpl),
		fset(257, 2, rec),
	), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample (options data must NOT emit), got %d (events=%v)", len(got), getEvents())
	}
	if got[0].SamplingRate != 100 || got[0].Bytes != 8800 || got[0].Packets != 100 {
		t.Errorf("rate/bytes/pkts = %d/%d/%d, want 100/8800/100 — sampler table corrupted?",
			got[0].SamplingRate, got[0].Bytes, got[0].Packets)
	}
}

// TestParseV9_FortiGateSampledBiflow is the FortiGate-shaped conformance
// fixture: 7.6 sampled-scale counters (research correction 1.1 — rate 100,
// dOctets 88 must store 8800) learned via per-record SamplerID + options
// data, and OUT_BYTES/OUT_PKTS per-session reverse counters emitting a
// second, mirrored row.
func TestParseV9_FortiGateSampledBiflow(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	optTmpl := v9OptionsTemplate(256,
		[][]byte{tf(1, 4)},
		[][]byte{tf(ieSamplerID, 1), tf(ieSamplerRandomInterval, 4)},
	)
	optData := append(append(u32be(nil, 0), byte(1)), u32be(nil, 100)...) // sampler 1 → rate 100

	dataTmpl := v9Template(258,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieIngressInterface, 4), tf(ieEgressInterface, 4),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4),
		tf(iePostOctetDeltaCount, 4), tf(iePostPacketDeltaCount, 4),
		tf(ieSamplerID, 1),
	)
	rec := []byte{10, 0, 0, 5, 8, 8, 8, 8}
	rec = u16be(rec, 50000)
	rec = u16be(rec, 443)
	rec = append(rec, 6)
	rec = u32be(rec, 3)
	rec = u32be(rec, 7)
	rec = u32be(rec, 88) // forward bytes, sampled scale
	rec = u32be(rec, 1)  // forward packets
	rec = u32be(rec, 42) // OUT_BYTES = reverse
	rec = u32be(rec, 1)  // OUT_PKTS
	rec = append(rec, 1) // sampler 1

	hdr := v9HdrAt(now, 100000)
	r.parseDatagram(buildV9(hdr,
		fset(1, 2, optTmpl),
		fset(256, 3, optData),
		fset(0, 0, dataTmpl),
		fset(258, 2, rec),
	), "192.0.2.9", now)

	got := getSamples()
	if len(got) != 2 {
		t.Fatalf("expected forward+reverse samples, got %d (events=%v)", len(got), getEvents())
	}
	fwd, rev := got[0], got[1]
	if fwd.Bytes != 8800 || fwd.Packets != 100 || fwd.SamplingRate != 100 {
		t.Errorf("forward = %d bytes / %d pkts / rate %d, want 8800/100/100 (sampled-scale ×rate)", fwd.Bytes, fwd.Packets, fwd.SamplingRate)
	}
	if rev.Bytes != 4200 || rev.Packets != 100 {
		t.Errorf("reverse = %d bytes / %d pkts, want 4200/100", rev.Bytes, rev.Packets)
	}
	if rev.SrcAddr != fwd.DstAddr || rev.DstAddr != fwd.SrcAddr ||
		rev.SrcPort != fwd.DstPort || rev.DstPort != fwd.SrcPort {
		t.Errorf("reverse 5-tuple not mirrored: fwd %s:%d->%s:%d rev %s:%d->%s:%d",
			fwd.SrcAddr, fwd.SrcPort, fwd.DstAddr, fwd.DstPort,
			rev.SrcAddr, rev.SrcPort, rev.DstAddr, rev.DstPort)
	}
	if rev.InputIfIndex != fwd.OutputIfIndex || rev.OutputIfIndex != fwd.InputIfIndex {
		t.Errorf("reverse ifindexes not swapped: fwd %d/%d rev %d/%d",
			fwd.InputIfIndex, fwd.OutputIfIndex, rev.InputIfIndex, rev.OutputIfIndex)
	}
	if !rev.Timestamp.Equal(fwd.Timestamp) || rev.FlowSource != fwd.FlowSource {
		t.Errorf("reverse timestamps/source differ from forward")
	}
}

// TestParseV9_PANShaped is the Palo Alto conformance fixture: the raw
// vendor-squatted 56701 App-ID string (fixed-width, null-padded in v9) maps
// to AppName, timestamps ride the 21/22 uptime hot path, and with no sampler
// options anywhere the rate defaults to 1 — never held waiting for options.
func TestParseV9_PANShaped(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := v9Template(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4),
		tf(ieFlowEndSysUpTime, 4), tf(ieFlowStartSysUpTime, 4),
		tf(ieFlowDirection, 1), // deliberately unmapped — server derives direction
		tf(fieldPANAppID, 32),  // PAN raw ID: 32-byte null-padded string
	)
	app := make([]byte, 32)
	copy(app, "dns")
	rec := []byte{10, 0, 0, 1, 10, 0, 0, 2}
	rec = u16be(rec, 34567)
	rec = u16be(rec, 53)
	rec = append(rec, 17)
	rec = u32be(rec, 300)
	rec = u32be(rec, 2)
	rec = u32be(rec, 490000) // LAST_SWITCHED
	rec = u32be(rec, 440000) // FIRST_SWITCHED
	rec = append(rec, 1)     // direction: egress (ignored)
	rec = append(rec, app...)

	hdr := v9HdrAt(now, 500000)
	r.parseDatagram(buildV9(hdr, fset(0, 0, tmpl), fset(256, 3, rec)), "192.0.2.7", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d (events=%v)", len(got), getEvents())
	}
	s := got[0]
	if s.AppName != "dns" {
		t.Errorf("AppName = %q, want %q (null padding trimmed)", s.AppName, "dns")
	}
	if s.SamplingRate != 1 || s.Bytes != 300 || s.Packets != 2 {
		t.Errorf("rate/bytes/pkts = %d/%d/%d, want 1/300/2 (unsampled PAN default)", s.SamplingRate, s.Bytes, s.Packets)
	}
	wantEnd := time.Unix(now.Unix(), 0).Add(-10 * time.Second) // v9 export time is second-granular
	if s.FlowEnd == nil || absDuration(s.FlowEnd.Sub(wantEnd)) > time.Millisecond {
		t.Errorf("FlowEnd = %v, want ~%v (21/22 uptime math)", s.FlowEnd, wantEnd)
	}
	if dur := s.FlowEnd.Sub(*s.FlowStart); dur != 50*time.Second {
		t.Errorf("duration = %v, want 50s", dur)
	}
}

// asaTemplate is the NSEL-shaped teardown template: 231/232 are the ONLY byte
// counters ASA ever sends (no packet counters exist), the post-NAT tuple uses
// the legacy 40001-40004 raw IDs, and event time is absolute 323 (+161).
func asaTemplate(tid uint16) []byte {
	return v9Template(tid,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieInitiatorOctets, 4), tf(ieResponderOctets, 4),
		tf(ieFirewallEvent, 1),
		tf(fieldASAXlateSrcAddrIPv4, 4), tf(fieldASAXlateDstAddrIPv4, 4),
		tf(fieldASAXlateSrcPort, 2), tf(fieldASAXlateDstPort, 2),
		tf(ieObservationTimeMilliseconds, 8),
		tf(ieFlowDurationMilliseconds, 4),
	)
}

func asaRecord(initOctets, respOctets uint32, event byte, obsMs uint64, durMs uint32) []byte {
	rec := []byte{10, 0, 0, 1, 192, 0, 2, 50}
	rec = u16be(rec, 44444)
	rec = u16be(rec, 443)
	rec = append(rec, 6)
	rec = u32be(rec, initOctets)
	rec = u32be(rec, respOctets)
	rec = append(rec, event)
	rec = append(rec, 198, 51, 100, 1) // xlate src
	rec = append(rec, 192, 0, 2, 50)   // xlate dst
	rec = u16be(rec, 20000)
	rec = u16be(rec, 443)
	rec = u32be(rec, uint32(obsMs>>32))
	rec = u32be(rec, uint32(obsMs))
	rec = u32be(rec, durMs)
	return rec
}

// TestParseV9_ASATeardownBiflow: an NSEL teardown with both 231 and 232 must
// emit forward + reverse rows — bytes land, packets stay 0 (ASA sends none).
func TestParseV9_ASATeardownBiflow(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	obsMs := uint64(now.Add(-5 * time.Second).UnixMilli()) // flow end 5 s ago
	hdr := v9HdrAt(now, 100000)
	r.parseDatagram(buildV9(hdr,
		fset(0, 0, asaTemplate(263)),
		fset(263, 3, asaRecord(5000, 7000, 2, obsMs, 60000)),
	), "192.0.2.20", now)

	got := getSamples()
	if len(got) != 2 {
		t.Fatalf("expected forward+reverse rows, got %d (events=%v)", len(got), getEvents())
	}
	fwd, rev := got[0], got[1]
	if fwd.Bytes != 5000 || fwd.Packets != 0 {
		t.Errorf("forward = %d bytes / %d pkts, want 5000/0 (ASA has NO packet counters)", fwd.Bytes, fwd.Packets)
	}
	if rev.Bytes != 7000 || rev.Packets != 0 {
		t.Errorf("reverse = %d bytes / %d pkts, want 7000/0", rev.Bytes, rev.Packets)
	}
	if fwd.FirewallEvent != 2 {
		t.Errorf("FirewallEvent = %d, want 2 (teardown)", fwd.FirewallEvent)
	}
	if fwd.PostNATSrcAddr != "198.51.100.1" || fwd.PostNATSrcPort != 20000 {
		t.Errorf("post-NAT src = %s:%d, want 198.51.100.1:20000 (40001/40003 aliases)", fwd.PostNATSrcAddr, fwd.PostNATSrcPort)
	}
	if rev.SrcAddr != fwd.DstAddr || rev.DstAddr != fwd.SrcAddr {
		t.Errorf("reverse addrs not mirrored: %q->%q vs %q->%q", fwd.SrcAddr, fwd.DstAddr, rev.SrcAddr, rev.DstAddr)
	}
	if rev.PostNATSrcAddr != fwd.PostNATDstAddr || rev.PostNATDstAddr != fwd.PostNATSrcAddr {
		t.Errorf("reverse post-NAT tuple not mirrored")
	}
	// 323 + 161: end = obs time, start = end − 60 s.
	wantEnd := time.UnixMilli(int64(obsMs))
	if fwd.FlowEnd == nil || absDuration(fwd.FlowEnd.Sub(wantEnd)) > time.Millisecond {
		t.Errorf("FlowEnd = %v, want ~%v (IE 323)", fwd.FlowEnd, wantEnd)
	}
	if dur := fwd.FlowEnd.Sub(*fwd.FlowStart); dur != time.Minute {
		t.Errorf("duration = %v, want 1m (IE 161)", dur)
	}
}

// TestParseV9_ASADeniedZeroCounters: NSEL denied records carry NO counters at
// all — they must still emit (Bytes=0, FirewallEvent=3): denied-flow
// visibility is the headline NetFlow win, and rejecting zero-byte rows would
// erase it.
func TestParseV9_ASADeniedZeroCounters(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	deniedTmpl := v9Template(261,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1),
		tf(ieFirewallEvent, 1),
	)
	rec := []byte{10, 0, 0, 66, 192, 0, 2, 50}
	rec = u16be(rec, 51234)
	rec = u16be(rec, 3389)
	rec = append(rec, 6)
	rec = append(rec, 3) // denied

	hdr := v9HdrAt(now, 100000)
	r.parseDatagram(buildV9(hdr, fset(0, 0, deniedTmpl), fset(261, 2, rec)), "192.0.2.20", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("denied record dropped: %d samples (events=%v)", len(got), getEvents())
	}
	s := got[0]
	if s.Bytes != 0 || s.Packets != 0 {
		t.Errorf("counters = %d/%d, want 0/0", s.Bytes, s.Packets)
	}
	if s.FirewallEvent != 3 {
		t.Errorf("FirewallEvent = %d, want 3 (denied)", s.FirewallEvent)
	}
	if s.SrcAddr != "10.0.0.66" || s.DstPort != 3389 {
		t.Errorf("denied tuple lost: %s -> :%d", s.SrcAddr, s.DstPort)
	}
	// No timestamps in the record → stamped with the receive time.
	if s.FlowEnd == nil || !s.FlowEnd.Equal(now) {
		t.Errorf("FlowEnd = %v, want receive time", s.FlowEnd)
	}
}

// TestParseV9_MikroTikIE34InData: MikroTik ships the legacy sampling rate IE
// 34 inside DATA records (goflow2 #113) — the rate must be learned from the
// record AND applied to that very record.
func TestParseV9_MikroTikIE34InData(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tmpl := v9Template(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4),
		tf(ieSamplingInterval, 4),
	)
	rec := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 10)...)
	rec = append(rec, u32be(nil, 1)...)
	rec = append(rec, u32be(nil, 50)...) // IE 34: rate 50

	hdr := v9HdrAt(now, 100000)
	r.parseDatagram(buildV9(hdr, fset(0, 0, tmpl), fset(256, 0, rec)), "192.0.2.30", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d (events=%v)", len(got), getEvents())
	}
	if got[0].SamplingRate != 50 || got[0].Bytes != 500 || got[0].Packets != 50 {
		t.Errorf("rate/bytes/pkts = %d/%d/%d, want 50/500/50 (IE 34 learned in-record)", got[0].SamplingRate, got[0].Bytes, got[0].Packets)
	}

	// The learned rate persists as the domain rate for later records that
	// don't carry IE 34.
	tmpl2 := v9Template(257, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4))
	rec2 := append([]byte{10, 0, 0, 3, 10, 0, 0, 4}, u32be(nil, 20)...)
	hdr.seq = 1
	r.parseDatagram(buildV9(hdr, fset(0, 0, tmpl2), fset(257, 0, rec2)), "192.0.2.30", now)
	got = getSamples()
	if len(got) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(got))
	}
	if got[1].SamplingRate != 50 || got[1].Bytes != 1000 {
		t.Errorf("follow-up rate/bytes = %d/%d, want 50/1000 (domain rate learned)", got[1].SamplingRate, got[1].Bytes)
	}
}

// TestParseV9_ICMPConvention: for protocol 1 the IE 32 type*256+code moves to
// ICMPTypeCode and both ports zero — and when IE 32 is absent, Cisco's
// L4_DST_PORT mirror is the fallback (same convention as v5/server).
func TestParseV9_ICMPConvention(t *testing.T) {
	now := time.Now()
	r, getSamples, _ := newTestReceiver()

	withIE32 := v9Template(256,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1), tf(ieICMPTypeCodeIPv4, 2),
		tf(ieOctetDeltaCount, 4),
	)
	rec := []byte{10, 0, 0, 1, 10, 0, 0, 2}
	rec = u16be(rec, 1234)
	rec = u16be(rec, 0)
	rec = append(rec, 1)     // ICMP
	rec = u16be(rec, 0x0303) // type 3 code 3
	rec = append(rec, u32be(nil, 84)...)

	hdr := v9HdrAt(now, 100000)
	r.parseDatagram(buildV9(hdr, fset(0, 0, withIE32), fset(256, 1, rec)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	if got[0].ICMPTypeCode != 771 || got[0].SrcPort != 0 || got[0].DstPort != 0 {
		t.Errorf("ICMP mapping = code %d ports %d/%d, want 771 0/0", got[0].ICMPTypeCode, got[0].SrcPort, got[0].DstPort)
	}

	// Fallback: no IE 32, type*256+code mirrored in dst port.
	mirror := v9Template(257,
		tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4),
		tf(ieSourceTransportPort, 2), tf(ieDestinationTransportPort, 2),
		tf(ieProtocolIdentifier, 1), tf(ieOctetDeltaCount, 4),
	)
	rec2 := []byte{10, 0, 0, 1, 10, 0, 0, 2}
	rec2 = u16be(rec2, 0)
	rec2 = u16be(rec2, 0x0800) // echo request in the dst-port mirror
	rec2 = append(rec2, 1)
	rec2 = append(rec2, u32be(nil, 84)...)
	hdr.seq = 1
	r.parseDatagram(buildV9(hdr, fset(0, 0, mirror), fset(257, 3, rec2)), "192.0.2.1", now)
	got = getSamples()
	if len(got) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(got))
	}
	if got[1].ICMPTypeCode != 0x0800 || got[1].DstPort != 0 {
		t.Errorf("dst-port mirror fallback: code %d dstPort %d, want 2048/0", got[1].ICMPTypeCode, got[1].DstPort)
	}
}

// TestParseV9_MultipleTemplatesOneFlowset: one template flowset may carry
// several templates back-to-back.
func TestParseV9_MultipleTemplatesOneFlowset(t *testing.T) {
	now := time.Now()
	r, getSamples, getEvents := newTestReceiver()

	tA := v9Template(256, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4))
	tB := v9Template(257, tf(ieSourceIPv4Address, 4), tf(ieOctetDeltaCount, 4))
	recA := append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 100)...)
	recB := append([]byte{10, 0, 0, 3}, u32be(nil, 200)...)

	hdr := v9HdrAt(now, 100000)
	r.parseDatagram(buildV9(hdr, fset(0, 0, tA, tB), fset(256, 0, recA), fset(257, 0, recB)), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 2 {
		t.Fatalf("expected 2 samples from 2 templates in one flowset, got %d (events=%v)", len(got), getEvents())
	}
	if got[0].Bytes != 100 || got[1].Bytes != 200 {
		t.Errorf("bytes = %d/%d, want 100/200", got[0].Bytes, got[1].Bytes)
	}
}
