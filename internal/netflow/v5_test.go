package netflow

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// newTestReceiver builds a NetFlowReceiver whose handler captures emitted flow
// samples and whose parse-event callback captures event labels. The receiver
// is otherwise unstarted — tests call parseDatagram/handleDatagram directly to
// keep the suite deterministic and race-detector friendly (same idiom as the
// sFlow suite).
func newTestReceiver() (*NetFlowReceiver, func() []*relay.FlowSample, func() []string) {
	var (
		mu      sync.Mutex
		samples []*relay.FlowSample
		events  []string
	)
	r := New("127.0.0.1", 2055, 4739)
	r.handler = func(s *relay.FlowSample) {
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
	}
	r.onParseEvent = func(e string) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	getSamples := func() []*relay.FlowSample {
		mu.Lock()
		defer mu.Unlock()
		out := make([]*relay.FlowSample, len(samples))
		copy(out, samples)
		return out
	}
	getEvents := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(events))
		copy(out, events)
		return out
	}
	return r, getSamples, getEvents
}

func u16be(buf []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(buf, v)
}

func u32be(buf []byte, v uint32) []byte {
	return binary.BigEndian.AppendUint32(buf, v)
}

// v5Header parameterizes the 24-byte NetFlow v5 header for the builders.
type v5Header struct {
	count     uint16
	sysUptime uint32 // ms since exporter boot
	unixSecs  uint32
	unixNsecs uint32
	flowSeq   uint32
	sampling  uint16 // raw sampling word: mode(2 bits) | interval(14 bits)
}

// v5Record parameterizes one 48-byte v5 flow record. Zero values are valid on
// the wire, so tests set only what they assert.
type v5Record struct {
	src, dst, nextHop [4]byte
	input, output     uint16
	packets, octets   uint32
	first, last       uint32 // sysUptime offsets, ms
	srcPort, dstPort  uint16
	tcpFlags          uint8
	proto             uint8
	tos               uint8
	srcAS, dstAS      uint16
}

// buildV5 assembles a complete v5 datagram from a header and records. When
// hdr.count is 0 it is auto-filled with len(recs); tests exercising count lies
// set it explicitly.
func buildV5(hdr v5Header, recs ...v5Record) []byte {
	count := hdr.count
	if count == 0 {
		count = uint16(len(recs))
	}
	d := make([]byte, 0, v5HeaderLen+len(recs)*v5RecordLen)
	d = u16be(d, 5) // version
	d = u16be(d, count)
	d = u32be(d, hdr.sysUptime)
	d = u32be(d, hdr.unixSecs)
	d = u32be(d, hdr.unixNsecs)
	d = u32be(d, hdr.flowSeq)
	d = append(d, 0, 0) // engine_type, engine_id
	d = u16be(d, hdr.sampling)
	for _, r := range recs {
		d = append(d, r.src[:]...)
		d = append(d, r.dst[:]...)
		d = append(d, r.nextHop[:]...)
		d = u16be(d, r.input)
		d = u16be(d, r.output)
		d = u32be(d, r.packets)
		d = u32be(d, r.octets)
		d = u32be(d, r.first)
		d = u32be(d, r.last)
		d = u16be(d, r.srcPort)
		d = u16be(d, r.dstPort)
		d = append(d, 0)          // pad1
		d = append(d, r.tcpFlags) // tcp_flags
		d = append(d, r.proto)    // prot
		d = append(d, r.tos)      // tos
		d = u16be(d, r.srcAS)
		d = u16be(d, r.dstAS)
		d = append(d, 24, 24) // src_mask, dst_mask
		d = append(d, 0, 0)   // pad2
	}
	return d
}

// hdrAt builds a v5 header whose export time is `now` and whose uptime is
// sysUptime — the common "healthy exporter" baseline for timestamp tests.
func hdrAt(now time.Time, sysUptime uint32) v5Header {
	return v5Header{
		sysUptime: sysUptime,
		unixSecs:  uint32(now.Unix()),
		unixNsecs: uint32(now.Nanosecond()),
	}
}

// TestParseV5_FullFieldMapping is the golden-bytes test: every v5 record field
// must land on its relay.FlowSample counterpart, with FlowSource=1, the UDP
// source IP as SamplerAddress, and Timestamp = flow end.
func TestParseV5_FullFieldMapping(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 500000)
	hdr.flowSeq = 12345
	rec := v5Record{
		src:      [4]byte{10, 0, 0, 1},
		dst:      [4]byte{192, 0, 2, 50},
		nextHop:  [4]byte{10, 0, 0, 254},
		input:    3,
		output:   7,
		packets:  10,
		octets:   4200,
		first:    440000, // 60 s of flow, ending 10 s before export
		last:     490000,
		srcPort:  55000,
		dstPort:  443,
		tcpFlags: 0x1b,
		proto:    6,
		tos:      0xb8,
		srcAS:    64500,
		dstAS:    64511,
	}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "203.0.113.9", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	s := got[0]
	if s.FlowSource != relay.FlowSourceNetFlowV5 {
		t.Errorf("FlowSource = %d, want %d", s.FlowSource, relay.FlowSourceNetFlowV5)
	}
	if s.SamplerAddress != "203.0.113.9" {
		t.Errorf("SamplerAddress = %q, want the UDP source IP", s.SamplerAddress)
	}
	if s.SequenceNumber != 12345 {
		t.Errorf("SequenceNumber = %d, want 12345", s.SequenceNumber)
	}
	if s.SamplingRate != 1 {
		t.Errorf("SamplingRate = %d, want 1", s.SamplingRate)
	}
	if s.SrcAddr != "10.0.0.1" || s.DstAddr != "192.0.2.50" {
		t.Errorf("addrs = %q -> %q", s.SrcAddr, s.DstAddr)
	}
	if s.NextHop != "10.0.0.254" {
		t.Errorf("NextHop = %q, want 10.0.0.254", s.NextHop)
	}
	if s.InputIfIndex != 3 || s.OutputIfIndex != 7 {
		t.Errorf("ifindexes = %d/%d, want 3/7", s.InputIfIndex, s.OutputIfIndex)
	}
	if s.Packets != 10 || s.Bytes != 4200 {
		t.Errorf("counters = %d pkts / %d bytes, want 10 / 4200", s.Packets, s.Bytes)
	}
	if s.SrcPort != 55000 || s.DstPort != 443 {
		t.Errorf("ports = %d -> %d, want 55000 -> 443", s.SrcPort, s.DstPort)
	}
	if s.TCPFlags != 0x1b || s.Protocol != 6 || s.TOS != 0xb8 {
		t.Errorf("flags/proto/tos = 0x%02x/%d/0x%02x", s.TCPFlags, s.Protocol, s.TOS)
	}
	if s.SrcAS != 64500 || s.DstAS != 64511 {
		t.Errorf("AS = %d/%d, want 64500/64511", s.SrcAS, s.DstAS)
	}
	if s.Drops != 0 {
		t.Errorf("Drops = %d, want 0 (NetFlow rows never carry sFlow drop semantics)", s.Drops)
	}
	if s.FlowStart == nil || s.FlowEnd == nil {
		t.Fatalf("FlowStart/FlowEnd not set: %v/%v", s.FlowStart, s.FlowEnd)
	}
	// last is 10 s before the header uptime, first 60 s before last.
	wantEnd := now.Truncate(time.Millisecond).Add(-10 * time.Second)
	if diff := s.FlowEnd.Sub(wantEnd); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("FlowEnd = %v, want ~%v", s.FlowEnd, wantEnd)
	}
	if dur := s.FlowEnd.Sub(*s.FlowStart); dur != 50*time.Second {
		t.Errorf("duration = %v, want 50s", dur)
	}
	if !s.Timestamp.Equal(*s.FlowEnd) {
		t.Errorf("legacy Timestamp = %v, want = FlowEnd %v", s.Timestamp, *s.FlowEnd)
	}
}

// TestParseV5_SamplingMultiplication is THE regression from research
// correction 1.1: sampled v5 counters are sampled-scale, so the collector must
// multiply by the rate (rate 100 × 88 bytes → 8800) or every sampled exporter
// undercounts by the rate.
func TestParseV5_SamplingMultiplication(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000)
	hdr.sampling = 100 // mode 0, interval 100
	rec := v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, packets: 1, octets: 88, first: 90000, last: 95000}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	if got[0].Bytes != 8800 || got[0].Packets != 100 {
		t.Errorf("counters = %d bytes / %d pkts, want 8800 / 100 (×rate renormalization)", got[0].Bytes, got[0].Packets)
	}
	if got[0].SamplingRate != 100 {
		t.Errorf("SamplingRate = %d, want 100", got[0].SamplingRate)
	}
}

// TestParseV5_SamplingModeBitsMasked verifies the top-2 mode bits of the
// sampling word are masked off before use: 0xC064 (mode 3, interval 100) must
// yield rate 100, not 49252.
func TestParseV5_SamplingModeBitsMasked(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000)
	hdr.sampling = 0xC064
	rec := v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, packets: 1, octets: 1, first: 90000, last: 95000}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	if got[0].SamplingRate != 100 {
		t.Errorf("SamplingRate = %d, want 100 (0xC064 & 0x3FFF)", got[0].SamplingRate)
	}
}

// TestParseV5_SamplingZeroDefaultsToOne: unsampled exporters send 0; the rate
// must default to 1 (multiplying by 0 would zero every counter).
func TestParseV5_SamplingZeroDefaultsToOne(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000) // sampling word 0
	rec := v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, packets: 7, octets: 700, first: 90000, last: 95000}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	if got[0].SamplingRate != 1 || got[0].Bytes != 700 || got[0].Packets != 7 {
		t.Errorf("rate/bytes/pkts = %d/%d/%d, want 1/700/7", got[0].SamplingRate, got[0].Bytes, got[0].Packets)
	}
}

// TestParseV5_CountLieClamped: a header claiming more records than the
// datagram carries must salvage the records that ARE present and fire the
// malformed event — not trust the count into adjacent memory or drop the
// whole datagram.
func TestParseV5_CountLieClamped(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000)
	hdr.count = 5 // lie: only 2 records follow
	recs := []v5Record{
		{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1, first: 90000, last: 95000},
		{src: [4]byte{10, 0, 0, 3}, dst: [4]byte{10, 0, 0, 4}, octets: 2, first: 90000, last: 95000},
	}

	r, getSamples, getEvents := newTestReceiver()
	r.parseDatagram(buildV5(hdr, recs...), "192.0.2.1", now)

	if got := getSamples(); len(got) != 2 {
		t.Fatalf("expected 2 salvaged samples, got %d", len(got))
	}
	if ev := getEvents(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("events = %v, want [%q]", ev, eventMalformed)
	}
}

// TestParseV5_TruncatedRecordSalvaged: a datagram cut mid-record must yield
// the complete records only, plus the malformed event for the ragged tail.
func TestParseV5_TruncatedRecordSalvaged(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000)
	recs := []v5Record{
		{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1, first: 90000, last: 95000},
		{src: [4]byte{10, 0, 0, 3}, dst: [4]byte{10, 0, 0, 4}, octets: 2, first: 90000, last: 95000},
	}
	dg := buildV5(hdr, recs...)
	dg = dg[:len(dg)-20] // cut the second record short

	r, getSamples, getEvents := newTestReceiver()
	r.parseDatagram(dg, "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 complete sample from truncated datagram, got %d", len(got))
	}
	if got[0].SrcAddr != "10.0.0.1" {
		t.Errorf("salvaged the wrong record: %q", got[0].SrcAddr)
	}
	if ev := getEvents(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("events = %v, want [%q]", ev, eventMalformed)
	}
}

// TestParseV5_TruncatedHeader: fewer than 24 bytes cannot be a v5 datagram.
func TestParseV5_TruncatedHeader(t *testing.T) {
	r, getSamples, getEvents := newTestReceiver()
	short := u16be(nil, 5)
	short = u16be(short, 1)
	r.parseDatagram(short, "192.0.2.1", time.Now())

	if got := getSamples(); len(got) != 0 {
		t.Fatalf("expected 0 samples from truncated header, got %d", len(got))
	}
	if ev := getEvents(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("events = %v, want [%q]", ev, eventMalformed)
	}
}

// TestParseV5_ICMPConvention: v5 encodes ICMP type*256+code in the dst_port
// field. For protocol 1 the parser must move it to ICMPTypeCode and zero BOTH
// ports so ICMP never pollutes port-based filters (destination-unreachable/
// port-unreachable = 3*256+3 = 771).
func TestParseV5_ICMPConvention(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000)
	rec := v5Record{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2},
		proto: 1, srcPort: 1234, dstPort: 0x0303,
		octets: 84, packets: 1, first: 90000, last: 95000,
	}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	s := got[0]
	if s.ICMPTypeCode != 771 {
		t.Errorf("ICMPTypeCode = %d, want 771 (type 3 code 3)", s.ICMPTypeCode)
	}
	if s.SrcPort != 0 || s.DstPort != 0 {
		t.Errorf("ICMP ports not zeroed: %d -> %d", s.SrcPort, s.DstPort)
	}

	// A TCP record with the same port values must be left alone.
	rec.proto = 6
	r2, getSamples2, _ := newTestReceiver()
	r2.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)
	got2 := getSamples2()
	if len(got2) != 1 || got2[0].ICMPTypeCode != 0 || got2[0].DstPort != 0x0303 {
		t.Errorf("non-ICMP record mangled: %+v", got2[0])
	}
}

// TestParseV5_WrapCorrectionFirstGreaterLast pins nfdump's first wrap rule:
// First > Last means the uptime counter wrapped mid-flow, so the start belongs
// one 2^32 ms wrap earlier — the duration must come out small and positive,
// not ~49.7 days negative.
func TestParseV5_WrapCorrectionFirstGreaterLast(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 200000)
	rec := v5Record{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1,
		first: 4294800000, // pre-wrap
		last:  100000,     // post-wrap
	}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	s := got[0]
	// end = export − (200000 − 100000) = export − 100 s.
	wantEnd := now.Truncate(time.Millisecond).Add(-100 * time.Second)
	if diff := s.FlowEnd.Sub(wantEnd); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("FlowEnd = %v, want ~%v", s.FlowEnd, wantEnd)
	}
	// duration = Last − First + 2^32 = 267296 ms.
	if dur := s.FlowEnd.Sub(*s.FlowStart); dur != 267296*time.Millisecond {
		t.Errorf("duration = %v, want 267.296s (wrap-corrected)", dur)
	}
}

// TestParseV5_WrapCorrectionLastExceedsUptime pins the Cisco-CSCei12353 rule:
// Last exceeding sysUptime by more than 100000 ms means the HEADER's uptime
// wrapped after the record was stamped, so both First and Last belong one wrap
// earlier. Without the correction the flow end lands ~49.7 days in the future.
func TestParseV5_WrapCorrectionLastExceedsUptime(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 5000) // uptime just wrapped
	rec := v5Record{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1,
		first: 4294400000, // pre-wrap
		last:  4294500000, // pre-wrap, exceeds sysUptime by ≫ 100000 ms
	}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	s := got[0]
	// end = export − 5000 + 4294500000 − 2^32 = export − 472296 ms (~7.9 min
	// ago — inside the plausibility window, so the correction, not the clamp,
	// must have produced it).
	wantEnd := now.Truncate(time.Millisecond).Add(-472296 * time.Millisecond)
	if diff := s.FlowEnd.Sub(wantEnd); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("FlowEnd = %v, want ~%v (both-wrap correction)", s.FlowEnd, wantEnd)
	}
	if dur := s.FlowEnd.Sub(*s.FlowStart); dur != 100*time.Second {
		t.Errorf("duration = %v, want 100s", dur)
	}
}

// TestParseV5_SmallLastExcessNotCorrected: Last slightly ahead of sysUptime
// (records queued after the header was stamped) is normal jitter, NOT a wrap —
// the −2^32 correction must not fire.
func TestParseV5_SmallLastExcessNotCorrected(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000)
	rec := v5Record{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1,
		first: 90000,
		last:  100500, // 500 ms past sysUptime — under the 100000 ms slack
	}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	// end = export + 500 ms — plausible, uncorrected.
	wantEnd := now.Truncate(time.Millisecond).Add(500 * time.Millisecond)
	if diff := got[0].FlowEnd.Sub(wantEnd); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("FlowEnd = %v, want ~%v (no correction for small excess)", got[0].FlowEnd, wantEnd)
	}
}

// TestParseV5_SkewFallbackToReceiveTime: a broken exporter clock (export time
// hours off the receive time) must not stamp garbage into the time index —
// FlowEnd falls back to the receive time, keeping the flow's internal duration
// when it is believable.
func TestParseV5_SkewFallbackToReceiveTime(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now.Add(-3*time.Hour), 100000) // exporter clock 3 h behind
	rec := v5Record{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1,
		first: 40000, last: 90000, // 50 s duration — believable
	}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	s := got[0]
	if !s.FlowEnd.Equal(now) {
		t.Errorf("FlowEnd = %v, want receive time %v (skew fallback)", s.FlowEnd, now)
	}
	if dur := s.FlowEnd.Sub(*s.FlowStart); dur != 50*time.Second {
		t.Errorf("duration = %v, want preserved 50s", dur)
	}
	if !s.Timestamp.Equal(now) {
		t.Errorf("legacy Timestamp = %v, want receive time", s.Timestamp)
	}
}

// TestParseV5_NextHopZeroOmitted: 0.0.0.0 means "no next hop" on the wire and
// must not be stored (or serialized) as a real address.
func TestParseV5_NextHopZeroOmitted(t *testing.T) {
	now := time.Now()
	hdr := hdrAt(now, 100000)
	rec := v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1, first: 90000, last: 95000}

	r, getSamples, _ := newTestReceiver()
	r.parseDatagram(buildV5(hdr, rec), "192.0.2.1", now)

	got := getSamples()
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	if got[0].NextHop != "" {
		t.Errorf("NextHop = %q, want empty for 0.0.0.0", got[0].NextHop)
	}
	b, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"next_hop":`) {
		t.Errorf("JSON should omit next_hop for 0.0.0.0: %s", b)
	}
}

// TestSFlowZeroValuesOmitNewWireFields pins deliverable A's compatibility
// contract: a FlowSample the sFlow path emits (none of the Tranche 3 fields
// set) must serialize WITHOUT any of the new JSON keys, so a pre-adopting
// server sees an unchanged wire format.
func TestSFlowZeroValuesOmitNewWireFields(t *testing.T) {
	s := &relay.FlowSample{
		Timestamp:      time.Now(),
		SamplerAddress: "192.0.2.1",
		SrcAddr:        "10.0.0.1",
		DstAddr:        "10.0.0.2",
		Bytes:          100,
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		"flow_source", "flow_start", "flow_end", "firewall_event",
		"flow_end_reason", "post_nat_src_addr", "post_nat_dst_addr",
		"post_nat_src_port", "post_nat_dst_port", "icmp_type_code",
		"tos", "src_vlan", "dst_vlan", "app_name",
	} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("zero-valued FlowSample leaked new wire field %q: %s", key, b)
		}
	}
}
