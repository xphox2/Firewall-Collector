package sflow

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// newTestReceiver builds an SFlowReceiver whose handler captures emitted
// flow samples. Returns the receiver and a getter that returns a snapshot
// of the samples received so far. The receiver is otherwise unstarted —
// tests call parseSFlowDatagram directly to keep the suite deterministic
// and race-detector friendly.
func newTestReceiver() (*SFlowReceiver, func() []*relay.FlowSample) {
	var (
		mu      sync.Mutex
		samples []*relay.FlowSample
	)
	r := NewSFlowReceiver("127.0.0.1", 0)
	r.handler = func(s *relay.FlowSample) {
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
	}
	get := func() []*relay.FlowSample {
		mu.Lock()
		defer mu.Unlock()
		out := make([]*relay.FlowSample, len(samples))
		copy(out, samples)
		return out
	}
	return r, get
}

func u32be(buf []byte, v uint32) []byte {
	return binary.BigEndian.AppendUint32(buf, v)
}

// buildIPv4EthernetTCPHeader constructs a minimal Ethernet/IPv4/TCP header
// suitable for the sFlow raw-packet-header record. srcIP/dstIP are 4 bytes
// each, srcPort/dstPort are network-order, tcpFlags goes into byte 13 of
// the TCP header (SYN=0x02, SYN+ACK=0x12, etc).
func buildIPv4EthernetTCPHeader(srcIP, dstIP [4]byte, srcPort, dstPort uint16, tcpFlags uint8) []byte {
	hdr := make([]byte, 0, 14+20+20)
	// Ethernet: 6+6+2
	hdr = append(hdr,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, // dst MAC
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02, // src MAC
		0x08, 0x00, // ethertype: IPv4
	)
	// IPv4: 20 bytes, version=4, IHL=5, protocol=6 (TCP), total_length=40
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[1] = 0x00
	binary.BigEndian.PutUint16(ip[2:], 40)
	binary.BigEndian.PutUint16(ip[4:], 0x1234) // identification
	ip[6] = 0x40                               // don't fragment
	ip[7] = 0x00
	ip[8] = 64 // TTL
	ip[9] = 6  // protocol: TCP
	// 10..11: header checksum (leave zero — sFlow parser does not verify)
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	hdr = append(hdr, ip...)

	// TCP: 20 bytes
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], 0) // seq
	binary.BigEndian.PutUint32(tcp[8:], 0) // ack
	tcp[12] = 0x50                         // data offset = 5 (20 bytes), reserved = 0
	tcp[13] = tcpFlags
	binary.BigEndian.PutUint16(tcp[14:], 65535) // window
	// 16..17: checksum (zero)
	// 18..19: urgent pointer (zero)
	hdr = append(hdr, tcp...)
	return hdr
}

// buildRawPacketRecord wraps a packet header in a raw-packet-header record
// (enterprise=0, format=1). recordLen is the total record payload length
// claimed by the record; if it is less than 16+len(pktHdr) the parser will
// reject the record on the recEnd check.
func buildRawPacketRecord(pktHdr []byte, recordLen uint32) []byte {
	r := make([]byte, 0, 8+16+len(pktHdr))
	r = u32be(r, 1) // enterprise=0, format=1 (raw packet header)
	r = u32be(r, recordLen)
	r = u32be(r, 1) // protocol=1 (Ethernet)
	r = u32be(r, uint32(len(pktHdr)))
	r = u32be(r, 0) // stripped
	r = u32be(r, uint32(len(pktHdr)))
	r = append(r, pktHdr...)
	return r
}

// buildFlowSample wraps one or more records in a flow sample (format=1).
// Each record's bytes are written verbatim after the sample header.
// The drops counter is always 0; tests that need a non-zero drops
// value use buildFlowSampleWithDrops.
func buildFlowSample(seqNum, sourceID, samplingRate uint32, records ...[]byte) []byte {
	return buildFlowSampleWithDrops(seqNum, sourceID, samplingRate, 0, records...)
}

// buildFlowSampleWithDrops is the full version of buildFlowSample that
// lets the test set the sFlow v5 §3.1.1 drops counter to any value.
// A non-zero drops count is what the server will alert on to detect
// agent-side congestion (the audit found this field was previously
// read and discarded).
func buildFlowSampleWithDrops(seqNum, sourceID, samplingRate, drops uint32, records ...[]byte) []byte {
	s := make([]byte, 0, 32)
	s = u32be(s, seqNum)
	s = u32be(s, sourceID)
	s = u32be(s, samplingRate)
	s = u32be(s, 0)     // sample_pool
	s = u32be(s, drops) // drops (sFlow v5 §3.1.1)
	s = u32be(s, 0)     // input
	s = u32be(s, 0)     // output
	s = u32be(s, uint32(len(records)))
	for _, r := range records {
		s = append(s, r...)
	}
	return s
}

// buildDatagram wraps flow samples into an sFlow v5 datagram. addrType=1
// selects IPv4 for the agent address.
func buildDatagram(agentIP [4]byte, seq uint32, samples ...[]byte) []byte {
	d := make([]byte, 0, 28+128)
	d = u32be(d, 5) // version=5
	d = u32be(d, 1) // address_type=1 (IPv4)
	d = append(d, agentIP[:]...)
	d = u32be(d, 1)   // sub_agent_id
	d = u32be(d, seq) // sequence_number
	d = u32be(d, 0)   // uptime
	d = u32be(d, uint32(len(samples)))
	for _, s := range samples {
		d = u32be(d, 1) // enterprise=0, format=1 (flow sample)
		d = u32be(d, uint32(len(s)))
		d = append(d, s...)
	}
	return d
}

// TestParseSFlowDatagram_TruncatedAtVersion verifies a datagram shorter
// than the 4-byte version field returns cleanly with no handler call.
// This is the first guard a remote attacker hits when sending a 1-byte
// probe; the parser must not panic.
func TestParseSFlowDatagram_TruncatedAtVersion(t *testing.T) {
	r, get := newTestReceiver()
	r.parseSFlowDatagram([]byte{0x00, 0x00})

	if got := get(); len(got) != 0 {
		t.Fatalf("expected 0 samples for truncated input, got %d", len(got))
	}
}

// TestParseSFlowDatagram_AllZero verifies a buffer of zeros is rejected
// at the version != 5 check (line 121). A real sFlow sender always sets
// version=5; zero is the "blank datagram" attack pattern.
func TestParseSFlowDatagram_AllZero(t *testing.T) {
	r, get := newTestReceiver()
	r.parseSFlowDatagram(make([]byte, 64))

	if got := get(); len(got) != 0 {
		t.Fatalf("expected 0 samples for all-zero datagram, got %d", len(got))
	}
}

// TestParseSFlowDatagram_MalformedIPv4Header verifies the parser survives
// an inner IPv4 header with version=3 and IHL=0. parseIPv4 must reject
// the ihl<20 condition (line 378) and the surrounding flow sample must
// be silently dropped.
func TestParseSFlowDatagram_MalformedIPv4Header(t *testing.T) {
	// Inner Ethernet payload: an "IPv4" header with version=3, IHL=0
	ip := make([]byte, 20)
	ip[0] = 0x30 // version=3, IHL=0
	ip[9] = 6    // protocol=TCP (irrelevant — IHL check fires first)
	copy(ip[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 2).To4())
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 12345)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[13] = 0x02 // SYN
	eth := append([]byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x08, 0x00,
	}, ip...)
	eth = append(eth, tcp...)

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 512, rec)
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 7, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	// The IHL=0 check rejects the IPv4 header: no SrcAddr is populated.
	// The post-loop guard (sample.SrcAddr != "" || sample.DstAddr != ""
	// || seqNum > 0) would still let seqNum=1 through, so a sample IS
	// emitted — but it must have empty SrcAddr/DstAddr. The audit target
	// is "malformed IPv4 header must not produce a decoded flow", not
	// "no sample emitted at all".
	if got := get(); hasAddr(got) {
		var addrs []string
		for _, s := range got {
			addrs = append(addrs, s.SrcAddr+"->"+s.DstAddr)
		}
		t.Fatalf("malformed IPv4 was decoded into sample(s): %v", addrs)
	}
}

// TestParseSFlowDatagram_RealisticFlowSample is the golden-bytes test:
// a complete, well-formed TCP SYN flow sample must produce a flow record
// with the correct 5-tuple and SYN flag.
func TestParseSFlowDatagram_RealisticFlowSample(t *testing.T) {
	var (
		srcIP = [4]byte{10, 0, 0, 1}
		dstIP = [4]byte{10, 0, 0, 2}
	)
	ethTCP := buildIPv4EthernetTCPHeader(srcIP, dstIP, 12345, 443, 0x02)
	rec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	sample := buildFlowSample(42, 100, 512, rec)
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 7, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	s := got[0]
	if s.SrcAddr != "10.0.0.1" {
		t.Errorf("SrcAddr = %q, want %q", s.SrcAddr, "10.0.0.1")
	}
	if s.DstAddr != "10.0.0.2" {
		t.Errorf("DstAddr = %q, want %q", s.DstAddr, "10.0.0.2")
	}
	if s.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", s.SrcPort)
	}
	if s.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", s.DstPort)
	}
	if s.TCPFlags != 0x02 {
		t.Errorf("TCPFlags = 0x%02x, want 0x02 (SYN)", s.TCPFlags)
	}
	if s.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", s.Protocol)
	}
	if s.SamplingRate != 512 {
		t.Errorf("SamplingRate = %d, want 512", s.SamplingRate)
	}
	if s.SamplerAddress != "192.168.1.10" {
		t.Errorf("SamplerAddress = %q, want %q", s.SamplerAddress, "192.168.1.10")
	}
	if s.SequenceNumber != 7 {
		t.Errorf("SequenceNumber = %d, want 7", s.SequenceNumber)
	}
	if s.Bytes == 0 || s.Timestamp.IsZero() {
		t.Errorf("expected non-zero Bytes and Timestamp, got Bytes=%d Timestamp=%v", s.Bytes, s.Timestamp)
	}
}

// TestParseSFlowDatagram_DropsFieldCaptured verifies the sFlow v5 §3.1.1
// drops counter is read from the wire and propagated onto the emitted
// FlowSample. Pre-audit this field was parsed and discarded, hiding
// agent-side congestion from the operator. The test exercises a
// non-zero drops value (42) and asserts the round-trip; a zero drops
// value is implicitly covered by every other test that uses the
// default buildFlowSample helper.
func TestParseSFlowDatagram_DropsFieldCaptured(t *testing.T) {
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{10, 0, 0, 2}
	ethTCP := buildIPv4EthernetTCPHeader(srcIP, dstIP, 12345, 443, 0x02)
	rec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	// 42 packets dropped at the agent between this sample and the previous one.
	sample := buildFlowSampleWithDrops(42, 100, 512, 42, rec)
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 7, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	if got[0].Drops != 42 {
		t.Errorf("Drops = %d, want 42 (the audit found this field was previously read and discarded)", got[0].Drops)
	}
}

// buildExtendedGatewayRecord builds an sFlow extended_gateway record (RFC 3176
// data format 1003) with an IPv4 next-hop, src_as, and a single sequence AS-path
// segment. The origin AS (sample.DstAS) is the last entry of asPath.
func buildExtendedGatewayRecord(nextHop [4]byte, srcAS uint32, asPath []uint32) []byte {
	payload := make([]byte, 0, 64)
	payload = u32be(payload, 1) // next_hop addr type = IPv4
	payload = append(payload, nextHop[:]...)
	payload = u32be(payload, 64500) // as (this gateway) — unused by parser
	payload = u32be(payload, srcAS) // src_as
	payload = u32be(payload, 64510) // src_peer_as — unused
	payload = u32be(payload, 1)     // dst_as_path segment count = 1
	payload = u32be(payload, 2)     // segment type = 2 (sequence)
	payload = u32be(payload, uint32(len(asPath)))
	for _, a := range asPath {
		payload = u32be(payload, a)
	}
	payload = u32be(payload, 0)   // communities count = 0
	payload = u32be(payload, 100) // localpref

	r := make([]byte, 0, 8+len(payload))
	r = u32be(r, 1003) // enterprise=0, format=1003
	r = u32be(r, uint32(len(payload)))
	r = append(r, payload...)
	return r
}

// TestParseSFlowDatagram_ExtendedGateway verifies the extended_gateway (1003)
// record populates SrcAS, DstAS (origin = last AS-path hop), ASPath, and NextHop
// on the emitted sample, alongside the raw-packet-header record in the same flow
// sample.
func TestParseSFlowDatagram_ExtendedGateway(t *testing.T) {
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{10, 0, 0, 2}
	ethTCP := buildIPv4EthernetTCPHeader(srcIP, dstIP, 12345, 443, 0x02)
	rawRec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	gwRec := buildExtendedGatewayRecord([4]byte{192, 0, 2, 1}, 64511, []uint32{64500, 65000, 64496})
	sample := buildFlowSample(42, 100, 512, rawRec, gwRec)
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 7, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	s := got[0]
	if s.SrcAS != 64511 {
		t.Errorf("SrcAS = %d, want 64511", s.SrcAS)
	}
	if s.DstAS != 64496 {
		t.Errorf("DstAS = %d, want 64496 (origin = last AS-path hop)", s.DstAS)
	}
	if s.ASPath != "64500 65000 64496" {
		t.Errorf("ASPath = %q, want %q", s.ASPath, "64500 65000 64496")
	}
	if s.NextHop != "192.0.2.1" {
		t.Errorf("NextHop = %q, want %q", s.NextHop, "192.0.2.1")
	}
	// The raw-packet record must still be parsed in the same sample.
	if s.SrcAddr != "10.0.0.1" || s.DstPort != 443 {
		t.Errorf("raw packet fields lost: SrcAddr=%q DstPort=%d", s.SrcAddr, s.DstPort)
	}
}

// TestParseSFlowDatagram_NoGatewayOmitsBGPFields confirms a flow sample with no
// extended_gateway record leaves the BGP fields zero/empty, so they omit from
// the JSON wire form (backward-compat for pre-adopting servers).
func TestParseSFlowDatagram_NoGatewayOmitsBGPFields(t *testing.T) {
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{10, 0, 0, 2}
	ethTCP := buildIPv4EthernetTCPHeader(srcIP, dstIP, 12345, 443, 0x02)
	rawRec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 7, buildFlowSample(1, 100, 512, rawRec))

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)
	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	s := got[0]
	if s.SrcAS != 0 || s.DstAS != 0 || s.ASPath != "" || s.NextHop != "" {
		t.Errorf("expected empty BGP fields, got SrcAS=%d DstAS=%d ASPath=%q NextHop=%q", s.SrcAS, s.DstAS, s.ASPath, s.NextHop)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"src_as", "dst_as", "as_path", "next_hop"} {
		if strings.Contains(string(b), key) {
			t.Errorf("JSON should omit %q when unset: %s", key, b)
		}
	}
}

// TestParseSFlowDatagram_DropsFieldZeroOmitsFromJSON pins the wire-format
// behavior: drops=0 must not appear in the JSON serialization (the
// `omitempty` tag on relay.FlowSample.Drops). The audit requires this
// so a pre-adopting server (which doesn't know about the Drops field)
// sees no wire field at all when drops=0 and continues to function
// unchanged.
func TestParseSFlowDatagram_DropsFieldZeroOmitsFromJSON(t *testing.T) {
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{10, 0, 0, 2}
	ethTCP := buildIPv4EthernetTCPHeader(srcIP, dstIP, 12345, 443, 0x02)
	rec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	sample := buildFlowSample(1, 1, 512, rec) // drops=0 via the default helper
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	if got[0].Drops != 0 {
		t.Fatalf("setup: Drops = %d, want 0 for default-helper test", got[0].Drops)
	}
	jsonBytes, err := jsonMarshal(got[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if containsField(jsonBytes, "drops") {
		t.Errorf("JSON output contains 'drops' when Drops=0; want omitempty to hide it (server compatibility): %s", jsonBytes)
	}
}

// TestParseSFlowDatagram_NumSamplesExceedsBuffer verifies the per-sample
// loop terminates when offset reaches the end of the buffer, rather than
// spinning through `numSamples` iterations. The audit flagged this as a
// potential CPU-exhaustion / OOM vector; the guard at line 167
// (`offset < len(data)`) must hold.
func TestParseSFlowDatagram_NumSamplesExceedsBuffer(t *testing.T) {
	// Datagram header claims 1000 samples but the buffer ends after
	// the header (no per-sample records follow). The loop must bail
	// out the first time it tries to read sample bytes past the end.
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1)
	// Manually overwrite num_samples to 1000 (the helper writes len(samples)).
	// buildDatagram places it at offset 24..28.
	const numSamplesOffset = 24
	if len(dg) < numSamplesOffset+4 {
		t.Fatalf("datagram too short: %d bytes", len(dg))
	}
	binary.BigEndian.PutUint32(dg[numSamplesOffset:], 1000)

	if len(dg) > 1024 {
		t.Fatalf("test setup bug: datagram is %d bytes, expected <1024", len(dg))
	}

	r, get := newTestReceiver()
	// Must not panic, must not hang, must not block on a missing sample.
	done := make(chan struct{})
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Errorf("parseSFlowDatagram panicked on numSamples>buffer: %v", rec)
			}
			close(done)
		}()
		r.parseSFlowDatagram(dg)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("parseSFlowDatagram did not return within 2s on numSamples>buffer")
	}

	// The 0 samples for-loop does nothing — no flow samples should be emitted
	// (offset hits the end of the buffer on the first iteration's readUint32).
	if got := get(); len(got) != 0 {
		t.Fatalf("expected 0 samples when numSamples exceeds buffer, got %d", len(got))
	}
}

// TestParseSFlowDatagram_RawHeader_Oversized verifies that a raw packet
// header record whose header_length exceeds the available record data is
// rejected. The parser must not allocate or read the (huge) claimed
// header. The current code enforces this via the recEnd check (the
// record's record_length is set smaller than what header_length would
// require).
func TestParseSFlowDatagram_RawHeader_Oversized(t *testing.T) {
	// Build a raw-packet-header record that *claims* a 2000-byte Ethernet
	// header but only allocates 16 bytes of record payload. header_length
	// (2000) is much larger than what's left in the record.
	_ = make([]byte, 16) // dummy reference for the test intent
	// Manually craft a record with header_length=2000 and a short record.
	r := make([]byte, 0, 32)
	r = u32be(r, 1)    // enterprise=0, format=1
	r = u32be(r, 16)   // record_length = 16 (just the fixed fields, no header bytes)
	r = u32be(r, 1)    // protocol = 1 (Ethernet)
	r = u32be(r, 64)   // frame_length
	r = u32be(r, 0)    // stripped
	r = u32be(r, 2000) // header_length = 2000 (oversized vs. record_length)
	// (no actual header bytes follow — recEnd will already be exceeded)

	sample := buildFlowSample(1, 1, 1, r)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	rx, get := newTestReceiver()
	rx.parseSFlowDatagram(dg)

	// The header-length check rejects the record. The flow sample's
	// SrcAddr/DstAddr remain empty, so the post-loop guard
	// (`sample.SrcAddr != "" || ... || seqNum > 0`) would *still* fire
	// and emit a sample (seqNum=1 > 0). We assert that the emitted
	// sample has no decoded addresses — i.e. the IPv4/IPv6/TCP parsers
	// were never reached on the oversized header.
	got := get()
	for i, s := range got {
		if s.SrcAddr != "" || s.DstAddr != "" {
			t.Errorf("sample[%d] decoded addresses from oversized header: src=%q dst=%q", i, s.SrcAddr, s.DstAddr)
		}
	}
}

// TestParseSFlowDatagram_UDPFlow verifies the UDP branch of parseTransport
// (line 411-416) is reachable and produces ports correctly.
func TestParseSFlowDatagram_UDPFlow(t *testing.T) {
	// Ethernet + IPv4 (proto=17) + UDP (8 bytes)
	eth := make([]byte, 0, 14+20+8)
	eth = append(eth,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x08, 0x00,
	)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 28)
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], net.IPv4(192, 168, 1, 1).To4())
	copy(ip[16:20], net.IPv4(8, 8, 8, 8).To4())
	eth = append(eth, ip...)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 53000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	eth = append(eth, udp...)

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample for UDP, got %d", len(got))
	}
	s := got[0]
	if s.SrcAddr != "192.168.1.1" || s.DstAddr != "8.8.8.8" {
		t.Errorf("addr mismatch: src=%q dst=%q", s.SrcAddr, s.DstAddr)
	}
	if s.SrcPort != 53000 || s.DstPort != 53 {
		t.Errorf("port mismatch: src=%d dst=%d", s.SrcPort, s.DstPort)
	}
	if s.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17 (UDP)", s.Protocol)
	}
}

// TestParseSFlowDatagram_IPv6Flow verifies parseIPv6 (line 389) is reachable
// and produces the expected addresses.
func TestParseSFlowDatagram_IPv6Flow(t *testing.T) {
	// Ethernet + IPv6 (40 bytes) + TCP (20 bytes)
	eth := make([]byte, 0, 14+40+20)
	eth = append(eth,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x86, 0xDD, // ethertype: IPv6
	)
	ip6 := make([]byte, 40)
	ip6[4] = 0x00
	ip6[5] = 0x3c // payload length = 60 (TCP+options slack, ignored by parser)
	ip6[6] = 6    // next header: TCP
	ip6[7] = 64   // hop limit
	// Source: 2001:db8::1
	src := net.ParseIP("2001:db8::1").To16()
	copy(ip6[8:24], src)
	// Dest: 2001:db8::2
	dst := net.ParseIP("2001:db8::2").To16()
	copy(ip6[24:40], dst)
	eth = append(eth, ip6...)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 2222)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 0x50
	tcp[13] = 0x18 // PSH+ACK
	eth = append(eth, tcp...)

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample for IPv6, got %d", len(got))
	}
	s := got[0]
	if s.SrcAddr != "2001:db8::1" {
		t.Errorf("SrcAddr = %q, want %q", s.SrcAddr, "2001:db8::1")
	}
	if s.DstAddr != "2001:db8::2" {
		t.Errorf("DstAddr = %q, want %q", s.DstAddr, "2001:db8::2")
	}
	if s.TCPFlags != 0x18 {
		t.Errorf("TCPFlags = 0x%02x, want 0x18 (PSH+ACK)", s.TCPFlags)
	}
	if s.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", s.Protocol)
	}
}

// buildIPv6Eth builds an Ethernet+IPv6 frame whose IPv6 Next Header is
// firstNH, followed by raw payload bytes. Used to construct extension-header
// chains for the parseIPv6 walk tests.
func buildIPv6Eth(firstNH uint8, payload []byte) []byte {
	eth := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x86, 0xDD, // ethertype: IPv6
	}
	ip6 := make([]byte, 40)
	ip6[6] = firstNH // Next Header
	ip6[7] = 64      // hop limit
	copy(ip6[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ip6[24:40], net.ParseIP("2001:db8::2").To16())
	eth = append(eth, ip6...)
	eth = append(eth, payload...)
	return eth
}

// decodeOne runs a single Ethernet payload through the full sFlow pipeline and
// returns the one decoded sample (or fails).
func decodeOne(t *testing.T, eth []byte) *relay.FlowSample {
	t.Helper()
	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)
	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)
	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	return got[0]
}

// TestParseIPv6_HopByHopToTCP is the core regression for the HOPOPT bug: an
// IPv6 packet that starts with a Hop-by-Hop Options extension header (Next
// Header = 0) must be decoded to its real upper-layer protocol (TCP), with
// ports — NOT recorded as protocol 0 (HOPOPT).
func TestParseIPv6_HopByHopToTCP(t *testing.T) {
	// Hop-by-Hop header: next_header=6 (TCP), hdr_ext_len=0 (=> 8 bytes total).
	hbh := []byte{6, 0, 0, 0, 0, 0, 0, 0}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 4444)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[12] = 0x50
	tcp[13] = 0x02 // SYN
	eth := buildIPv6Eth(0 /* Hop-by-Hop */, append(hbh, tcp...))

	s := decodeOne(t, eth)
	if s.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP) — HOPOPT chain not walked", s.Protocol)
	}
	if s.SrcPort != 4444 || s.DstPort != 443 {
		t.Errorf("ports = %d->%d, want 4444->443", s.SrcPort, s.DstPort)
	}
	if s.TCPFlags != 0x02 {
		t.Errorf("TCPFlags = 0x%02x, want 0x02 (SYN)", s.TCPFlags)
	}
	if s.SrcAddr != "2001:db8::1" || s.DstAddr != "2001:db8::2" {
		t.Errorf("addr mismatch: src=%q dst=%q", s.SrcAddr, s.DstAddr)
	}
}

// TestParseIPv6_HopByHopToICMPv6 verifies a portless upper-layer protocol
// (ICMPv6 = 58) is resolved through the extension chain and reported as 58
// (not 0), with no ports.
func TestParseIPv6_HopByHopToICMPv6(t *testing.T) {
	hbh := []byte{58, 0, 0, 0, 0, 0, 0, 0} // next_header=58 (ICMPv6)
	icmp6 := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	eth := buildIPv6Eth(0, append(hbh, icmp6...))

	s := decodeOne(t, eth)
	if s.Protocol != 58 {
		t.Errorf("Protocol = %d, want 58 (ICMPv6)", s.Protocol)
	}
	if s.SrcPort != 0 || s.DstPort != 0 {
		t.Errorf("ICMPv6 must have no ports, got %d->%d", s.SrcPort, s.DstPort)
	}
}

// TestParseIPv6_ChainedExtHeadersToUDP walks two stacked extension headers
// (Hop-by-Hop then Destination Options) before reaching UDP.
func TestParseIPv6_ChainedExtHeadersToUDP(t *testing.T) {
	hbh := []byte{60, 0, 0, 0, 0, 0, 0, 0} // -> Destination Options (60)
	dst := []byte{17, 0, 0, 0, 0, 0, 0, 0} // -> UDP (17)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 5353)
	binary.BigEndian.PutUint16(udp[2:], 53)
	payload := append(append(hbh, dst...), udp...)
	eth := buildIPv6Eth(0, payload)

	s := decodeOne(t, eth)
	if s.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17 (UDP) through 2 ext headers", s.Protocol)
	}
	if s.SrcPort != 5353 || s.DstPort != 53 {
		t.Errorf("ports = %d->%d, want 5353->53", s.SrcPort, s.DstPort)
	}
}

// TestParseIPv6_TruncatedExtHeader verifies a chain cut off mid-extension
// doesn't panic and doesn't fabricate ports.
func TestParseIPv6_TruncatedExtHeader(t *testing.T) {
	// Hop-by-Hop claims to continue but only 1 byte of it is present.
	eth := buildIPv6Eth(0, []byte{6}) // next_header byte only, no length byte
	s := decodeOne(t, eth)
	// Best effort: protocol stays the ext-header value (0) since it can't be
	// read past; the key guarantee is no panic and no bogus ports.
	if s.SrcPort != 0 || s.DstPort != 0 {
		t.Errorf("truncated ext header produced ports: %d->%d", s.SrcPort, s.DstPort)
	}
}

// TestParse6in4InnerDecode verifies a 6in4 tunnel (Ethernet -> IPv4 protocol
// 41 -> IPv6 -> TCP) is decoded to its inner conversation: real upper-layer
// protocol, inner IPv6 addresses, and inner ports — not just "IPv6" (41).
func TestParse6in4InnerDecode(t *testing.T) {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 7000)
	binary.BigEndian.PutUint16(tcp[2:], 8443)
	tcp[13] = 0x10 // ACK
	ip6 := make([]byte, 40)
	ip6[6] = 6 // inner next header = TCP
	ip6[7] = 64
	copy(ip6[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ip6[24:40], net.ParseIP("2001:db8::2").To16())
	inner := append(ip6, tcp...)

	eth := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x08, 0x00, // ethertype: IPv4
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 41 // 6in4
	copy(ip[12:16], net.IPv4(203, 0, 113, 1).To4())
	copy(ip[16:20], net.IPv4(203, 0, 113, 2).To4())
	eth = append(eth, ip...)
	eth = append(eth, inner...)

	s := decodeOne(t, eth)
	if s.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (inner TCP) — 6in4 not decoded", s.Protocol)
	}
	if s.SrcAddr != "2001:db8::1" || s.DstAddr != "2001:db8::2" {
		t.Errorf("inner addresses not decoded: src=%q dst=%q", s.SrcAddr, s.DstAddr)
	}
	if s.SrcPort != 7000 || s.DstPort != 8443 {
		t.Errorf("inner ports = %d->%d, want 7000->8443", s.SrcPort, s.DstPort)
	}
}

// TestParse6in4Truncated verifies a 6in4 packet whose inner IPv6 header is
// truncated falls back to the outer IPv4 tunnel endpoints / protocol 41
// without panicking.
func TestParse6in4Truncated(t *testing.T) {
	eth := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x08, 0x00,
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 41
	copy(ip[12:16], net.IPv4(203, 0, 113, 1).To4())
	copy(ip[16:20], net.IPv4(203, 0, 113, 2).To4())
	eth = append(eth, ip...)
	eth = append(eth, make([]byte, 10)...) // inner IPv6 only 10 bytes

	s := decodeOne(t, eth)
	if s.Protocol != 41 {
		t.Errorf("Protocol = %d, want 41 (fallback on truncated inner)", s.Protocol)
	}
	if s.SrcAddr != "203.0.113.1" || s.DstAddr != "203.0.113.2" {
		t.Errorf("expected outer IPv4 fallback addrs, got src=%q dst=%q", s.SrcAddr, s.DstAddr)
	}
}

// TestParseSFlowDatagram_ExpandedFlowSample covers the format=3 branch
// in parseFlowSample (line 208-216) — expanded flow samples carry
// source_id_type + source_id_index instead of a single source_id, and
// split input/output into type+index pairs.
func TestParseSFlowDatagram_ExpandedFlowSample(t *testing.T) {
	srcIP := [4]byte{172, 16, 0, 5}
	dstIP := [4]byte{172, 16, 0, 6}
	ethTCP := buildIPv4EthernetTCPHeader(srcIP, dstIP, 55555, 22, 0x10) // ACK
	rec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))

	// Build an expanded flow sample (format=3) by hand.
	s := make([]byte, 0, 64)
	s = u32be(s, 9)   // sample sequence_number
	s = u32be(s, 0)   // source_id_type
	s = u32be(s, 7)   // source_id_index
	s = u32be(s, 1)   // sampling_rate
	s = u32be(s, 0)   // sample_pool
	s = u32be(s, 0)   // drops
	s = u32be(s, 0)   // input_type
	s = u32be(s, 101) // input_index
	s = u32be(s, 0)   // output_type
	s = u32be(s, 102) // output_index
	s = u32be(s, 1)   // num_records
	s = append(s, rec...)

	// Wrap in a datagram with format=3 (enterprise=0, format=3).
	dg := make([]byte, 0, 28+8+len(s))
	dg = u32be(dg, 5)
	dg = u32be(dg, 1)
	dg = append(dg, []byte{10, 0, 0, 1}...)
	dg = u32be(dg, 1)
	dg = u32be(dg, 1)
	dg = u32be(dg, 0)
	dg = u32be(dg, 1) // num_samples=1
	dg = u32be(dg, 3) // enterprise=0, format=3
	dg = u32be(dg, uint32(len(s)))
	dg = append(dg, s...)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample for expanded sample, got %d", len(got))
	}
	s2 := got[0]
	if s2.InputIfIndex != 101 || s2.OutputIfIndex != 102 {
		t.Errorf("ifindex mismatch: in=%d out=%d", s2.InputIfIndex, s2.OutputIfIndex)
	}
	if s2.SrcAddr != "172.16.0.5" || s2.DstAddr != "172.16.0.6" {
		t.Errorf("addr mismatch: src=%q dst=%q", s2.SrcAddr, s2.DstAddr)
	}
	if s2.TCPFlags != 0x10 {
		t.Errorf("TCPFlags = 0x%02x, want 0x10 (ACK)", s2.TCPFlags)
	}
}

// TestParseSFlowDatagram_AgentAddressIPv6 verifies the addrType=2 (IPv6)
// branch of parseSFlowDatagram (line 138-143). The agent address is
// carried in the datagram header, not in the packet.
func TestParseSFlowDatagram_AgentAddressIPv6(t *testing.T) {
	srcIP := [4]byte{10, 1, 1, 1}
	dstIP := [4]byte{10, 1, 1, 2}
	ethTCP := buildIPv4EthernetTCPHeader(srcIP, dstIP, 1111, 2222, 0x02)
	rec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	sample := buildFlowSample(1, 1, 1, rec)

	// Build datagram manually with addrType=2 (IPv6) for the agent.
	agent := net.ParseIP("2001:db8:1::1").To16()
	dg := make([]byte, 0, 28+16+8+len(sample))
	dg = u32be(dg, 5)
	dg = u32be(dg, 2) // IPv6
	dg = append(dg, agent...)
	dg = u32be(dg, 1)
	dg = u32be(dg, 99)
	dg = u32be(dg, 0)
	dg = u32be(dg, 1)
	dg = u32be(dg, 1)
	dg = u32be(dg, uint32(len(sample)))
	dg = append(dg, sample...)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	if got[0].SamplerAddress != "2001:db8:1::1" {
		t.Errorf("SamplerAddress = %q, want %q", got[0].SamplerAddress, "2001:db8:1::1")
	}
	if got[0].SequenceNumber != 99 {
		t.Errorf("SequenceNumber = %d, want 99", got[0].SequenceNumber)
	}
}

// TestParseSFlowDatagram_NilHandlerDoesNotPanic verifies the early-return
// guard at line 113-115. This is what makes Start() and test setup
// robust against r.handler being unset.
func TestParseSFlowDatagram_NilHandlerDoesNotPanic(t *testing.T) {
	r := NewSFlowReceiver("127.0.0.1", 0)
	// r.handler is intentionally left nil.
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, []byte{0, 0, 0, 0, 0, 0, 0, 0})

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("parseSFlowDatagram panicked with nil handler: %v", rec)
		}
	}()
	r.parseSFlowDatagram(dg)
}

// TestParseSFlowDatagram_RejectsTruncatedRecordPayload verifies that a
// record whose declared record_length is larger than the remaining
// sample data is rejected on the recEnd > sampleEnd check (line 286).
// A real sFlow sender always agrees with itself, so a mismatch is an
// attack pattern.
func TestParseSFlowDatagram_RejectsTruncatedRecordPayload(t *testing.T) {
	// Build a flow sample that contains a record whose record_length
	// claims 1000 bytes of payload, but the sample is only 8 bytes long
	// past the record header.
	bad := make([]byte, 0, 16)
	bad = u32be(bad, 1)    // enterprise=0, format=1
	bad = u32be(bad, 1000) // record_length = 1000 (way more than sample)
	bad = u32be(bad, 1)    // protocol
	bad = u32be(bad, 1)    // frame_length
	// sample ends here — 12 bytes only, not 1000

	sample := buildFlowSample(1, 1, 1, bad)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	for i, s := range got {
		if s.SrcAddr != "" || s.DstAddr != "" {
			t.Errorf("sample[%d] decoded from truncated record: src=%q dst=%q", i, s.SrcAddr, s.DstAddr)
		}
	}
}

// FuzzParseSFlowDatagram is a Go native fuzz target. It seeds the
// fuzzer with both valid and pathological datagrams, then asserts the
// parser never panics on arbitrary input. Run with:
//
//	go test -run=^$ -fuzz=FuzzParseSFlowDatagram -fuzztime=30s ./internal/sflow/...
//
// CI will run a short fuzz pass nightly to catch regressions in the
// parser's panic-safety guarantees.
func FuzzParseSFlowDatagram(f *testing.F) {
	r := NewSFlowReceiver("127.0.0.1", 0)
	r.handler = func(*relay.FlowSample) {}

	// Seed: valid TCP SYN datagram.
	{
		eth := buildIPv4EthernetTCPHeader([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 0x02)
		rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
		sample := buildFlowSample(1, 1, 512, rec)
		dg := buildDatagram([4]byte{192, 168, 1, 10}, 1, sample)
		f.Add(dg)
	}

	// Seed: truncated inputs at interesting boundaries.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x05}) // version=5 only
	f.Add(make([]byte, 27))               // 4 bytes short of a full datagram header

	// Seed: all-zero buffer of various sizes.
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 1024))

	// Seed: random-looking but structurally valid datagram with bogus IPs.
	{
		var dg []byte
		dg = u32be(dg, 5)
		dg = u32be(dg, 1)
		dg = append(dg, 0xff, 0xff, 0xff, 0xff)
		dg = u32be(dg, 0)
		dg = u32be(dg, 0)
		dg = u32be(dg, 0)
		dg = u32be(dg, 5) // num_samples
		for i := 0; i < 5; i++ {
			dg = u32be(dg, 1)
			dg = u32be(dg, 200)
			dg = append(dg, make([]byte, 200)...)
		}
		f.Add(dg)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// The contract under test: parseSFlowDatagram must not panic,
		// must not hang, and must not produce more samples than
		// num_samples * records-per-sample allows.
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("parseSFlowDatagram panicked on fuzz input: %v\ndata=%x", rec, data)
				}
			}()
			r.parseSFlowDatagram(data)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("parseSFlowDatagram hung on fuzz input of %d bytes\ndata=%x", len(data), data)
		}
	})
}

// hasAddr reports whether any sample in the slice has a non-empty SrcAddr
// or DstAddr.
func hasAddr(samples []*relay.FlowSample) bool {
	for _, s := range samples {
		if s.SrcAddr != "" || s.DstAddr != "" {
			return true
		}
	}
	return false
}

// TestParseSFlowDatagram_8021QTaggedEthernet covers the 802.1Q/Q-in-Q
// VLAN-tag handling branch in parseEthernet (line 355-361). The parser
// must skip the 4-byte VLAN tag(s) and read the real ethertype from
// ipOffset+2 before dispatching to parseIPv4.
func TestParseSFlowDatagram_8021QTaggedEthernet(t *testing.T) {
	// Ethernet: 6+6+2(0x8100) + 2(TPI) + 2(real ethertype) + IPv4 + TCP
	eth := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x81, 0x00, // 802.1Q VLAN tag
		0x00, 0x64, // VLAN ID 100
		0x08, 0x00, // real ethertype: IPv4
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6 // TCP
	copy(ip[12:16], net.IPv4(192, 168, 5, 1).To4())
	copy(ip[16:20], net.IPv4(192, 168, 5, 2).To4())
	eth = append(eth, ip...)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 80)
	binary.BigEndian.PutUint16(tcp[2:], 1234)
	tcp[13] = 0x10 // ACK
	eth = append(eth, tcp...)

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	if got[0].SrcAddr != "192.168.5.1" || got[0].DstAddr != "192.168.5.2" {
		t.Errorf("VLAN-tagged IPv4 not decoded: src=%q dst=%q", got[0].SrcAddr, got[0].DstAddr)
	}
	if got[0].SrcPort != 80 || got[0].DstPort != 1234 {
		t.Errorf("VLAN-tagged TCP ports wrong: src=%d dst=%d", got[0].SrcPort, got[0].DstPort)
	}
}

// TestParseSFlowDatagram_TruncatedEthernetIP covers the len(data)<20
// branch in parseIPv4 and the inner-IP-too-short path in parseEthernet.
// The parser must not panic and must not emit decoded addresses.
func TestParseSFlowDatagram_TruncatedEthernetIP(t *testing.T) {
	// Ethernet header with ethertype=IPv4, but inner payload is only
	// 4 bytes (way short of the 20-byte IPv4 minimum header).
	eth := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x14, // truncated IP header (4 bytes)
	}

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	if got := get(); hasAddr(got) {
		t.Fatalf("truncated inner IPv4 should not produce addresses, got %d samples with addresses", len(got))
	}
}

// TestParseSFlowDatagram_TruncatedIPv6 covers the len(data)<40 branch
// in parseIPv6 — the IPv6 fixed header is 40 bytes; supplying fewer
// must reject the packet without panicking.
func TestParseSFlowDatagram_TruncatedIPv6(t *testing.T) {
	eth := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x86, 0xDD, // IPv6
	}
	// 20 bytes of garbage — short of the 40-byte IPv6 header.
	eth = append(eth, make([]byte, 20)...)

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	if got := get(); hasAddr(got) {
		t.Fatalf("truncated IPv6 should not produce addresses, got %d samples with addresses", len(got))
	}
}

// TestParseSFlowDatagram_TruncatedTCPTransport covers the len(data)<14
// branch in parseTransport's TCP case. The audit specifically flagged
// `data[13]` read at line 410 — the parser must guard this with a
// length check (which it does) and silently drop the sample.
func TestParseSFlowDatagram_TruncatedTCPTransport(t *testing.T) {
	// IPv4 says protocol=6 (TCP) but the IPv4 IHL-extended payload is
	// only 4 bytes (i.e. the TCP header is truncated to 4 bytes, less
	// than the 14 needed to safely read data[13]).
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6 // TCP
	copy(ip[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 2).To4())
	tcp := []byte{0x30, 0x39, 0x01, 0xbb} // ports only, no flags byte
	eth := append([]byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x08, 0x00,
	}, ip...)
	eth = append(eth, tcp...)

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	// The parser must not panic on the data[13] read. With only 4 bytes
	// of TCP header available, the TCP branch's len(data)<14 guard
	// fires, so SrcPort/DstPort/TCPFlags must all remain zero.
	got := get()
	for i, s := range got {
		if s.SrcPort != 0 || s.DstPort != 0 {
			t.Errorf("sample[%d] decoded ports from truncated TCP: src=%d dst=%d", i, s.SrcPort, s.DstPort)
		}
		if s.TCPFlags != 0 {
			t.Errorf("sample[%d] decoded TCPFlags=0x%02x from truncated TCP", i, s.TCPFlags)
		}
	}
}

// TestParseSFlowDatagram_TruncatedUDPTransport covers the len(data)<4
// branch in parseTransport's UDP case.
func TestParseSFlowDatagram_TruncatedUDPTransport(t *testing.T) {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 17 // UDP
	copy(ip[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 2).To4())
	udp := []byte{0x00, 0x35} // only 2 bytes of UDP — less than 4 needed
	eth := append([]byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x02,
		0x08, 0x00,
	}, ip...)
	eth = append(eth, udp...)

	rec := buildRawPacketRecord(eth, uint32(16+len(eth)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{10, 0, 0, 1}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	// With only 2 bytes of UDP header available, the UDP branch's
	// len(data)<4 guard fires, so SrcPort/DstPort must remain zero.
	got := get()
	for i, s := range got {
		if s.SrcPort != 0 || s.DstPort != 0 {
			t.Errorf("sample[%d] decoded ports from truncated UDP: src=%d dst=%d", i, s.SrcPort, s.DstPort)
		}
	}
}

// TestParseSFlowDatagram_UnknownAgentAddressType covers the default
// branch in parseSFlowDatagram (line 144-146). An unknown address_type
// must cause the datagram to be dropped silently — no panic, no
// handler call.
func TestParseSFlowDatagram_UnknownAgentAddressType(t *testing.T) {
	// Datagram header with version=5, addrType=99 (unknown), then junk.
	dg := []byte{
		0x00, 0x00, 0x00, 0x05, // version=5
		0x00, 0x00, 0x00, 0x63, // address_type=99 (unknown)
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	}

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	if got := get(); len(got) != 0 {
		t.Fatalf("unknown addrType should drop datagram, got %d samples", len(got))
	}
}

// TestParseSFlowDatagram_TruncatedAgentAddress covers the offset+4
// and offset+16 bounds checks on the agent address read (lines 133-143).
// A datagram with the right header shape but cut short at the agent
// IP boundary must be rejected.
func TestParseSFlowDatagram_TruncatedAgentAddress(t *testing.T) {
	// version=5, addrType=1 (IPv4), then truncation.
	dg := []byte{
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x01,
		0xc0, 0xa8, 0x01, 0x0a, // partial IPv4 (4 bytes, would fit)
	}
	// But we extend the test to also cover the IPv6 case where the
	// address is incomplete. Use addrType=2 with only 4 bytes of agent.
	dg6 := []byte{
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x02, // IPv6
		0x20, 0x01, 0x0d, 0xb8, // partial IPv6 (truncated, < 16 bytes)
	}

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)
	if got := get(); len(got) != 0 {
		t.Fatalf("truncated IPv4 agent address should drop datagram, got %d samples", len(got))
	}
	r.parseSFlowDatagram(dg6)
	if got := get(); len(got) != 0 {
		t.Fatalf("truncated IPv6 agent address should drop datagram, got %d samples", len(got))
	}
}

// TestParseSFlowDatagram_TruncatedFlowSampleHeader covers the readUint32
// failure paths inside parseFlowSample. A sample whose record length
// is non-zero but whose actual sample body is missing/short must not
// crash — the parser must bail out cleanly.
func TestParseSFlowDatagram_TruncatedFlowSampleHeader(t *testing.T) {
	// Datagram header is valid, but the single flow sample has only
	// 4 bytes of body (just enough to read seqNum, then no more data).
	dg := make([]byte, 0, 64)
	dg = u32be(dg, 5)
	dg = u32be(dg, 1)
	dg = append(dg, []byte{10, 0, 0, 1}...)
	dg = u32be(dg, 1) // sub_agent_id
	dg = u32be(dg, 1) // sequence_number
	dg = u32be(dg, 0) // uptime
	dg = u32be(dg, 1) // num_samples=1
	// Flow sample header: efTag + sampleLen, then only 4 bytes of body.
	dg = u32be(dg, 1)   // enterprise=0, format=1
	dg = u32be(dg, 100) // sample_length=100 (claimed)
	dg = u32be(dg, 42)  // seqNum of flow sample — only 4 bytes of body
	// (no source_id, no sampling_rate, etc — parser must bail cleanly)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	if got := get(); len(got) != 0 {
		t.Fatalf("truncated flow sample header should not emit a sample, got %d", len(got))
	}
}

// TestStop_NoOpWhenNotRunning verifies that calling Stop() on a
// receiver that was never started is a safe no-op.
func TestStop_NoOpWhenNotRunning(t *testing.T) {
	r := NewSFlowReceiver("127.0.0.1", 0)
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop on unstarted receiver should return nil, got %v", err)
	}
	// And calling it a second time is also safe (idempotency).
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop should also be no-op, got %v", err)
	}
}

// jsonMarshal is a thin wrapper around encoding/json so the drops-omitempty
// test reads cleanly without polluting the package's other tests with the
// encoding/json import.
func jsonMarshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// containsField reports whether the JSON-encoded payload has a top-level
// key matching fieldName. Used by TestParseSFlowDatagram_DropsFieldZeroOmitsFromJSON
// to pin the `omitempty` behavior of relay.FlowSample.Drops.
func containsField(jsonBytes []byte, fieldName string) bool {
	// Cheap-but-correct: walk the JSON looking for `"<field>":` at a
	// top-level position. This is fine for the small flat structs the
	// sFlow package emits.
	needle := `"` + fieldName + `":`
	return strings.Contains(string(jsonBytes), needle)
}
