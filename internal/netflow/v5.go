package netflow

import (
	"encoding/binary"
	"net"
	"time"

	"firewall-collector/internal/relay"
)

// NetFlow v5 wire layout (fixed format, IPv4-only — documented vendor limit,
// not ours): a 24-byte header followed by count 48-byte flow records.
const (
	v5HeaderLen = 24
	v5RecordLen = 48

	// v5 sampling header: top 2 bits are the sampling mode, low 14 bits the
	// interval. Mode is not needed for renormalization — only the interval is.
	v5SamplingRateMask = 0x3FFF

	// uptimeWrapMs is 2^32 ms (~49.7 days) — the sysUptime/First/Last counters
	// are unsigned 32-bit milliseconds and wrap at this boundary.
	uptimeWrapMs = int64(1) << 32

	// v5LastWrapSlackMs is nfdump's Cisco-CSCei12353 guard: Last legitimately
	// exceeds sysUptime by a little (records queued before the header was
	// stamped), but by more than this the uptime counter must have wrapped
	// between the record and the header, so both First and Last belong one
	// wrap earlier.
	v5LastWrapSlackMs = 100000

	// flowTimeSkewLimit is the plausibility clamp: a derived flow-end more
	// than this far from the datagram's receive time means the exporter's
	// clock or uptime math is broken (softflowd header bugs, Catalyst 1970
	// epochs, Nexus sysUptime/1000) — fall back to receive time rather than
	// stamping garbage into the flow_samples time index.
	flowTimeSkewLimit = 15 * time.Minute

	// maxPlausibleFlowDurationMs bounds the First..Last span we trust when
	// reconstructing FlowStart after a clamp. Active timeouts run to 30 min,
	// but v5 can report a whole unexpired flow's lifetime; 24 h is beyond any
	// real timeout config while still rejecting wrap-garbage durations.
	maxPlausibleFlowDurationMs = int64(24 * time.Hour / time.Millisecond)
)

// parseV5 decodes one NetFlow v5 datagram and emits one relay.FlowSample per
// salvageable record. exporterIP is the UDP source address (always the
// SamplerAddress — v5 has no in-band agent address), now is the receive time
// used for the timestamp plausibility clamp.
func (r *NetFlowReceiver) parseV5(data []byte, exporterIP string, now time.Time) {
	if len(data) < v5HeaderLen {
		r.emitParseEvent(eventMalformed)
		return
	}
	hdr := data[:v5HeaderLen]

	count := int(binary.BigEndian.Uint16(hdr[2:4]))
	sysUptime := int64(binary.BigEndian.Uint32(hdr[4:8]))
	unixSecs := int64(binary.BigEndian.Uint32(hdr[8:12]))
	unixNsecs := int64(binary.BigEndian.Uint32(hdr[12:16]))
	flowSequence := binary.BigEndian.Uint32(hdr[16:20])
	// engine_type/engine_id key the sequence-loss tracker's domain — a chassis
	// can run several v5 engines behind one source IP, each with its own
	// sequence space (the v5 analogue of the v9 sourceID).
	engine := uint32(hdr[20])<<8 | uint32(hdr[21])
	rate := binary.BigEndian.Uint16(hdr[22:24]) & v5SamplingRateMask
	if rate == 0 {
		rate = 1 // unsampled exporters send 0; multiplying by 0 would zero every counter
	}

	// v5 sequence semantics (research §2.7): the header carries the sequence
	// number of the FIRST record in this datagram, incrementing by the record
	// count. The exporter's DECLARED count is its own accounting — the clamped
	// salvage count below is ours.
	if ev := r.seq.observe(seqKey{exporterIP, engine, 5}, flowSequence, uint32(binary.BigEndian.Uint16(hdr[2:4])), sysUptime, true, true); ev != "" {
		r.emitParseEvent(ev)
	}

	// Count validation with clamping: the header count and the actual bytes
	// present routinely disagree in the wild (truncated datagrams, buggy
	// senders, deliberate lies). Salvage the records that ARE fully present
	// instead of trusting either side blindly, and surface the disagreement.
	available := (len(data) - v5HeaderLen) / v5RecordLen
	if count > available || (len(data)-v5HeaderLen)%v5RecordLen != 0 {
		r.emitParseEvent(eventMalformed)
	}
	if count > available {
		count = available
	}

	exportTimeMs := unixSecs*1000 + unixNsecs/1000000

	for i := 0; i < count; i++ {
		// Record-local bounded slice (audit-L9 discipline): every read below is
		// against this record's own 48 bytes, so no index arithmetic can reach
		// a neighboring record.
		off := v5HeaderLen + i*v5RecordLen
		rec := data[off : off+v5RecordLen]
		r.parseV5Record(rec, exporterIP, flowSequence, uint32(rate), sysUptime, exportTimeMs, now)
	}
}

// parseV5Record decodes one 48-byte v5 flow record and emits it.
//
// Layout: srcaddr(4) dstaddr(4) nexthop(4) input(2) output(2) dPkts(4)
// dOctets(4) First(4) Last(4) srcport(2) dstport(2) pad1(1) tcp_flags(1)
// prot(1) tos(1) src_as(2) dst_as(2) src_mask(1) dst_mask(1) pad2(2).
func (r *NetFlowReceiver) parseV5Record(rec []byte, exporterIP string, flowSequence, rate uint32, sysUptime, exportTimeMs int64, now time.Time) {
	sample := &relay.FlowSample{
		SamplerAddress: exporterIP,
		SequenceNumber: flowSequence,
		SamplingRate:   rate,
		FlowSource:     relay.FlowSourceNetFlowV5,
		SrcAddr:        net.IP(rec[0:4]).String(),
		DstAddr:        net.IP(rec[4:8]).String(),
		InputIfIndex:   uint32(binary.BigEndian.Uint16(rec[12:14])),
		OutputIfIndex:  uint32(binary.BigEndian.Uint16(rec[14:16])),
		// v5 counters are per-flow deltas at sampled scale: multiply by the
		// sampling rate so the stored bytes/packets estimate the true totals —
		// the same pre-multiplied contract as the sFlow path (a rate-100
		// exporter reporting 88 bytes really saw ~8800).
		Packets:  uint64(binary.BigEndian.Uint32(rec[16:20])) * uint64(rate),
		Bytes:    uint64(binary.BigEndian.Uint32(rec[20:24])) * uint64(rate),
		SrcPort:  binary.BigEndian.Uint16(rec[32:34]),
		DstPort:  binary.BigEndian.Uint16(rec[34:36]),
		TCPFlags: rec[37],
		Protocol: rec[38],
		TOS:      rec[39],
		SrcAS:    uint32(binary.BigEndian.Uint16(rec[40:42])),
		DstAS:    uint32(binary.BigEndian.Uint16(rec[42:44])),
		// Drops stays 0 for NetFlow: it carries sFlow agent-drop semantics;
		// export loss shows up as sequence gaps (collector metric, later phase).
	}

	// next_hop: 0.0.0.0 means "none" on the wire, not a real neighbor — omit
	// it so the server's BGP columns stay empty rather than storing a bogus
	// unspecified address for every non-routing exporter.
	if nh := net.IP(rec[8:12]); !nh.Equal(net.IPv4zero) {
		sample.NextHop = nh.String()
	}

	// ICMP convention: v5 encodes type*256+code in the dst_port field
	// (protocol 1 = ICMPv4; v5 is IPv4-only so 58 can't appear). Move it to
	// ICMPTypeCode and zero BOTH ports so ICMP traffic never pollutes
	// port-based filters/classification — the same convention as the server.
	if sample.Protocol == 1 {
		sample.ICMPTypeCode = sample.DstPort
		sample.SrcPort = 0
		sample.DstPort = 0
	}

	first := int64(binary.BigEndian.Uint32(rec[24:28]))
	last := int64(binary.BigEndian.Uint32(rec[28:32]))
	flowStart, flowEnd := resolveV5Times(first, last, sysUptime, exportTimeMs, now)
	sample.FlowStart = &flowStart
	sample.FlowEnd = &flowEnd
	// Legacy single-timestamp column = flow end (chart compatibility; the
	// server keeps this contract until duration-aware bucketing lands).
	sample.Timestamp = flowEnd

	r.handler(sample)
}

// resolveV5Times converts a record's First/Last sysUptime offsets (ms) into
// absolute flow start/end times, applying nfdump's exact wrap corrections
// followed by a plausibility clamp against the receive time.
//
// Base math: bootMs = exportTimeMs − sysUptime; endMs = bootMs + Last;
// startMs = bootMs + First. Wrap corrections (netflow_v5_v7.c):
//   - First > Last: the uptime counter wrapped between flow start and end, so
//     the start belongs one 2^32 ms (~49.7 day) wrap earlier.
//   - Last > sysUptime by more than 100000 ms (Cisco CSCei12353): sysUptime
//     wrapped after the record's timestamps were taken, so BOTH First and
//     Last belong one wrap earlier. (A small excess is just records queued
//     after the header was stamped — left alone.)
func resolveV5Times(first, last, sysUptime, exportTimeMs int64, now time.Time) (flowStart, flowEnd time.Time) {
	bootMs := exportTimeMs - sysUptime
	startMs := bootMs + first
	endMs := bootMs + last
	if first > last {
		startMs -= uptimeWrapMs
	}
	if last > sysUptime && last-sysUptime > v5LastWrapSlackMs {
		startMs -= uptimeWrapMs
		endMs -= uptimeWrapMs
	}

	// Shared plausibility clamp (record.go) — exporters ship broken clocks and
	// broken uptime math (research §2.5).
	return clampFlowTimes(startMs, endMs, now)
}
