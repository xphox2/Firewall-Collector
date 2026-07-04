package netflow

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"strings"
	"time"

	"firewall-collector/internal/relay"
)

// This file is the SHARED v9/IPFIX data-record decoder: both framers cut
// records from their data sets and feed them here. Everything template-shaped
// (field walk incl. IPFIX varlen, counter fallback chain, biflow reverse
// emission, sampling resolution, timestamp resolution) lives in one place so
// the two protocols cannot drift apart on record semantics — only their
// FRAMING differs (v9.go / ipfix.go).

const (
	// ntpEpochOffset converts NTP-format seconds (epoch 1900-01-01) to Unix
	// seconds (RFC 7011 §6.1.9/6.1.10 dateTimeMicro/Nanoseconds).
	ntpEpochOffset = 2208988800

	// ntpMicroFracMask clears the bottom 11 bits of the 2^-32 fraction word:
	// dateTimeMicroseconds senders MUST zero them (µs resolution) but broken
	// exporters don't, so the collector masks unconditionally (RFC 7011 §6.1.9).
	ntpMicroFracMask = ^uint64(0x7FF)

	// maxAppNameLen bounds the exporter-provided application string — the
	// server column is varchar(64), and a hostile varlen field could otherwise
	// relay a 64 KiB "app name" per flow.
	maxAppNameLen = 64
)

// recordContext carries the per-datagram state the shared record decoder
// needs: which exporter domain the record belongs to (cache key), which
// protocol framed it (FlowSource label + whether sysUptime exists), the header
// times for uptime/delta timestamp math, and the receive time for the
// plausibility clamp.
type recordContext struct {
	key          exporterKey
	flowSource   uint8  // relay.FlowSourceNetFlowV9 or relay.FlowSourceIPFIX
	seqNum       uint32 // header sequence, stamped onto emitted samples
	exportTimeMs int64  // header export time (ms epoch)
	sysUptime    int64  // v9 header sysUptime (ms); meaningless for IPFIX
	hasSysUptime bool   // true only for v9 — IPFIX has no sysUptime, so IEs 21/22 are undecodable there
	now          time.Time
}

// optU64 is an optional unsigned field value: v9/IPFIX templates make every
// field optional AND width-variable (reduced-size encoding), so presence must
// be tracked separately from the value — 0 is a legal on-wire value for
// almost everything.
type optU64 struct {
	v  uint64
	ok bool
}

// set decodes val big-endian (1-8 bytes, length-agnostic) into the option.
// Oversized numeric fields are ignored rather than mis-decoded — the template
// quarantine bounds them at registration, but enterprise fields of any length
// still flow through mapField.
func (o *optU64) set(val []byte) {
	if v, ok := decodeBE(val); ok {
		o.v, o.ok = v, true
	}
}

// timeFields collects every timestamp IE a record may carry; resolveFlowTimes
// walks them in research-§2.5 priority order.
type timeFields struct {
	startMilli, endMilli       optU64 // 152/153 — ms epoch (highest priority)
	startSec, endSec           optU64 // 150/151 — s epoch
	startMicroNTP, endMicroNTP optU64 // 154/155 — 64-bit NTP format, µs resolution
	startNanoNTP, endNanoNTP   optU64 // 156/157 — 64-bit NTP format
	startUptime, endUptime     optU64 // 22/21 — sysUptime offsets (v9 only)
	startDeltaUs, endDeltaUs   optU64 // 158/159 — µs before export time
	obsMilli                   optU64 // 323 — observation time (FortiGate CGN / ASA event time)
	durMilli                   optU64 // 161 — pairs with 323: start = end − duration
}

// decodedRecord accumulates the mapped fields of one data record before
// emission. Counter families are kept separate so the fallback chain and
// biflow reverse emission can reason about which encodings were present.
type decodedRecord struct {
	// Counter families (research §2.2).
	fwdBytes, fwdPackets    optU64 // IE 1/2 — preferred
	outBytes, outPackets    optU64 // IE 23/24 — forward fallback, or reverse when 1/2 present
	initOctets, respOctets  optU64 // IE 231/232 — ASA's only byte fields (no packets exist)
	totalOctets, totalPkts  optU64 // IE 85/86 — running totals, never summed as deltas
	revPENBytes, revPENPkts optU64 // PEN-29305 reverse IE 1/2 (RFC 5103 biflow)

	protocol, tos, tcpFlags optU64
	srcPort, dstPort        optU64
	srcV4, dstV4            net.IP
	srcV6, dstV6            net.IP
	inIf, outIf             optU64
	nextHop                 net.IP // 15/62, all-zero skipped at map time
	srcAS, dstAS            optU64
	srcVLAN, dstVLAN        optU64
	icmpTypeCode            optU64
	endReason               optU64 // 136
	fwEvent                 optU64 // 233
	natEvent                optU64 // 230 — qualifies the record as an event, not mapped to a wire field
	postNATSrc, postNATDst  net.IP
	postNATSrcPort          optU64
	postNATDstPort          optU64
	appName                 string

	// Sampling references (data records AND options data records).
	samplerID    optU64 // 48/302
	sampIval305  optU64 // options rate chain: 305 (+306) > 50 > 34
	sampSpace306 optU64
	sampRand50   optU64
	sampIval34   optU64 // legacy rate — MikroTik ships it in DATA records

	times timeFields
}

// decodeString extracts a printable exporter string (PAN App-ID style): fixed
// v9 string fields are null-padded, so content stops at the first NUL; the
// result is length-capped and space-trimmed.
func decodeString(val []byte) string {
	if i := bytes.IndexByte(val, 0); i >= 0 {
		val = val[:i]
	}
	if len(val) > maxAppNameLen {
		val = val[:maxAppNameLen]
	}
	return strings.TrimSpace(string(val))
}

// ipField returns val as an IP address when it is exactly IPv4 or IPv6 sized;
// any other width is a template lie and yields nil (skip, not garbage).
func ipField(val []byte, want int) net.IP {
	if len(val) != want {
		return nil
	}
	ip := make(net.IP, want)
	copy(ip, val)
	return ip
}

// mapField routes one field's value into the accumulator per the research
// field tables (§2.1/§2.2). Unknown IEs — IANA, enterprise, or vendor-squatted
// — are skipped by length, never an error (RFC 5153 §5.1).
func (d *decodedRecord) mapField(f templateField, val []byte) {
	if f.EnterpriseID != 0 {
		switch f.EnterpriseID {
		case penReverse:
			// RFC 5103 biflow: reverse-direction counterpart of any IE. Only
			// the reverse counters are consumed; other reverse IEs are opaque.
			switch f.Type {
			case ieOctetDeltaCount:
				d.revPENBytes.set(val)
			case iePacketDeltaCount:
				d.revPENPkts.set(val)
			}
		case penPaloAlto:
			if f.Type == fieldPANAppID {
				d.appName = decodeString(val)
			}
		}
		// Every other enterprise field (SonicWall PEN-8741 AppFlow, Fortinet
		// 12356, …) is skipped by length here — the walk already consumed it.
		return
	}
	switch f.Type {
	case ieOctetDeltaCount:
		d.fwdBytes.set(val)
	case iePacketDeltaCount:
		d.fwdPackets.set(val)
	case ieProtocolIdentifier:
		d.protocol.set(val)
	case ieIPClassOfService:
		d.tos.set(val)
	case ieTCPControlBits:
		d.tcpFlags.set(val)
	case ieSourceTransportPort:
		d.srcPort.set(val)
	case ieDestinationTransportPort:
		d.dstPort.set(val)
	case ieSourceIPv4Address:
		d.srcV4 = ipField(val, 4)
	case ieDestinationIPv4Address:
		d.dstV4 = ipField(val, 4)
	case ieSourceIPv6Address:
		d.srcV6 = ipField(val, 16)
	case ieDestinationIPv6Address:
		d.dstV6 = ipField(val, 16)
	case ieIngressInterface:
		d.inIf.set(val)
	case ieEgressInterface:
		d.outIf.set(val)
	case ieIPNextHopIPv4Address:
		// 0.0.0.0/:: mean "none" on the wire — skip so the BGP column stays
		// empty for non-routing exporters (same rule as the v5 parser).
		if ip := ipField(val, 4); ip != nil && !ip.IsUnspecified() {
			d.nextHop = ip
		}
	case ieIPNextHopIPv6Address:
		if ip := ipField(val, 16); ip != nil && !ip.IsUnspecified() {
			d.nextHop = ip // v6 wins over a v4 next hop if both appear
		}
	case ieBGPSourceASNumber:
		d.srcAS.set(val) // 2- or 4-byte — decodeBE is length-agnostic
	case ieBGPDestinationASNumber:
		d.dstAS.set(val)
	case ieVLANID:
		d.srcVLAN.set(val)
	case iePostVLANID:
		d.dstVLAN.set(val)
	case ieFlowDirection:
		// DELIBERATELY ignored: the server derives direction from its own
		// site/interface model; exporter direction override is a later phase.
	case ieFlowID, ieNATType, ieSamplingAlgorithm, ieSamplerMode:
		// Recognized, parsed by length, intentionally unmapped.
	case ieBasicList, ieSubTemplateList, ieSubTemplateMultiList:
		// RFC 6313 structured data: recognized-and-skipped opaquely (they are
		// usually varlen; the field walk already consumed the right length).
	case iePostOctetDeltaCount:
		d.outBytes.set(val)
	case iePostPacketDeltaCount:
		d.outPackets.set(val)
	case ieOctetTotalCount:
		d.totalOctets.set(val)
	case iePacketTotalCount:
		d.totalPkts.set(val)
	case ieInitiatorOctets:
		d.initOctets.set(val)
	case ieResponderOctets:
		d.respOctets.set(val)
	case ieICMPTypeCodeIPv4, ieICMPTypeCodeIPv6:
		d.icmpTypeCode.set(val)
	case ieFlowEndReason:
		d.endReason.set(val)
	case ieFirewallEvent:
		d.fwEvent.set(val)
	case ieNATEvent:
		d.natEvent.set(val)
	case iePostNATSourceIPv4Address:
		d.postNATSrc = ipField(val, 4)
	case iePostNATDestinationIPv4Addr:
		d.postNATDst = ipField(val, 4)
	case iePostNATSourceIPv6Address:
		d.postNATSrc = ipField(val, 16)
	case iePostNATDestinationIPv6Addr:
		d.postNATDst = ipField(val, 16)
	case iePostNAPTSourceTransportPort, fieldASAXlateSrcPort:
		d.postNATSrcPort.set(val)
	case iePostNAPTDestTransportPort, fieldASAXlateDstPort:
		d.postNATDstPort.set(val)
	case fieldASAXlateSrcAddrIPv4:
		d.postNATSrc = ipField(val, 4)
	case fieldASAXlateDstAddrIPv4:
		d.postNATDst = ipField(val, 4)
	case fieldPANAppID:
		d.appName = decodeString(val) // PAN squats the raw ID in v9 (no PEN there)
	case fieldPANUserID:
		// Recognized, not mapped (Tranche 3 scope).
	case ieSamplerID, ieSelectorID:
		d.samplerID.set(val)
	case ieSamplingInterval:
		d.sampIval34.set(val)
	case ieSamplingPacketInterval:
		d.sampIval305.set(val)
	case ieSamplingPacketSpace:
		d.sampSpace306.set(val)
	case ieSamplerRandomInterval:
		d.sampRand50.set(val)
	case ieFlowEndSysUpTime:
		d.times.endUptime.set(val)
	case ieFlowStartSysUpTime:
		d.times.startUptime.set(val)
	case ieFlowStartSeconds:
		d.times.startSec.set(val)
	case ieFlowEndSeconds:
		d.times.endSec.set(val)
	case ieFlowStartMilliseconds:
		d.times.startMilli.set(val)
	case ieFlowEndMilliseconds:
		d.times.endMilli.set(val)
	case ieFlowStartMicroseconds:
		d.times.startMicroNTP.set(val)
	case ieFlowEndMicroseconds:
		d.times.endMicroNTP.set(val)
	case ieFlowStartNanoseconds:
		d.times.startNanoNTP.set(val)
	case ieFlowEndNanoseconds:
		d.times.endNanoNTP.set(val)
	case ieFlowStartDeltaMicroseconds:
		d.times.startDeltaUs.set(val)
	case ieFlowEndDeltaMicroseconds:
		d.times.endDeltaUs.set(val)
	case ieFlowDurationMilliseconds:
		d.times.durMilli.set(val)
	case ieObservationTimeMilliseconds:
		d.times.obsMilli.set(val)
	}
}

// decodeDataRecord cuts ONE record from the front of data using tmpl's field
// layout (fixed widths plus IPFIX varlen: template length 0xFFFF → 1-byte
// actual length, first byte 255 escaping to a 2-byte BE length, prefix
// excluded from the field length — RFC 7011 §7) and dispatches it: options
// records update the sampler cache, data records emit FlowSamples. Returns
// the bytes consumed; ok=false means the record is truncated (a lying varlen
// prefix or a ragged set tail) and the caller must drop the REST of the set —
// after a framing desync every subsequent "record" would be garbage.
func (r *NetFlowReceiver) decodeDataRecord(data []byte, tmpl *templateRecord, ctx recordContext) (int, bool) {
	var dec decodedRecord
	off := 0
	for _, f := range tmpl.fields {
		flen := int(f.Length)
		if f.Length == varlenFieldLen {
			if off >= len(data) {
				return 0, false
			}
			flen = int(data[off])
			off++
			if flen == 255 {
				if off+2 > len(data) {
					return 0, false
				}
				flen = int(binary.BigEndian.Uint16(data[off : off+2]))
				off += 2
			}
		}
		if off+flen > len(data) {
			return 0, false
		}
		dec.mapField(f, data[off:off+flen])
		off += flen
	}
	if tmpl.isOptions {
		r.applyOptionsRecord(&dec, ctx)
		return off, true
	}
	r.emitDataRecord(&dec, ctx)
	return off, true
}

// applyOptionsRecord digests one OPTIONS data record into the sampler cache:
// rate from 305 (+306: effective rate = (interval+space)/interval), else 50,
// else 34; bound to the record's sampler ID (48/302) when one is present,
// else to the whole exporter domain. Options data NEVER emits FlowSamples.
func (r *NetFlowReceiver) applyOptionsRecord(dec *decodedRecord, ctx recordContext) {
	var rate uint64
	switch {
	case dec.sampIval305.ok:
		rate = dec.sampIval305.v
		if dec.sampSpace306.ok && dec.sampIval305.v > 0 {
			// PSAMP count-based sampling: interval packets taken, space packets
			// skipped — one flow in every (interval+space)/interval.
			rate = (dec.sampIval305.v + dec.sampSpace306.v) / dec.sampIval305.v
		}
	case dec.sampRand50.ok:
		rate = dec.sampRand50.v
	case dec.sampIval34.ok:
		rate = dec.sampIval34.v
	}
	if rate == 0 || rate > math.MaxUint32 {
		return // no usable rate in this record (e.g. app-name options tables)
	}
	if dec.samplerID.ok {
		r.caches.samplers.setSamplerRate(ctx.key, uint32(dec.samplerID.v), uint32(rate))
	} else {
		r.caches.samplers.setDomainRate(ctx.key, uint32(rate))
	}
}

// emitDataRecord turns one decoded data record into zero, one (forward), or
// two (forward + biflow reverse) relay.FlowSamples.
func (r *NetFlowReceiver) emitDataRecord(dec *decodedRecord, ctx recordContext) {
	// Family 4 guard (research §2.2): IEs 85/86 are running totals since
	// metering-process init. Summing them as deltas would count every flow's
	// whole history once per record — skip the record instead unless real
	// delta counters (1/2) ride alongside.
	if (dec.totalOctets.ok || dec.totalPkts.ok) && !dec.fwdBytes.ok && !dec.fwdPackets.ok {
		r.emitParseEvent(eventTotalCountersSkipped)
		return
	}

	// Forward counters — the three-family fallback chain.
	var fwdBytes, fwdPkts uint64
	hasForward := false
	outIsReverse := false
	switch {
	case dec.fwdBytes.ok || dec.fwdPackets.ok:
		fwdBytes, fwdPkts = dec.fwdBytes.v, dec.fwdPackets.v
		hasForward = true
		// With IE 1/2 present, 23/24 are the FortiGate per-session REVERSE
		// counters, not a forward fallback.
		outIsReverse = dec.outBytes.ok || dec.outPackets.ok
	case dec.outBytes.ok || dec.outPackets.ok:
		fwdBytes, fwdPkts = dec.outBytes.v, dec.outPackets.v
		hasForward = true
	case dec.initOctets.ok:
		fwdBytes = dec.initOctets.v // ASA: bytes only, packets stay 0 (none exist)
		hasForward = true
	}

	// Reverse counters — three encodings normalized to one pair (research §2.2).
	var revBytes, revPkts uint64
	hasReverse := false
	switch {
	case dec.revPENBytes.ok || dec.revPENPkts.ok:
		revBytes, revPkts = dec.revPENBytes.v, dec.revPENPkts.v
		hasReverse = true
	case outIsReverse:
		revBytes, revPkts = dec.outBytes.v, dec.outPackets.v
		hasReverse = true
	case dec.respOctets.ok:
		revBytes = dec.respOctets.v
		hasReverse = true
	}

	// A record carrying ONLY reverse counters has no forward flow to attach
	// them to — synthesizing one would invent a zero-byte forward row.
	if !hasForward && hasReverse {
		r.emitParseEvent(eventReverseOnlyDropped)
		return
	}

	// Addresses: IPv6 wins when a template carries both families.
	srcAddr, dstAddr := "", ""
	switch {
	case dec.srcV6 != nil:
		srcAddr = dec.srcV6.String()
	case dec.srcV4 != nil:
		srcAddr = dec.srcV4.String()
	}
	switch {
	case dec.dstV6 != nil:
		dstAddr = dec.dstV6.String()
	case dec.dstV4 != nil:
		dstAddr = dec.dstV4.String()
	}

	// Zero-byte EVENT records are legal (ASA create/denied, RFC 8158 NAT
	// events) — denied-flow visibility is the headline NetFlow win. But a
	// record with no counters, no event, and no addresses carries nothing the
	// pipeline can use (the sFlow emission-gate lesson: phantom
	// 0.0.0.0→0.0.0.0 rows poison analytics) — skip it.
	eventPresent := dec.fwEvent.ok || dec.natEvent.ok
	if !hasForward && !eventPresent && srcAddr == "" && dstAddr == "" {
		return
	}

	// Sampling: IE 34 seen in a DATA record (MikroTik) teaches the domain rate
	// before this record resolves, so the very record that carried it is
	// already renormalized.
	if dec.sampIval34.ok && dec.sampIval34.v > 0 && dec.sampIval34.v <= math.MaxUint32 {
		r.caches.samplers.setDomainRate(ctx.key, uint32(dec.sampIval34.v))
	}
	rate := r.caches.samplers.rateFor(ctx.key, uint32(dec.samplerID.v), dec.samplerID.ok)

	flowStart, flowEnd := resolveFlowTimes(&dec.times, ctx)

	s := &relay.FlowSample{
		Timestamp:      flowEnd, // legacy single-timestamp column = flow end
		SamplerAddress: ctx.key.exporter,
		SequenceNumber: ctx.seqNum,
		SamplingRate:   rate,
		FlowSource:     ctx.flowSource,
		SrcAddr:        srcAddr,
		DstAddr:        dstAddr,
		SrcPort:        uint16(dec.srcPort.v),
		DstPort:        uint16(dec.dstPort.v),
		Protocol:       uint8(dec.protocol.v),
		// Counters are pre-multiplied by the sampling rate at the collector —
		// the same contract as the sFlow and v5 paths.
		Bytes:         fwdBytes * uint64(rate),
		Packets:       fwdPkts * uint64(rate),
		InputIfIndex:  uint32(dec.inIf.v),
		OutputIfIndex: uint32(dec.outIf.v),
		TCPFlags:      uint8(dec.tcpFlags.v),
		TOS:           uint8(dec.tos.v),
		SrcAS:         uint32(dec.srcAS.v),
		DstAS:         uint32(dec.dstAS.v),
		SrcVLAN:       uint16(dec.srcVLAN.v),
		DstVLAN:       uint16(dec.dstVLAN.v),
		FirewallEvent: uint8(dec.fwEvent.v),
		FlowEndReason: uint8(dec.endReason.v),
		AppName:       dec.appName,
		// Drops stays 0 for NetFlow: it carries sFlow agent-drop semantics;
		// export loss is the sequence tracker's job (seq_gap events).
	}
	fs, fe := flowStart, flowEnd
	s.FlowStart, s.FlowEnd = &fs, &fe
	if dec.nextHop != nil {
		s.NextHop = dec.nextHop.String()
	}
	if dec.postNATSrc != nil {
		s.PostNATSrcAddr = dec.postNATSrc.String()
	}
	if dec.postNATDst != nil {
		s.PostNATDstAddr = dec.postNATDst.String()
	}
	s.PostNATSrcPort = uint16(dec.postNATSrcPort.v)
	s.PostNATDstPort = uint16(dec.postNATDstPort.v)

	// ICMP convention (same as v5/server): for protocol 1/58 the type*256+code
	// moves to ICMPTypeCode and BOTH ports are zeroed so ICMP never pollutes
	// port-based filters. IE 32/139 is authoritative; Cisco also mirrors the
	// value into L4_DST_PORT, which serves as the fallback.
	if s.Protocol == 1 || s.Protocol == 58 {
		if dec.icmpTypeCode.ok {
			s.ICMPTypeCode = uint16(dec.icmpTypeCode.v)
		} else {
			s.ICMPTypeCode = s.DstPort
		}
		s.SrcPort, s.DstPort = 0, 0
	}

	r.handler(s)

	// Biflow reverse emission: a second sample with the 5-tuple mirrored and
	// the reverse counters, same timestamps/source. Emitted only when the
	// reverse counters are actually non-zero — FortiGate/ASA ship the fields
	// zero-filled for one-way traffic.
	if hasReverse && (revBytes > 0 || revPkts > 0) {
		rev := *s
		rfs, rfe := flowStart, flowEnd
		rev.FlowStart, rev.FlowEnd = &rfs, &rfe
		rev.SrcAddr, rev.DstAddr = s.DstAddr, s.SrcAddr
		rev.SrcPort, rev.DstPort = s.DstPort, s.SrcPort
		rev.InputIfIndex, rev.OutputIfIndex = s.OutputIfIndex, s.InputIfIndex
		rev.SrcAS, rev.DstAS = s.DstAS, s.SrcAS
		rev.SrcVLAN, rev.DstVLAN = s.DstVLAN, s.SrcVLAN
		rev.PostNATSrcAddr, rev.PostNATDstAddr = s.PostNATDstAddr, s.PostNATSrcAddr
		rev.PostNATSrcPort, rev.PostNATDstPort = s.PostNATDstPort, s.PostNATSrcPort
		rev.Bytes = revBytes * uint64(rate)
		rev.Packets = revPkts * uint64(rate)
		r.handler(&rev)
	}
}

// resolveFlowTimes derives absolute flow start/end from whichever timestamp
// IEs the record carried, in research-§2.5 priority order:
//
//	152/153 ms > 150/151 s > 154-157 NTP format > 21/22 uptime math (v9 only —
//	IPFIX has no sysUptime, so they are skipped there) > 158/159 delta-µs
//	before export > 323 observation time (+161 duration → start).
//
// A missing side inherits the other; a record with no timestamps at all gets
// the receive time. Everything is plausibility-clamped against the receive
// time (broken exporter clocks are the norm, not the exception).
func resolveFlowTimes(t *timeFields, ctx recordContext) (time.Time, time.Time) {
	exportSecs := ctx.exportTimeMs / 1000

	var endMs int64
	hasEnd := true
	switch {
	case t.endMilli.ok:
		endMs = int64(t.endMilli.v)
	case t.endSec.ok:
		endMs = int64(t.endSec.v) * 1000
	case t.endMicroNTP.ok:
		endMs = ntpToMs(t.endMicroNTP.v, true, exportSecs)
	case t.endNanoNTP.ok:
		endMs = ntpToMs(t.endNanoNTP.v, false, exportSecs)
	case t.endUptime.ok && ctx.hasSysUptime:
		// Wrap-safe unsigned uptime math (nfdump): the uint32 subtraction
		// wraps correctly when sysUptime rolled over after the record's stamp.
		endMs = ctx.exportTimeMs - int64(uint32(ctx.sysUptime)-uint32(t.endUptime.v))
	case t.endDeltaUs.ok:
		endMs = ctx.exportTimeMs - int64(t.endDeltaUs.v/1000)
	case t.obsMilli.ok:
		endMs = int64(t.obsMilli.v)
	default:
		hasEnd = false
	}

	var startMs int64
	hasStart := true
	switch {
	case t.startMilli.ok:
		startMs = int64(t.startMilli.v)
	case t.startSec.ok:
		startMs = int64(t.startSec.v) * 1000
	case t.startMicroNTP.ok:
		startMs = ntpToMs(t.startMicroNTP.v, true, exportSecs)
	case t.startNanoNTP.ok:
		startMs = ntpToMs(t.startNanoNTP.v, false, exportSecs)
	case t.startUptime.ok && ctx.hasSysUptime:
		startMs = ctx.exportTimeMs - int64(uint32(ctx.sysUptime)-uint32(t.startUptime.v))
	case t.startDeltaUs.ok:
		startMs = ctx.exportTimeMs - int64(t.startDeltaUs.v/1000)
	case t.obsMilli.ok && t.durMilli.ok:
		startMs = int64(t.obsMilli.v) - int64(t.durMilli.v)
	default:
		hasStart = false
	}

	switch {
	case !hasEnd && !hasStart:
		return ctx.now, ctx.now // event-only records: stamp arrival
	case !hasEnd:
		endMs = startMs
	case !hasStart:
		startMs = endMs
	}
	return clampFlowTimes(startMs, endMs, ctx.now)
}

// ntpToMs converts an RFC 7011 §6.1.9/6.1.10 64-bit NTP-format timestamp
// (seconds since 1900-01-01 in the top word, 2^-32 fraction in the bottom) to
// ms epoch. The seconds word wraps every ~136 years (era 0 ends 2036-02-07),
// so the era is disambiguated against the message's export time: whichever
// era lands the value within ±2^31 s of the export time wins. micro masks the
// bottom 11 fraction bits (dateTimeMicroseconds resolution rule).
func ntpToMs(v uint64, micro bool, exportSecs int64) int64 {
	secs := int64(v>>32) - ntpEpochOffset
	frac := v & 0xFFFFFFFF
	if micro {
		frac &= ntpMicroFracMask
	}
	for secs < exportSecs-(1<<31) {
		secs += 1 << 32
	}
	for secs > exportSecs+(1<<31) {
		secs -= 1 << 32
	}
	return secs*1000 + int64(frac*1000>>32)
}

// clampFlowTimes is the shared plausibility clamp (research §2.5 hardening):
// a derived flow end more than ±15 min from the datagram's receive time means
// the exporter's clock or uptime math is broken (softflowd header bugs,
// Catalyst 1970 epochs, Nexus sysUptime/1000) — fall back to the receive time
// for the end, keeping the flow's internal duration when it is believable.
func clampFlowTimes(startMs, endMs int64, now time.Time) (time.Time, time.Time) {
	durationMs := endMs - startMs
	end := time.UnixMilli(endMs)
	if skew := end.Sub(now); skew > flowTimeSkewLimit || skew < -flowTimeSkewLimit {
		end = now
		if durationMs >= 0 && durationMs <= maxPlausibleFlowDurationMs {
			return end.Add(-time.Duration(durationMs) * time.Millisecond), end
		}
		return end, end
	}
	return time.UnixMilli(startMs), end
}
