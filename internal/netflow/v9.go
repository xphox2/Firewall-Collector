package netflow

import (
	"encoding/binary"
	"time"

	"firewall-collector/internal/relay"
)

// NetFlow v9 framing (RFC 3954): a 20-byte header followed by FlowSets, each
// with a 4-byte (ID, length) header. The walk trusts FlowSet LENGTHS ONLY —
// the header's Count field is ambiguous in the wild (records? flowsets?) and
// is a sanity hint at best (RFC 5153 §10.1), so it is deliberately unused.
const (
	v9HeaderLen    = 20
	v9SetHeaderLen = 4

	// v9 set IDs: 0 = template set, 1 = options template set, 2-255 reserved
	// (skipped by length), >= 256 = data sets referencing a template ID.
	// These differ from IPFIX (2/3) — set IDs are version-keyed.
	v9SetTemplates        = 0
	v9SetOptionsTemplates = 1

	// minDataSetID is the first template/data-set ID in both protocols.
	minDataSetID = 256
)

// parseV9 decodes one NetFlow v9 datagram: header, sequence accounting, then
// the FlowSet walk. exporterIP is the UDP source (always the SamplerAddress),
// now is the receive time for TTL refresh and timestamp clamping.
func (r *NetFlowReceiver) parseV9(data []byte, exporterIP string, now time.Time) {
	if len(data) < v9HeaderLen {
		r.emitParseEvent(eventMalformed)
		return
	}
	// data[2:4] is the header Count — see the file comment for why it is not read.
	sysUptime := int64(binary.BigEndian.Uint32(data[4:8]))
	unixSecs := int64(binary.BigEndian.Uint32(data[8:12]))
	sequence := binary.BigEndian.Uint32(data[12:16])
	sourceID := binary.BigEndian.Uint32(data[16:20])

	key := exporterKey{exporter: exporterIP, sourceID: sourceID}
	ctx := recordContext{
		key:          key,
		flowSource:   relay.FlowSourceNetFlowV9,
		seqNum:       sequence,
		exportTimeMs: unixSecs * 1000,
		sysUptime:    sysUptime,
		hasSysUptime: true,
		now:          now,
	}

	// v9 sequence increments by ONE per export packet (RFC 3954 §5.1) —
	// unlike v5 (records) and IPFIX (data records).
	if ev := r.seq.observe(seqKey{exporterIP, sourceID, 9}, sequence, 1, sysUptime, true, true); ev != "" {
		r.emitParseEvent(ev)
	}

	off := v9HeaderLen
	for off+v9SetHeaderLen <= len(data) {
		setID := binary.BigEndian.Uint16(data[off : off+2])
		setLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		// A FlowSet length under 4 can't even cover its own header — the walk
		// would spin or desync, so the REST of the datagram is unrecoverable.
		// Same for a length past the datagram end (truncation/lie).
		if setLen < v9SetHeaderLen || off+setLen > len(data) {
			r.emitParseEvent(eventMalformed)
			return
		}
		body := data[off+v9SetHeaderLen : off+setLen]
		switch {
		case setID == v9SetTemplates:
			r.parseV9TemplateSet(body, key, now)
		case setID == v9SetOptionsTemplates:
			r.parseV9OptionsTemplateSet(body, key, now)
		case setID >= minDataSetID:
			r.parseDataSet(body, setID, ctx)
		default:
			// Reserved set IDs 2-255: unknown ≠ error (RFC 5153 §5.1) — skip
			// by length so a future set type never breaks the walk.
		}
		off += setLen
	}
	// Trailing bytes shorter than a set header are datagram padding.
}

// parseV9TemplateSet registers every template record in a set-0 body: each is
// templateID(2) + fieldCount(2) + fieldCount × (type(2), length(2)). One set
// may hold several templates; trailing zeros are padding.
func (r *NetFlowReceiver) parseV9TemplateSet(body []byte, key exporterKey, now time.Time) {
	rem := body
	for len(rem) >= 4 {
		tid := binary.BigEndian.Uint16(rem[0:2])
		fieldCount := int(binary.BigEndian.Uint16(rem[2:4]))
		if tid == 0 {
			return // 4-byte-boundary padding, not another template
		}
		need := 4 + fieldCount*4
		// Template IDs below 256 collide with set IDs; fieldCount 0 would
		// register a zero-length template (v9 has no withdrawals — that's an
		// IPFIX-only concept). Either desyncs the rest of the set.
		if tid < minDataSetID || fieldCount == 0 || len(rem) < need {
			r.emitParseEvent(eventMalformed)
			return
		}
		fields := make([]templateField, fieldCount)
		varlen := false
		for i := 0; i < fieldCount; i++ {
			fields[i] = templateField{
				Type:   binary.BigEndian.Uint16(rem[4+i*4 : 6+i*4]),
				Length: binary.BigEndian.Uint16(rem[6+i*4 : 8+i*4]),
			}
			if fields[i].Length == varlenFieldLen {
				varlen = true
			}
		}
		// AUDIT-284: v9/NetFlow has no variable-length fields (RFC 3954) — the
		// 0xFFFF sentinel is IPFIX-only. put() exempts 0xFFFF from its
		// field-width cap for legitimate IPFIX varlen IEs, so a v9 template
		// carrying it would slip past registration and decodeDataRecord would
		// read it as a 1-byte varlen length prefix, desyncing every field
		// offset for that exporter. Quarantine this template (skip the put) but
		// keep parsing sibling templates in the set.
		if varlen {
			r.emitParseEvent(eventMalformed)
			rem = rem[need:]
			continue
		}
		if reason := r.caches.templates.put(templateKey{key, tid}, fields, 0, false, now); reason != putOK {
			r.emitParseEvent(reason)
		}
		rem = rem[need:]
	}
}

// parseV9OptionsTemplateSet registers every options template in a set-1 body:
// templateID(2) + optionScopeLength(2) + optionLength(2) + scope pairs +
// option pairs. THE v9/IPFIX TRAP: both length words are in BYTES (RFC 3954
// §6.1), not field counts like IPFIX set 3 — sharing the IPFIX parse would
// silently corrupt the sampler table (research §2.6), so this path is v9-only.
//
// v9 scope field "types" are scope kinds (1=System … 5=Template), NOT IEs;
// they are stored as-is and are harmless downstream because the options-data
// consumer only reads the sampling IEs (34/48/50/302/305/306), none of which
// collide with kinds 1-5.
func (r *NetFlowReceiver) parseV9OptionsTemplateSet(body []byte, key exporterKey, now time.Time) {
	rem := body
	for len(rem) >= 6 {
		tid := binary.BigEndian.Uint16(rem[0:2])
		if tid == 0 {
			return // padding
		}
		scopeLen := int(binary.BigEndian.Uint16(rem[2:4]))
		optionLen := int(binary.BigEndian.Uint16(rem[4:6]))
		need := 6 + scopeLen + optionLen
		if tid < minDataSetID || scopeLen%4 != 0 || optionLen%4 != 0 || len(rem) < need {
			r.emitParseEvent(eventMalformed)
			return
		}
		scopeCount := scopeLen / 4
		total := scopeCount + optionLen/4
		fields := make([]templateField, total)
		varlen := false
		for i := 0; i < total; i++ {
			fields[i] = templateField{
				Type:   binary.BigEndian.Uint16(rem[6+i*4 : 8+i*4]),
				Length: binary.BigEndian.Uint16(rem[8+i*4 : 10+i*4]),
			}
			if fields[i].Length == varlenFieldLen {
				varlen = true
			}
		}
		// AUDIT-284: as with v9 data templates, a 0xFFFF field length has no
		// meaning in v9 (no varlen fields) and would desync record decoding —
		// quarantine this options template but keep parsing the rest of the set.
		if varlen {
			r.emitParseEvent(eventMalformed)
			rem = rem[need:]
			continue
		}
		if reason := r.caches.templates.put(templateKey{key, tid}, fields, scopeCount, true, now); reason != putOK {
			r.emitParseEvent(reason)
		}
		rem = rem[need:]
	}
}

// parseDataSet decodes the records of one data set (v9 and IPFIX share this —
// only the framing above differs) using the cached template keyed by setID.
// Returns the number of records decoded and whether the count is COMPLETE
// (false when the template is missing or a record was truncated) — the IPFIX
// sequence tracker must not treat a partial count as authoritative.
func (r *NetFlowReceiver) parseDataSet(body []byte, setID uint16, ctx recordContext) (records int, complete bool) {
	tmpl := r.caches.templates.get(templateKey{ctx.key, setID}, ctx.now)
	if tmpl == nil {
		// Normal after a restart or exporter reboot until the next template
		// refresh — a counter, never a per-packet error log.
		r.emitParseEvent(eventDataNoTemplate)
		return 0, false
	}
	rem := body
	// Padding stop: remaining bytes shorter than the template's minimum
	// record length are the set's 4-byte-boundary padding — decoding them
	// would fabricate phantom 0.0.0.0→0.0.0.0 flows.
	for len(rem) >= tmpl.minRecLen {
		n, ok := r.decodeDataRecord(rem, tmpl, ctx)
		if !ok {
			r.emitParseEvent(eventMalformed)
			return records, false
		}
		rem = rem[n:]
		records++
	}
	return records, true
}
