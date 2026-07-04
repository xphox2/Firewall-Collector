package netflow

import (
	"encoding/binary"
	"time"

	"firewall-collector/internal/relay"
)

// IPFIX framing (RFC 7011): a 16-byte header carrying an explicit message
// LENGTH, followed by Sets with 4-byte (ID, length) headers. Unlike v9 the
// header length is trusted as the parse bound — bytes past it are trailing
// garbage (middlebox padding) and ignored, never "more sets".
const (
	ipfixHeaderLen    = 16
	ipfixSetHeaderLen = 4

	// IPFIX set IDs: 2 = template set, 3 = options template set, 0/1 and
	// 4-255 reserved (skipped by length), >= 256 = data sets. v9 uses 0/1 for
	// its template sets — the IDs are version-keyed, never shared.
	ipfixSetTemplates        = 2
	ipfixSetOptionsTemplates = 3

	// ipfixEnterpriseBit flags a field specifier's type word as
	// enterprise-scoped: strip it and read the 4-byte PEN that follows the
	// length (RFC 7011 §3.2).
	ipfixEnterpriseBit = 0x8000
)

// parseIPFIX decodes one IPFIX message: header, Set walk, then sequence
// accounting (IPFIX sequences count DATA RECORDS, so the walk must finish
// before the tracker can be fed).
func (r *NetFlowReceiver) parseIPFIX(data []byte, exporterIP string, now time.Time) {
	if len(data) < ipfixHeaderLen {
		r.emitParseEvent(eventMalformed)
		return
	}
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	exportSecs := int64(binary.BigEndian.Uint32(data[4:8]))
	sequence := binary.BigEndian.Uint32(data[8:12])
	odid := binary.BigEndian.Uint32(data[12:16])
	if msgLen < ipfixHeaderLen {
		r.emitParseEvent(eventMalformed)
		return
	}
	// Parse bound = min(header length, datagram length): a header length
	// SHORTER than the datagram means trailing garbage to ignore; LONGER
	// means truncation — parse the sets that did arrive (the set-length
	// bound below catches the ragged one).
	if msgLen > len(data) {
		msgLen = len(data)
	}
	msg := data[:msgLen]

	key := exporterKey{exporter: exporterIP, sourceID: odid}
	ctx := recordContext{
		key:          key,
		flowSource:   relay.FlowSourceIPFIX,
		seqNum:       sequence,
		exportTimeMs: exportSecs * 1000,
		// No sysUptime in IPFIX — hasSysUptime stays false, so uptime-relative
		// IEs 21/22 are undecodable here by design (research §2.5).
		now: now,
	}

	dataRecords := 0
	countable := true
	off := ipfixHeaderLen
	for off+ipfixSetHeaderLen <= len(msg) {
		setID := binary.BigEndian.Uint16(msg[off : off+2])
		setLen := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		if setLen < ipfixSetHeaderLen || off+setLen > len(msg) {
			// A set length under 4 or past the message end desyncs the walk —
			// the rest of the message is unrecoverable, and this message's
			// record count is no longer knowable.
			r.emitParseEvent(eventMalformed)
			countable = false
			break
		}
		body := msg[off+ipfixSetHeaderLen : off+setLen]
		switch {
		case setID == ipfixSetTemplates:
			r.parseIPFIXTemplateSet(body, key, now)
		case setID == ipfixSetOptionsTemplates:
			r.parseIPFIXOptionsTemplateSet(body, key, now)
		case setID >= minDataSetID:
			n, complete := r.parseDataSet(body, setID, ctx)
			dataRecords += n
			if !complete {
				countable = false
			}
		default:
			// Reserved set IDs 0/1/4-255: skip by length (RFC 5153 §5.1).
		}
		off += setLen
	}

	// IPFIX sequence increments by the message's DATA record count, templates
	// excluded (RFC 7011 §3.1). countable=false (missing template / truncated
	// set) resyncs the tracker silently instead of guessing.
	if ev := r.seq.observe(seqKey{exporterIP, odid, 10}, sequence, uint32(dataRecords), 0, false, countable); ev != "" {
		r.emitParseEvent(ev)
	}
}

// parseIPFIXFieldSpecs reads count field specifiers (type(2), length(2), plus
// a 4-byte PEN when the enterprise bit is set) from rem and returns the
// parsed fields with the bytes consumed, or ok=false on truncation.
func parseIPFIXFieldSpecs(rem []byte, off, count int) ([]templateField, int, bool) {
	fields := make([]templateField, 0, count)
	for i := 0; i < count; i++ {
		if off+4 > len(rem) {
			return nil, 0, false
		}
		typ := binary.BigEndian.Uint16(rem[off : off+2])
		length := binary.BigEndian.Uint16(rem[off+2 : off+4])
		off += 4
		var pen uint32
		if typ&ipfixEnterpriseBit != 0 {
			if off+4 > len(rem) {
				return nil, 0, false
			}
			pen = binary.BigEndian.Uint32(rem[off : off+4])
			off += 4
			typ &^= ipfixEnterpriseBit
		}
		fields = append(fields, templateField{Type: typ, Length: length, EnterpriseID: pen})
	}
	return fields, off, true
}

// parseIPFIXTemplateSet registers every template record in a set-2 body:
// templateID(2) + fieldCount(2) + fieldCount enterprise-aware specifiers.
//
// A fieldCount of 0 is a TEMPLATE WITHDRAWAL (RFC 7011 §8.1 — templateID 2
// withdraws all data templates): withdrawals MUST be ignored over UDP, but
// they MUST still be parsed — treating the 4-byte record as a template would
// either corrupt the set iteration or register a zero-length template whose
// data-set walk never advances.
func (r *NetFlowReceiver) parseIPFIXTemplateSet(body []byte, key exporterKey, now time.Time) {
	rem := body
	for len(rem) >= 4 {
		tid := binary.BigEndian.Uint16(rem[0:2])
		fieldCount := int(binary.BigEndian.Uint16(rem[2:4]))
		if tid == 0 {
			return // padding, not another record
		}
		if fieldCount == 0 {
			r.emitParseEvent(eventTemplateWithdrawal)
			rem = rem[4:] // parsed-then-ignored; iteration continues cleanly
			continue
		}
		if tid < minDataSetID {
			r.emitParseEvent(eventMalformed)
			return
		}
		fields, consumed, ok := parseIPFIXFieldSpecs(rem, 4, fieldCount)
		if !ok {
			r.emitParseEvent(eventMalformed)
			return
		}
		if reason := r.caches.templates.put(templateKey{key, tid}, fields, 0, false, now); reason != putOK {
			r.emitParseEvent(reason)
		}
		rem = rem[consumed:]
	}
}

// parseIPFIXOptionsTemplateSet registers every options template in a set-3
// body: templateID(2) + totalFieldCount(2) + scopeFieldCount(2) + totalFieldCount
// specifiers (the first scopeFieldCount of which are scope). THE v9/IPFIX
// TRAP, other side: both count words are FIELD COUNTS (RFC 7011 §3.4.2.2),
// not byte lengths like v9 set 1 — sharing the v9 parse would silently
// corrupt the sampler table (research §2.6).
//
// A totalFieldCount of 0 is a withdrawal (templateID 3 = withdraw all options
// templates) — same parsed-then-ignored handling as set 2, and the withdrawal
// record is 4 bytes (no scopeFieldCount word follows).
func (r *NetFlowReceiver) parseIPFIXOptionsTemplateSet(body []byte, key exporterKey, now time.Time) {
	rem := body
	for len(rem) >= 4 {
		tid := binary.BigEndian.Uint16(rem[0:2])
		totalCount := int(binary.BigEndian.Uint16(rem[2:4]))
		if tid == 0 {
			return // padding
		}
		if totalCount == 0 {
			r.emitParseEvent(eventTemplateWithdrawal)
			rem = rem[4:]
			continue
		}
		if len(rem) < 6 {
			r.emitParseEvent(eventMalformed)
			return
		}
		scopeCount := int(binary.BigEndian.Uint16(rem[4:6]))
		// scopeCount > totalCount is self-contradictory; RFC 7011 also forbids
		// scopeCount 0, but a lenient accept there can't desync anything.
		if tid < minDataSetID || scopeCount > totalCount {
			r.emitParseEvent(eventMalformed)
			return
		}
		fields, consumed, ok := parseIPFIXFieldSpecs(rem, 6, totalCount)
		if !ok {
			r.emitParseEvent(eventMalformed)
			return
		}
		if reason := r.caches.templates.put(templateKey{key, tid}, fields, scopeCount, true, now); reason != putOK {
			r.emitParseEvent(reason)
		}
		rem = rem[consumed:]
	}
}
