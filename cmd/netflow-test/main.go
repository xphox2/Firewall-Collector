// netflow-test is a standalone NetFlow v5 / v9 / IPFIX test sender for
// operators and end-to-end verification (the flow analogue of cmd/tftp-test).
// It crafts spec-correct datagrams for the vendor conformance shapes the
// collector's parser guarantees (docs/flow-protocol-research-2026-07-03.md,
// server repo) and fires them at a collector, printing what was sent and what
// should land server-side.
//
// The exporter identity is ALWAYS the sending socket's source IP — v5/v9/IPFIX
// carry no in-band agent address, so there is no -exporter-ip flag (it would
// be a no-op). The collector's source-IP allowlist therefore only accepts
// datagrams from monitored device IPs: for a local test, either run this on a
// monitored host or watch firewall_collector_rate_limited_drops_total
// {listener="netflow_srcip"} count your packets.
//
// Template packets are sent before data packets (a real exporter's refresh
// discipline); dispatch on the collector is content-based, so any -proto works
// against either the NetFlow (2055) or IPFIX (4739) port.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	target := flag.String("target", "127.0.0.1:2055", "collector host:port (NetFlow 2055 or IPFIX 4739 — dispatch is content-based)")
	proto := flag.String("proto", "all", "shape to send: v5|v9|ipfix|fortigate|pan|asa|sonicwall|mikrotik|all")
	rate := flag.Int("rate", 1, "sampling rate (v5 header interval / v9 sampler-options rate / MikroTik IE34); collector multiplies counters by it")
	byteCount := flag.Int("bytes", 1000, "per-record byte counter (dOctets / octetDeltaCount) at SAMPLED scale")
	count := flag.Int("count", 3, "data records per shape")
	flag.Parse()

	if *rate < 1 || *rate > 0x3FFF {
		log.Fatalf("-rate must be 1..16383 (v5 carries it in 14 bits)")
	}
	if *count < 1 || *byteCount < 0 {
		log.Fatalf("-count must be >= 1 and -bytes >= 0")
	}

	shapes := []string{"v5", "v9", "ipfix", "fortigate", "pan", "asa", "sonicwall", "mikrotik"}
	if *proto != "all" {
		found := false
		for _, s := range shapes {
			if s == *proto {
				found = true
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "unknown -proto %q\n", *proto)
			flag.Usage()
			os.Exit(2)
		}
		shapes = []string{*proto}
	}

	conn, err := net.Dial("udp", *target)
	if err != nil {
		log.Fatalf("dial %s: %v", *target, err)
	}
	defer conn.Close()

	fmt.Printf("=== netflow-test → %s (rate=%d bytes=%d count=%d) ===\n", *target, *rate, *byteCount, *count)
	fmt.Println("note: the collector attributes flows to THIS host's source IP; it must be a monitored device IP or the allowlist drops the packets")
	for _, s := range shapes {
		pkts, expect := buildShape(s, uint32(*rate), uint64(*byteCount), *count)
		fmt.Printf("\n--- %s ---\n", s)
		for _, p := range pkts {
			if _, err := conn.Write(p.data); err != nil {
				log.Fatalf("send %s (%s): %v", s, p.desc, err)
			}
			fmt.Printf("sent %-4d bytes: %s\n", len(p.data), p.desc)
			time.Sleep(50 * time.Millisecond) // keep template-before-data ordering honest
		}
		fmt.Printf("expect: %s\n", expect)
	}
	fmt.Println("\ndone. Verify on the server (flows page / GET /api/flows?flow_source=N) or on the collector's /metrics (firewall_collector_netflow_events_total).")
}

// packet is one crafted datagram plus its human description.
type packet struct {
	data []byte
	desc string
}

// buildShape returns the datagrams for one conformance shape and the expected
// server-side outcome.
func buildShape(shape string, rate uint32, byteCount uint64, count int) ([]packet, string) {
	switch shape {
	case "v5":
		return buildV5(rate, byteCount, count)
	case "v9":
		return buildV9Generic(byteCount, count)
	case "ipfix":
		return buildIPFIXGeneric(byteCount, count)
	case "fortigate":
		return buildFortiGate(rate, byteCount, count)
	case "pan":
		return buildPAN(byteCount, count)
	case "asa":
		return buildASA(byteCount, count)
	case "sonicwall":
		return buildSonicWall(byteCount, count)
	case "mikrotik":
		return buildMikroTik(rate, byteCount, count)
	}
	return nil, ""
}

// ---- tiny big-endian builders (test-only; the real parsers live in
// internal/netflow and _test helpers can't be imported from a cmd) ----

type buf struct{ b []byte }

func (p *buf) u8(v uint8)          { p.b = append(p.b, v) }
func (p *buf) u16(v uint16)        { p.b = binary.BigEndian.AppendUint16(p.b, v) }
func (p *buf) u32(v uint32)        { p.b = binary.BigEndian.AppendUint32(p.b, v) }
func (p *buf) u64(v uint64)        { p.b = binary.BigEndian.AppendUint64(p.b, v) }
func (p *buf) raw(bs []byte)       { p.b = append(p.b, bs...) }
func (p *buf) ip4(a, b, c, d byte) { p.raw([]byte{a, b, c, d}) }

// pad4 pads to a 4-byte boundary (v9/IPFIX sets SHOULD be 32-bit aligned).
func (p *buf) pad4() {
	for len(p.b)%4 != 0 {
		p.b = append(p.b, 0)
	}
}

// fieldSpec is one (type, length) template field. For IPFIX enterprise fields
// set pen != 0 (the enterprise bit + 4-byte PEN are emitted automatically).
type fieldSpec struct {
	typ, length uint16
	pen         uint32
}

// exporter clock model shared by every shape: the "device" booted an hour ago.
const sysUptimeMs = 3_600_000

func nowSecs() uint32 { return uint32(time.Now().Unix()) }

// v9Packet frames flowsets into one NetFlow v9 datagram.
func v9Packet(seq, sourceID uint32, sets ...struct {
	id   uint16
	body []byte
}) []byte {
	var p buf
	p.u16(9)
	p.u16(uint16(len(sets))) // header Count — a hint at best (RFC 5153 §10.1)
	p.u32(sysUptimeMs)
	p.u32(nowSecs())
	p.u32(seq)
	p.u32(sourceID)
	for _, s := range sets {
		var body buf
		body.raw(s.body)
		body.pad4()
		p.u16(s.id)
		p.u16(uint16(4 + len(body.b)))
		p.raw(body.b)
	}
	return p.b
}

// ipfixPacket frames sets into one IPFIX message (header Length backpatched).
func ipfixPacket(seq, odid uint32, sets ...struct {
	id   uint16
	body []byte
}) []byte {
	var p buf
	p.u16(10)
	p.u16(0) // length backpatched below
	p.u32(nowSecs())
	p.u32(seq)
	p.u32(odid)
	for _, s := range sets {
		var body buf
		body.raw(s.body)
		body.pad4()
		p.u16(s.id)
		p.u16(uint16(4 + len(body.b)))
		p.raw(body.b)
	}
	binary.BigEndian.PutUint16(p.b[2:4], uint16(len(p.b)))
	return p.b
}

type set = struct {
	id   uint16
	body []byte
}

// v9Template builds one set-0 template record body (v9 fields have no PENs).
func v9Template(tid uint16, fields []fieldSpec) []byte {
	var p buf
	p.u16(tid)
	p.u16(uint16(len(fields)))
	for _, f := range fields {
		p.u16(f.typ)
		p.u16(f.length)
	}
	return p.b
}

// v9OptionsTemplate builds one set-1 options template record body. Scope and
// option lengths are BYTE lengths (RFC 3954 §6.1 — the v9/IPFIX trap).
func v9OptionsTemplate(tid uint16, scope, options []fieldSpec) []byte {
	var p buf
	p.u16(tid)
	p.u16(uint16(len(scope) * 4))
	p.u16(uint16(len(options) * 4))
	for _, f := range append(append([]fieldSpec{}, scope...), options...) {
		p.u16(f.typ)
		p.u16(f.length)
	}
	return p.b
}

// ipfixTemplate builds one set-2/set-3 template record body. counts are FIELD
// counts (RFC 7011 — the other side of the trap). scopeCount 0 = data template.
func ipfixTemplate(tid uint16, scopeCount int, fields []fieldSpec) []byte {
	var p buf
	p.u16(tid)
	p.u16(uint16(len(fields)))
	if scopeCount > 0 {
		p.u16(uint16(scopeCount))
	}
	for _, f := range fields {
		if f.pen != 0 {
			p.u16(f.typ | 0x8000)
			p.u16(f.length)
			p.u32(f.pen)
		} else {
			p.u16(f.typ)
			p.u16(f.length)
		}
	}
	return p.b
}

// ---- shape builders ----

// buildV5 crafts a NetFlow v5 datagram: 24-byte header + count 48-byte records
// with the given sampling interval in the header (mode 1 = deterministic when
// rate > 1). Counters are at SAMPLED scale — the collector multiplies.
func buildV5(rate uint32, byteCount uint64, count int) ([]packet, string) {
	var p buf
	p.u16(5)
	p.u16(uint16(count))
	p.u32(sysUptimeMs)
	p.u32(nowSecs())
	p.u32(0) // unix nsecs
	p.u32(1) // flow_sequence
	p.u8(0)  // engine_type
	p.u8(0)  // engine_id
	sampling := uint16(rate)
	if rate > 1 {
		sampling |= 0x4000 // mode 1 (deterministic sampling)
	}
	p.u16(sampling)
	for i := 0; i < count; i++ {
		p.ip4(192, 0, 2, 1)            // srcaddr
		p.ip4(198, 51, 100, byte(1+i)) // dstaddr
		p.ip4(0, 0, 0, 0)              // nexthop ("none")
		p.u16(1)                       // input ifIndex
		p.u16(2)                       // output ifIndex
		p.u32(10)                      // dPkts (sampled scale)
		p.u32(uint32(byteCount))       // dOctets (sampled scale)
		p.u32(sysUptimeMs - 60000)     // First
		p.u32(sysUptimeMs - 1000)      // Last
		p.u16(12345)                   // srcport
		p.u16(443)                     // dstport
		p.u8(0)                        // pad1
		p.u8(0x18)                     // tcp_flags (PSH|ACK)
		p.u8(6)                        // proto TCP
		p.u8(0)                        // tos
		p.u16(0)                       // src_as
		p.u16(0)                       // dst_as
		p.u8(24)                       // src_mask
		p.u8(24)                       // dst_mask
		p.u16(0)                       // pad2
	}
	exp := fmt.Sprintf("%d rows, flow_source=1, bytes=%d packets=%d each (collector multiplies sampled-scale counters by rate %d), 192.0.2.1→198.51.100.x tcp/443",
		count, byteCount*uint64(rate), 10*uint64(rate), rate)
	return []packet{{p.b, fmt.Sprintf("v5 header (sampling mode 1 rate %d) + %d records", rate, count)}}, exp
}

// genericV9Fields is the RFC-clean v9/IPFIX data template every shape riffs on.
func addrPortFields() []fieldSpec {
	return []fieldSpec{
		{typ: 8, length: 4},  // IPV4_SRC_ADDR
		{typ: 12, length: 4}, // IPV4_DST_ADDR
		{typ: 7, length: 2},  // L4_SRC_PORT
		{typ: 11, length: 2}, // L4_DST_PORT
		{typ: 4, length: 1},  // PROTOCOL
	}
}

// addrPortValues writes the values matching addrPortFields.
func addrPortValues(p *buf, i int) {
	p.ip4(192, 0, 2, 1)
	p.ip4(198, 51, 100, byte(1+i))
	p.u16(12345)
	p.u16(443)
	p.u8(6)
}

// buildV9Generic crafts an RFC-clean unsampled v9 exporter: template packet,
// then a data packet with uptime-relative timestamps (IEs 21/22).
func buildV9Generic(byteCount uint64, count int) ([]packet, string) {
	fields := append(addrPortFields(),
		fieldSpec{typ: 6, length: 1},  // TCP_FLAGS
		fieldSpec{typ: 1, length: 4},  // IN_BYTES
		fieldSpec{typ: 2, length: 4},  // IN_PKTS
		fieldSpec{typ: 10, length: 4}, // INPUT_SNMP
		fieldSpec{typ: 14, length: 4}, // OUTPUT_SNMP
		fieldSpec{typ: 22, length: 4}, // FIRST_SWITCHED
		fieldSpec{typ: 21, length: 4}, // LAST_SWITCHED
	)
	tmplPkt := v9Packet(1, 1, set{0, v9Template(256, fields)})

	var d buf
	for i := 0; i < count; i++ {
		addrPortValues(&d, i)
		d.u8(0x18)
		d.u32(uint32(byteCount))
		d.u32(10)
		d.u32(1)
		d.u32(2)
		d.u32(sysUptimeMs - 60000)
		d.u32(sysUptimeMs - 1000)
	}
	dataPkt := v9Packet(2, 1, set{256, d.b})
	exp := fmt.Sprintf("%d rows, flow_source=2, bytes=%d each (unsampled, rate defaults to 1), flow_start≈now-60s flow_end≈now-1s from uptime math", count, byteCount)
	return []packet{
		{tmplPkt, "v9 template flowset (tid 256, 12 fields)"},
		{dataPkt, fmt.Sprintf("v9 data flowset (tid 256, %d records)", count)},
	}, exp
}

// buildIPFIXGeneric crafts an RFC-clean IPFIX exporter: template with 8-byte
// counters, ms-epoch timestamps, flowEndReason, and a varlen field
// (interfaceName, IE 82 — exercises the varlen walk; the IE itself is
// recognized-and-skipped).
func buildIPFIXGeneric(byteCount uint64, count int) ([]packet, string) {
	fields := append(addrPortFields(),
		fieldSpec{typ: 1, length: 8},       // octetDeltaCount (8-byte encoding)
		fieldSpec{typ: 2, length: 8},       // packetDeltaCount
		fieldSpec{typ: 152, length: 8},     // flowStartMilliseconds
		fieldSpec{typ: 153, length: 8},     // flowEndMilliseconds
		fieldSpec{typ: 136, length: 1},     // flowEndReason
		fieldSpec{typ: 82, length: 0xFFFF}, // interfaceName — VARLEN
	)
	tmplPkt := ipfixPacket(0, 1, set{2, ipfixTemplate(256, 0, fields)})

	nowMs := uint64(time.Now().UnixMilli())
	var d buf
	for i := 0; i < count; i++ {
		addrPortValues(&d, i)
		d.u64(byteCount)
		d.u64(10)
		d.u64(nowMs - 60000)
		d.u64(nowMs - 1000)
		d.u8(1)               // flowEndReason 1 = idle timeout
		d.u8(4)               // varlen length prefix
		d.raw([]byte("wan1")) // interfaceName
	}
	dataPkt := ipfixPacket(uint32(count), 1, set{256, d.b})
	exp := fmt.Sprintf("%d rows, flow_source=3, bytes=%d each, flow_end_reason=1, varlen interfaceName consumed cleanly", count, byteCount)
	return []packet{
		{tmplPkt, "IPFIX template set (tid 256, incl. varlen IE 82)"},
		{dataPkt, fmt.Sprintf("IPFIX data set (tid 256, %d records)", count)},
	}, exp
}

// buildFortiGate crafts the FortiGate 7.6 sampled-NetFlow shape: v9 with a
// sampler options template + options data (FLOW_SAMPLER_ID 48 + rate 50),
// per-record sampler reference, and OUT_BYTES/OUT_PKTS (IEs 23/24) as the
// per-session REVERSE counters (biflow). Counters at sampled scale — the
// collector must multiply (the FortiGate multiply correction).
func buildFortiGate(rate uint32, byteCount uint64, count int) ([]packet, string) {
	fields := append(addrPortFields(),
		fieldSpec{typ: 1, length: 4},  // IN_BYTES (forward, sampled scale)
		fieldSpec{typ: 2, length: 4},  // IN_PKTS
		fieldSpec{typ: 23, length: 4}, // OUT_BYTES (reverse — biflow)
		fieldSpec{typ: 24, length: 4}, // OUT_PKTS
		fieldSpec{typ: 48, length: 2}, // FLOW_SAMPLER_ID
		fieldSpec{typ: 22, length: 4}, // FIRST_SWITCHED
		fieldSpec{typ: 21, length: 4}, // LAST_SWITCHED
	)
	tmplPkt := v9Packet(1, 1,
		set{0, v9Template(257, fields)},
		set{1, v9OptionsTemplate(260,
			[]fieldSpec{{typ: 1, length: 4}},                        // scope: System
			[]fieldSpec{{typ: 48, length: 2}, {typ: 50, length: 4}}, // sampler ID + random interval
		)},
	)

	var o buf
	o.u32(1)    // scope value (system 1)
	o.u16(1)    // FLOW_SAMPLER_ID = 1
	o.u32(rate) // FLOW_SAMPLER_RANDOM_INTERVAL = rate
	optPkt := v9Packet(2, 1, set{260, o.b})

	revBytes := byteCount / 2
	var d buf
	for i := 0; i < count; i++ {
		addrPortValues(&d, i)
		d.u32(uint32(byteCount)) // IN_BYTES, sampled scale
		d.u32(10)                // IN_PKTS
		d.u32(uint32(revBytes))  // OUT_BYTES (reverse)
		d.u32(5)                 // OUT_PKTS
		d.u16(1)                 // sampler ID 1
		d.u32(sysUptimeMs - 60000)
		d.u32(sysUptimeMs - 1000)
	}
	dataPkt := v9Packet(3, 1, set{257, d.b})
	exp := fmt.Sprintf("%d forward rows bytes=%d + %d REVERSE rows (mirrored 5-tuple) bytes=%d, flow_source=2 — sampler rate %d learned from options data and multiplied in",
		count, byteCount*uint64(rate), count, revBytes*uint64(rate), rate)
	return []packet{
		{tmplPkt, "v9 template (tid 257) + options template (tid 260, v9 BYTE-length words)"},
		{optPkt, fmt.Sprintf("v9 options data (sampler 1 → rate %d)", rate)},
		{dataPkt, fmt.Sprintf("v9 data (tid 257, %d biflow records, sampled-scale counters)", count)},
	}, exp
}

// buildPAN crafts the Palo Alto shape: v9-only, never sampled, no sampler
// options, uptime-math timestamps (the hot path), and the vendor-squatted
// App-ID string field 56701 (32 bytes, null-padded).
func buildPAN(byteCount uint64, count int) ([]packet, string) {
	fields := append(addrPortFields(),
		fieldSpec{typ: 1, length: 4},
		fieldSpec{typ: 2, length: 4},
		fieldSpec{typ: 56701, length: 32}, // PAN App-ID (raw squatted v9 ID)
		fieldSpec{typ: 22, length: 4},
		fieldSpec{typ: 21, length: 4},
	)
	tmplPkt := v9Packet(1, 1, set{0, v9Template(258, fields)})

	app := make([]byte, 32)
	copy(app, "ssl")
	var d buf
	for i := 0; i < count; i++ {
		addrPortValues(&d, i)
		d.u32(uint32(byteCount))
		d.u32(10)
		d.raw(app)
		d.u32(sysUptimeMs - 60000)
		d.u32(sysUptimeMs - 1000)
	}
	dataPkt := v9Packet(2, 1, set{258, d.b})
	exp := fmt.Sprintf("%d rows, flow_source=2, bytes=%d each (PAN is never sampled → rate 1), app_name=\"ssl\" (exporter truth beats port heuristics)", count, byteCount)
	return []packet{
		{tmplPkt, "v9 template (tid 258, incl. 32-byte App-ID field 56701)"},
		{dataPkt, fmt.Sprintf("v9 data (tid 258, %d records)", count)},
	}, exp
}

// buildASA crafts the Cisco ASA NSEL shape: v9 transport, event-driven, bytes
// ONLY in initiatorOctets(231)/responderOctets(232) (no packet counters exist
// on ASA), absolute event time (IE 323), firewallEvent(233): -count teardown
// records plus one zero-counter DENIED record (233=3) — zero-byte rows are
// legal and are the headline NetFlow win.
func buildASA(byteCount uint64, count int) ([]packet, string) {
	fields := append(addrPortFields(),
		fieldSpec{typ: 231, length: 4}, // initiatorOctets — ASA's ONLY byte fields
		fieldSpec{typ: 232, length: 4}, // responderOctets
		fieldSpec{typ: 233, length: 1}, // firewallEvent
		fieldSpec{typ: 323, length: 8}, // observationTimeMilliseconds
	)
	tmplPkt := v9Packet(1, 1, set{0, v9Template(259, fields)})

	nowMs := uint64(time.Now().UnixMilli())
	respBytes := byteCount / 2
	var d buf
	for i := 0; i < count; i++ { // teardowns
		addrPortValues(&d, i)
		d.u32(uint32(byteCount))
		d.u32(uint32(respBytes))
		d.u8(2) // flow deleted (teardown)
		d.u64(nowMs)
	}
	// One denied record: no byte counters at all is how a real ASA sends it —
	// the template still carries 231/232, zero-filled.
	addrPortValues(&d, count)
	d.u32(0)
	d.u32(0)
	d.u8(3) // flow denied
	d.u64(nowMs)
	dataPkt := v9Packet(2, 1, set{259, d.b})
	exp := fmt.Sprintf("%d teardown rows bytes=%d packets=0 (ASA sends no packet counters) + %d reverse rows bytes=%d + 1 DENIED row bytes=0 firewall_event=3 (deny badge), flow_source=2",
		count, byteCount, count, respBytes)
	return []packet{
		{tmplPkt, "v9 NSEL template (tid 259, 231/232-only counters)"},
		{dataPkt, fmt.Sprintf("v9 NSEL data (%d teardowns + 1 denied)", count)},
	}, exp
}

// buildSonicWall crafts the SonicWall "IPFIX with extensions" shape: a plain
// IPFIX template with a PEN-8741 AppFlow enterprise field interleaved
// mid-record — the collector must skip it by length without desyncing.
func buildSonicWall(byteCount uint64, count int) ([]packet, string) {
	fields := append(addrPortFields(),
		fieldSpec{typ: 1, length: 4},
		fieldSpec{typ: 2, length: 4},
		fieldSpec{typ: 22000, length: 4, pen: 8741}, // SonicWall AppFlow extension (opaque)
		fieldSpec{typ: 152, length: 8},
		fieldSpec{typ: 153, length: 8},
	)
	tmplPkt := ipfixPacket(0, 1, set{2, ipfixTemplate(257, 0, fields)})

	nowMs := uint64(time.Now().UnixMilli())
	var d buf
	for i := 0; i < count; i++ {
		addrPortValues(&d, i)
		d.u32(uint32(byteCount))
		d.u32(10)
		d.u32(0xDEADBEEF) // opaque AppFlow bytes — must be skipped, not decoded
		d.u64(nowMs - 60000)
		d.u64(nowMs - 1000)
	}
	dataPkt := ipfixPacket(uint32(count), 1, set{257, d.b})
	exp := fmt.Sprintf("%d rows, flow_source=3, bytes=%d each — PEN-8741 enterprise field skipped by length, no desync/malformed events", count, byteCount)
	return []packet{
		{tmplPkt, "IPFIX template (tid 257, PEN-8741 enterprise field interleaved)"},
		{dataPkt, fmt.Sprintf("IPFIX data (tid 257, %d records)", count)},
	}, exp
}

// buildMikroTik crafts the MikroTik shape: v9 with legacy samplingInterval
// (IE 34) carried INSIDE the data records (no options template at all) — the
// collector learns the domain rate from the very record that carries it.
func buildMikroTik(rate uint32, byteCount uint64, count int) ([]packet, string) {
	fields := append(addrPortFields(),
		fieldSpec{typ: 1, length: 4},
		fieldSpec{typ: 2, length: 4},
		fieldSpec{typ: 34, length: 4}, // samplingInterval, in-data (MikroTik)
		fieldSpec{typ: 22, length: 4},
		fieldSpec{typ: 21, length: 4},
	)
	tmplPkt := v9Packet(1, 1, set{0, v9Template(261, fields)})

	var d buf
	for i := 0; i < count; i++ {
		addrPortValues(&d, i)
		d.u32(uint32(byteCount))
		d.u32(10)
		d.u32(rate)
		d.u32(sysUptimeMs - 60000)
		d.u32(sysUptimeMs - 1000)
	}
	dataPkt := v9Packet(2, 1, set{261, d.b})
	exp := fmt.Sprintf("%d rows, flow_source=2, bytes=%d each — rate %d learned from IE 34 inside the data record itself (no options template)",
		count, byteCount*uint64(rate), rate)
	return []packet{
		{tmplPkt, "v9 template (tid 261, incl. in-data IE 34)"},
		{dataPkt, fmt.Sprintf("v9 data (tid 261, %d records carrying samplingInterval)", count)},
	}, exp
}
