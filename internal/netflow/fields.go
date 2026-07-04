// Package netflow implements the collector's NetFlow v5/v9 + IPFIX receiver
// (Tranche 3). This file holds the IANA IPFIX Information Element numbers the
// parsers use across phases (v5 today; v9/IPFIX framing next phase) plus the
// length-agnostic big-endian integer decoder mandated by the research report
// (docs/flow-protocol-research-2026-07-03.md §2.2): v9 counter fields "can be
// 8 bytes on core routers" (RFC 3954 §8) and IPFIX permits reduced-size
// encoding of any unsigned IE (RFC 7011 §6.2), so no fixed-width read is safe.
package netflow

// IANA IPFIX Information Elements (v9 field types share the same registry
// below 128; vendor-squatted raw v9 IDs live above it). Source:
// https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv
const (
	ieOctetDeltaCount             = 1   // IN_BYTES
	iePacketDeltaCount            = 2   // IN_PKTS
	ieProtocolIdentifier          = 4   // PROTOCOL
	ieIPClassOfService            = 5   // TOS
	ieTCPControlBits              = 6   // TCP_FLAGS
	ieSourceTransportPort         = 7   // L4_SRC_PORT
	ieSourceIPv4Address           = 8   // IPV4_SRC_ADDR
	ieIngressInterface            = 10  // INPUT_SNMP
	ieDestinationTransportPort    = 11  // L4_DST_PORT
	ieDestinationIPv4Address      = 12  // IPV4_DST_ADDR
	ieEgressInterface             = 14  // OUTPUT_SNMP
	ieIPNextHopIPv4Address        = 15  // IPV4_NEXT_HOP
	ieBGPSourceASNumber           = 16  // SRC_AS
	ieBGPDestinationASNumber      = 17  // DST_AS
	ieFlowEndSysUpTime            = 21  // LAST_SWITCHED (uptime ms — the PAN/FortiGate hot path)
	ieFlowStartSysUpTime          = 22  // FIRST_SWITCHED
	iePostOctetDeltaCount         = 23  // OUT_BYTES (FortiGate per-session reverse counter)
	iePostPacketDeltaCount        = 24  // OUT_PKTS
	ieSourceIPv6Address           = 27  // IPV6_SRC_ADDR
	ieDestinationIPv6Address      = 28  // IPV6_DST_ADDR
	ieICMPTypeCodeIPv4            = 32  // ICMP_TYPE (type*256+code)
	ieSamplingInterval            = 34  // legacy sampling rate — MikroTik sends it in DATA records
	ieSamplingAlgorithm           = 35  //
	ieSamplerID                   = 48  // FLOW_SAMPLER_ID (per-record sampler reference)
	ieSamplerMode                 = 49  // FLOW_SAMPLER_MODE
	ieSamplerRandomInterval       = 50  // FLOW_SAMPLER_RANDOM_INTERVAL
	ieVLANID                      = 58  // SRC_VLAN
	iePostVLANID                  = 59  // DST_VLAN
	ieFlowDirection               = 61  // 0=ingress 1=egress
	ieIPNextHopIPv6Address        = 62  // IPV6_NEXT_HOP
	ieOctetTotalCount             = 85  // running total since metering init — NEVER sum as delta (RFC 5153 §4.3)
	iePacketTotalCount            = 86  //
	ieFlowEndReason               = 136 // 2 = active timeout → flow continues in a later record
	ieICMPTypeCodeIPv6            = 139 //
	ieFlowID                      = 148 //
	ieFlowStartSeconds            = 150 //
	ieFlowEndSeconds              = 151 //
	ieFlowStartMilliseconds       = 152 // highest-priority timestamp pair
	ieFlowEndMilliseconds         = 153 //
	ieFlowStartMicroseconds       = 154 // 64-bit NTP format (RFC 7011 §6.1.9)
	ieFlowEndMicroseconds         = 155 //
	ieFlowStartNanoseconds        = 156 // 64-bit NTP format (RFC 7011 §6.1.10)
	ieFlowEndNanoseconds          = 157 //
	ieFlowStartDeltaMicroseconds  = 158 // µs before export time
	ieFlowEndDeltaMicroseconds    = 159 //
	ieFlowDurationMilliseconds    = 161 // pairs with 323 (FortiGate CGN / ASA event time)
	iePostNATSourceIPv4Address    = 225 //
	iePostNATDestinationIPv4Addr  = 226 //
	iePostNAPTSourceTransportPort = 227 //
	iePostNAPTDestTransportPort   = 228 //
	ieNATEvent                    = 230 // RFC 8158 NAT event logs
	ieInitiatorOctets             = 231 // ASA's ONLY byte counters — no IE 1/23 in any NSEL template
	ieResponderOctets             = 232 //
	ieFirewallEvent               = 233 // NSEL: 0 ignore/1 created/2 deleted/3 denied/4 alert/5 update
	iePostNATSourceIPv6Address    = 281 //
	iePostNATDestinationIPv6Addr  = 282 //
	ieBasicList                   = 291 // RFC 6313 structured data — recognized-and-skipped by length
	ieSubTemplateList             = 292 //
	ieSubTemplateMultiList        = 293 //
	ieNATType                     = 297 // unsigned8 (NOT a varlen string — research correction 1.8)
	ieSelectorID                  = 302 // IPFIX PSAMP sampler reference (v9's 48 analogue)
	ieSamplingPacketInterval      = 305 // options rate; multiplier = (interval+space)/interval with 306
	ieSamplingPacketSpace         = 306 //
	ieObservationTimeMilliseconds = 323 // FortiGate CGN template 280 / ASA absolute event time
)

// Vendor-squatted raw v9 field IDs (v9 has no PEN mechanism, so vendors claim
// numbers above the IANA range and collision safety is by convention only).
const (
	fieldASAXlateSrcAddrIPv4 = 40001 // ASA pre-9.x post-NAT tuple (225-228 aliases)
	fieldASAXlateDstAddrIPv4 = 40002 //
	fieldASAXlateSrcPort     = 40003 //
	fieldASAXlateDstPort     = 40004 //
	fieldPANAppID            = 56701 // PAN App-ID string (≤32 B, null-padded in v9)
	fieldPANUserID           = 56702 // PAN User-ID string — recognized, not mapped (Tranche 3)
)

// Private Enterprise Numbers seen on IPFIX enterprise-bit fields (RFC 7011
// §3.2). v9 has no PEN mechanism — vendors squat raw IDs there instead.
const (
	penReverse   = 29305 // RFC 5103 biflow reverse IEs
	penPaloAlto  = 25461 // PAN App-ID (56701) / User-ID (56702) strings
	penFortinet  = 12356 //
	penSonicWall = 8741  // "IPFIX with extensions" AppFlow tables
)

// decodeBE decodes a big-endian unsigned integer of 1–8 bytes into a uint64.
// NetFlow v9 and IPFIX carry the SAME IE at different widths depending on the
// exporter (RFC 3954 §8 counters "can be 8 bytes"; RFC 7011 §6.2 reduced-size
// encoding), so every numeric field read must be length-agnostic. Returns
// ok=false for 0 bytes or more than 8 (a template that wide for a numeric IE
// is quarantined at registration anyway).
func decodeBE(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, true
}
