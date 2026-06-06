package snmp

import (
	"bytes"
	"log"
	"net"
	"strings"
	"testing"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

func withCapturedLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

func TestTrapReceiver_CommunityMismatch_Drops(t *testing.T) {
	const want = "public"
	tr := NewTrapReceiver("127.0.0.1", 0, want)

	if got := tr.allowCommunity("private"); got {
		t.Errorf("allowCommunity(%q) = true, want false (expected %q)", "private", want)
	}
	if got := tr.allowCommunity(""); got {
		t.Errorf("allowCommunity(\"\") = true, want false — empty packet community must be rejected, not silently accepted")
	}
	if got := tr.allowCommunity(want); !got {
		t.Errorf("allowCommunity(%q) = false, want true", want)
	}
}

func TestTrapReceiver_CommunityMismatch_LogsDrop(t *testing.T) {
	tr := NewTrapReceiver("127.0.0.1", 0, "public")

	out := withCapturedLog(t, func() {
		if tr.allowCommunity("private") {
			t.Fatal("expected drop")
		}
	})
	if !strings.Contains(out, "community mismatch") {
		t.Errorf("expected a 'community mismatch' log line, got: %q", out)
	}
	if !strings.Contains(out, "public") || !strings.Contains(out, "private") {
		t.Errorf("expected the log to mention both expected and got community, got: %q", out)
	}
}

func TestTrapReceiver_Start_EmptyCommunity_RefusesError(t *testing.T) {
	tr := NewTrapReceiver("127.0.0.1", 1162, "")

	err := tr.Start(func(*relay.TrapEvent) {})
	if err == nil {
		t.Fatal("Start() with empty community returned nil error; want an error that explains the spoofing hazard")
	}
	if !strings.Contains(err.Error(), "PROBE_SNMP_TRAP_COMMUNITY") {
		t.Errorf("error should name the env var, got: %v", err)
	}
}

// TestTrapReceiver_V1EnterpriseConstruction verifies the SNMPv1 trap-OID
// reconstruction path. RFC 1157 v1 traps carry the enterprise OID plus a
// specific-trap integer in SEPARATE fields (no resolved trapOID varbind),
// so the receiver must synthesize the modern OID by appending ".0.<spec>"
// to the enterprise OID. This is the path FortiGate's older SNMPv1 trap
// emitter uses for IPS/AV alerts when sysAdmin hasn't upgraded to v2c.
//
// Test scenario: enterprise=".1.3.6.1.4.1.12356.101.4.1.10",
// SpecificTrap=42 → expect synthesized trapOID
// ".1.3.6.1.4.1.12356.101.4.1.10.0.42".
func TestTrapReceiver_V1EnterpriseConstruction(t *testing.T) {
	// Register a vendor profile that knows the synthetic OID so the receiver
	// can map it to a real trap type (otherwise parseTrap drops the trap).
	withCleanVendorRegistry(t, func() {
		const enterprise = ".1.3.6.1.4.1.12356.101.4.1.10"
		const specific = 42
		const expectedOID = enterprise + ".0.42"

		// Register a stub profile whose TrapOIDs() recognizes the synthetic
		// OID so parseTrap can label it instead of dropping as Unknown.
		RegisterVendor(&stubVendorProfile{
			name:     "v1-trap-test",
			trapOIDs: map[string]TrapDef{expectedOID: {Type: "V1_TEST", Severity: "info"}},
		})

		tr := NewTrapReceiver("127.0.0.1", 0, "public")
		tr.handler = func(*relay.TrapEvent) {}

		packet := &gosnmp.SnmpPacket{
			Version:   gosnmp.Version1,
			Community: "public",
			SnmpTrap: gosnmp.SnmpTrap{
				Enterprise:   enterprise,
				SpecificTrap: specific,
			},
			Variables: []gosnmp.SnmpPDU{
				// v1 traps still carry varbinds; include one so parseTrap
				// doesn't early-return on len==0.
				{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("fw1")},
			},
		}
		addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 162}

		evt := tr.parseTrap(packet, addr)
		if evt == nil {
			t.Fatal("parseTrap returned nil for valid v1 trap; expected synthesized trapOID to match")
		}
		if evt.TrapOID != expectedOID {
			t.Errorf("synthesized TrapOID = %q, want %q (RFC 1157 v1 → v2 trap-OID mapping)",
				evt.TrapOID, expectedOID)
		}
		if evt.TrapType != "V1_TEST" {
			t.Errorf("TrapType = %q, want %q", evt.TrapType, "V1_TEST")
		}
		if evt.SourceIP != "10.0.0.1" {
			t.Errorf("SourceIP = %q, want %q", evt.SourceIP, "10.0.0.1")
		}
	})
}

// TestTrapReceiver_V1EmptyEnterprise_DropsAsUnknown verifies that a v1 trap
// with an empty enterprise OID (malformed packet from a buggy device) does
// not silently produce a trap event — it must be dropped or fall through to
// the varbind-scan fallback. Without this guard, a buggy emitter could
// flood the relay with TrapOID="" events that no downstream alerting rule
// matches.
func TestTrapReceiver_V1EmptyEnterprise_DropsAsUnknown(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		tr := NewTrapReceiver("127.0.0.1", 0, "public")
		tr.handler = func(*relay.TrapEvent) {}

		packet := &gosnmp.SnmpPacket{
			Version: gosnmp.Version1,
			SnmpTrap: gosnmp.SnmpTrap{
				Enterprise:   "",
				SpecificTrap: 1,
			},
			Variables: []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("fw1")},
			},
		}
		addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 162}

		evt := tr.parseTrap(packet, addr)
		if evt != nil {
			t.Errorf("parseTrap returned event for v1 trap with empty enterprise; got %+v, want nil drop", evt)
		}
	})
}

// TestTrapReceiver_V2KnownTrap verifies the v2c happy path: the receiver
// reads snmpTrapOID.0 from the varbinds and looks it up in the registered
// vendor profiles to fill TrapType and Severity.
func TestTrapReceiver_V2KnownTrap(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		const oid = ".1.3.6.1.4.1.12356.101.2.0.302" // fgTrapVPNTunnelDown
		RegisterVendor(&FortiGateProfile{})          // re-register the real FortiGate

		tr := NewTrapReceiver("127.0.0.1", 0, "public")
		tr.handler = func(*relay.TrapEvent) {}

		packet := &gosnmp.SnmpPacket{
			Version:   gosnmp.Version2c,
			Community: "public",
			Variables: []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(12345)},
				{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: oid},
				{Name: ".1.3.6.1.4.1.12356.101.12.2.2.1.3.1", Type: gosnmp.OctetString, Value: []byte("vpn-to-hq")},
			},
		}
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 162}

		evt := tr.parseTrap(packet, addr)
		if evt == nil {
			t.Fatal("parseTrap returned nil for known v2c trap")
		}
		if evt.TrapOID != oid {
			t.Errorf("TrapOID = %q, want %q", evt.TrapOID, oid)
		}
		if evt.TrapType != "VPN_TUNNEL_DOWN" {
			t.Errorf("TrapType = %q, want VPN_TUNNEL_DOWN", evt.TrapType)
		}
		if evt.Severity != "critical" {
			t.Errorf("Severity = %q, want critical", evt.Severity)
		}
		// Message should include the trap type and the tunnel-name varbind.
		if !strings.Contains(evt.Message, "VPN_TUNNEL_DOWN") {
			t.Errorf("Message missing trap type: %q", evt.Message)
		}
		if !strings.Contains(evt.Message, "vpn-to-hq") {
			t.Errorf("Message missing tunnel-name varbind: %q", evt.Message)
		}
	})
}

// TestTrapReceiver_EmptyVariables_ReturnsNil verifies the cheap early-exit:
// a trap PDU with zero varbinds is malformed (every real trap has at least
// sysUpTime + snmpTrapOID) and must be dropped without further processing.
func TestTrapReceiver_EmptyVariables_ReturnsNil(t *testing.T) {
	tr := NewTrapReceiver("127.0.0.1", 0, "public")
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Variables: nil,
	}
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 162}

	if got := tr.parseTrap(packet, addr); got != nil {
		t.Errorf("parseTrap on empty varbinds = %+v, want nil", got)
	}
}

// TestTrapReceiver_UnknownOIDFallback_Generic verifies that a v1 trap with a
// well-formed (synthesized) OID that doesn't match any registered vendor
// still produces a generic event so the operator at least sees something
// arrived. Without this fallback, a brand-new vendor would appear "silent"
// during a misconfiguration debug.
func TestTrapReceiver_UnknownOIDFallback_Generic(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		// Register no vendors → no trap-OID will match → fallthrough path.
		tr := NewTrapReceiver("127.0.0.1", 0, "public")

		packet := &gosnmp.SnmpPacket{
			Version: gosnmp.Version1,
			SnmpTrap: gosnmp.SnmpTrap{
				Enterprise:   ".1.3.6.1.4.1.99999",
				SpecificTrap: 1,
			},
			Variables: []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("unknown-vendor-fw")},
			},
		}
		addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 162}

		evt := tr.parseTrap(packet, addr)
		if evt == nil {
			t.Fatal("parseTrap dropped unknown-OID v1 trap; expected GENERIC fallback so operator can see something arrived")
		}
		if evt.TrapType != "GENERIC" {
			t.Errorf("TrapType = %q, want GENERIC", evt.TrapType)
		}
		if evt.TrapOID != ".1.3.6.1.4.1.99999.0.1" {
			t.Errorf("TrapOID = %q, want synthesized .1.3.6.1.4.1.99999.0.1", evt.TrapOID)
		}
	})
}

// TestTrapReceiver_VarbindScanFallback verifies that a v2c trap whose
// snmpTrapOID.0 references an OID we don't know, but which carries a
// known trap OID elsewhere in the varbinds (some legacy emitters do this),
// still gets recognized via the varbind scan.
func TestTrapReceiver_VarbindScanFallback(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		const knownOID = ".1.3.6.1.4.1.12356.101.2.0.301" // fgTrapVPNTunnelUp
		RegisterVendor(&FortiGateProfile{})

		tr := NewTrapReceiver("127.0.0.1", 0, "public")

		packet := &gosnmp.SnmpPacket{
			Version:   gosnmp.Version2c,
			Community: "public",
			Variables: []gosnmp.SnmpPDU{
				// snmpTrapOID.0 points to an UNKNOWN OID — buggy emitter.
				{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.99999.0.1"},
				// But a known trap OID appears as a varbind name — the
				// fallback scan should find it.
				{Name: knownOID, Type: gosnmp.OctetString, Value: []byte("info")},
			},
		}
		addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 162}

		evt := tr.parseTrap(packet, addr)
		if evt == nil {
			t.Fatal("parseTrap dropped trap whose known OID was in a varbind name")
		}
		if evt.TrapType != "VPN_TUNNEL_UP" {
			t.Errorf("TrapType = %q, want VPN_TUNNEL_UP (varbind-scan fallback)", evt.TrapType)
		}
	})
}

// TestLookupTrapOID verifies the cross-vendor lookup walks every registered
// profile and returns the first match. Unknown OIDs yield ("", "").
func TestLookupTrapOID(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		RegisterVendor(&FortiGateProfile{})
		RegisterVendor(&PaloAltoProfile{})

		tests := []struct {
			oid      string
			wantType string
			wantSev  string
		}{
			// FortiGate
			{".1.3.6.1.4.1.12356.101.2.0.301", "VPN_TUNNEL_UP", "info"},
			{".1.3.6.1.4.1.12356.101.2.0.601", "AV_VIRUS", "critical"},
			// Palo Alto
			{".1.3.6.1.4.1.25461.2.1.3.2.0.1746", "vpn-tunnel-up", "info"},
			{".1.3.6.1.4.1.25461.2.1.3.2.0.916", "hw-fan-failure", "critical"},
			// Unknown
			{".1.3.6.1.4.1.99999.1.2.3", "", ""},
			{"", "", ""},
		}
		for _, tt := range tests {
			gotType, gotSev := lookupTrapOID(tt.oid)
			if gotType != tt.wantType || gotSev != tt.wantSev {
				t.Errorf("lookupTrapOID(%q) = (%q, %q), want (%q, %q)",
					tt.oid, gotType, gotSev, tt.wantType, tt.wantSev)
			}
		}
	})
}

// TestBuildTrapMessage verifies the trap-message formatter skips the
// "decorative" varbinds (snmpTrapOID, sysUpTime) and concatenates the rest
// with "; " separators. The first token is always the trap type.
func TestBuildTrapMessage(t *testing.T) {
	vars := []gosnmp.SnmpPDU{
		{Name: sysUpTimeOID, Type: gosnmp.TimeTicks, Value: uint32(12345)},
		{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.12356.101.2.0.301"},
		{Name: ".1.3.6.1.4.1.12356.101.12.2.2.1.3.1", Type: gosnmp.OctetString, Value: []byte("vpn-to-hq")},
		{Name: ".1.3.6.1.4.1.12356.101.12.2.2.1.4.1", Type: gosnmp.OctetString, Value: []byte("203.0.113.5")},
	}
	got := buildTrapMessage("VPN_TUNNEL_UP", vars)
	wantPrefix := "VPN_TUNNEL_UP"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("trap message must start with type, got: %q", got)
	}
	if !strings.Contains(got, "vpn-to-hq") {
		t.Errorf("trap message must include data varbind, got: %q", got)
	}
	if !strings.Contains(got, "203.0.113.5") {
		t.Errorf("trap message must include remote IP varbind, got: %q", got)
	}
	if strings.Contains(got, "12345") {
		t.Errorf("trap message must NOT include sysUpTime ticks; got: %q", got)
	}
	if strings.Contains(got, ".1.3.6.1.4.1.12356.101.2.0.301") {
		t.Errorf("trap message must NOT include snmpTrapOID value verbatim; got: %q", got)
	}
}

// TestFormatVarbindValue covers every type the parser is expected to handle
// PLUS rejects the types that should yield "" so they get filtered by
// buildTrapMessage.
func TestFormatVarbindValue(t *testing.T) {
	tests := []struct {
		name string
		pdu  gosnmp.SnmpPDU
		want string
	}{
		{"octet_string",
			gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("hello")},
			"hello"},
		{"octet_string_empty_skipped",
			gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte{}},
			""},
		{"octet_string_wrong_type_skipped",
			gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: "not-a-byte-slice"},
			""},
		{"integer",
			gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 42},
			"42"},
		{"counter32",
			gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint32(1234)},
			"1234"},
		{"gauge32",
			gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint(99)},
			"99"},
		{"counter64",
			gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(1 << 33)},
			"8589934592"},
		{"oid",
			gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1"},
			".1.3.6.1"},
		{"ipaddr_string",
			gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: "10.0.0.1"},
			"10.0.0.1"},
		{"timeticks_returns_empty",
			gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: uint32(123)},
			""},
		{"null_returns_empty",
			gosnmp.SnmpPDU{Type: gosnmp.Null, Value: nil},
			""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatVarbindValue(tt.pdu); got != tt.want {
				t.Errorf("formatVarbindValue(%v) = %q, want %q", tt.pdu, got, tt.want)
			}
		})
	}
}
