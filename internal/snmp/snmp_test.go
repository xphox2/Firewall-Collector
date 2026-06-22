package snmp

import (
	"testing"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// TestSafeString_VariousInputs verifies safeString handles all gosnmp value
// shapes the parsers may encounter — []byte (the common OctetString
// representation), plain string (some types), and anything else (must yield
// "" rather than a panic or "%!s(int=…)"-style garbage).
func TestSafeString_VariousInputs(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want string
	}{
		{"byte_slice", []byte("FortiGate-60F"), "FortiGate-60F"},
		{"empty_byte_slice", []byte{}, ""},
		{"nil_byte_slice", []byte(nil), ""},
		{"plain_string", "panFW-3000", "panFW-3000"},
		{"empty_string", "", ""},
		{"int_returns_empty", 42, ""},
		{"nil_returns_empty", nil, ""},
		{"struct_returns_empty", struct{ X int }{1}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeString(tt.in); got != tt.want {
				t.Errorf("safeString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestGetIndexFromOID_Valid verifies that the index extractor handles the two
// shapes used in the codebase:
//
//   - simple table OIDs like .1.3.6.1.2.1.2.2.1.10.5 where the index is the
//     last element (5),
//   - multi-element index OIDs like .1.3.6.1.4.1.12356.101.4.3.2.1.3.1
//     where 1 is the index for a single-VDOM table.
func TestGetIndexFromOID_Valid(t *testing.T) {
	tests := []struct {
		name string
		oid  string
		base string
		want int
	}{
		{"single_digit_last", ".1.3.6.1.2.1.2.2.1.10.5", ".1.3.6.1.2.1.2.2.1.10", 5},
		{"two_digit", ".1.3.6.1.2.1.2.2.1.10.42", ".1.3.6.1.2.1.2.2.1.10", 42},
		{"large_index", ".1.3.6.1.2.1.2.2.1.10.65536", ".1.3.6.1.2.1.2.2.1.10", 65536},
		{"index_one", ".1.3.6.1.4.1.12356.101.4.3.2.1.3.1", ".1.3.6.1.4.1.12356.101.4.3.2.1.3", 1},
		{"index_zero", ".1.3.6.1.4.1.12356.101.4.1.3.0", ".1.3.6.1.4.1.12356.101.4.1.3", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getIndexFromOID(tt.oid, tt.base); got != tt.want {
				t.Errorf("getIndexFromOID(%q, %q) = %d, want %d", tt.oid, tt.base, got, tt.want)
			}
		})
	}
}

// TestGetIndexFromOID_MalformedOID guards the regression path: a malformed
// OID with a non-numeric index must return -1, never panic, and never
// silently match index 0. Every parser checks `idx < 0` and skips the PDU
// on negative return, so getting this wrong would cause garbled data being
// attributed to a real index 0 row.
//
// NOTE: every caller already guards with `strings.HasPrefix(name, base+".")`
// before calling getIndexFromOID, so the bare-base case (name == base, no
// trailing dot) is unreachable in practice. This test covers only the
// reachable malformed inputs.
func TestGetIndexFromOID_MalformedOID(t *testing.T) {
	tests := []struct {
		name string
		oid  string
		base string
		want int
	}{
		// Non-numeric tail: scanf can't parse "foo" as %d, so both the
		// last-element and first-element fallbacks fail → -1.
		{"non_numeric_tail", ".1.3.6.1.2.1.2.2.1.10.foo", ".1.3.6.1.2.1.2.2.1.10", -1},
		// Just a trailing dot (empty index element). scanf("", "%d") returns
		// 0 matches → both fallbacks fail → -1.
		{"trailing_dot_only", ".1.3.6.1.2.1.2.2.1.10.", ".1.3.6.1.2.1.2.2.1.10", -1},
		// Non-numeric middle AND tail: e.g. an ENTITY-MIB child OID that
		// the parser shouldn't have matched but somehow did.
		{"all_non_numeric_tail", ".1.3.6.1.2.1.2.2.1.10.abc.def", ".1.3.6.1.2.1.2.2.1.10", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getIndexFromOID(tt.oid, tt.base); got != tt.want {
				t.Errorf("getIndexFromOID(%q, %q) = %d, want %d (must reject malformed without panic)",
					tt.oid, tt.base, got, tt.want)
			}
		})
	}
}

// TestGetIndexFromOID_BareBaseQuirk documents (and pins) the bare-base
// behavior. When called with oid==base (no trailing dot), the function
// does NOT return -1 — it actually parses the LAST element of the base
// itself (e.g. ".1.3.6.1.2.1.2.2.1.10" → 10). This is unreachable in
// practice because every caller guards with HasPrefix(name, base+"."),
// but if a refactor ever removes that guard, this test will flag the
// resulting subtle behavior so the new caller adds its own validation
// instead of silently emitting bogus "index=10" records.
func TestGetIndexFromOID_BareBaseQuirk(t *testing.T) {
	got := getIndexFromOID(".1.3.6.1.2.1.2.2.1.10", ".1.3.6.1.2.1.2.2.1.10")
	if got != 10 {
		t.Errorf("getIndexFromOID(bare base) = %d, want 10 (quirky but stable); "+
			"if this changes, audit all callers to ensure HasPrefix guard is still in place", got)
	}
}

// TestFormatMAC_VariousInputs verifies the MAC formatter handles the two
// formats gosnmp produces ([]byte for binary OctetString, string for
// some weird devices that send hex), rejects anything that isn't a 6-byte
// value, and produces upper-case colon-delimited output.
func TestFormatMAC_VariousInputs(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want string
	}{
		{"valid_6_bytes",
			[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			"AA:BB:CC:DD:EE:FF"},
		{"valid_zero_mac",
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			"00:00:00:00:00:00"},
		{"valid_string_6_bytes",
			string([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}),
			"12:34:56:78:9A:BC"},
		// Wrong-length values must yield "" not partial output, so the
		// "OUI 00:00:00:" garbage doesn't get exported as a real MAC.
		{"too_short", []byte{0xAA, 0xBB, 0xCC}, ""},
		{"too_long", []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11}, ""},
		{"empty", []byte{}, ""},
		// Non-string, non-byte input must not panic.
		{"int_returns_empty", 0xAABBCCDDEEFF, ""},
		{"nil_returns_empty", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatMAC(tt.in); got != tt.want {
				t.Errorf("formatMAC(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestV3MsgFlags verifies the v3 message-flag mapping that controls which
// security layer is used. Mismatches here would mean we'd silently downgrade
// from authPriv to authNoPriv (loss of confidentiality) or fail to
// authenticate when a passphrase IS configured.
func TestV3MsgFlags(t *testing.T) {
	tests := []struct {
		name string
		cfg  SNMPv3Config
		want gosnmp.SnmpV3MsgFlags
	}{
		{"auth_and_priv",
			SNMPv3Config{AuthPass: "x", PrivPass: "y"}, gosnmp.AuthPriv},
		{"auth_only",
			SNMPv3Config{AuthPass: "x"}, gosnmp.AuthNoPriv},
		{"no_auth_no_priv",
			SNMPv3Config{}, gosnmp.NoAuthNoPriv},
		// Edge: priv set without auth → still authPriv (v3MsgFlags checks
		// PrivPass first). This is documented behavior; the test pins it so
		// future refactors don't accidentally invert the order.
		{"priv_without_auth_still_authpriv",
			SNMPv3Config{PrivPass: "y"}, gosnmp.AuthPriv},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v3MsgFlags(&tt.cfg); got != tt.want {
				t.Errorf("v3MsgFlags(%+v) = %v, want %v", tt.cfg, got, tt.want)
			}
		})
	}
}

// TestV3AuthProto pins the auth-protocol mapping. Any silent default-fallback
// change (e.g. SHA → MD5) would weaken security across the entire fleet on
// the next deploy.
func TestV3AuthProto(t *testing.T) {
	tests := []struct {
		in   string
		want gosnmp.SnmpV3AuthProtocol
	}{
		{"MD5", gosnmp.MD5},
		{"SHA", gosnmp.SHA},
		{"SHA224", gosnmp.SHA224},
		{"SHA256", gosnmp.SHA256},
		{"SHA384", gosnmp.SHA384},
		{"SHA512", gosnmp.SHA512},
		// Case insensitivity (documented).
		{"sha256", gosnmp.SHA256},
		{"Md5", gosnmp.MD5},
		// Unknown → SHA (safe modern default, NOT NoAuth).
		{"", gosnmp.SHA},
		{"BLAKE3", gosnmp.SHA},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := v3AuthProto(tt.in); got != tt.want {
				t.Errorf("v3AuthProto(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestV3PrivProto pins the privacy-protocol mapping. Like the auth-protocol
// test, this prevents silent fallback to a weaker cipher (DES is broken).
func TestV3PrivProto(t *testing.T) {
	tests := []struct {
		in   string
		want gosnmp.SnmpV3PrivProtocol
	}{
		{"DES", gosnmp.DES},
		{"AES", gosnmp.AES},
		{"AES192", gosnmp.AES192},
		{"AES256", gosnmp.AES256},
		{"aes256", gosnmp.AES256},
		// Unknown → AES (modern default, NOT DES).
		{"", gosnmp.AES},
		{"3DES", gosnmp.AES},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := v3PrivProto(tt.in); got != tt.want {
				t.Errorf("v3PrivProto(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestNewSNMPClient_InvalidPort verifies the port-validation gate. Without
// this, an invalid port would be coerced to a uint16 and we'd silently
// connect to the wrong port (or 0).
func TestNewSNMPClient_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero", 0},
		{"negative", -1},
		{"over_max", 65536},
		{"huge", 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSNMPClient("127.0.0.1", tt.port, "public", "2c", nil)
			if err == nil {
				t.Errorf("NewSNMPClient(port=%d) returned nil error; want validation error", tt.port)
			}
		})
	}
}

// TestIfTypeNames_KnownVendorValues verifies the IANA ifType table covers
// the values the FortiGate / Palo Alto / pfSense fleets actually report.
// If this breaks, GetInterfaceStats would leave TypeName="" for known
// interfaces.
func TestIfTypeNames_KnownVendorValues(t *testing.T) {
	want := map[int]string{
		6:   "ethernet",    // physical NIC
		24:  "loopback",    // loopback iface
		53:  "propVirtual", // FortiGate VDOM / virtual link
		131: "tunnel",      // IPSec / GRE tunnel
		135: "l2vlan",      // 802.1Q VLAN
		161: "lag",         // LACP bond / FortiGate aggregate
	}
	for ifType, name := range want {
		got, ok := IfTypeNames[ifType]
		if !ok {
			t.Errorf("IfTypeNames[%d] missing — devices reporting ifType=%d would have empty TypeName", ifType, ifType)
			continue
		}
		if got != name {
			t.Errorf("IfTypeNames[%d] = %q, want %q", ifType, got, name)
		}
	}
}

// TestGetOrCreateVPN verifies the helper: first call creates a new entry,
// second call returns the SAME pointer so the parsers can accumulate
// fields. Pointer identity matters — every vendor's VPN parser walks the
// PDU list once and assumes name+remoteIP+bytes for the same index land
// on the same struct.
func TestGetOrCreateVPN(t *testing.T) {
	m := make(map[int]*relay.VPNStatus)

	first := getOrCreateVPN(m, 7)
	if first == nil {
		t.Fatal("first call returned nil")
	}
	first.TunnelName = "marker"

	second := getOrCreateVPN(m, 7)
	if second != first {
		t.Errorf("second call returned different pointer (%p vs %p) — parsers would lose accumulated fields", second, first)
	}
	if second.TunnelName != "marker" {
		t.Errorf("accumulated field lost: TunnelName = %q, want %q", second.TunnelName, "marker")
	}

	// Different index → different pointer.
	other := getOrCreateVPN(m, 8)
	if other == first {
		t.Errorf("getOrCreateVPN(8) returned same pointer as getOrCreateVPN(7) — index isolation broken")
	}
}

// TestGetOrCreateInterface verifies the value-semantics helper. Unlike the
// pointer helpers above, GetInterfaceStats uses value semantics for
// InterfaceStats (the caller MUST write the value back into the map after
// mutation). The test pins the contract: a fresh index returns a zero
// value with Index set; an existing index returns whatever's in the map.
func TestGetOrCreateInterface(t *testing.T) {
	m := make(map[int]relay.InterfaceStats)

	// Fresh index → zero value with Index set.
	got := getOrCreateInterface(m, 5)
	if got.Index != 5 {
		t.Errorf("fresh: Index = %d, want 5", got.Index)
	}
	if got.Name != "" {
		t.Errorf("fresh: Name = %q, want \"\"", got.Name)
	}

	// Existing index → returns the stored value (NOT a new zero).
	m[3] = relay.InterfaceStats{Index: 3, Name: "wan1"}
	got2 := getOrCreateInterface(m, 3)
	if got2.Name != "wan1" {
		t.Errorf("existing: Name = %q, want %q — accumulator overwrote existing entry", got2.Name, "wan1")
	}
}

// TestGetOrCreateSensor mirrors TestGetOrCreateVPN for the sensor helper
// (pointer-based accumulation). FortiGate's ParseHardwareSensors depends
// on it.
func TestGetOrCreateSensor(t *testing.T) {
	m := make(map[int]*relay.HardwareSensor)

	first := getOrCreateSensor(m, 1)
	first.Name = "DTS_CPU"

	second := getOrCreateSensor(m, 1)
	if second != first {
		t.Errorf("getOrCreateSensor: pointer identity broken (%p vs %p)", second, first)
	}
	if second.Name != "DTS_CPU" {
		t.Errorf("accumulated field lost: Name = %q", second.Name)
	}
}

// TestSNMPClient_Close_NilSafe verifies Close() does not panic when the
// underlying client is nil (called by collector cleanup paths even when
// the client failed to initialize).
func TestSNMPClient_Close_NilSafe(t *testing.T) {
	s := &SNMPClient{client: nil}
	if err := s.Close(); err != nil {
		t.Errorf("Close() on nil client returned error: %v", err)
	}
	s2 := &SNMPClient{client: &gosnmp.GoSNMP{}}
	if err := s2.Close(); err != nil {
		t.Errorf("Close() on client with nil Conn returned error: %v", err)
	}
}

func TestIPv4FromTableIndex(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.25.1", "192.168.25.1"},         // clean 4-octet (newer FortiOS)
		{"192.168.25.254.1", "192.168.25.254"},   // FortiOS quirk: extra .1 sub-index
		{"10.25.25.1.1", "10.25.25.1"},           // quirk on a low-octet IP
		{"205.207.224.142.1", "205.207.224.142"}, // quirk on a public IP
		{"169.254.1.1.1", "169.254.1.1"},         // quirk on link-local
		{"1.2.3", ""},                            // too short
		{"999.1.1.1", ""},                        // not a valid IPv4
		{"", ""},                                 // empty
	}
	for _, c := range cases {
		if got := ipv4FromTableIndex(c.in); got != c.want {
			t.Errorf("ipv4FromTableIndex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
