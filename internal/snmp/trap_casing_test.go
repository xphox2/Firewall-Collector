package snmp

import (
	"strings"
	"testing"
)

// TestLookupTrapOID_NormalizesCase: the Palo Alto and SonicWall profiles spell
// their trap types in lower-kebab form (`ha-state-change`), but the server's
// alert types, per-type policy lookup and seeded trap rules (`trap_type eq
// HA_STATE_CHANGE`) all use the upper-snake form the FortiGate profile has
// always used. lookupTrapOID is the one place every classified trap passes
// through, so it returns the canonical name whatever the profile wrote.
// Pre-1.3.49 a PAN HA transition was sent as `ha-state-change`, which matched
// no alert type and no seed on a pre-0.11.291 server.
func TestLookupTrapOID_NormalizesCase(t *testing.T) {
	const want = "HA_STATE_CHANGE"
	for _, tc := range []struct{ vendor, oid, severity string }{
		{"paloalto", ".1.3.6.1.4.1.25461.2.1.3.2.0.801", "warning"},
		{"sonicwall", ".1.3.6.1.4.1.8741.1.1.2.0.126", "warning"},
		{"fortigate", fgTrapHAStateChange, "warning"},
	} {
		got, sev := lookupTrapOID(tc.oid)
		if got != want {
			t.Errorf("%s %s: lookupTrapOID type = %q, want %q (the HA_STATE_CHANGE seed rule and alert type)", tc.vendor, tc.oid, got, want)
		}
		if sev != tc.severity {
			t.Errorf("%s %s: severity = %q, want %q", tc.vendor, tc.oid, sev, tc.severity)
		}
	}
	// The PAN VPN trap lands on the shared VPN_TUNNEL_DOWN alert type too.
	if got, _ := lookupTrapOID(".1.3.6.1.4.1.25461.2.1.3.2.0.1747"); got != "VPN_TUNNEL_DOWN" {
		t.Errorf("paloalto vpn-tunnel-down = %q, want VPN_TUNNEL_DOWN", got)
	}
}

// TestNormalizeTrapType covers the helper: upper-case, `-` to `_`, trimmed;
// already canonical names and empty input pass through unchanged.
func TestNormalizeTrapType(t *testing.T) {
	for in, want := range map[string]string{
		"ha-state-change":   "HA_STATE_CHANGE",
		" vpn-tunnel-down ": "VPN_TUNNEL_DOWN",
		"HA_MEMBER_DOWN":    "HA_MEMBER_DOWN",
		"LINK_DOWN":         "LINK_DOWN",
		"":                  "",
	} {
		if got := NormalizeTrapType(in); got != want {
			t.Errorf("NormalizeTrapType(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRegisteredTrapTypes_AllCanonical: with the lookup normalizing, no
// registered profile can leak a non-canonical name through the trap receiver.
// Pinned over the whole registry so a new profile with a `-` in a trap name
// is still fine (it is normalized), while a `.` or a space — which the
// normalizer does not touch — is caught here.
func TestRegisteredTrapTypes_AllCanonical(t *testing.T) {
	vendorMu.RLock()
	defer vendorMu.RUnlock()
	for name, p := range vendorRegistry {
		for oid, def := range p.TrapOIDs() {
			got := NormalizeTrapType(def.Type)
			if got == "" || got != strings.ToUpper(got) || strings.ContainsAny(got, "-. ") {
				t.Errorf("%s %s: trap type %q normalizes to %q, which is not an alert-type name", name, oid, def.Type, got)
			}
		}
	}
}
