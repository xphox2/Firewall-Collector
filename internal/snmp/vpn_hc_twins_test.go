package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// TestBSDVPN_UsesHC64BitOctets guards the AUDIT-221 twin fix for pfSense/OPNsense
// (parseBSDVPNFromInterfaces): 64-bit HC octet counters win over the 32-bit
// ifTable values for a WireGuard/OpenVPN/IPSec interface.
func TestBSDVPN_UsesHC64BitOctets(t *testing.T) {
	const idx = "4"
	const hcIn = uint64(9_500_000_000)
	const hcOut = uint64(10_500_000_000)
	pdus := []gosnmp.SnmpPDU{
		{Name: OIDIfDescr + "." + idx, Type: gosnmp.OctetString, Value: []byte("wg0")},
		{Name: OIDIfOperStatus + "." + idx, Type: gosnmp.Integer, Value: 1},
		{Name: OIDIfInOctets + "." + idx, Type: gosnmp.Counter32, Value: uint(910_032_704)},
		{Name: OIDIfOutOctets + "." + idx, Type: gosnmp.Counter32, Value: uint(1_910_065_408)},
		{Name: OIDIfHCInOctets + "." + idx, Type: gosnmp.Counter64, Value: hcIn},
		{Name: OIDIfHCOutOctets + "." + idx, Type: gosnmp.Counter64, Value: hcOut},
	}
	result := parseBSDVPNFromInterfaces(pdus)
	if len(result) != 1 {
		t.Fatalf("got %d statuses; want 1", len(result))
	}
	if result[0].BytesIn != hcIn || result[0].BytesOut != hcOut {
		t.Errorf("BytesIn/Out = %d/%d; want HC %d/%d", result[0].BytesIn, result[0].BytesOut, hcIn, hcOut)
	}
}

// TestLinuxVPN_UsesHC64BitOctets guards the AUDIT-221 twin fix for Firewalla
// (parseLinuxVPNFromInterfaces).
func TestLinuxVPN_UsesHC64BitOctets(t *testing.T) {
	const idx = "6"
	const hcIn = uint64(8_800_000_000)
	const hcOut = uint64(13_300_000_000)
	pdus := []gosnmp.SnmpPDU{
		{Name: OIDIfDescr + "." + idx, Type: gosnmp.OctetString, Value: []byte("vti0")},
		{Name: OIDIfOperStatus + "." + idx, Type: gosnmp.Integer, Value: 1},
		{Name: OIDIfInOctets + "." + idx, Type: gosnmp.Counter32, Value: uint(210_065_408)},
		{Name: OIDIfOutOctets + "." + idx, Type: gosnmp.Counter32, Value: uint(4_005_032_704)},
		{Name: OIDIfHCInOctets + "." + idx, Type: gosnmp.Counter64, Value: hcIn},
		{Name: OIDIfHCOutOctets + "." + idx, Type: gosnmp.Counter64, Value: hcOut},
	}
	result := parseLinuxVPNFromInterfaces(pdus)
	if len(result) != 1 {
		t.Fatalf("got %d statuses; want 1", len(result))
	}
	if result[0].BytesIn != hcIn || result[0].BytesOut != hcOut {
		t.Errorf("BytesIn/Out = %d/%d; want HC %d/%d", result[0].BytesIn, result[0].BytesOut, hcIn, hcOut)
	}
}
