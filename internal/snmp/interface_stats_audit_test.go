package snmp

import (
	"testing"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// TestApplyIfXTable_HC64BitUcastWins is the AUDIT-294 regression: the 64-bit HC
// ucast packet counters from ifXTable must overwrite the 32-bit ifTable values,
// so busy links don't report packet counts wrapped at 4 Gpkt. It also confirms
// the adjacent HC-octet byte branches are untouched.
func TestApplyIfXTable_HC64BitUcastWins(t *testing.T) {
	const idx = 3
	// Seed the map as the base ifTable walk would: 32-bit packet + byte counters.
	interfaces := map[int]relay.InterfaceStats{
		idx: {InPackets: 100, OutPackets: 200, InBytes: 1, OutBytes: 2},
	}

	const hcInPkts = uint64(5_000_000_000)  // > 4 Gpkt
	const hcOutPkts = uint64(6_000_000_000) // > 4 Gpkt
	const hcInBytes = uint64(9_000_000_000)
	const hcOutBytes = uint64(12_000_000_000)

	xPdus := []gosnmp.SnmpPDU{
		{Name: OIDIfHCInUcastPkts + ".3", Type: gosnmp.Counter64, Value: hcInPkts},
		{Name: OIDIfHCOutUcastPkts + ".3", Type: gosnmp.Counter64, Value: hcOutPkts},
		{Name: OIDIfHCInOctets + ".3", Type: gosnmp.Counter64, Value: hcInBytes},
		{Name: OIDIfHCOutOctets + ".3", Type: gosnmp.Counter64, Value: hcOutBytes},
	}

	applyIfXTablePDUs(interfaces, xPdus)

	got := interfaces[idx]
	if got.InPackets != hcInPkts {
		t.Errorf("InPackets = %d; want HC %d", got.InPackets, hcInPkts)
	}
	if got.OutPackets != hcOutPkts {
		t.Errorf("OutPackets = %d; want HC %d", got.OutPackets, hcOutPkts)
	}
	if got.InBytes != hcInBytes {
		t.Errorf("InBytes = %d; want HC %d (octet branch must be undisturbed)", got.InBytes, hcInBytes)
	}
	if got.OutBytes != hcOutBytes {
		t.Errorf("OutBytes = %d; want HC %d (octet branch must be undisturbed)", got.OutBytes, hcOutBytes)
	}
}

// TestApplyPVIDs_ResolvesBasePortToIfIndex is the AUDIT-295 regression: dot1qPvid
// is indexed by dot1dBasePort, which need not equal ifIndex. With divergent
// numbering the PVID must attach to the resolved ifIndex, not the raw base port.
func TestApplyPVIDs_ResolvesBasePortToIfIndex(t *testing.T) {
	// basePort 1 -> ifIndex 10, basePort 2 -> ifIndex 20 (deliberately divergent).
	interfaces := map[int]relay.InterfaceStats{
		10: {Name: "port1"},
		20: {Name: "port2"},
	}
	basePortPdus := []gosnmp.SnmpPDU{
		{Name: OIDdot1dBasePortIfIndex + ".1", Type: gosnmp.Integer, Value: 10},
		{Name: OIDdot1dBasePortIfIndex + ".2", Type: gosnmp.Integer, Value: 20},
	}
	vlanPdus := []gosnmp.SnmpPDU{
		{Name: OIDdot1qPvid + ".1", Type: gosnmp.Gauge32, Value: uint(100)},
		{Name: OIDdot1qPvid + ".2", Type: gosnmp.Gauge32, Value: uint(200)},
	}

	applyPVIDs(interfaces, vlanPdus, basePortPdus)

	if got := interfaces[10].VLANID; got != 100 {
		t.Errorf("ifIndex 10 VLANID = %d; want 100 (basePort 1 resolves here)", got)
	}
	if got := interfaces[20].VLANID; got != 200 {
		t.Errorf("ifIndex 20 VLANID = %d; want 200 (basePort 2 resolves here)", got)
	}
	// The raw base-port indices (1, 2) must never have been touched.
	if _, ok := interfaces[1]; ok {
		t.Error("VLAN mis-attributed to raw base port 1 instead of ifIndex 10")
	}
}

// TestApplyPVIDs_SkipsUnmappedPortWhenTablePresent verifies that a base port not
// in the mapping table is skipped (safer than mis-attribution) rather than
// falling through to the raw index.
func TestApplyPVIDs_SkipsUnmappedPortWhenTablePresent(t *testing.T) {
	interfaces := map[int]relay.InterfaceStats{5: {Name: "port"}}
	basePortPdus := []gosnmp.SnmpPDU{
		{Name: OIDdot1dBasePortIfIndex + ".1", Type: gosnmp.Integer, Value: 10},
	}
	// PVID for base port 5, which has no mapping entry.
	vlanPdus := []gosnmp.SnmpPDU{
		{Name: OIDdot1qPvid + ".5", Type: gosnmp.Gauge32, Value: uint(300)},
	}
	applyPVIDs(interfaces, vlanPdus, basePortPdus)
	if got := interfaces[5].VLANID; got != 0 {
		t.Errorf("unmapped base port should be skipped; VLANID = %d, want 0", got)
	}
}

// TestApplyPVIDs_FallsBackWhenNoMappingTable verifies the no-regression path:
// when the device exposes no dot1dBasePortIfIndex table at all, the PVID index
// is treated as the ifIndex (pre-AUDIT-295 behavior).
func TestApplyPVIDs_FallsBackWhenNoMappingTable(t *testing.T) {
	interfaces := map[int]relay.InterfaceStats{4: {Name: "port"}}
	vlanPdus := []gosnmp.SnmpPDU{
		{Name: OIDdot1qPvid + ".4", Type: gosnmp.Gauge32, Value: uint(400)},
	}
	applyPVIDs(interfaces, vlanPdus, nil)
	if got := interfaces[4].VLANID; got != 400 {
		t.Errorf("fallback VLANID = %d; want 400", got)
	}
}

// TestIfTypeNames_GreAndBridge is the AUDIT-293 parity regression.
func TestIfTypeNames_GreAndBridge(t *testing.T) {
	if got := IfTypeNames[47]; got != "gre" {
		t.Errorf("IfTypeNames[47] = %q; want gre", got)
	}
	if got := IfTypeNames[209]; got != "bridge" {
		t.Errorf("IfTypeNames[209] = %q; want bridge", got)
	}
}
