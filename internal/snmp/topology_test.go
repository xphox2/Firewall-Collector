package snmp

import (
	"fmt"
	"testing"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

func pduInt(oid string, v int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: v}
}

func pduBytes(oid string, b []byte) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: b}
}

func pduStr(oid, s string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(s)}
}

// TestParseIPNetToMedia: index is ifIndex.a.b.c.d; MACs come out canonical
// lowercase; multicast and malformed rows are dropped.
func TestParseIPNetToMedia(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		pduBytes(OIDIpNetToMediaPhys+".4.192.168.5.107", []byte{0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22}),
		pduBytes(OIDIpNetToMediaPhys+".7.10.0.0.1", []byte{0x00, 0x09, 0x0F, 0x09, 0x00, 0x02}),
		// multicast (I/G bit) — dropped
		pduBytes(OIDIpNetToMediaPhys+".4.224.0.0.5", []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x05}),
		// all-zero — dropped
		pduBytes(OIDIpNetToMediaPhys+".4.10.0.0.9", []byte{0, 0, 0, 0, 0, 0}),
		// malformed index — dropped
		pduBytes(OIDIpNetToMediaPhys+".4.192.168.5", []byte{0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x23}),
	}
	got := parseIPNetToMedia(pdus)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].IfIndex != 4 || got[0].IPAddress != "192.168.5.107" || got[0].MACAddress != "aa:bb:cc:00:11:22" {
		t.Errorf("row 0 wrong: %+v", got[0])
	}
	if got[1].MACAddress != "00:09:0f:09:00:02" {
		t.Errorf("MAC must be canonical lowercase, got %q", got[1].MACAddress)
	}
	for _, e := range got {
		if e.EntryType != "arp" {
			t.Errorf("entry type = %q, want arp", e.EntryType)
		}
	}
}

// TestParseIPNetToPhysical: RFC 4293 index carries addrType and (usually) the
// InetAddress length octet; both shapes parse, non-IPv4 rows are skipped.
func TestParseIPNetToPhysical(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		// standards shape: ifIndex.type(1).len(4).a.b.c.d
		pduBytes(OIDIpNetToPhysicalPhys+".2.1.4.10.1.1.5", []byte{0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x33}),
		// length-omitted shape: ifIndex.type(1).a.b.c.d
		pduBytes(OIDIpNetToPhysicalPhys+".3.1.10.1.1.6", []byte{0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x44}),
		// IPv6 (type 2) — skipped
		pduBytes(OIDIpNetToPhysicalPhys+".2.2.16.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16", []byte{0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x55}),
	}
	got := parseIPNetToPhysical(pdus)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].IfIndex != 2 || got[0].IPAddress != "10.1.1.5" {
		t.Errorf("standards-shape row wrong: %+v", got[0])
	}
	if got[1].IfIndex != 3 || got[1].IPAddress != "10.1.1.6" {
		t.Errorf("length-omitted row wrong: %+v", got[1])
	}
}

func fdbOID(base string, fdbID int, mac [6]byte) string {
	return fmt.Sprintf("%s.%d.%d.%d.%d.%d.%d.%d", base, fdbID, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// TestParseFDB_Dot1q: fdbId is treated as the VLAN, bridge ports resolve
// through dot1dBasePortIfIndex, only learned unicast entries survive.
func TestParseFDB_Dot1q(t *testing.T) {
	portToIfIndex := map[int]int{1: 9, 2: 10}
	mac1 := [6]byte{0xAA, 0xBB, 0xCC, 0x00, 0x22, 0x01}
	mac2 := [6]byte{0xAA, 0xBB, 0xCC, 0x00, 0x22, 0x02}
	mac3 := [6]byte{0xAA, 0xBB, 0xCC, 0x00, 0x22, 0x03}
	macMcast := [6]byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}

	ports := []gosnmp.SnmpPDU{
		pduInt(fdbOID(OIDDot1qTpFdbPort, 10, mac1), 1),
		pduInt(fdbOID(OIDDot1qTpFdbPort, 20, mac2), 2),
		pduInt(fdbOID(OIDDot1qTpFdbPort, 10, mac3), 1),                                        // status self → dropped
		pduInt(fdbOID(OIDDot1qTpFdbPort, 10, macMcast), 1),                                    // multicast → dropped
		pduInt(fdbOID(OIDDot1qTpFdbPort, 10, [6]byte{0xAA, 0xBB, 0xCC, 0x00, 0x22, 0x04}), 7), // unmapped bridge port → dropped
	}
	status := []gosnmp.SnmpPDU{
		pduInt(fdbOID(OIDDot1qTpFdbStatus, 10, mac1), 3), // learned
		// mac2 has no status row → treated as learned
		pduInt(fdbOID(OIDDot1qTpFdbStatus, 10, mac3), 4), // self
	}

	got := parseFDB(ports, status, OIDDot1qTpFdbPort, OIDDot1qTpFdbStatus, true, portToIfIndex)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].MACAddress != "aa:bb:cc:00:22:01" || got[0].IfIndex != 9 || got[0].VlanID != 10 {
		t.Errorf("row 0 wrong: %+v", got[0])
	}
	if got[1].MACAddress != "aa:bb:cc:00:22:02" || got[1].IfIndex != 10 || got[1].VlanID != 20 {
		t.Errorf("row 1 wrong: %+v", got[1])
	}
	for _, e := range got {
		if e.EntryType != "fdb" {
			t.Errorf("entry type = %q, want fdb", e.EntryType)
		}
	}
}

// TestParseFDB_Dot1dLegacy: the legacy table has no fdbId prefix and no VLAN.
func TestParseFDB_Dot1dLegacy(t *testing.T) {
	mac := [6]byte{0xAA, 0xBB, 0xCC, 0x00, 0x33, 0x01}
	oid := fmt.Sprintf("%s.%d.%d.%d.%d.%d.%d", OIDDot1dTpFdbPort, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	statusOID := fmt.Sprintf("%s.%d.%d.%d.%d.%d.%d", OIDDot1dTpFdbStatus, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])

	got := parseFDB(
		[]gosnmp.SnmpPDU{pduInt(oid, 2)},
		[]gosnmp.SnmpPDU{pduInt(statusOID, 3)},
		OIDDot1dTpFdbPort, OIDDot1dTpFdbStatus, false, map[int]int{2: 5})
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].MACAddress != "aa:bb:cc:00:33:01" || got[0].IfIndex != 5 || got[0].VlanID != 0 {
		t.Errorf("row wrong: %+v", got[0])
	}
}

// TestParseLLDPRemTable: chassis MAC subtype renders lowercase-colon, local
// port names resolve through lldpLocPortTable, control characters in
// neighbor-controlled strings are stripped.
func TestParseLLDPRemTable(t *testing.T) {
	rem := []gosnmp.SnmpPDU{
		pduInt(OIDLldpRemChassisIdSubtype+".0.3.1", 4), // macAddress
		pduBytes(OIDLldpRemChassisId+".0.3.1", []byte{0xAA, 0xBB, 0xCC, 0x00, 0x44, 0x01}),
		pduInt(OIDLldpRemPortIdSubtype+".0.3.1", 5), // interfaceName
		pduStr(OIDLldpRemPortId+".0.3.1", "port7"),
		pduStr(OIDLldpRemPortDesc+".0.3.1", "uplink"),
		pduStr(OIDLldpRemSysName+".0.3.1", "fw-branch\x1b[31m"), // control chars stripped
		pduStr(OIDLldpRemSysDesc+".0.3.1", "FortiGate-60F"),
	}
	loc := []gosnmp.SnmpPDU{
		pduStr(OIDLldpLocPortId+".3", "internal3"),
		pduStr(OIDLldpLocPortDesc+".3", "lan-side"),
	}

	got := parseLLDPRemTable(rem, loc)
	if len(got) != 1 {
		t.Fatalf("got %d neighbors, want 1", len(got))
	}
	n := got[0]
	if n.Protocol != "lldp" || n.LocalIfIndex != 3 {
		t.Errorf("protocol/local port wrong: %+v", n)
	}
	if n.LocalPortName != "lan-side" {
		t.Errorf("LocalPortName = %q, want lldpLocPortDesc value", n.LocalPortName)
	}
	if n.RemoteChassisID != "aa:bb:cc:00:44:01" {
		t.Errorf("chassis MAC not canonical lowercase: %q", n.RemoteChassisID)
	}
	if n.RemotePortID != "port7" || n.RemotePortDesc != "uplink" {
		t.Errorf("port id/desc wrong: %+v", n)
	}
	if n.RemoteSysName != "fw-branch[31m" {
		t.Errorf("control characters not stripped: %q", n.RemoteSysName)
	}
}

// TestCapCombinedTopology: the combined cap truncates FDB first and preserves
// ARP — a partial FDB still attributes ports, ARP evidence is irreplaceable.
func TestCapCombinedTopology(t *testing.T) {
	mkEntries := func(n int, typ string) []relay.TopologyEntry {
		out := make([]relay.TopologyEntry, n)
		for i := range out {
			out[i] = relay.TopologyEntry{EntryType: typ}
		}
		return out
	}

	// Under cap: nothing dropped, ARP rows first.
	merged, dropped := CapCombinedTopology(mkEntries(10, "arp"), mkEntries(20, "fdb"))
	if len(merged) != 30 || dropped != 0 {
		t.Fatalf("under cap: len=%d dropped=%d", len(merged), dropped)
	}

	// FDB overflows: truncated to the remaining room, ARP intact.
	merged, dropped = CapCombinedTopology(mkEntries(1000, "arp"), mkEntries(MaxTopologyEntriesPerDevice, "fdb"))
	if len(merged) != MaxTopologyEntriesPerDevice || dropped != 1000 {
		t.Fatalf("fdb overflow: len=%d dropped=%d", len(merged), dropped)
	}
	arpCount := 0
	for _, e := range merged {
		if e.EntryType == "arp" {
			arpCount++
		}
	}
	if arpCount != 1000 {
		t.Fatalf("ARP rows lost to the cap: %d/1000 kept", arpCount)
	}

	// ARP alone overflows: capped too.
	merged, dropped = CapCombinedTopology(mkEntries(MaxTopologyEntriesPerDevice+5, "arp"), mkEntries(3, "fdb"))
	if len(merged) != MaxTopologyEntriesPerDevice || dropped != 8 {
		t.Fatalf("arp overflow: len=%d dropped=%d", len(merged), dropped)
	}
}

// TestTopologyVendorConformance: every supported vendor resolves to a profile
// and runs the SHARED standard-MIB topology parsers (empty walks stay empty,
// no per-vendor code); cisco_asa is the only CDPProvider and parses its cache.
func TestTopologyVendorConformance(t *testing.T) {
	vendors := []string{"fortigate", "paloalto", "cisco_asa", "sonicwall", "firewalla", "pfsense", "opnsense", "generic"}
	for _, v := range vendors {
		t.Run(v, func(t *testing.T) {
			profile := GetVendorProfile(v)
			if profile == nil {
				t.Fatalf("vendor %q has no registered profile", v)
			}
			_, isCDP := profile.(CDPProvider)
			if isCDP != (v == "cisco_asa") {
				t.Fatalf("CDPProvider mismatch for %q: got %v", v, isCDP)
			}
			// The topology walks are vendor-neutral: empty PDU sets parse to
			// empty results for every vendor (devices without BRIDGE/LLDP MIBs
			// must be silent, not erroring).
			if got := parseIPNetToMedia(nil); len(got) != 0 {
				t.Errorf("empty ARP walk produced %d entries", len(got))
			}
			if got := parseFDB(nil, nil, OIDDot1qTpFdbPort, OIDDot1qTpFdbStatus, true, nil); len(got) != 0 {
				t.Errorf("empty FDB walk produced %d entries", len(got))
			}
			if got := parseLLDPRemTable(nil, nil); len(got) != 0 {
				t.Errorf("empty LLDP walk produced %d neighbors", len(got))
			}
		})
	}
}

// TestParseCDPNeighbors: cdpCache rows resolve local ifIndex from the index,
// carry the device id as chassis/sysname (CDP has no chassis-MAC TLV).
func TestParseCDPNeighbors(t *testing.T) {
	profile := GetVendorProfile("cisco_asa").(CDPProvider)
	base := profile.CDPCacheBaseOID()
	pdus := []gosnmp.SnmpPDU{
		pduBytes(base+".4.5.1", []byte{10, 1, 1, 2}),   // cdpCacheAddress
		pduStr(base+".6.5.1", "core-switch.lab"),       // cdpCacheDeviceId
		pduStr(base+".7.5.1", "GigabitEthernet1/0/24"), // cdpCacheDevicePort
		pduStr(base+".8.5.1", "cisco WS-C3750X-48"),    // cdpCachePlatform
	}
	got := profile.ParseCDPNeighbors(pdus)
	if len(got) != 1 {
		t.Fatalf("got %d neighbors, want 1", len(got))
	}
	n := got[0]
	if n.Protocol != "cdp" || n.LocalIfIndex != 5 {
		t.Errorf("protocol/ifIndex wrong: %+v", n)
	}
	if n.RemoteSysName != "core-switch.lab" || n.RemotePortID != "GigabitEthernet1/0/24" {
		t.Errorf("identity wrong: %+v", n)
	}
	if n.RemoteCaps != "10.1.1.2" {
		t.Errorf("address = %q, want 10.1.1.2", n.RemoteCaps)
	}
}
