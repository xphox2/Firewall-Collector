package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// Canned Get response for the ASA SystemOIDs set (conformance fixture).
func asaSystemFixture() []gosnmp.SnmpPDU {
	return []gosnmp.SnmpPDU{
		{Name: asaOIDSysName, Type: gosnmp.OctetString, Value: "asa-branch-01"},
		{Name: asaOIDSysDescr, Type: gosnmp.OctetString, Value: "Cisco Adaptive Security Appliance Version 9.16(4)8"},
		{Name: asaOIDSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(360000)}, // 360000 raw hundredths (AUDIT-220)
		{Name: asaOIDCpu1MinFirst, Type: gosnmp.Gauge32, Value: uint(17)},
		{Name: asaOIDMemPoolUsed, Type: gosnmp.Gauge32, Value: uint(1073741824)}, // 1 GiB used
		{Name: asaOIDMemPoolFree, Type: gosnmp.Gauge32, Value: uint(3221225472)}, // 3 GiB free
		{Name: asaOIDConnCurrent, Type: gosnmp.Gauge32, Value: uint(12345)},
	}
}

func TestCiscoASA_ParseSystemStatus(t *testing.T) {
	p := GetVendorProfile("cisco_asa")
	if p == nil {
		t.Fatal("cisco_asa profile not registered")
	}

	status := p.ParseSystemStatus(asaSystemFixture())
	if status.Hostname != "asa-branch-01" {
		t.Errorf("Hostname = %q, want asa-branch-01", status.Hostname)
	}
	if status.Version != "ASA 9.16(4)8" {
		t.Errorf("Version = %q, want ASA 9.16(4)8", status.Version)
	}
	if status.Uptime != 360000 { // AUDIT-220: raw hundredths, not seconds
		t.Errorf("Uptime = %d, want 360000", status.Uptime)
	}
	if status.CPUUsage != 17 {
		t.Errorf("CPUUsage = %v, want 17", status.CPUUsage)
	}
	if status.MemoryTotal != 4096 { // (1+3) GiB in MB
		t.Errorf("MemoryTotal = %d MB, want 4096", status.MemoryTotal)
	}
	if status.MemoryUsage != 25 {
		t.Errorf("MemoryUsage = %v%%, want 25", status.MemoryUsage)
	}
	if status.SessionCount != 12345 {
		t.Errorf("SessionCount = %d, want 12345", status.SessionCount)
	}
}

// An agent that lacks CISCO-FIREWALL-MIB connection stats answers
// NoSuchInstance — the parser must skip it, not record garbage.
func TestCiscoASA_ParseSystemStatus_MissingConnStat(t *testing.T) {
	p := GetVendorProfile("cisco_asa")
	pdus := []gosnmp.SnmpPDU{
		{Name: asaOIDSysName, Type: gosnmp.OctetString, Value: "asa-01"},
		{Name: asaOIDConnCurrent, Type: gosnmp.NoSuchInstance, Value: nil},
		{Name: asaOIDCpu1MinFirst, Type: gosnmp.NoSuchInstance, Value: nil},
	}
	status := p.ParseSystemStatus(pdus)
	if status.SessionCount != 0 {
		t.Errorf("SessionCount = %d, want 0 for NoSuchInstance", status.SessionCount)
	}
	if status.CPUUsage != 0 {
		t.Errorf("CPUUsage = %v, want 0 for NoSuchInstance", status.CPUUsage)
	}
}

func TestCiscoASA_ParseProcessorStats_Prefers1MinRev(t *testing.T) {
	p := GetVendorProfile("cisco_asa")
	pdus := []gosnmp.SnmpPDU{
		{Name: asaOIDCpu1MinRev + ".1", Type: gosnmp.Gauge32, Value: uint(10)},
		{Name: asaOIDCpu5MinRev + ".1", Type: gosnmp.Gauge32, Value: uint(50)}, // ignored: 1-min present
		{Name: asaOIDCpu5MinRev + ".2", Type: gosnmp.Gauge32, Value: uint(20)}, // used: no 1-min for idx 2
	}
	procs := p.ParseProcessorStats(pdus)
	if len(procs) != 2 {
		t.Fatalf("got %d processors, want 2", len(procs))
	}
	byIdx := map[int]float64{}
	for _, pr := range procs {
		byIdx[pr.Index] = pr.Usage
	}
	if byIdx[1] != 10 {
		t.Errorf("cpu 1 usage = %v, want 10 (1-min rev preferred over 5-min)", byIdx[1])
	}
	if byIdx[2] != 20 {
		t.Errorf("cpu 2 usage = %v, want 20 (5-min fallback)", byIdx[2])
	}
}

func TestCiscoASA_ParseHAStatus_FailoverPair(t *testing.T) {
	p := GetVendorProfile("cisco_asa")
	haProvider, ok := p.(HAProvider)
	if !ok {
		t.Fatal("cisco_asa profile must implement HAProvider")
	}
	if len(haProvider.HAScalarOIDs()) == 0 {
		t.Fatal("HAScalarOIDs must be non-empty or GetHAStatus skips ASA failover polling")
	}

	scalars := []gosnmp.SnmpPDU{
		{Name: asaOIDFailoverInfo + ".6", Type: gosnmp.OctetString, Value: "Failover LAN Interface"},
		{Name: asaOIDFailoverValue + ".6", Type: gosnmp.Integer, Value: 9}, // active
		{Name: asaOIDFailoverDetail + ".6", Type: gosnmp.OctetString, Value: "Active unit"},
		{Name: asaOIDFailoverInfo + ".7", Type: gosnmp.OctetString, Value: "Secondary unit"},
		{Name: asaOIDFailoverValue + ".7", Type: gosnmp.Integer, Value: 10}, // standby
		{Name: asaOIDFailoverDetail + ".7", Type: gosnmp.OctetString, Value: "Standby unit"},
	}
	// Table walk also returns non-failover hardware rows — must be ignored.
	members := []gosnmp.SnmpPDU{
		{Name: asaOIDFailoverValue + ".4", Type: gosnmp.Integer, Value: 2}, // power supply row
	}

	result := haProvider.ParseHAStatus(scalars, members)
	if len(result) != 2 {
		t.Fatalf("got %d HA members, want 2", len(result))
	}
	primary, secondary := result[0], result[1]
	if primary.MemberIndex != 1 || secondary.MemberIndex != 2 {
		t.Errorf("member indices = %d/%d, want 1/2", primary.MemberIndex, secondary.MemberIndex)
	}
	if primary.SystemMode != "failover" {
		t.Errorf("SystemMode = %q, want failover", primary.SystemMode)
	}
	if primary.SyncStatus != "active (Active unit)" {
		t.Errorf("primary SyncStatus = %q, want %q", primary.SyncStatus, "active (Active unit)")
	}
	if secondary.SyncStatus != "standby (Standby unit)" {
		t.Errorf("secondary SyncStatus = %q, want %q", secondary.SyncStatus, "standby (Standby unit)")
	}
}

func TestCiscoASA_ParseHAStatus_StandaloneReturnsNil(t *testing.T) {
	p := GetVendorProfile("cisco_asa")
	haProvider := p.(HAProvider)

	// Standalone unit: the scalar Gets answer NoSuchInstance.
	scalars := []gosnmp.SnmpPDU{
		{Name: asaOIDFailoverValue + ".6", Type: gosnmp.NoSuchInstance, Value: nil},
		{Name: asaOIDFailoverValue + ".7", Type: gosnmp.NoSuchInstance, Value: nil},
	}
	if got := haProvider.ParseHAStatus(scalars, nil); len(got) != 0 {
		t.Errorf("ParseHAStatus(standalone) = %v, want empty", got)
	}
	if got := haProvider.ParseHAStatus(nil, nil); len(got) != 0 {
		t.Errorf("ParseHAStatus(nil, nil) = %v, want empty", got)
	}
}

// VPN, sensors, and enterprise traps are deliberately omitted (see the OID
// block comment) — they must signal unsupported, not fall through to garbage.
func TestCiscoASA_DeliberateOmissions(t *testing.T) {
	p := GetVendorProfile("cisco_asa")
	if oid := p.VPNBaseOID(); oid != "" {
		t.Errorf("VPNBaseOID = %q, want empty (deliberately omitted)", oid)
	}
	if oid := p.HWSensorBaseOID(); oid != "" {
		t.Errorf("HWSensorBaseOID = %q, want empty (deliberately omitted)", oid)
	}
	if defs := p.TrapOIDs(); len(defs) != 0 {
		t.Errorf("TrapOIDs = %v, want none (deliberately omitted)", defs)
	}
	if _, ok := p.(SecurityStatsProvider); ok {
		t.Error("cisco_asa must not implement SecurityStatsProvider (no standard ASA MIB objects)")
	}
	if _, ok := p.(SDWANProvider); ok {
		t.Error("cisco_asa must not implement SDWANProvider")
	}
	if _, ok := p.(LicenseProvider); ok {
		t.Error("cisco_asa must not implement LicenseProvider")
	}
}
