package snmp

import (
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// The generic profile is standards-only: every OID it asks a device for must
// live under the standard mgmt.mib-2 subtree (1.3.6.1.2.1) — no enterprise
// OIDs (1.3.6.1.4.1.*), which is the whole point of the profile.
func TestGeneric_StandardsOnlyOIDs(t *testing.T) {
	p := GetVendorProfile("generic")
	if p == nil {
		t.Fatal("generic profile not registered")
	}

	var oids []string
	oids = append(oids, p.SystemOIDs()...)
	for _, b := range []string{p.VPNBaseOID(), p.HWSensorBaseOID(), p.ProcessorBaseOID()} {
		if b != "" {
			oids = append(oids, b)
		}
	}
	for _, oid := range oids {
		if !strings.HasPrefix(oid, ".1.3.6.1.2.1.") {
			t.Errorf("generic profile OID %s is not under mib-2 (.1.3.6.1.2.1) — enterprise OIDs are forbidden in the generic profile", oid)
		}
	}
}

func TestGeneric_ParseSystemStatus(t *testing.T) {
	p := GetVendorProfile("generic")
	if p == nil {
		t.Fatal("generic profile not registered")
	}

	pdus := []gosnmp.SnmpPDU{
		{Name: genOIDSysName, Type: gosnmp.OctetString, Value: "edge-fw-01"},
		{Name: genOIDSysDescr, Type: gosnmp.OctetString, Value: "Acme Router OS 4.2 build 1234"},
		{Name: genOIDSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(8640000)}, // 86400 s
		{Name: genOIDHrMemorySize, Type: gosnmp.Integer, Value: 4194304},        // KB → 4096 MB
	}

	status := p.ParseSystemStatus(pdus)
	if status.Hostname != "edge-fw-01" {
		t.Errorf("Hostname = %q, want edge-fw-01", status.Hostname)
	}
	if status.Version != "Acme Router OS 4.2 build 1234" {
		t.Errorf("Version = %q", status.Version)
	}
	if status.Uptime != 8640000 { // AUDIT-220: raw hundredths, not seconds
		t.Errorf("Uptime = %d, want 8640000", status.Uptime)
	}
	if status.MemoryTotal != 4096 {
		t.Errorf("MemoryTotal = %d MB, want 4096", status.MemoryTotal)
	}
	// No standard scalar exists for these — must stay zero, not garbage.
	if status.CPUUsage != 0 || status.MemoryUsage != 0 || status.SessionCount != 0 {
		t.Errorf("CPUUsage/MemoryUsage/SessionCount = %v/%v/%v, want all zero (unsupported)",
			status.CPUUsage, status.MemoryUsage, status.SessionCount)
	}
}

func TestGeneric_ParseSystemStatus_SkipsSNMPExceptions(t *testing.T) {
	p := GetVendorProfile("generic")
	pdus := []gosnmp.SnmpPDU{
		{Name: genOIDSysName, Type: gosnmp.OctetString, Value: "host"},
		{Name: genOIDHrMemorySize, Type: gosnmp.NoSuchObject, Value: nil}, // agent without HOST-RESOURCES
	}
	status := p.ParseSystemStatus(pdus)
	if status.MemoryTotal != 0 {
		t.Errorf("MemoryTotal = %d, want 0 when hrMemorySize is NoSuchObject", status.MemoryTotal)
	}
	if status.Hostname != "host" {
		t.Errorf("Hostname = %q, want host", status.Hostname)
	}
}

func TestGeneric_ParseProcessorStats_HrProcessorLoad(t *testing.T) {
	p := GetVendorProfile("generic")
	pdus := []gosnmp.SnmpPDU{
		{Name: genOIDProcessorLoad + ".196608", Type: gosnmp.Integer, Value: 12},
		{Name: genOIDProcessorLoad + ".196609", Type: gosnmp.Integer, Value: 34},
		{Name: genBaseOIDProcessor + ".1.196608", Type: gosnmp.Integer, Value: 196608}, // hrProcessorFrwID col — ignored
	}
	procs := p.ParseProcessorStats(pdus)
	if len(procs) != 2 {
		t.Fatalf("got %d processors, want 2", len(procs))
	}
	byIdx := map[int]float64{}
	for _, pr := range procs {
		byIdx[pr.Index] = pr.Usage
	}
	if byIdx[196608] != 12 || byIdx[196609] != 34 {
		t.Errorf("processor loads = %v, want {196608:12, 196609:34}", byIdx)
	}
}

// Vendor-specific metric families siblings populate must be cleanly absent:
// empty base OIDs, nil parse results, and none of the optional provider
// interfaces implemented.
func TestGeneric_UnsupportedMetricFamilies(t *testing.T) {
	p := GetVendorProfile("generic")
	if p == nil {
		t.Fatal("generic profile not registered")
	}
	if oid := p.VPNBaseOID(); oid != "" {
		t.Errorf("VPNBaseOID = %q, want empty (unsupported)", oid)
	}
	if oid := p.HWSensorBaseOID(); oid != "" {
		t.Errorf("HWSensorBaseOID = %q, want empty (unsupported)", oid)
	}
	if defs := p.TrapOIDs(); len(defs) != 0 {
		t.Errorf("TrapOIDs = %v, want none", defs)
	}
	if got := p.ParseVPNStatus(nil); len(got) != 0 {
		t.Errorf("ParseVPNStatus = %v, want empty", got)
	}
	if got := p.ParseHardwareSensors(nil); len(got) != 0 {
		t.Errorf("ParseHardwareSensors = %v, want empty", got)
	}
	// Optional providers must NOT be implemented — GetHAStatus/GetSecurityStats
	// etc. skip vendors that don't type-assert to the provider interfaces.
	if _, ok := p.(HAProvider); ok {
		t.Error("generic profile must not implement HAProvider")
	}
	if _, ok := p.(SecurityStatsProvider); ok {
		t.Error("generic profile must not implement SecurityStatsProvider")
	}
	if _, ok := p.(DialupVPNProvider); ok {
		t.Error("generic profile must not implement DialupVPNProvider")
	}
	if _, ok := p.(SSLVPNProvider); ok {
		t.Error("generic profile must not implement SSLVPNProvider")
	}
	if _, ok := p.(SDWANProvider); ok {
		t.Error("generic profile must not implement SDWANProvider")
	}
	if _, ok := p.(LicenseProvider); ok {
		t.Error("generic profile must not implement LicenseProvider")
	}
}

// resolveVendor fallback semantics: empty/legacy vendor stays FortiGate
// (load-bearing default), unknown strings resolve to generic — never to
// FortiGate enterprise OIDs.
func TestResolveVendor_FallbackSemantics(t *testing.T) {
	s := &SNMPClient{} // resolveVendor does not touch connection state

	if got := s.resolveVendor("").Name(); got != "fortigate" {
		t.Errorf("resolveVendor(\"\") = %q, want fortigate (load-bearing legacy default)", got)
	}
	if got := s.resolveVendor("no-such-vendor").Name(); got != "generic" {
		t.Errorf("resolveVendor(unknown) = %q, want generic", got)
	}
	for _, v := range []string{"fortigate", "paloalto", "cisco_asa", "sonicwall", "firewalla", "pfsense", "opnsense", "generic"} {
		if got := s.resolveVendor(v).Name(); got != v {
			t.Errorf("resolveVendor(%q) = %q, want %q", v, got, v)
		}
	}
}
