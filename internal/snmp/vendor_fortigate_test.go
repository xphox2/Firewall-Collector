package snmp

// Parser fixture tests for the FortiGate vendor profile — the production
// default vendor, which previously had no parser coverage beyond one
// hardware-sensor regression (AUDIT-218). Fixture style follows
// vendor_cisco_asa_test.go: builders returning []gosnmp.SnmpPDU with an
// explicit Type per PDU.
//
// The SD-WAN (AUDIT-177) and dialup (AUDIT-217) fixtures deliberately use
// LITERAL OID strings, not the fg* constants: a constant-built fixture would
// pass tautologically against wrong constants — which is exactly how the
// entry-level-omitting SD-WAN OIDs went unnoticed.

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// ── ParseSDWANHealth (AUDIT-177 / AUDIT-219) ─────────────────────────────────

// T1: one fgVWLHealthCheckLinkTable row, literal OIDs. Before AUDIT-177 the
// Name "column" constant was the table node itself, so every one of these
// PDUs fell into the Name branch and all metrics were zero/garbage.
func TestFortiGate_ParseSDWANHealth_SingleRow(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.2.1.1", Type: gosnmp.OctetString, Value: []byte("wan-hc")},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.4.1.1", Type: gosnmp.Integer, Value: 0},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.5.1.1", Type: gosnmp.OctetString, Value: []byte("12.500000")},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.7.1.1", Type: gosnmp.Counter64, Value: uint64(1000)},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.8.1.1", Type: gosnmp.Counter64, Value: uint64(990)},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.14.1.1", Type: gosnmp.OctetString, Value: []byte("wan1")},
		// NoSuchInstance must be skipped by isValidPDU — no phantom row.
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.2.9.9", Type: gosnmp.NoSuchInstance, Value: nil},
	}
	result := f.ParseSDWANHealth(pdus)
	if len(result) != 1 {
		t.Fatalf("got %d SD-WAN entries, want 1", len(result))
	}
	h := result[0]
	if h.Name != "wan-hc" {
		t.Errorf("Name = %q, want wan-hc", h.Name)
	}
	if h.Interface != "wan1" {
		t.Errorf("Interface = %q, want wan1", h.Interface)
	}
	if h.State != "alive" {
		t.Errorf("State = %q, want alive", h.State)
	}
	if h.Latency != 12.5 {
		t.Errorf("Latency = %v, want 12.5", h.Latency)
	}
	if h.PacketSend != 1000 {
		t.Errorf("PacketSend = %d, want 1000", h.PacketSend)
	}
	if h.PacketRecv != 990 {
		t.Errorf("PacketRecv = %d, want 990", h.PacketRecv)
	}
	if h.PacketLoss != 1.0 { // (1000-990)/1000*100 fallback — no .9 column here
		t.Errorf("PacketLoss = %v, want 1.0", h.PacketLoss)
	}
}

// T1b: the table may be composite-indexed (health-check id + member id).
// Index suffixes ".1.1" and ".2.1" share the same LAST arc — keying by
// getIndexFromOID would silently merge them into one row.
func TestFortiGate_ParseSDWANHealth_CompositeIndexRowsStayDistinct(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.2.1.1", Type: gosnmp.OctetString, Value: []byte("hc-a")},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.14.1.1", Type: gosnmp.OctetString, Value: []byte("wan1")},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.2.2.1", Type: gosnmp.OctetString, Value: []byte("hc-b")},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.14.2.1", Type: gosnmp.OctetString, Value: []byte("wan2")},
	}
	result := f.ParseSDWANHealth(pdus)
	if len(result) != 2 {
		t.Fatalf("got %d SD-WAN entries, want 2 (composite-index rows must not merge)", len(result))
	}
	byName := map[string]string{}
	for _, h := range result {
		byName[h.Name] = h.Interface
	}
	if byName["hc-a"] != "wan1" || byName["hc-b"] != "wan2" {
		t.Errorf("row attribution = %v, want hc-a→wan1, hc-b→wan2", byName)
	}
}

// T2: packet loss must never underflow (AUDIT-219) and the device's own .9
// column must win over the send/recv subtraction.
func TestFortiGate_ParseSDWANHealth_PacketLoss(t *testing.T) {
	f := &FortiGateProfile{}

	// Counter timing skew: recv > send. The old unguarded uint64 subtraction
	// produced ~1.8e19 percent loss.
	pdus := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.2.1.1", Type: gosnmp.OctetString, Value: []byte("skewed")},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.7.1.1", Type: gosnmp.Counter64, Value: uint64(100)},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.8.1.1", Type: gosnmp.Counter64, Value: uint64(105)},
	}
	result := f.ParseSDWANHealth(pdus)
	if len(result) != 1 {
		t.Fatalf("got %d entries, want 1", len(result))
	}
	if loss := result[0].PacketLoss; loss < 0 || loss > 100 {
		t.Errorf("PacketLoss = %v, want 0 <= loss <= 100 (recv>send must not underflow)", loss)
	}

	// Device-computed .9 column present: it is authoritative; the subtraction
	// (which would say 1.0) must not override it.
	pdus = []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.2.1.1", Type: gosnmp.OctetString, Value: []byte("with-loss-col")},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.7.1.1", Type: gosnmp.Counter64, Value: uint64(1000)},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.8.1.1", Type: gosnmp.Counter64, Value: uint64(990)},
		{Name: ".1.3.6.1.4.1.12356.101.4.9.2.1.9.1.1", Type: gosnmp.OctetString, Value: []byte("1.250000")},
	}
	result = f.ParseSDWANHealth(pdus)
	if len(result) != 1 {
		t.Fatalf("got %d entries, want 1", len(result))
	}
	if result[0].PacketLoss != 1.25 {
		t.Errorf("PacketLoss = %v, want 1.25 (.9 column must win over send/recv subtraction)", result[0].PacketLoss)
	}
}

// ── ParseDialupVPNStatus (AUDIT-217) ─────────────────────────────────────────

// T3: dialup column .7 is fgVpnDialUpDstAddr (a single address) and .8 is
// fgVpnDialUpVdom — an INTEGER the old code parsed as a "destination end IP".
// Literal OIDs; the load-bearing assertion is that presence/absence of .8
// yields IDENTICAL output (proving .8 is unread).
func TestFortiGate_ParseDialupVPNStatus_VdomColumnUnread(t *testing.T) {
	f := &FortiGateProfile{}
	base := func() []gosnmp.SnmpPDU {
		return []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.4.1.12356.101.12.2.1.1.2.1", Type: gosnmp.IPAddress, Value: "203.0.113.50"},
			{Name: ".1.3.6.1.4.1.12356.101.12.2.1.1.3.1", Type: gosnmp.Gauge32, Value: uint(43200)},
			{Name: ".1.3.6.1.4.1.12356.101.12.2.1.1.5.1", Type: gosnmp.IPAddress, Value: "10.10.0.0"},
			{Name: ".1.3.6.1.4.1.12356.101.12.2.1.1.6.1", Type: gosnmp.IPAddress, Value: "10.10.0.255"},
			{Name: ".1.3.6.1.4.1.12356.101.12.2.1.1.7.1", Type: gosnmp.IPAddress, Value: "192.0.2.77"},
			// NoSuchInstance must be skipped, not create a phantom tunnel.
			{Name: ".1.3.6.1.4.1.12356.101.12.2.1.1.2.9", Type: gosnmp.NoSuchInstance, Value: nil},
		}
	}

	withVdom := append(base(), gosnmp.SnmpPDU{
		Name: ".1.3.6.1.4.1.12356.101.12.2.1.1.8.1", Type: gosnmp.Integer, Value: 3, // vdom id
	})
	got := f.ParseDialupVPNStatus(withVdom)
	if len(got) != 1 {
		t.Fatalf("got %d dialup tunnels, want 1", len(got))
	}
	a := got[0]
	if a.RemoteSubnet != "192.0.2.77/32" {
		t.Errorf("RemoteSubnet = %q, want 192.0.2.77/32 (vdom integer 3 must not leak into the subnet)", a.RemoteSubnet)
	}
	if a.LocalSubnet != "10.10.0.0/24" {
		t.Errorf("LocalSubnet = %q, want 10.10.0.0/24 (from the .5/.6 range)", a.LocalSubnet)
	}
	if a.RemoteIP != "203.0.113.50" || a.TunnelName != "dialup-203.0.113.50" {
		t.Errorf("RemoteIP/TunnelName = %q/%q, want 203.0.113.50/dialup-203.0.113.50", a.RemoteIP, a.TunnelName)
	}
	if a.TunnelUptime != 43200 {
		t.Errorf("TunnelUptime = %d, want 43200", a.TunnelUptime)
	}
	if a.Status != "up" || a.TunnelType != "ipsec-dialup" {
		t.Errorf("Status/TunnelType = %q/%q, want up/ipsec-dialup", a.Status, a.TunnelType)
	}

	// Same fixture WITHOUT the .8 PDU must yield the identical result.
	got = f.ParseDialupVPNStatus(base())
	if len(got) != 1 {
		t.Fatalf("without .8: got %d dialup tunnels, want 1", len(got))
	}
	b := got[0]
	if b.RemoteSubnet != a.RemoteSubnet || b.LocalSubnet != a.LocalSubnet ||
		b.RemoteIP != a.RemoteIP || b.TunnelName != a.TunnelName || b.TunnelUptime != a.TunnelUptime {
		t.Errorf("presence of the vdom column changed the output: with=%+v without=%+v (the .8 column must be unread)", a, b)
	}
}

// ── rangeToCIDR (AUDIT-299) ──────────────────────────────────────────────────

func TestRangeToCIDR(t *testing.T) {
	cases := []struct {
		begin, end, want string
	}{
		{"10.0.0.0", "10.0.0.255", "10.0.0.0/24"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
		{"192.168.1.10", "", "192.168.1.10/32"},
		{"192.168.1.10", "192.168.1.10", "192.168.1.10/32"},
		// Contiguous XOR but begin is NOT the block's network address — the
		// old code rendered this as a wrong CIDR (AUDIT-299). The fallback
		// must be the SPACED form the server's cidrToLikePattern splits on.
		{"10.0.1.255", "10.0.2.0", "10.0.1.255 - 10.0.2.0"},
		// Non-contiguous host bits — also the spaced form (the old code
		// emitted an unspaced "begin-end" the server cannot parse).
		{"10.0.0.0", "10.0.5.0", "10.0.0.0 - 10.0.5.0"},
		{"", "x", ""},
		{"not-an-ip", "y", "not-an-ip"},
	}
	for _, c := range cases {
		if got := rangeToCIDR(c.begin, c.end); got != c.want {
			t.Errorf("rangeToCIDR(%q, %q) = %q, want %q", c.begin, c.end, got, c.want)
		}
	}
}

// ── Hardware sensors: voltage unit (AUDIT-300) ───────────────────────────────

// T5: fgHwSensorEntValue is a DisplayString in VOLTS ("12.070000"); the unit
// label must be "V" — "mV" was a 1000x mislabel.
func TestFortiGate_ParseHardwareSensors_VoltageUnitVolts(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDHWSensorName + ".1", Type: gosnmp.OctetString, Value: []byte("+12V Rail")},
		{Name: fgOIDHWSensorValue + ".1", Type: gosnmp.OctetString, Value: []byte("12.070000")},
		{Name: fgOIDHWSensorAlarm + ".1", Type: gosnmp.Integer, Value: 0},
	}
	sensors := f.ParseHardwareSensors(pdus)
	if len(sensors) != 1 {
		t.Fatalf("got %d sensors, want 1", len(sensors))
	}
	s := sensors[0]
	if s.Type != "voltage" {
		t.Errorf("Type = %q, want voltage", s.Type)
	}
	if s.Unit != "V" {
		t.Errorf("Unit = %q, want V (value is in volts; mV was a 1000x mislabel)", s.Unit)
	}
	if s.Value != 12.07 {
		t.Errorf("Value = %v, want 12.07", s.Value)
	}
}

// ── T8: coverage fixtures for the remaining FortiGate parsers ────────────────

func TestFortiGate_ParseSystemStatus(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDSystemHostname, Type: gosnmp.OctetString, Value: []byte("fg-branch-01")},
		{Name: fgOIDSystemVersion, Type: gosnmp.OctetString, Value: []byte("FortiGate-60F v7.0.12")},
		{Name: fgOIDSystemCPU, Type: gosnmp.Gauge32, Value: uint(12)},
		{Name: fgOIDSystemMemory, Type: gosnmp.Gauge32, Value: uint(38)},
		{Name: fgOIDSystemMemoryCap, Type: gosnmp.Gauge32, Value: uint(2007040)},
		{Name: fgOIDSystemDisk, Type: gosnmp.Gauge32, Value: uint(5120)},
		{Name: fgOIDSystemDiskCap, Type: gosnmp.Gauge32, Value: uint(10240)},
		{Name: fgOIDSystemSessions, Type: gosnmp.Gauge32, Value: uint(4321)},
		{Name: fgOIDSystemUptime, Type: gosnmp.TimeTicks, Value: uint32(8640000)},
		// SSL-VPN scalars answered NoSuchObject (feature disabled / older
		// firmware) — documented accepted behavior: they stay 0.
		{Name: fgOIDSSLVPNUsers, Type: gosnmp.NoSuchObject, Value: nil},
		{Name: fgOIDSSLVPNActive, Type: gosnmp.NoSuchObject, Value: nil},
	}
	status := f.ParseSystemStatus(pdus)
	if status.Hostname != "fg-branch-01" {
		t.Errorf("Hostname = %q, want fg-branch-01", status.Hostname)
	}
	if status.Version != "FortiGate-60F v7.0.12" {
		t.Errorf("Version = %q, want FortiGate-60F v7.0.12", status.Version)
	}
	if status.CPUUsage != 12 {
		t.Errorf("CPUUsage = %v, want 12", status.CPUUsage)
	}
	if status.MemoryUsage != 38 {
		t.Errorf("MemoryUsage = %v, want 38", status.MemoryUsage)
	}
	// fgSysDiskUsage/Capacity are MB — DiskUsage is the computed percentage.
	if status.DiskUsage != 50 {
		t.Errorf("DiskUsage = %v%%, want 50 (5120/10240 MB)", status.DiskUsage)
	}
	if status.DiskTotal != 10240 {
		t.Errorf("DiskTotal = %d, want 10240", status.DiskTotal)
	}
	if status.SessionCount != 4321 {
		t.Errorf("SessionCount = %d, want 4321", status.SessionCount)
	}
	if status.Uptime != 8640000 {
		t.Errorf("Uptime = %d, want 8640000", status.Uptime)
	}
	if status.SSLVPNUsers != 0 || status.SSLVPNTunnels != 0 {
		t.Errorf("SSLVPNUsers/Tunnels = %d/%d, want 0/0 for NoSuchObject", status.SSLVPNUsers, status.SSLVPNTunnels)
	}
}

func TestFortiGate_ParseVPNStatus(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDVPNTunnelPhase1Name + ".1", Type: gosnmp.OctetString, Value: []byte("hq-p1")},
		{Name: fgOIDVPNTunnelName + ".1", Type: gosnmp.OctetString, Value: []byte("hq-tunnel")},
		{Name: fgOIDVPNTunnelRemoteGW + ".1", Type: gosnmp.IPAddress, Value: "198.51.100.9"},
		{Name: fgOIDVPNTunnelSrcBeginIP + ".1", Type: gosnmp.IPAddress, Value: "192.168.1.0"},
		{Name: fgOIDVPNTunnelSrcEndIP + ".1", Type: gosnmp.IPAddress, Value: "192.168.1.255"},
		{Name: fgOIDVPNTunnelDstBeginIP + ".1", Type: gosnmp.IPAddress, Value: "10.20.0.0"},
		{Name: fgOIDVPNTunnelDstEndIP + ".1", Type: gosnmp.IPAddress, Value: "10.20.0.255"},
		{Name: fgOIDVPNTunnelInOctets + ".1", Type: gosnmp.Counter64, Value: uint64(1111)},
		{Name: fgOIDVPNTunnelOutOctets + ".1", Type: gosnmp.Counter64, Value: uint64(2222)},
		{Name: fgOIDVPNTunnelStatus + ".1", Type: gosnmp.Integer, Value: 2}, // up
		{Name: fgOIDVPNTunnelStatus + ".2", Type: gosnmp.Integer, Value: 1}, // down
		{Name: fgOIDVPNTunnelName + ".2", Type: gosnmp.OctetString, Value: []byte("dead-tunnel")},
		{Name: fgOIDVPNTunnelName + ".3", Type: gosnmp.NoSuchInstance, Value: nil}, // must be skipped
	}
	result := f.ParseVPNStatus(pdus)
	if len(result) != 2 {
		t.Fatalf("got %d tunnels, want 2", len(result))
	}
	byName := map[string]struct {
		status, state, local, remote string
	}{}
	for _, v := range result {
		byName[v.TunnelName] = struct{ status, state, local, remote string }{v.Status, v.State, v.LocalSubnet, v.RemoteSubnet}
	}
	up := byName["hq-tunnel"]
	if up.status != "up" || up.state != "active" {
		t.Errorf("hq-tunnel status/state = %q/%q, want up/active for status value 2", up.status, up.state)
	}
	// Site-to-site selectors are emitted as the spaced range join.
	if up.local != "192.168.1.0 - 192.168.1.255" {
		t.Errorf("LocalSubnet = %q, want %q", up.local, "192.168.1.0 - 192.168.1.255")
	}
	if up.remote != "10.20.0.0 - 10.20.0.255" {
		t.Errorf("RemoteSubnet = %q, want %q", up.remote, "10.20.0.0 - 10.20.0.255")
	}
	down := byName["dead-tunnel"]
	if down.status != "down" || down.state != "inactive" {
		t.Errorf("dead-tunnel status/state = %q/%q, want down/inactive for status value 1", down.status, down.state)
	}
}

func TestFortiGate_ParseSSLVPNTunnels(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDSSLVPNTunnelUserName + ".1", Type: gosnmp.OctetString, Value: []byte("alice")},
		{Name: fgOIDSSLVPNTunnelSrcIP + ".1", Type: gosnmp.IPAddress, Value: "203.0.113.7"},
		{Name: fgOIDSSLVPNTunnelBytesIn + ".1", Type: gosnmp.Counter64, Value: uint64(100)},
		{Name: fgOIDSSLVPNTunnelBytesOut + ".1", Type: gosnmp.Counter64, Value: uint64(200)},
		{Name: fgOIDSSLVPNTunnelUserName + ".2", Type: gosnmp.NoSuchInstance, Value: nil}, // skipped
	}
	result := f.ParseSSLVPNTunnels(pdus)
	if len(result) != 1 {
		t.Fatalf("got %d SSL-VPN tunnels, want 1", len(result))
	}
	s := result[0]
	if s.TunnelName != "sslvpn-alice" {
		t.Errorf("TunnelName = %q, want sslvpn-alice", s.TunnelName)
	}
	if s.RemoteIP != "203.0.113.7" {
		t.Errorf("RemoteIP = %q, want 203.0.113.7", s.RemoteIP)
	}
	if s.TunnelType != "sslvpn" || s.Status != "up" {
		t.Errorf("TunnelType/Status = %q/%q, want sslvpn/up", s.TunnelType, s.Status)
	}
	if s.BytesIn != 100 || s.BytesOut != 200 {
		t.Errorf("BytesIn/Out = %d/%d, want 100/200", s.BytesIn, s.BytesOut)
	}
}

func TestFortiGate_ParseHAStatus_StandaloneReturnsNil(t *testing.T) {
	f := &FortiGateProfile{}
	scalars := []gosnmp.SnmpPDU{
		{Name: fgOIDHASystemMode, Type: gosnmp.Integer, Value: 1}, // standalone
		{Name: fgOIDHAGroupId, Type: gosnmp.NoSuchInstance, Value: nil},
	}
	if got := f.ParseHAStatus(scalars, nil); len(got) != 0 {
		t.Errorf("ParseHAStatus(standalone) = %v, want empty", got)
	}
}

func TestFortiGate_ParseHAStatus_ActivePassivePair(t *testing.T) {
	f := &FortiGateProfile{}
	scalars := []gosnmp.SnmpPDU{
		{Name: fgOIDHASystemMode, Type: gosnmp.Integer, Value: 3}, // activePassive
		{Name: fgOIDHAGroupId, Type: gosnmp.Integer, Value: 10},
		{Name: fgOIDHAGroupName, Type: gosnmp.OctetString, Value: []byte("ha-grp")},
	}
	members := []gosnmp.SnmpPDU{
		{Name: fgOIDHAStatsSerial + ".1", Type: gosnmp.OctetString, Value: []byte("FGT60F0001")},
		{Name: fgOIDHAStatsHostname + ".1", Type: gosnmp.OctetString, Value: []byte("fg-primary")},
		{Name: fgOIDHAStatsCPU + ".1", Type: gosnmp.Gauge32, Value: uint(15)},
		{Name: fgOIDHAStatsSync + ".1", Type: gosnmp.Integer, Value: 1},
		{Name: fgOIDHAStatsSerial + ".2", Type: gosnmp.OctetString, Value: []byte("FGT60F0002")},
		{Name: fgOIDHAStatsHostname + ".2", Type: gosnmp.OctetString, Value: []byte("fg-standby")},
		{Name: fgOIDHAStatsCPU + ".2", Type: gosnmp.Gauge32, Value: uint(3)},
		{Name: fgOIDHAStatsSync + ".2", Type: gosnmp.Integer, Value: 0},
		{Name: fgOIDHAStatsSerial + ".3", Type: gosnmp.NoSuchInstance, Value: nil}, // skipped
	}
	result := f.ParseHAStatus(scalars, members)
	if len(result) != 2 {
		t.Fatalf("got %d HA members, want 2", len(result))
	}
	byIdx := map[int]struct {
		serial, host, sync string
		cpu                float64
	}{}
	for _, m := range result {
		if m.SystemMode != "activePassive" || m.GroupID != 10 || m.GroupName != "ha-grp" {
			t.Errorf("member %d mode/group = %q/%d/%q, want activePassive/10/ha-grp", m.MemberIndex, m.SystemMode, m.GroupID, m.GroupName)
		}
		byIdx[m.MemberIndex] = struct {
			serial, host, sync string
			cpu                float64
		}{m.MemberSerial, m.MemberHostname, m.SyncStatus, m.CPUUsage}
	}
	p := byIdx[1]
	if p.serial != "FGT60F0001" || p.host != "fg-primary" || p.sync != "in-sync" || p.cpu != 15 {
		t.Errorf("primary = %+v, want FGT60F0001/fg-primary/in-sync/15", p)
	}
	s := byIdx[2]
	if s.serial != "FGT60F0002" || s.host != "fg-standby" || s.sync != "out-of-sync" || s.cpu != 3 {
		t.Errorf("standby = %+v, want FGT60F0002/fg-standby/out-of-sync/3", s)
	}
}

func TestFortiGate_ParseSecurityStats(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDAVDetected, Type: gosnmp.Counter32, Value: uint(5)},
		{Name: fgOIDIPSBlocked, Type: gosnmp.Counter32, Value: uint(7)},
		{Name: fgOIDWFURLBlocked, Type: gosnmp.Counter32, Value: uint(9)},
		{Name: fgOIDIPSInfo, Type: gosnmp.NoSuchInstance, Value: nil}, // skipped → stays 0
	}
	stats := f.ParseSecurityStats(pdus)
	if stats.AVDetected != 5 {
		t.Errorf("AVDetected = %d, want 5", stats.AVDetected)
	}
	if stats.IPSBlocked != 7 {
		t.Errorf("IPSBlocked = %d, want 7", stats.IPSBlocked)
	}
	if stats.WFURLBlocked != 9 {
		t.Errorf("WFURLBlocked = %d, want 9", stats.WFURLBlocked)
	}
	if stats.IPSInfo != 0 {
		t.Errorf("IPSInfo = %d, want 0 for NoSuchInstance", stats.IPSInfo)
	}
}

func TestFortiGate_ParseLicenseInfo(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDLicenseDesc + ".1", Type: gosnmp.OctetString, Value: []byte("AV Definitions")},
		{Name: fgOIDLicenseExpiry + ".1", Type: gosnmp.OctetString, Value: []byte("2027-03-01")},
		{Name: fgOIDLicenseDesc + ".2", Type: gosnmp.OctetString, Value: []byte("IPS Definitions")},
		{Name: fgOIDLicenseExpiry + ".2", Type: gosnmp.OctetString, Value: []byte("2027-03-01")},
		{Name: fgOIDLicenseDesc + ".3", Type: gosnmp.NoSuchInstance, Value: nil}, // skipped
	}
	result := f.ParseLicenseInfo(pdus)
	if len(result) != 2 {
		t.Fatalf("got %d licenses, want 2", len(result))
	}
	byDesc := map[string]string{}
	for _, l := range result {
		byDesc[l.Description] = l.ExpiryDate
	}
	if byDesc["AV Definitions"] != "2027-03-01" || byDesc["IPS Definitions"] != "2027-03-01" {
		t.Errorf("licenses = %v, want AV/IPS Definitions expiring 2027-03-01", byDesc)
	}
}
