package ssh

import (
	"testing"
)

// ── ParseSensorInfo ──────────────────────────────────────────────────────────

// Single-line dot-separator format (sensorLineRegex). This was the format
// broken in v1.2.41 and v1.2.45 when \.+ was changed to [^\w]+.
func TestParseSensorInfo_SingleLineFormat(t *testing.T) {
	output := `
  1  CPU Core Temp   .........   52.0   C    Normal
  2  FAN1 Speed      .........  3200.0  RPM  Normal
  3  PSU Voltage     .........  12.1    V    Normal
`
	sensors := ParseSensorInfo(output)
	if len(sensors) != 3 {
		t.Fatalf("expected 3 sensors, got %d", len(sensors))
	}
	if sensors[0].Value != 52.0 {
		t.Errorf("sensors[0].Value = %v, want 52.0", sensors[0].Value)
	}
	if sensors[0].Unit != "C" {
		t.Errorf("sensors[0].Unit = %q, want %q", sensors[0].Unit, "C")
	}
	if sensors[1].Value != 3200.0 {
		t.Errorf("sensors[1].Value = %v, want 3200.0", sensors[1].Value)
	}
	if sensors[1].Unit != "RPM" {
		t.Errorf("sensors[1].Unit = %q, want %q", sensors[1].Unit, "RPM")
	}
	if sensors[2].Unit != "V" {
		t.Errorf("sensors[2].Unit = %q, want %q", sensors[2].Unit, "V")
	}
}

// Multi-line block format (Sensor N: / Value: / Status:).
func TestParseSensorInfo_MultiLineBlockFormat(t *testing.T) {
	output := `Sensor 1: CPU Core Temp
  Value: 52.0 C
  Status: Normal

Sensor 2: FAN1 Speed
  Value: 3200.0 RPM
  Status: Alarm
`
	sensors := ParseSensorInfo(output)
	if len(sensors) != 2 {
		t.Fatalf("expected 2 sensors, got %d", len(sensors))
	}
	if sensors[0].Name != "CPU Core Temp" {
		t.Errorf("sensors[0].Name = %q, want %q", sensors[0].Name, "CPU Core Temp")
	}
	if sensors[0].Value != 52.0 {
		t.Errorf("sensors[0].Value = %v, want 52.0", sensors[0].Value)
	}
	if sensors[1].Status != "Alarm" {
		t.Errorf("sensors[1].Status = %q, want %q", sensors[1].Status, "Alarm")
	}
}

// Alarm status is preserved (not silently overwritten).
func TestParseSensorInfo_AlarmStatus(t *testing.T) {
	output := `Sensor 1: PSU Voltage
  Value: 8.2 V
  Status: Alarm
`
	sensors := ParseSensorInfo(output)
	if len(sensors) != 1 {
		t.Fatalf("expected 1 sensor, got %d", len(sensors))
	}
	if sensors[0].Status != "Alarm" {
		t.Errorf("Status = %q, want %q", sensors[0].Status, "Alarm")
	}
}

// Unit variants used by FortiGate hardware.
func TestParseSensorInfo_UnitVariants(t *testing.T) {
	output := `
  1  CPU Temp  .....  45.0  C    Normal
  2  FAN Speed .....  2800  RPM  Normal
  3  CPU mV    .....  1050  mV   Normal
  4  SSD Usage .....  42.0  %    Normal
`
	sensors := ParseSensorInfo(output)
	if len(sensors) != 4 {
		t.Fatalf("expected 4 sensors, got %d", len(sensors))
	}
	units := []string{"C", "RPM", "mV", "%"}
	for i, want := range units {
		if sensors[i].Unit != want {
			t.Errorf("sensors[%d].Unit = %q, want %q", i, sensors[i].Unit, want)
		}
	}
}

// Empty input returns nil (no panic).
func TestParseSensorInfo_EmptyInput(t *testing.T) {
	sensors := ParseSensorInfo("")
	if len(sensors) != 0 {
		t.Errorf("expected 0 sensors for empty input, got %d", len(sensors))
	}
}

// Regression: dot-separator regex \.+ must match one-or-more dots.
// If the regex is changed to [^\w]+, spaces around the value also match and
// the capture groups shift, returning wrong values.
func TestParseSensorInfo_Regression_DotSeparatorRegex(t *testing.T) {
	output := `  1  CPU Core Temp   .........   52.0   C    Normal` + "\n"
	sensors := ParseSensorInfo(output)
	if len(sensors) == 0 {
		t.Fatal("single-line dot-separator produced no sensors (regex broken)")
	}
	if sensors[0].Value != 52.0 {
		t.Errorf("Value = %v, want 52.0 (regex may have shifted capture groups)", sensors[0].Value)
	}
}

// ── ParsePerformanceStatus ───────────────────────────────────────────────────

func TestParsePerformanceStatus_FullOutput(t *testing.T) {
	output := `CPU states:  5% user   3% system   0% nice  90% idle   0% iowait   1% irq   1% softirq
Memory: 4096000k total, 2048000k used (50.0%), 1024000k free (25.0%), 512000k freeable (12.5%)
Average network usage: 1234.5 / 567.8 kbps in 1 minute
Current sessions: 8542
Uptime: 42 days`

	info := ParsePerformanceStatus(output)
	if info == nil {
		t.Fatal("returned nil")
	}
	if info.CPUUser != 5.0 {
		t.Errorf("CPUUser = %v, want 5.0", info.CPUUser)
	}
	if info.CPUSystem != 3.0 {
		t.Errorf("CPUSystem = %v, want 3.0", info.CPUSystem)
	}
	if info.CPUIdle != 90.0 {
		t.Errorf("CPUIdle = %v, want 90.0", info.CPUIdle)
	}
	if info.NetworkIn != 1234.5 {
		t.Errorf("NetworkIn = %v, want 1234.5", info.NetworkIn)
	}
	if info.NetworkOut != 567.8 {
		t.Errorf("NetworkOut = %v, want 567.8", info.NetworkOut)
	}
	if info.SessionCount != 8542 {
		t.Errorf("SessionCount = %d, want 8542", info.SessionCount)
	}
}

// Memory values parsed as kibibytes must be multiplied by 1024.
func TestParsePerformanceStatus_MemoryKilobyteToBytes(t *testing.T) {
	output := `Memory: 4096000k total, 2048000k used (50.0%), 1024000k free (25.0%), 512000k freeable (12.5%)`
	info := ParsePerformanceStatus(output)
	want := uint64(4096000) * 1024
	if info.MemoryTotal != want {
		t.Errorf("MemoryTotal = %d, want %d (missing ×1024 conversion)", info.MemoryTotal, want)
	}
	if info.MemoryUsed != uint64(2048000)*1024 {
		t.Errorf("MemoryUsed not converted: got %d", info.MemoryUsed)
	}
}

// Uptime is emitted in HUNDREDTHS of a second (AUDIT-220: canonical SNMP timeticks unit; days × 8640000).
func TestParsePerformanceStatus_UptimeDaysToSeconds(t *testing.T) {
	output := `Uptime: 42 days`
	info := ParsePerformanceStatus(output)
	want := uint64(42 * 86400 * 100)
	if info.Uptime != want {
		t.Errorf("Uptime = %d, want %d", info.Uptime, want)
	}
}

// The full FortiOS form carries hours and minutes; they were formerly
// discarded, so a fresh-booted device reported Uptime=0 for a whole day
// (AUDIT-303).
func TestParsePerformanceStatus_UptimeDaysHoursMinutes(t *testing.T) {
	output := `Uptime: 20 days, 3 hours, 26 minutes`
	info := ParsePerformanceStatus(output)
	want := uint64((20*86400 + 3*3600 + 26*60) * 100) // 174036000 (AUDIT-220: hundredths)
	if info.Uptime != want {
		t.Errorf("Uptime = %d, want %d", info.Uptime, want)
	}

	// Fresh boot: less than a day up must not round down to zero.
	info = ParsePerformanceStatus(`Uptime: 0 days, 0 hours, 5 minutes`)
	if info.Uptime != 30000 { // AUDIT-220: 300s × 100
		t.Errorf("fresh-boot Uptime = %d, want 30000", info.Uptime)
	}
}

// Network kbps values are parsed as floats from the output line.
func TestParsePerformanceStatus_NetworkKbpsParsed(t *testing.T) {
	output := `Average network usage: 0.5 / 1000.0 kbps in 5 minute`
	info := ParsePerformanceStatus(output)
	if info.NetworkIn != 0.5 {
		t.Errorf("NetworkIn = %v, want 0.5", info.NetworkIn)
	}
	if info.NetworkOut != 1000.0 {
		t.Errorf("NetworkOut = %v, want 1000.0", info.NetworkOut)
	}
}

// Empty output returns zero-value struct (not nil, not panic).
func TestParsePerformanceStatus_EmptyInput(t *testing.T) {
	info := ParsePerformanceStatus("")
	if info == nil {
		t.Fatal("returned nil for empty input")
	}
	if info.CPUUser != 0 || info.MemoryTotal != 0 {
		t.Errorf("expected zero values for empty input")
	}
}

// ── ParseVPNPhase1 ────────────────────────────────────────────────────────────

func TestParseVPNPhase1_SingleTunnel(t *testing.T) {
	output := `config vpn ipsec phase1-interface
    edit "HQ-VPN"
        set type tunnel
        set interface "wan1"
        set remote-gw 203.0.113.1
        set mode aggressive
    next
end`
	tunnels := ParseVPNPhase1(output)
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Name != "HQ-VPN" {
		t.Errorf("Name = %q, want %q", tunnels[0].Name, "HQ-VPN")
	}
	if tunnels[0].Interface != `"wan1"` {
		t.Errorf("Interface = %q, want %q", tunnels[0].Interface, `"wan1"`)
	}
	if tunnels[0].RemoteGateway != "203.0.113.1" {
		t.Errorf("RemoteGateway = %q, want %q", tunnels[0].RemoteGateway, "203.0.113.1")
	}
}

func TestParseVPNPhase1_MultipleTunnels(t *testing.T) {
	output := `config vpn ipsec phase1-interface
    edit "HQ-VPN"
        set type tunnel
        set interface "wan1"
        set remote-gw 203.0.113.1
    next
    edit "Branch-VPN"
        set type tunnel
        set interface "wan2"
        set remote-gw 198.51.100.1
    next
end`
	tunnels := ParseVPNPhase1(output)
	if len(tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(tunnels))
	}
	if tunnels[0].Name != "HQ-VPN" {
		t.Errorf("tunnels[0].Name = %q, want HQ-VPN", tunnels[0].Name)
	}
	if tunnels[1].Name != "Branch-VPN" {
		t.Errorf("tunnels[1].Name = %q, want Branch-VPN", tunnels[1].Name)
	}
}

// Last tunnel must be flushed after the loop. If the post-loop append is
// removed, a single-entry output returns empty — this catches that regression.
func TestParseVPNPhase1_LastEntryFlushed(t *testing.T) {
	output := `config vpn ipsec phase1-interface
    edit "SOLE-VPN"
        set type tunnel
        set remote-gw 10.0.0.1
end`
	tunnels := ParseVPNPhase1(output)
	if len(tunnels) == 0 {
		t.Fatal("last VPN phase1 entry not flushed (missing post-loop append)")
	}
	if tunnels[0].Name != "SOLE-VPN" {
		t.Errorf("Name = %q, want SOLE-VPN", tunnels[0].Name)
	}
}

// ── ParseVPNPhase2 ────────────────────────────────────────────────────────────

func TestParseVPNPhase2_Phase1NameLinked(t *testing.T) {
	output := `config vpn ipsec phase2-interface
    edit "HQ-VPN_0"
        set phase1name "HQ-VPN"
        set remote-gw 203.0.113.1
    next
end`
	tunnels := ParseVPNPhase2(output)
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 phase2 entry, got %d", len(tunnels))
	}
	if tunnels[0].Phase1Name != "HQ-VPN" {
		t.Errorf("Phase1Name = %q, want %q", tunnels[0].Phase1Name, "HQ-VPN")
	}
}

func TestParseVPNPhase2_LastEntryFlushed(t *testing.T) {
	output := `config vpn ipsec phase2-interface
    edit "SOLE-P2"
        set phase1name "SOLE-VPN"
end`
	tunnels := ParseVPNPhase2(output)
	if len(tunnels) == 0 {
		t.Fatal("last VPN phase2 entry not flushed (missing post-loop append)")
	}
}

// ── ParseProcessTop ───────────────────────────────────────────────────────────

// Triggers on "Run Time:" header line (older FortiOS firmware).
func TestParseProcessTop_TriggersOnRunTimeLine(t *testing.T) {
	output := `Run Time:  5 days,  3 hours and 12 minutes
U, process       PID    T     CPU   Memory    CMD
httpsd            1234  S   0.0    1.5    9999
dnsproxy          5678  S   0.1    0.8    8888`
	procs := ParseProcessTop(output)
	if len(procs) == 0 {
		t.Fatal("no processes parsed; 'Run Time:' trigger not working")
	}
	if procs[0].Name != "httpsd" {
		t.Errorf("procs[0].Name = %q, want httpsd", procs[0].Name)
	}
}

// Triggers on a header line containing both "U," and "T," (newer FortiOS firmware).
func TestParseProcessTop_TriggersOnColumnHeader(t *testing.T) {
	output := `U, process       PID   T,     CPU   Memory    CMD
httpsd            1234  S   0.0    1.5    9999`
	procs := ParseProcessTop(output)
	if len(procs) == 0 {
		t.Fatal("no processes parsed; 'U, ... T,' column header trigger not working")
	}
}

// Header keywords ("process", "CPU", "MEM", "node") must be filtered out.
func TestParseProcessTop_FiltersHeaderKeywords(t *testing.T) {
	output := `Run Time:  1 day
process           1234  S   0.0    1.5    9999
CPU               5678  S   0.1    0.8    8888
httpsd            9999  S   1.2    3.4    1111`
	procs := ParseProcessTop(output)
	for _, p := range procs {
		if p.Name == "process" || p.Name == "CPU" {
			t.Errorf("header keyword %q not filtered from results", p.Name)
		}
	}
	found := false
	for _, p := range procs {
		if p.Name == "httpsd" {
			found = true
		}
	}
	if !found {
		t.Error("real process 'httpsd' missing from results")
	}
}

func TestParseProcessTop_MultipleProcesses(t *testing.T) {
	output := `Run Time:  1 day
httpsd            1234  S   2.5    1.5    9999
sshd              5678  S   0.0    0.3    8888
miglogd           9012  S   0.1    0.5    7777`
	procs := ParseProcessTop(output)
	if len(procs) != 3 {
		t.Fatalf("expected 3 processes, got %d", len(procs))
	}
	if procs[0].CPU != 2.5 {
		t.Errorf("procs[0].CPU = %v, want 2.5", procs[0].CPU)
	}
	if procs[0].PID != 1234 {
		t.Errorf("procs[0].PID = %d, want 1234", procs[0].PID)
	}
}

// ── ParseInterfaceList ────────────────────────────────────────────────────────

func TestParseInterfaceList_SingleInterface(t *testing.T) {
	output := `Name: wan1
        RX bytes 1000000  errors 5  discards 3
        TX bytes 2000000  errors 0  discards 1
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	if ifaces[0].Name != "wan1" {
		t.Errorf("Name = %q, want wan1", ifaces[0].Name)
	}
}

// Last interface must be flushed after the loop.
func TestParseInterfaceList_LastInterfaceFlushed(t *testing.T) {
	output := `Name: wan1
        RX bytes 500  errors 0  discards 0
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) == 0 {
		t.Fatal("last interface not flushed (missing post-loop append)")
	}
}

func TestParseInterfaceList_MultipleInterfaces(t *testing.T) {
	output := `Name: wan1
        RX bytes 1000  errors 2  discards 1
Name: lan1
        RX bytes 2000  errors 0  discards 0
Name: dmz
        RX bytes 500   errors 1  discards 0
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) != 3 {
		t.Fatalf("expected 3 interfaces, got %d", len(ifaces))
	}
	if ifaces[0].Name != "wan1" {
		t.Errorf("ifaces[0].Name = %q, want wan1", ifaces[0].Name)
	}
	if ifaces[2].Name != "dmz" {
		t.Errorf("ifaces[2].Name = %q, want dmz", ifaces[2].Name)
	}
}

// assertIfaceCounters pins all four error/discard counters of one interface.
func assertIfaceCounters(t *testing.T, got InterfaceErrorInfo, inErr, inDisc, outErr, outDisc uint64) {
	t.Helper()
	if got.InErrors != inErr || got.InDiscards != inDisc {
		t.Errorf("In errors/discards = %d/%d, want %d/%d", got.InErrors, got.InDiscards, inErr, inDisc)
	}
	if got.OutErrors != outErr || got.OutDiscards != outDisc {
		t.Errorf("Out errors/discards = %d/%d, want %d/%d", got.OutErrors, got.OutDiscards, outErr, outDisc)
	}
}

// Before AUDIT-222 the outer gate required "rx" on the line and the direction
// was taken from the LINE text, so a TX-only line could never populate the
// Out* counters — the TX branch was structurally unreachable.
func TestParseInterfaceList_SplitRxTxLines(t *testing.T) {
	output := `Name: wan1
        RX bytes 1000000  errors 5  discards 3
        TX bytes 2000000  errors 7  discards 2
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	assertIfaceCounters(t, ifaces[0], 5, 3, 7, 2)
}

// A single line carrying both directions must fill both — the old code let
// the TX group overwrite the RX values (direction came from the line, and
// "rx" was always present on a combined line).
func TestParseInterfaceList_CombinedRxTxLine(t *testing.T) {
	output := `Name: wan1
        RX bytes 1000000 errors 5 discards 3 TX bytes 2000000 errors 7 discards 2
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	assertIfaceCounters(t, ifaces[0], 5, 3, 7, 2)
}

// Real FortiOS `diagnose netlink interface list` blocks start with
// "if=<name> family=..." and carry token-form counters (AUDIT-222). No
// verbatim device capture exists yet — this fixture mirrors the documented
// token shapes; a real capture should replace it when available.
func TestParseInterfaceList_NetlinkTokens(t *testing.T) {
	output := `if=wan1 family=00 type=1 index=3 mtu=1500 link=0 master=0
rx_errors=5 rx_dropped=3 tx_errors=7 tx_dropped=2
if=lan1 family=00 type=1 index=4 mtu=1500 link=0 master=0
rx_errors=1 rx_dropped=0 tx_errors=0 tx_dropped=4
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(ifaces))
	}
	if ifaces[0].Name != "wan1" || ifaces[1].Name != "lan1" {
		t.Fatalf("names = %q/%q, want wan1/lan1 (the if= header form must be recognized)", ifaces[0].Name, ifaces[1].Name)
	}
	assertIfaceCounters(t, ifaces[0], 5, 3, 7, 2)
	assertIfaceCounters(t, ifaces[1], 1, 0, 0, 4)
}

// The compact netlink stat line uses rxe=/txe=/rxd=/txd= tokens with no
// "errors"/"dropped" words at all.
func TestParseInterfaceList_NetlinkCompactStat(t *testing.T) {
	output := `if=wan1 family=00 type=1 index=3 mtu=1500 link=0 master=0
stat: rxp=4986 txp=4459 rxb=331621 txb=879130 rxe=5 txe=7 rxd=3 txd=2 mc=0 collision=0
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	if ifaces[0].Name != "wan1" {
		t.Errorf("Name = %q, want wan1", ifaces[0].Name)
	}
	assertIfaceCounters(t, ifaces[0], 5, 3, 7, 2)
}

// Real netlink output follows the cumulative "stat:" line with a "re:" RATE
// line carrying the SAME compact tokens (near-always zeros). Last-match-wins
// parsing would let the rate line clobber the cumulative counters — every
// interface with real errors would report all zeros.
func TestParseInterfaceList_NetlinkRateLineDoesNotClobberStat(t *testing.T) {
	output := `if=wan1 family=00 type=1 index=3 mtu=1500 link=0 master=0
stat: rxp=4986 txp=4459 rxb=331621 txb=879130 rxe=1 txe=2 rxd=3 txd=4 mc=0 collision=0
re: rxp=1 txp=1 rxb=52 txb=64 rxe=0 txe=0 rxd=0 txd=0 mc=0 collision=0
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	assertIfaceCounters(t, ifaces[0], 1, 3, 2, 4)
}

// ── ParseLicenseStatus ────────────────────────────────────────────────────────

func TestParseLicenseStatus_ValidEntries(t *testing.T) {
	output := `FortiGuard: valid
Antivirus: valid
IPS: expired
Web Filter: none
`
	licenses := ParseLicenseStatus(output)
	if len(licenses) == 0 {
		t.Fatal("no licenses parsed")
	}

	byType := make(map[string]LicenseDetailInfo)
	for _, l := range licenses {
		byType[l.LicenseType] = l
	}

	if byType["FortiGuard"].Status != "licensed" {
		t.Errorf("FortiGuard.Status = %q, want licensed", byType["FortiGuard"].Status)
	}
	if byType["IPS"].Status != "expired" {
		t.Errorf("IPS.Status = %q, want expired", byType["IPS"].Status)
	}
	if byType["Web Filter"].Status != "no_license" {
		t.Errorf("Web Filter.Status = %q, want no_license", byType["Web Filter"].Status)
	}
}

func TestParseLicenseStatus_NoneStatus(t *testing.T) {
	output := `Application Control: none`
	licenses := ParseLicenseStatus(output)
	if len(licenses) == 0 {
		t.Fatal("no licenses parsed")
	}
	if licenses[0].Status != "no_license" {
		t.Errorf("Status = %q, want no_license", licenses[0].Status)
	}
}

// TestParseARPTable characterizes FortiOS `get system arp` parsing: header
// skipped, MACs canonical lowercase, incomplete/multicast entries dropped.
func TestParseARPTable(t *testing.T) {
	output := `Address           Age(min)   Hardware Addr      Interface
192.168.5.1       0          00:09:0F:09:00:02  internal
192.168.5.107     3          AA:BB:CC:00:55:01  lan2
10.0.0.9          1          00:00:00:00:00:00  wan1
224.0.0.5         0          01:00:5E:00:00:05  internal
garbage line
`
	got := ParseARPTable(output)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].IPAddress != "192.168.5.1" || got[0].MACAddress != "00:09:0f:09:00:02" || got[0].Interface != "internal" {
		t.Errorf("row 0 wrong: %+v", got[0])
	}
	if got[1].MACAddress != "aa:bb:cc:00:55:01" || got[1].Interface != "lan2" {
		t.Errorf("row 1 wrong (MAC must be lowercase): %+v", got[1])
	}
}

// TestParseBridgeList: names extracted from `diagnose netlink brctl list`,
// unsafe names (command-injection defense) dropped.
func TestParseBridgeList(t *testing.T) {
	output := `list bridge information
1. name=internal ifindex=9 mac_entries=5
2. name=lan-sw ifindex=12 mac_entries=2
3. name=bad;name ifindex=13
`
	got := ParseBridgeList(output)
	if len(got) != 2 || got[0] != "internal" || got[1] != "lan-sw" {
		t.Fatalf("got %v, want [internal lan-sw]", got)
	}
}

// TestParseBridgeFDB: learned unicast rows keep the member port NAME;
// Local/Static (self), multicast and header rows are dropped.
func TestParseBridgeFDB(t *testing.T) {
	output := `show bridge control interface internal host.
fdb: size=256, used=6, num=6, depth=1
Bridge internal host table
port no  device  devname  mac addr                 ttl    attributes
  3      9       internal3    E8:F6:D7:00:10:5B    88
  1      7       internal1    e0:23:ff:6a:e5:d8    31     Hit(31)
  2      8       internal2    00:09:0f:09:00:07    0      Local Static
  4      10      internal4    01:00:5e:00:00:05    12
`
	got := ParseBridgeFDB(output)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Interface != "internal3" || got[0].MACAddress != "e8:f6:d7:00:10:5b" {
		t.Errorf("row 0 wrong (MAC must be lowercase): %+v", got[0])
	}
	if got[1].Interface != "internal1" || got[1].MACAddress != "e0:23:ff:6a:e5:d8" {
		t.Errorf("row 1 wrong: %+v", got[1])
	}
}

// TestParseFreeBSDBridgeList: one name per line; unsafe names dropped;
// routed-only boxes (empty output) yield nil.
func TestParseFreeBSDBridgeList(t *testing.T) {
	if got := ParseFreeBSDBridgeList("bridge0\nbridge1\nbad name\n"); len(got) != 2 || got[0] != "bridge0" || got[1] != "bridge1" {
		t.Fatalf("got %v, want [bridge0 bridge1]", got)
	}
	if got := ParseFreeBSDBridgeList(""); len(got) != 0 {
		t.Fatalf("routed-only box must yield nothing, got %v", got)
	}
}

// TestParseFreeBSDBridgeFDB: learned rows keep the member interface, both
// with and without the Vlan column (FreeBSD version drift); STATIC/STICKY,
// multicast and zero MACs dropped.
func TestParseFreeBSDBridgeFDB(t *testing.T) {
	output := `	58:9c:fc:10:ff:a1 Vlan1 vtnet0 1141 flags=0<>
	E8:F6:D7:00:10:5B Vlan1 igb1 900 flags=0<>
	00:09:0f:09:00:07 Vlan1 igb0 0 flags=3<STATIC,STICKY>
	01:00:5e:00:00:05 Vlan1 igb1 12 flags=0<>
	aa:bb:cc:dd:ee:01 em0 300 flags=0<>
`
	got := ParseFreeBSDBridgeFDB(output)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(got), got)
	}
	if got[0].Interface != "vtnet0" || got[0].MACAddress != "58:9c:fc:10:ff:a1" {
		t.Errorf("row 0 wrong: %+v", got[0])
	}
	if got[1].Interface != "igb1" || got[1].MACAddress != "e8:f6:d7:00:10:5b" {
		t.Errorf("row 1 wrong (MAC must be lowercase): %+v", got[1])
	}
	if got[2].Interface != "em0" {
		t.Errorf("no-Vlan-column row wrong: %+v", got[2])
	}
}
