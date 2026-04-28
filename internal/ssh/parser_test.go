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

// Uptime days must be converted to seconds (days × 86400).
func TestParsePerformanceStatus_UptimeDaysToSeconds(t *testing.T) {
	output := `Uptime: 42 days`
	info := ParsePerformanceStatus(output)
	want := uint64(42 * 86400)
	if info.Uptime != want {
		t.Errorf("Uptime = %d, want %d", info.Uptime, want)
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
