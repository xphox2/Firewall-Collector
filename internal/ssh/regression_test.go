package ssh

import "testing"

// Regression v1.2.45: sensorLineRegex unit group changed from \w+ to [^\w]+,
// which shifted capture groups and broke all single-line sensor parsing.
// The \.+ dot-separator must remain the literal dot-one-or-more pattern.
func TestRegression_SensorRegex_DotSeparatorParsed(t *testing.T) {
	output := "  1  CPU Core Temp   .........   52.0   C    Normal\n"
	sensors := ParseSensorInfo(output)
	if len(sensors) == 0 {
		t.Fatal("v1.2.45 regression: dot-separator sensor line not parsed (regex broken)")
	}
	if sensors[0].Value != 52.0 {
		t.Errorf("v1.2.45 regression: Value = %v, want 52.0 (capture groups shifted)", sensors[0].Value)
	}
	if sensors[0].Unit != "C" {
		t.Errorf("v1.2.45 regression: Unit = %q, want \"C\"", sensors[0].Unit)
	}
}

// Regression: sensorLineRegex must handle non-\w unit characters such as %.
// Storage sensors report usage as "42.0 %" which was silently mis-parsed
// when the unit group was \w+ (digits leaked into the value, % into status).
func TestRegression_SensorUnit_PercentParsed(t *testing.T) {
	output := "  5  SSD Usage   .....  42.0  %    Normal\n"
	sensors := ParseSensorInfo(output)
	if len(sensors) == 0 {
		t.Fatal("% unit sensor line not parsed")
	}
	if sensors[0].Unit != "%" {
		t.Errorf("Unit = %q, want \"%%\" (\\w+ regex excludes %%)", sensors[0].Unit)
	}
	if sensors[0].Value != 42.0 {
		t.Errorf("Value = %v, want 42.0", sensors[0].Value)
	}
}

// Regression v1.2.46: $ in a config line value was treated as a CLI prompt
// and stripped by cleanOutput. Dollar signs in set values must pass through.
func TestRegression_DollarInConfigValue_NotFiltered(t *testing.T) {
	output := `set alias "FortiGate-100E$"
set password "$p@ssword123"
set description "cost: $0.00"
`
	cleaned := cleanOutput(output)
	if cleaned == "" {
		t.Fatal("all content stripped — dollar-in-value regression active")
	}
	// At least the set lines with $ in the value should survive
	if !contains(cleaned, "set alias") {
		t.Error("'set alias' line with $ in value was stripped (isCLIPrompt false-positive)")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Regression: last VPN phase1 tunnel must always be present in results.
// If the post-loop `append` is removed, a single-entry output returns empty.
func TestRegression_VPNPhase1_LastTunnelAlwaysPresent(t *testing.T) {
	output := `config vpn ipsec phase1-interface
    edit "SOLE-VPN"
        set type tunnel
        set remote-gw 10.0.0.1
end`
	tunnels := ParseVPNPhase1(output)
	if len(tunnels) == 0 {
		t.Fatal("regression: last VPN phase1 tunnel not returned (missing post-loop append)")
	}
	if tunnels[0].Name != "SOLE-VPN" {
		t.Errorf("Name = %q, want SOLE-VPN", tunnels[0].Name)
	}
}

// Regression: last VPN phase2 tunnel must always be present in results.
func TestRegression_VPNPhase2_LastTunnelAlwaysPresent(t *testing.T) {
	output := `config vpn ipsec phase2-interface
    edit "SOLE-P2"
        set phase1name "SOLE-VPN"
end`
	tunnels := ParseVPNPhase2(output)
	if len(tunnels) == 0 {
		t.Fatal("regression: last VPN phase2 tunnel not returned (missing post-loop append)")
	}
}

// Regression: last interface must always be present in ParseInterfaceList results.
func TestRegression_InterfaceList_LastInterfaceAlwaysPresent(t *testing.T) {
	output := `Name: wan1
        RX bytes 100  errors 0  discards 0
`
	ifaces := ParseInterfaceList(output)
	if len(ifaces) == 0 {
		t.Fatal("regression: last interface not returned (missing post-loop append)")
	}
}

// Regression: memory values must be multiplied by 1024 after parsing.
// ParsePerformanceStatus parses kibibyte values and must scale to bytes.
func TestRegression_PerformanceStatus_MemoryNotScaled(t *testing.T) {
	output := `Memory: 1000k total, 500k used (50.0%), 400k free (40.0%), 100k freeable (10.0%)`
	info := ParsePerformanceStatus(output)
	if info.MemoryTotal == 1000 {
		t.Error("regression: MemoryTotal is raw kibibytes (1000), must be bytes (1024000) — ×1024 missing")
	}
	if info.MemoryTotal != 1000*1024 {
		t.Errorf("MemoryTotal = %d, want %d", info.MemoryTotal, 1000*1024)
	}
}
