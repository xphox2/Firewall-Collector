package ssh

import "testing"

func TestNewConfigBackupClient_VendorDispatch(t *testing.T) {
	tests := []struct {
		vendor  string
		wantErr bool
		// wantType is checked via a type switch below.
		wantFortiGate bool
		wantOPNsense  bool
	}{
		{vendor: "fortigate", wantFortiGate: true},
		{vendor: "", wantFortiGate: true}, // legacy default
		{vendor: "opnsense", wantOPNsense: true},
		{vendor: "pfsense", wantErr: true},
		{vendor: "bogus", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			c, err := NewConfigBackupClient(tt.vendor, "10.0.0.1", 22, "user", "pass")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("vendor %q: expected error, got client %T", tt.vendor, c)
				}
				return
			}
			if err != nil {
				t.Fatalf("vendor %q: unexpected error: %v", tt.vendor, err)
			}
			switch c.(type) {
			case *FortiGateClient:
				if !tt.wantFortiGate {
					t.Fatalf("vendor %q: got FortiGateClient, did not expect it", tt.vendor)
				}
			case *OPNsenseClient:
				if !tt.wantOPNsense {
					t.Fatalf("vendor %q: got OPNsenseClient, did not expect it", tt.vendor)
				}
			default:
				t.Fatalf("vendor %q: unexpected client type %T", tt.vendor, c)
			}
		})
	}
}

// Both concrete clients must satisfy the ConfigBackupClient interface. This is a
// compile-time guard; the assignments fail to build if a method drifts.
func TestConfigBackupClient_InterfaceSatisfied(t *testing.T) {
	var _ ConfigBackupClient = NewFortiGateClient("h", 22, "u", "p")
	var _ ConfigBackupClient = NewOPNsenseClient("h", 22, "u", "p")
}

func TestParseHexHash(t *testing.T) {
	const validHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"sha256 -q bare hash with newline", validHash + "\n", validHash},
		{"default sha256 file form", "SHA256 (/conf/config.xml) = " + validHash + "\n", validHash},
		{"surrounding whitespace", "  " + validHash + "  ", validHash},
		{"empty output", "", ""},
		{"too short", "abc123", ""},
		{"right length but not hex", "zz" + validHash[2:], ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseHexHash(tt.in); got != tt.want {
				t.Errorf("parseHexHash(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// GetConfig / GetConfigChecksum must fail cleanly (not panic) when the client
// was never connected — the poll loop relies on an error here, not a crash.
func TestOPNsenseClient_NotConnected(t *testing.T) {
	c := NewOPNsenseClient("10.0.0.1", 22, "root", "pw")
	if _, err := c.GetConfig(); err == nil {
		t.Error("GetConfig on unconnected client: expected error, got nil")
	}
	if _, err := c.GetConfigChecksum(); err == nil {
		t.Error("GetConfigChecksum on unconnected client: expected error, got nil")
	}
}
