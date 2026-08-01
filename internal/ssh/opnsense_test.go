package ssh

import "testing"

func TestNewConfigBackupClient_VendorDispatch(t *testing.T) {
	tests := []struct {
		vendor  string
		wantErr bool
		// wantType is checked via a type switch below.
		wantFortiGate bool
		wantOPNsense  bool
		wantPfSense   bool
		wantPaloAlto  bool
	}{
		{vendor: "fortigate", wantFortiGate: true},
		{vendor: "", wantFortiGate: true}, // legacy default
		{vendor: "opnsense", wantOPNsense: true},
		{vendor: "paloalto", wantPaloAlto: true},
		{vendor: "pfsense", wantPfSense: true},
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
			case *PfSenseClient:
				if !tt.wantPfSense {
					t.Fatalf("vendor %q: got PfSenseClient, did not expect it", tt.vendor)
				}
			case *PaloAltoClient:
				if !tt.wantPaloAlto {
					t.Fatalf("vendor %q: got PaloAltoClient, did not expect it", tt.vendor)
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
	var _ ConfigBackupClient = NewPfSenseClient("h", 22, "u", "p")
}

func TestExtractOPNsenseConfig(t *testing.T) {
	const doc = `<?xml version="1.0"?>` + "\n<opnsense>\n  <system><hostname>fw</hostname></system>\n</opnsense>"
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"clean document", doc, doc, false},
		{"trailing newline from cat", doc + "\n", doc, false},
		{"leading shell/stderr noise", "Last login: Tue\ncsh: no such file\n" + doc, doc, false},
		{"trailing prompt noise", doc + "\nroot@fw:~ # ", doc, false},
		{"no xml decl, bare root", "<opnsense>\n<x/>\n</opnsense>", "<opnsense>\n<x/>\n</opnsense>", false},
		{"truncated: missing close tag", `<?xml version="1.0"?>` + "\n<opnsense>\n<system>", "", true},
		{"not a config (permission denied)", "cat: /conf/config.xml: Permission denied", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractOPNsenseConfig(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("extractOPNsenseConfig() = %q, want %q", got, tt.want)
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
