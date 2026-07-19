package ssh

import "testing"

// PaloAltoClient must satisfy the ConfigBackupClient interface (compile-time
// guard; the assignment fails to build if a method drifts).
func TestPaloAltoClient_InterfaceSatisfied(t *testing.T) {
	var _ ConfigBackupClient = NewPaloAltoClient("h", 22, "u", "p")
}

func TestExtractPaloAltoConfig(t *testing.T) {
	const doc = `<config version="8.1.0" urldb="paloaltonetworks">` +
		"\n  <mgt-config><users/></mgt-config>\n</config>"
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"clean document", doc, doc, false},
		{"trailing newline", doc + "\n", doc, false},
		{"echoed command + prompt before root", "admin@PA-500> show config running\n" + doc, doc, false},
		{"trailing prompt noise", doc + "\nadmin@PA-500> ", doc, false},
		{"bare root no attrs", "<config>\n<x/>\n</config>", "<config>\n<x/>\n</config>", false},
		{"truncated: missing close tag", `<config version="8.1.0">` + "\n<mgt-config>", "", true},
		{"operational-mode error", "Invalid syntax.", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractPaloAltoConfig(tt.in)
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
				t.Errorf("extractPaloAltoConfig() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A prompt line that itself contains the literal "<config " must not be mistaken
// for the document root: the real <config …> element still wins because it comes
// first only when it actually precedes. Here the noise has no root, so extraction
// must fail rather than return a fragment.
func TestExtractPaloAltoConfig_NoRootInNoise(t *testing.T) {
	if _, err := extractPaloAltoConfig("could not find <config > element"); err == nil {
		t.Fatal("expected error when no complete <config>…</config> present")
	}
}

// GetConfig / GetConfigChecksum must fail cleanly (not panic) when the client
// was never connected — the poll loop relies on an error here, not a crash.
func TestPaloAltoClient_NotConnected(t *testing.T) {
	c := NewPaloAltoClient("10.0.0.1", 22, "admin", "pw")
	if _, err := c.GetConfig(); err == nil {
		t.Fatal("expected error from GetConfig on unconnected client")
	}
	if _, err := c.GetConfigChecksum(); err == nil {
		t.Fatal("expected error from GetConfigChecksum on unconnected client")
	}
}
