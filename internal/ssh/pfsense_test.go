package ssh

import (
	"strings"
	"testing"
)

// TestNewConfigBackupClient_PfSense pins the vendor dispatch. Before this,
// "pfsense" hit the default branch and returned an error, so a pfSense device
// silently produced no config backups at all — the server could register a
// parser for it and still never receive a byte.
func TestNewConfigBackupClient_PfSense(t *testing.T) {
	c, err := NewConfigBackupClient("pfsense", "10.0.0.1", 22, "admin", "pw")
	if err != nil {
		t.Fatalf("pfsense should be supported: %v", err)
	}
	if _, ok := c.(*PfSenseClient); !ok {
		t.Fatalf("got %T, want *PfSenseClient", c)
	}
}

// TestPfSenseClient_InterfaceSatisfied is a compile-time guard: the assignment
// fails to build if a method drifts off the interface.
func TestPfSenseClient_InterfaceSatisfied(t *testing.T) {
	var _ ConfigBackupClient = NewPfSenseClient("h", 22, "u", "p")
}

// TestExtractXMLConfig_RootElementIsNotShared is the trap this client exists to
// avoid. pfSense's root is <pfsense>; reusing OPNsense's <opnsense> matcher
// rejects every backup a pfSense device produces, and reusing pfSense's matcher
// on OPNsense does the same in reverse. Neither failure is visible except as
// "config backup never works for this vendor".
func TestExtractXMLConfig_RootElementIsNotShared(t *testing.T) {
	const pf = `<?xml version="1.0"?><pfsense><system><hostname>fw</hostname></system></pfsense>`
	const opn = `<?xml version="1.0"?><opnsense><system><hostname>fw</hostname></system></opnsense>`

	if _, err := extractXMLConfig(pf, "pfsense", pfsenseConfigPath); err != nil {
		t.Errorf("pfSense config rejected by its own root matcher: %v", err)
	}
	if _, err := extractXMLConfig(pf, "opnsense", opnsenseConfigPath); err == nil {
		t.Error("a pfSense config was accepted by the OPNsense root matcher — the roots must not be interchangeable")
	}
	if _, err := extractOPNsenseConfig(opn); err != nil {
		t.Errorf("OPNsense extraction regressed after generalisation: %v", err)
	}
	if _, err := extractOPNsenseConfig(pf); err == nil {
		t.Error("the OPNsense matcher accepted a pfSense config")
	}
}

// TestExtractXMLConfig_ToleratesShellNoise covers the realistic capture: a login
// banner before the document and a shell prompt after it must not end up in the
// stored configuration, or every backup diffs on the banner.
func TestExtractXMLConfig_ToleratesShellNoise(t *testing.T) {
	const want = `<?xml version="1.0"?><pfsense><system/></pfsense>`
	raw := "Last login: Mon Jul 31 12:00:00 2026\n*** Welcome to pfSense ***\n" + want + "\nadmin@fw:~ # "

	got, err := extractXMLConfig(raw, "pfsense", pfsenseConfigPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("extractXMLConfig() = %q, want %q", got, want)
	}
}

// TestExtractXMLConfig_RejectsTruncated pins the failure mode that matters most
// downstream: a single-document config truncated mid-capture would make the
// server's object parser report the ENTIRE configuration as removed. Better to
// fail the capture here than store it.
func TestExtractXMLConfig_RejectsTruncated(t *testing.T) {
	cases := map[string]string{
		"no root":           "cat: /conf/config.xml: Permission denied\n",
		"unclosed root":     `<?xml version="1.0"?><pfsense><system><hostname>fw`,
		"console menu":      "0) Logout\t\t8) Shell\nEnter an option: ",
		"empty output":      "",
		"close before open": `</pfsense><?xml version="1.0"?>`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := extractXMLConfig(in, "pfsense", pfsenseConfigPath); err == nil {
				t.Errorf("expected an error for %q, got none — a bad capture would be stored as a real revision", name)
			}
		})
	}
}

// TestPfSenseClient_NotConnected pins that the methods fail rather than panic
// before Connect.
func TestPfSenseClient_NotConnected(t *testing.T) {
	c := NewPfSenseClient("10.0.0.1", 22, "admin", "pw")
	if _, err := c.GetConfig(); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Errorf("GetConfig() before Connect: got %v, want a not-connected error", err)
	}
	if _, err := c.GetConfigChecksum(); err == nil {
		t.Error("GetConfigChecksum() before Connect should fail")
	}
	if c.ObservedHostKey() != "" {
		t.Error("ObservedHostKey() should be empty before Connect")
	}
	c.Close() // must not panic on a never-connected client
}

// TestNewPfSenseClient_DefaultPort pins the zero-port default, so a device row
// with no explicit SSH port still dials 22.
func TestNewPfSenseClient_DefaultPort(t *testing.T) {
	if got := NewPfSenseClient("h", 0, "u", "p").port; got != 22 {
		t.Errorf("port = %d, want 22", got)
	}
}
