package snmp

import (
	"testing"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// D-31: device-supplied SNMP strings reach the DB, the logs and the UI. Control
// characters must not survive safeString; printable text and valid UTF-8 must.
func TestSafeString_NeutralisesControlCharacters(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
	}{
		{"CRLF log forging", []byte("fw01\r\n2026/01/01 forged line"), "fw01  2026/01/01 forged line"},
		{"ANSI escape", []byte("port1\x1b[2J\x1b]0;pwn\x07"), "port1 [2J ]0;pwn "},
		{"C1 CSI and DEL", "wan\u009b31m\x7f", "wan 31m "},
		{"NUL padding dropped", []byte("lan\x00\x00\x00"), "lan"},
		{"tab becomes space", "Cisco ASA\tVersion 9.8", "Cisco ASA Version 9.8"},
		{"valid UTF-8 kept", []byte("Zürich-東京 ✓"), "Zürich-東京 ✓"},
		{"plain unchanged", "FortiGate-60F v7.2.8", "FortiGate-60F v7.2.8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeString(tc.in); got != tc.want {
				t.Errorf("safeString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Invalid UTF-8 (a Latin-1 ifAlias) must come back as valid UTF-8 with the
// bad byte marked, not dropped silently and not passed through to the DB.
func TestSafeString_InvalidUTF8BecomesReplacementChar(t *testing.T) {
	got := safeString([]byte("Z\xfcrich"))
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
	if got != "Z�rich" {
		t.Fatalf("got %q, want %q", got, "Z�rich")
	}
}

// End to end through a profile parser: a sysName carrying CR/LF is stored clean.
func TestParseSystemStatus_HostnameControlCharsStripped(t *testing.T) {
	p := &GenericProfile{}
	st := p.ParseSystemStatus([]gosnmp.SnmpPDU{
		{Name: genOIDSysName, Type: gosnmp.OctetString, Value: []byte("edge\r\nINJECTED")},
	})
	if st.Hostname != "edge  INJECTED" {
		t.Fatalf("Hostname = %q, want control characters neutralised", st.Hostname)
	}
}
