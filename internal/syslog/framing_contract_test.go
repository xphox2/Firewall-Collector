package syslog

import (
	"testing"
)

// v6FormatValues is the closed set of `format` values the relay schema v6
// framing contract promises the server (relay.SchemaVersionMax = 6). A new
// value is a wire-format change and must bump the schema on both repos.
var v6FormatValues = map[Format]bool{
	FormatFortiOSKV: true,
	FormatRFC5424:   true,
	FormatRFC3164:   true,
	FormatMeraki:    true,
	FormatCEF:       true,
	FormatRaw:       true,
}

// TestParse_EveryBranchSetsFormat pins the schema v6 framing contract at the
// dispatcher: every branch of parseSyslog — each detectFraming outcome, the
// RFC 3164 line that parseBSD declines, the CEF relabel over either header and
// the bare-PRI raw fallback — returns a row whose Format is non-empty and one
// of the six documented values. A v6 server skips its re-framing fallback on
// that promise, so an unlabelled row would be stored with whatever columns the
// collector guessed and never re-parsed. TestParse_Golden checks the same on
// the fixture corpus; this test names each branch so a new one cannot ship
// without a labelled line here.
func TestParse_EveryBranchSetsFormat(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Format
	}{
		{"fortios_kv", `<189>date=2025-10-12 time=00:00:00 devname="fw-example-01" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.10 dstip=198.51.100.20 action="deny"`, FormatFortiOSKV},
		{"rfc5424 conformant", `<165>1 2025-10-12T00:00:00Z fw-example-01 sshd 123 ID47 - accepted alice from 192.0.2.10`, FormatRFC5424},
		{"rfc5424 lenient space", `<165> 1 2025-10-12T00:00:00Z fw-example-01 sshd - - - accepted alice from 192.0.2.10`, FormatRFC5424},
		{"rfc5424 nilvalue timestamp", `<165>1 - fw-example-01 sshd - - - accepted alice from 192.0.2.10`, FormatRFC5424},
		{"rfc3164", `<13>Oct 12 00:00:00 fw-example-01 sshd[123]: accepted alice from 192.0.2.10`, FormatRFC3164},
		{"rfc3164 declined by parseBSD -> raw", `<13>Oct 32 22:14:15 fw-example-01 impossible day`, FormatRaw},
		{"meraki", `<134>1 1760227200.123456 fw-example-01 flows src=192.0.2.10 dst=198.51.100.7 mac=00:00:5E:00:53:0A protocol=udp sport=55719 dport=53 pattern: allow all`, FormatMeraki},
		{"cef over rfc5424", `<134>1 2025-10-12T00:00:00Z fw-example-01 ulog-cef - - - CEF:0|Ubiquiti|UniFi|1.0|100|Firewall Block|5|src=192.0.2.10 dst=198.51.100.20`, FormatCEF},
		{"cef over rfc3164", `<134>Oct 12 00:00:00 fw-example-01 ulog-cef: CEF:0|Ubiquiti|UniFi|1.0|100|Firewall Block|5|src=192.0.2.10 dst=198.51.100.20`, FormatCEF},
		{"raw", `<13>something without a recognised header`, FormatRaw},
	}

	seen := map[Format]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := parseSyslog([]byte(tc.line), goldenNow)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if msg.Format == "" {
				t.Fatalf("Format is empty — the v6 contract requires every dispatcher branch to label its row")
			}
			if !v6FormatValues[Format(msg.Format)] {
				t.Errorf("Format = %q is not one of the six v6 values %v", msg.Format, v6FormatValues)
			}
			if msg.Format != string(tc.want) {
				t.Errorf("Format = %q, want %q", msg.Format, tc.want)
			}
			seen[Format(msg.Format)] = true
		})
	}

	// The table must exercise every documented value, or a branch could lose
	// its label without any case above noticing.
	for f := range v6FormatValues {
		if !seen[f] {
			t.Errorf("no case produced Format %q — add one for that dispatcher branch", f)
		}
	}
}
