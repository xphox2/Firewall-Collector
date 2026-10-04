package syslog

import (
	"testing"

	"firewall-collector/internal/relay"
)

// fortiOSKVBody is a FortiOS event-log config commit, condensed.
const fortiOSKVBody = `date=2025-04-10 time=05:23:12 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1744262592000000000 tz="+0000" logid="0100044546" type="event" subtype="system" level="information" vd="root" user="alice" ui="jsconsole(192.0.2.10)" action="Edit" cfgtid=821297153 cfgpath="system.global" cfgattr="admintimeout[5->120]" msg="Edit system.global"`

var wantFortiOSCommit = ConfigChangeEvent{EventID: "0100044546", TxnID: "821297153", Path: "system.global", Action: "Edit", User: "alice"}

func mustParse(t *testing.T, line string, want Format) *relay.SyslogMessage {
	t.Helper()
	msg, err := ParseRFC5424([]byte(line))
	if err != nil {
		t.Fatalf("line did not parse: %v", err)
	}
	if msg.Format != string(want) {
		t.Fatalf("line framed as %q, want %s (test precondition)", msg.Format, want)
	}
	return msg
}

// TestDetectConfigChange_FortiGateAllFramings: a FortiGate emits the same
// key=value body whatever framing it is configured for — native, `set format
// rfc5424` (conformant, and the lenient `<PRI> 1 …` spelling the collector
// has always accepted), or behind a BSD header from a relay — and every one
// of them must keep scheduling a backup when the device is a FortiGate.
func TestDetectConfigChange_FortiGateAllFramings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		line   string
		format Format
	}{
		{"native fortios_kv", `<189>` + fortiOSKVBody, FormatFortiOSKV},
		{"rfc5424 conformant (set format rfc5424)", `<189>1 2025-04-10T05:23:12Z fw-example-01 - - - - ` + fortiOSKVBody, FormatRFC5424},
		{"rfc5424 lenient <PRI> 1", `<189> 1 2025-04-10T05:23:12.000000-07:00 fw-example-01 fglog 1234 MSG-001 [origin] ` + fortiOSKVBody, FormatRFC5424},
		{"rfc3164 relay", `<189>Apr 10 05:23:12 fw-example-01 fglog: ` + fortiOSKVBody, FormatRFC3164},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := mustParse(t, tc.line, tc.format)
			ev, ok := DetectConfigChange("fortigate", msg)
			if !ok {
				t.Fatalf("FortiOS config commit framed %s not detected for a fortigate device — syslog-triggered backups would silently stop for this FortiGate syslog mode", tc.format)
			}
			want := wantFortiOSCommit
			want.Format = tc.format
			if ev != want {
				t.Errorf("event = %+v, want %+v", ev, want)
			}
		})
	}
}

// TestDetectConfigChange_KeyedOnDeviceVendor: the detector registry is keyed
// by the vendor of the device the packet's source IP resolved to. The same
// FortiOS commit body from a device that is not a FortiGate (a non-FortiGate
// box relaying or logging FortiGate output, or a spoofed line aimed at it)
// must not schedule a FortiOS TFTP backup against that box, and an unresolved
// source (empty vendor) has nothing to detect for.
func TestDetectConfigChange_KeyedOnDeviceVendor(t *testing.T) {
	bsd := mustParse(t, `<13>Oct 11 22:14:15 fw-example-02 sshd[123]: forwarded `+fortiOSKVBody, FormatRFC3164)
	kv := mustParse(t, `<189>`+fortiOSKVBody, FormatFortiOSKV)
	for _, vendor := range []string{"", "generic", "opnsense", "unifi", "paloalto"} {
		for name, msg := range map[string]*relay.SyslogMessage{"bsd": bsd, "fortios_kv": kv} {
			if ev, ok := DetectConfigChange(vendor, msg); ok {
				t.Errorf("vendor %q, %s-framed line with logid=0100044546 detected as config change: %+v — detection must key on the resolved device vendor", vendor, name, ev)
			}
		}
	}
}

// TestDetectConfigChange_NonCommitAndNonFortiOSFramings: a FortiOS line that
// is not a config commit, a row without a format (an older collector's
// spillover queue drained after an upgrade), Meraki/raw-framed bodies (never
// FortiOS event logs), and a nil message all report no change.
func TestDetectConfigChange_NonCommitAndNonFortiOSFramings(t *testing.T) {
	login := mustParse(t, `<189>date=2025-04-10 time=05:23:12 devname="fw-example-01" logid="0102043008" type="event" subtype="user" action="login" user="alice"`, FormatFortiOSKV)
	if _, ok := DetectConfigChange("fortigate", login); ok {
		t.Error("FortiOS login event detected as config change")
	}
	meraki := mustParse(t, `<134>1 1712725313.123456 fw-example-01 events `+fortiOSKVBody, FormatMeraki)
	if _, ok := DetectConfigChange("fortigate", meraki); ok {
		t.Error("Meraki-framed body detected as a FortiOS config change")
	}
	for name, msg := range map[string]*relay.SyslogMessage{
		"no format": {Message: fortiOSKVBody},
		"raw":       {Format: string(FormatRaw), Message: fortiOSKVBody},
	} {
		if _, ok := DetectConfigChange("fortigate", msg); ok {
			t.Errorf("%s row detected as config change", name)
		}
	}
	if _, ok := DetectConfigChange("fortigate", nil); ok {
		t.Error("nil message detected as config change")
	}
}
