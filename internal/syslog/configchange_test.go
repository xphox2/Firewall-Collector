package syslog

import (
	"testing"

	"firewall-collector/internal/relay"
)

// fortiOSConfigLine is a FortiOS event-log config commit, condensed, as the
// device emits it on the wire (PRI then `date=` with no space).
const fortiOSConfigLine = `<189>date=2025-04-10 time=05:23:12 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1744262592000000000 tz="+0000" logid="0100044546" type="event" subtype="system" level="information" vd="root" user="alice" ui="jsconsole(192.0.2.10)" action="Edit" cfgtid=821297153 cfgpath="system.global" cfgattr="admintimeout[5->120]" msg="Edit system.global"`

// TestDetectConfigChange_OnlyFortiOSFraming: the detector registry is keyed
// by the framing the dispatcher labelled the row with, so a FortiOS config
// event id inside the body of a BSD line (a non-FortiGate device logging
// about, or relaying, FortiGate output; or a spoofed line) must not schedule a
// FortiOS backup against whatever device owns that source IP. The same body
// framed as FortiOS key=value does.
func TestDetectConfigChange_OnlyFortiOSFraming(t *testing.T) {
	bsd, err := ParseRFC5424([]byte(`<13>Oct 11 22:14:15 fw-example-02 sshd[123]: forwarded logid="0100044546" type="event" cfgtid=821297153 cfgpath="system.global" action="Edit"`))
	if err != nil {
		t.Fatalf("BSD line did not parse: %v", err)
	}
	if bsd.Format != string(FormatRFC3164) {
		t.Fatalf("BSD line framed as %q, want rfc3164 (test precondition)", bsd.Format)
	}
	if ev, ok := DetectConfigChange(bsd); ok {
		t.Errorf("BSD-framed line with logid=0100044546 in its body detected as config change: %+v — detection must key on msg.Format, not on the body", ev)
	}

	kv, err := ParseRFC5424([]byte(fortiOSConfigLine))
	if err != nil {
		t.Fatalf("FortiOS line did not parse: %v", err)
	}
	if kv.Format != string(FormatFortiOSKV) {
		t.Fatalf("FortiOS line framed as %q, want fortios_kv (test precondition)", kv.Format)
	}
	ev, ok := DetectConfigChange(kv)
	if !ok {
		t.Fatal("FortiOS config-change line not detected")
	}
	want := ConfigChangeEvent{Format: FormatFortiOSKV, EventID: "0100044546", TxnID: "821297153", Path: "system.global", Action: "Edit", User: "alice"}
	if ev != want {
		t.Errorf("event = %+v, want %+v", ev, want)
	}
}

// TestDetectConfigChange_NonCommitAndUnframed: a FortiOS line that is not a
// config commit, a row without a format (an older collector's spillover
// queue drained after an upgrade), and a nil message all report no change.
func TestDetectConfigChange_NonCommitAndUnframed(t *testing.T) {
	login, err := ParseRFC5424([]byte(`<189>date=2025-04-10 time=05:23:12 devname="fw-example-01" logid="0102043008" type="event" subtype="user" action="login" user="alice"`))
	if err != nil {
		t.Fatalf("FortiOS login line did not parse: %v", err)
	}
	if _, ok := DetectConfigChange(login); ok {
		t.Error("FortiOS login event detected as config change")
	}
	unframed := &relay.SyslogMessage{Message: `logid="0100044547" cfgtid=1 cfgpath="firewall.policy"`}
	if _, ok := DetectConfigChange(unframed); ok {
		t.Error("row with no format detected as config change")
	}
	if _, ok := DetectConfigChange(nil); ok {
		t.Error("nil message detected as config change")
	}
}
