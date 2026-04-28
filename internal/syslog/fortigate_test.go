package syslog

import (
	"testing"

	"firewall-collector/internal/relay"
)

func TestParseFortiEventConfigObjAttr(t *testing.T) {
	// Real-shape FortiOS event-log line, condensed.
	msg := &relay.SyslogMessage{
		Message: `date=2025-04-10 time=05:01:53 logid="0100044547" type="event" subtype="system" level="information" vd="root" user="admin" ui="GUI(10.32.22.115)" action="Add" cfgtid=126746708 cfgpath="firewall.policy" cfgobj="8" cfgattr="name[testconfig]"`,
	}
	ev := ParseFortiEvent(msg)
	if ev == nil {
		t.Fatal("expected non-nil FortiEvent")
	}
	if !ev.IsConfigChange() {
		t.Errorf("logid %q must be recognized as config change", ev.Logid)
	}
	if ev.Logid != "0100044547" {
		t.Errorf("logid: got %q", ev.Logid)
	}
	if ev.Cfgtid != "126746708" {
		t.Errorf("cfgtid: got %q", ev.Cfgtid)
	}
	if ev.Cfgpath != "firewall.policy" {
		t.Errorf("cfgpath: got %q", ev.Cfgpath)
	}
	if ev.Cfgobj != "8" {
		t.Errorf("cfgobj: got %q", ev.Cfgobj)
	}
	if ev.Action != "Add" {
		t.Errorf("action: got %q", ev.Action)
	}
	if ev.User != "admin" {
		t.Errorf("user: got %q", ev.User)
	}
	if ev.UI != "GUI(10.32.22.115)" {
		t.Errorf("ui: got %q", ev.UI)
	}
}

func TestParseFortiEventConfigAttr(t *testing.T) {
	msg := &relay.SyslogMessage{
		Message: `date=2025-04-10 time=05:23:12 logid="0100044546" type="event" subtype="system" level="information" ui="jsconsole(10.32.22.115)" action="Edit" cfgtid=821297153 cfgpath="system.global" cfgattr="admintimeout[5->120]" msg="Edit system.global"`,
	}
	ev := ParseFortiEvent(msg)
	if ev == nil {
		t.Fatal("expected non-nil FortiEvent")
	}
	if !ev.IsConfigChange() {
		t.Errorf("0100044546 must be recognized as config change")
	}
	if ev.Cfgpath != "system.global" {
		t.Errorf("cfgpath: got %q", ev.Cfgpath)
	}
}

func TestParseFortiEventNonConfigEvent(t *testing.T) {
	msg := &relay.SyslogMessage{
		Message: `logid="0102043008" type="event" subtype="user" action="login" user="admin"`,
	}
	ev := ParseFortiEvent(msg)
	if ev == nil {
		t.Fatal("expected non-nil FortiEvent (any logid produces one)")
	}
	if ev.IsConfigChange() {
		t.Errorf("login event must NOT be flagged as config change")
	}
}

func TestParseFortiEventNoLogid(t *testing.T) {
	msg := &relay.SyslogMessage{
		Message: `<14>some random non-FortiGate syslog line`,
	}
	ev := ParseFortiEvent(msg)
	if ev != nil {
		t.Errorf("non-FortiGate body must return nil, got %+v", ev)
	}
}

func TestParseFortiEventEmptyMessage(t *testing.T) {
	if ev := ParseFortiEvent(&relay.SyslogMessage{Message: ""}); ev != nil {
		t.Errorf("empty body must return nil, got %+v", ev)
	}
	if ev := ParseFortiEvent(nil); ev != nil {
		t.Errorf("nil msg must return nil, got %+v", ev)
	}
}

func TestParseKVPairsQuotedAndUnquoted(t *testing.T) {
	in := `key1="value with spaces" key2=valueNoSpaces key3="" key4=`
	m := parseKVPairs(in)
	if m["key1"] != "value with spaces" {
		t.Errorf("key1: got %q", m["key1"])
	}
	if m["key2"] != "valueNoSpaces" {
		t.Errorf("key2: got %q", m["key2"])
	}
	if m["key3"] != "" {
		t.Errorf("key3: got %q (want empty)", m["key3"])
	}
	if _, ok := m["key4"]; !ok {
		t.Errorf("key4: should be present even with empty value")
	}
}
