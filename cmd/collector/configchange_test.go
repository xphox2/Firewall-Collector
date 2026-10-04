package main

import (
	"testing"

	"firewall-collector/internal/relay"
	"firewall-collector/internal/syslog"
)

// fortiOSCommitRFC5424 is a FortiGate config commit as emitted with
// `set format rfc5424` — the body a FortiGate writes whatever its framing.
const fortiOSCommitRFC5424 = `<189>1 2025-04-10T05:23:12Z fw-example-01 - - - - date=2025-04-10 time=05:23:12 devname="fw-example-01" logid="0100044546" type="event" subtype="system" user="alice" action="Edit" cfgtid=821297153 cfgpath="system.global" msg="Edit system.global"`

// TestConfigChangeFor_ResolvesDeviceVendorFirst: the handler resolves the
// sending device by source IP and dispatches on ITS vendor. The same RFC
// 5424-framed FortiOS commit schedules a backup for the FortiGate at that IP
// (with the commit's transaction id, user and path), and is ignored when the
// source IP belongs to a non-FortiGate device, to a device with no vendor, or
// to nobody — a FortiOS body cannot pick its own target.
func TestConfigChangeFor_ResolvesDeviceVendorFirst(t *testing.T) {
	c := &Collector{devices: []relay.DeviceInfo{
		{ID: 1, Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"},
		{ID: 2, Name: "fw-example-02", IPAddress: "192.0.2.2", Vendor: "opnsense"},
		{ID: 3, Name: "fw-example-03", IPAddress: "192.0.2.3"},
	}}
	parse := func(t *testing.T, sourceIP string) *relay.SyslogMessage {
		t.Helper()
		msg, err := syslog.ParseRFC5424([]byte(fortiOSCommitRFC5424))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if msg.Format != string(syslog.FormatRFC5424) {
			t.Fatalf("framed %q, want rfc5424 (test precondition)", msg.Format)
		}
		msg.SourceIP = sourceIP
		return msg
	}

	dev, ev, ok := c.configChangeFor(parse(t, "192.0.2.1"))
	if !ok {
		t.Fatal("rfc5424-framed FortiOS commit from the FortiGate's IP did not schedule a backup")
	}
	if dev.ID != 1 {
		t.Errorf("resolved device %d, want 1 (by source IP)", dev.ID)
	}
	want := syslog.ConfigChangeEvent{Format: syslog.FormatRFC5424, EventID: "0100044546", TxnID: "821297153", Path: "system.global", Action: "Edit", User: "alice"}
	if ev != want {
		t.Errorf("event = %+v, want %+v", ev, want)
	}

	for name, ip := range map[string]string{
		"non-FortiGate device":  "192.0.2.2",
		"device with no vendor": "192.0.2.3",
		"unknown source":        "198.51.100.9",
		"no source IP":          "",
	} {
		if dev, ev, ok := c.configChangeFor(parse(t, ip)); ok {
			t.Errorf("%s (%q): FortiOS commit body scheduled a backup for device %d: %+v", name, ip, dev.ID, ev)
		}
	}
}
