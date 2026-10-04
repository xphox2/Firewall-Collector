package main

import (
	"fmt"
	"testing"
	"time"

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

// TestShouldLogUnresolvedFortiOS_RateLimitAndBound: the unresolved-FortiOS
// hint fires once per source IP, again only after unresolvedFortiOSLogEvery,
// and the map it keeps cannot grow past unresolvedFortiOSLogMaxIPs under a
// spoofed-source flood (new IPs are suppressed until old entries expire).
func TestShouldLogUnresolvedFortiOS_RateLimitAndBound(t *testing.T) {
	c := &Collector{}
	t0 := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	if !c.shouldLogUnresolvedFortiOS("192.0.2.50", t0) {
		t.Fatal("first sighting must log")
	}
	if c.shouldLogUnresolvedFortiOS("192.0.2.50", t0.Add(unresolvedFortiOSLogEvery-time.Second)) {
		t.Error("repeat inside the interval must not log")
	}
	if !c.shouldLogUnresolvedFortiOS("192.0.2.50", t0.Add(unresolvedFortiOSLogEvery)) {
		t.Error("repeat after the interval must log again")
	}
	if !c.shouldLogUnresolvedFortiOS("192.0.2.51", t0) {
		t.Error("a different IP is independent")
	}

	// Flood: fill the map with distinct IPs at t0; the one past the cap is
	// suppressed, and the map stays bounded.
	for i := len(c.unresolvedFortiOSLogged); i < unresolvedFortiOSLogMaxIPs; i++ {
		c.shouldLogUnresolvedFortiOS(fmt.Sprintf("2001:db8::%x", i), t0)
	}
	if c.shouldLogUnresolvedFortiOS("203.0.113.9", t0.Add(time.Minute)) {
		t.Error("new IP with a full map of fresh entries must be suppressed")
	}
	if n := len(c.unresolvedFortiOSLogged); n != unresolvedFortiOSLogMaxIPs {
		t.Errorf("map holds %d entries, want exactly the cap %d", n, unresolvedFortiOSLogMaxIPs)
	}
	// Once the entries are stale they are evicted and the new IP logs.
	if !c.shouldLogUnresolvedFortiOS("203.0.113.9", t0.Add(unresolvedFortiOSLogEvery+time.Minute)) {
		t.Error("new IP after the old entries expired must log")
	}
	if n := len(c.unresolvedFortiOSLogged); n > unresolvedFortiOSLogMaxIPs {
		t.Errorf("map holds %d entries after eviction, want <= %d", n, unresolvedFortiOSLogMaxIPs)
	}
}
