package syslog

import (
	"strings"
	"testing"
	"time"
)

// A synthetic FortiOS traffic line in the exact shape FortiOS 7.x emits
// (serial, addresses and timestamps are made up). Under the old positional
// parse this produced hostname=`devid="FGT60F0000000000"`,
// app_name=`eventtime=1767225600123456789`, process_id=`tz="+0000"`,
// message_id=`logid="0000000015"`, structured_data=`type="traffic"`, and a
// message that began mid-record at `subtype=`.
const syntheticFortiLine = `<189>date=2026-01-01 time=00:00:00 devname="FGT-60F" devid="FGT60F0000000000" ` +
	`eventtime=1767225600123456789 tz="+0000" logid="0000000015" type="traffic" subtype="forward" ` +
	`level="notice" vd="root" srcip=203.0.113.211 srcport=40000 srcintf="wan1" action="accept"`

func TestParseFortiOSKV_TrafficLine(t *testing.T) {
	msg, err := ParseRFC5424([]byte(syntheticFortiLine))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == nil {
		t.Fatal("expected non-nil message")
	}

	// The PRI is still decoded from the wire, not the KV body.
	if msg.Priority != 189 || msg.Facility != 23 || msg.Severity != 5 {
		t.Errorf("priority/facility/severity = %d/%d/%d, want 189/23/5",
			msg.Priority, msg.Facility, msg.Severity)
	}

	// app_name is the whole point: low-cardinality, and usable as a grouping key.
	if msg.AppName != "traffic" {
		t.Errorf("AppName = %q, want %q — a per-message-unique app_name makes "+
			"syslog_summaries emit one row per raw row", msg.AppName, "traffic")
	}
	if strings.Contains(msg.AppName, "eventtime") {
		t.Errorf("AppName still holds the eventtime fragment: %q", msg.AppName)
	}
	if msg.Hostname != "FGT-60F" {
		t.Errorf("Hostname = %q, want devname %q", msg.Hostname, "FGT-60F")
	}
	if msg.MessageID != "0000000015" {
		t.Errorf("MessageID = %q, want logid %q", msg.MessageID, "0000000015")
	}
	if msg.ProcessID != "" {
		t.Errorf("ProcessID = %q, want empty (was carrying the tz fragment)", msg.ProcessID)
	}
	if msg.StructuredData != "" {
		t.Errorf("StructuredData = %q, want empty (was carrying the type fragment)", msg.StructuredData)
	}

	// eventtime is ns since epoch; date/time are device-local and deliberately unused.
	want := time.Unix(0, 1767225600123456789).UTC()
	if !msg.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v (from eventtime)", msg.Timestamp, want)
	}

	// Message keeps the WHOLE record — logid/type/devname stop being lost, which
	// is additive for every server-side KV consumer.
	for _, needle := range []string{"date=", "devname=", `logid="0000000015"`, `type="traffic"`, `subtype="forward"`, `action="accept"`} {
		if !strings.Contains(msg.Message, needle) {
			t.Errorf("Message lost %q; got %q", needle, msg.Message)
		}
	}
}

// The gate must be structural. This fixture is a genuine RFC 5424 line that
// happens to carry `logid=` in its body — gating the FortiOS branch on that
// token would capture it and destroy its parse. Guards the same property the
// pre-existing TestParseRFC5424_FortiGateTypical asserts, stated as intent.
func TestParseRFC5424_LogidInBodyDoesNotTriggerKVBranch(t *testing.T) {
	line := `<189> 1 2025-04-10T05:01:53.000000-07:00 FGT-1000 fglog 1234 MSG-001 [origin] date=2025-04-10 logid="0100044547"`
	msg, err := ParseRFC5424([]byte(line))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.AppName != "fglog" {
		t.Errorf("AppName = %q, want %q — an RFC 5424 line carrying logid= in its "+
			"body must NOT be routed through the FortiOS key=value branch",
			msg.AppName, "fglog")
	}
	if msg.MessageID != "MSG-001" {
		t.Errorf("MessageID = %q, want %q", msg.MessageID, "MSG-001")
	}
	if msg.StructuredData != "[origin]" {
		t.Errorf("StructuredData = %q, want %q", msg.StructuredData, "[origin]")
	}
}

func TestParseFortiEventTime(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		ok   bool
		want time.Time
	}{
		{"nanoseconds (FortiOS 7.x)", "1767225600123456789", true, time.Unix(0, 1767225600123456789).UTC()},
		{"seconds (FortiOS 6.x)", "1767225600", true, time.Unix(1767225600, 0).UTC()},
		{"empty", "", false, time.Time{}},
		{"not a number", "abc", false, time.Time{}},
		{"zero", "0", false, time.Time{}},
		{"negative", "-5", false, time.Time{}},
		// A malformed field must not be able to backdate a row past a retention
		// cutoff or into an unexpected partition.
		{"absurdly small", "1", false, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFortiEventTime(tc.raw)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
