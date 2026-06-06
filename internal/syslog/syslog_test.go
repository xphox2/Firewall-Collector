package syslog

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

func TestParseRFC5424_FortiGateTypical(t *testing.T) {
	line := `<189> 1 2025-04-10T05:01:53.000000-07:00 FGT-1000 fglog 1234 MSG-001 [origin] date=2025-04-10 time=05:01:53 logid="0100044547"`
	msg, err := ParseRFC5424([]byte(line))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == nil {
		t.Fatal("expected non-nil message")
	}

	if msg.Priority != 189 {
		t.Errorf("Priority: got %d, want 189", msg.Priority)
	}
	if msg.Facility != 23 {
		t.Errorf("Facility: got %d, want 23 (189/8)", msg.Facility)
	}
	if msg.Severity != 5 {
		t.Errorf("Severity: got %d, want 5 (189%%8)", msg.Severity)
	}

	wantTime := time.Date(2025, 4, 10, 5, 1, 53, 0, time.FixedZone("", -7*60*60))
	if !msg.Timestamp.Equal(wantTime) {
		t.Errorf("Timestamp: got %v, want %v", msg.Timestamp, wantTime)
	}

	if msg.Hostname != "FGT-1000" {
		t.Errorf("Hostname: got %q, want %q", msg.Hostname, "FGT-1000")
	}
	if msg.AppName != "fglog" {
		t.Errorf("AppName: got %q, want %q", msg.AppName, "fglog")
	}
	if msg.ProcessID != "1234" {
		t.Errorf("ProcessID: got %q, want %q", msg.ProcessID, "1234")
	}
	if msg.MessageID != "MSG-001" {
		t.Errorf("MessageID: got %q, want %q", msg.MessageID, "MSG-001")
	}

	if msg.StructuredData != "[origin]" {
		t.Errorf("StructuredData: got %q, want %q", msg.StructuredData, "[origin]")
	}

	if msg.DeviceID != 1000 {
		t.Errorf("DeviceID: got %d, want 1000 (extracted from hostname FGT-1000)", msg.DeviceID)
	}

	if !strings.HasPrefix(msg.Message, "date=2025-04-10") {
		t.Errorf("Message should start with date=2025-04-10, got %q", msg.Message)
	}
}

func TestParseRFC5424_BSD3164Format(t *testing.T) {
	// BSD-style syslog lines (RFC 3164) lack the RFC 5424 VERSION field.
	// The parser splits on space and grabs <PRI>Oct as the first token
	// (the closing > of PRI is not followed by a space, so the timestamp
	// month ends up glued to the priority). The version slot then gets
	// the day-of-month, the timestamp slot gets HH:MM:SS alone, and
	// parseTimestamp can't make sense of any of the formats it tries
	// (none match a bare "22:14:15") and falls back to time.Now().
	// The line is still "accepted" — no hard error is returned — but
	// every metadata field after PRI is mis-aligned. This test pins
	// that current best-effort behaviour so it can't silently change.
	line := `<34>Oct 11 22:14:15 fw-host sshd[123]: Failed password for invalid user admin from 10.0.0.1`

	msg, err := ParseRFC5424([]byte(line))
	if err != nil {
		t.Fatalf("BSD-style line should not return error (falls back to time.Now()), got: %v", err)
	}
	if msg == nil {
		t.Fatal("expected non-nil message")
	}

	if msg.Priority != 34 {
		t.Errorf("Priority: got %d, want 34 (best-effort BSD extraction)", msg.Priority)
	}
	if msg.Facility != 4 {
		t.Errorf("Facility: got %d, want 4 (34/8)", msg.Facility)
	}
	if msg.Severity != 2 {
		t.Errorf("Severity: got %d, want 2 (34%%8)", msg.Severity)
	}
}

func TestParseRFC5424_MalformedPriority(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantErr      bool
		wantPriority int
	}{
		{
			name:         "non-numeric priority value",
			input:        `<abc> 1 2025-04-10T05:01:53.000000-07:00 h a p m - - msg`,
			wantErr:      false,
			wantPriority: 0,
		},
		{
			name:         "empty priority value",
			input:        `<> 1 2025-04-10T05:01:53.000000-07:00 h a p m - - msg`,
			wantErr:      false,
			wantPriority: 0,
		},
		{
			name:         "missing closing bracket",
			input:        `<0 2025-04-10T05:01:53.000000-07:00 h a p m - - msg`,
			wantErr:      false,
			wantPriority: 0,
		},
		{
			name:    "priority above 191",
			input:   `<999> 1 2025-04-10T05:01:53.000000-07:00 h a p m - - msg`,
			wantErr: true,
		},
		{
			name:    "no priority bracket at all",
			input:   `1 2025-04-10T05:01:53.000000-07:00 h a p m - - msg`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseRFC5424([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (msg=%+v)", msg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if msg == nil {
				t.Fatal("expected non-nil message")
			}
			if msg.Priority != tt.wantPriority {
				t.Errorf("Priority: got %d, want %d", msg.Priority, tt.wantPriority)
			}
		})
	}
}

func TestParsePriority_OutOfRange(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"<0>", false},
		{"<191>", false},
		{"<192>", true},
		{"<200>", true},
		{"<999>", true},
		{"<9999>", true},
		{"<>", false},
		{"<abc>", false},
		{"no-bracket", true},
		{"<", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parsePriority([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
			}
		})
	}
}

func TestParseTimestamp_AllSixFormats(t *testing.T) {
	// All six timestamp formats declared at syslog.go:342-349, plus
	// edge cases (nil marker, empty, garbage).
	tests := []struct {
		name    string
		ts      string
		wantErr bool
	}{
		{
			name: "RFC5424 microseconds with timezone",
			ts:   "2025-04-10T05:01:53.000000-07:00",
		},
		{
			name: "RFC5424 milliseconds UTC",
			ts:   "2025-04-10T05:01:53.000Z",
		},
		{
			name: "RFC5424 with timezone no fractional",
			ts:   "2025-04-10T05:01:53+02:00",
		},
		{
			name: "RFC5424 UTC no fractional",
			ts:   "2025-04-10T05:01:53Z",
		},
		{
			name: "BSD3164 single digit day",
			ts:   "Oct  1 05:01:53",
		},
		{
			name: "BSD3164 double digit day",
			ts:   "Oct 11 05:01:53",
		},
		{
			name: "simple yyyy-MM-dd HH:mm:ss",
			ts:   "2025-04-10 05:01:53",
		},
		{
			name: "nil marker",
			ts:   "-",
		},
		{
			name: "empty string",
			ts:   "",
		},
		{
			name:    "completely unparseable",
			ts:      "not a timestamp",
			wantErr: true,
		},
		{
			name:    "reversed date",
			ts:      "10-04-2025T05:01:53Z",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, err := parseTimestamp(1, tt.ts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.ts)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.ts, err)
			}
			if ts.IsZero() && tt.ts != "" && tt.ts != "-" {
				t.Errorf("expected non-zero time for %q", tt.ts)
			}
		})
	}
}

func TestExtractDeviceID_PfSense_NotMatched(t *testing.T) {
	tests := []struct {
		hostname string
		sd       string
	}{
		{"pfsense-fw-01", ""},
		{"opnsense-edge-01", ""},
		{"paloalto-fw", ""},
		{"cisco-asa-01", ""},
		{"linux-host", ""},
		{"fortios-router", ""},
		{"forti-extender", ""},
		{"FG-abc", ""},
		{"FGT", ""},
		{"fortigate-edge", ""},
	}
	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			if id := extractDeviceID(tt.hostname, tt.sd); id != 0 {
				t.Errorf("extractDeviceID(%q, %q) = %d, want 0 (only fg/fgt hostnames extract)", tt.hostname, tt.sd, id)
			}
		})
	}
}

func TestExtractDeviceID_BracketInUnrelatedField(t *testing.T) {
	// Documented bug: syslog.go:399 — the regex \[(\d+)\] matches ANY
	// bracketed number in the structured data, not just FortiGate-related
	// ones. A future fix should restrict to SD elements whose ID contains
	// "fortigate" or "fgt". If this test ever returns 0 for the second
	// case, the bug has been fixed — update this assertion accordingly.
	sd := `{"origin":{"x":[42]}}`
	id := extractDeviceID("", sd)
	if id != 42 {
		t.Errorf("expected current behavior to extract 42 from unrelated [42], got %d", id)
	}

	// Non-JSON SD with a literal bracketed number is also extracted,
	// even though the regex has no idea whether it's a FortiGate ID.
	id = extractDeviceID("", `[1234]`)
	if id != 1234 {
		t.Errorf("expected current behavior to extract 1234 from [1234], got %d", id)
	}
}

func TestExtractDeviceID_FortiGateHostnames(t *testing.T) {
	tests := []struct {
		hostname string
		want     uint
	}{
		{"FGT-1000", 1000},
		{"fgt-1000", 1000},
		{"fgt.1000", 1000},
		{"fgt_1000", 1000},
		{"FGT1234", 1234},
		{"FG100A-0042", 100},
		{"FGT-abc", 0},
		{"FGT", 0},
		{"", 0},
		{"-", 0},
	}
	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			if id := extractDeviceID(tt.hostname, ""); id != tt.want {
				t.Errorf("extractDeviceID(%q, \"\") = %d, want %d", tt.hostname, id, tt.want)
			}
		})
	}
}

func TestParseDeviceID_LeadingZeros(t *testing.T) {
	tests := []struct {
		input string
		want  uint
	}{
		{"0000123", 123},
		{"00100", 100},
		{"0", 0},
		{"00000", 0},
		{"", 0},
		{"100", 100},
		{"abc", 0},
		{"12a34", 1234},
		{"FGVM010000123456", 10000123456},
		{"0x10", 10},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := parseDeviceID(tt.input); got != tt.want {
				t.Errorf("parseDeviceID(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestHandleConnection_Overflow(t *testing.T) {
	var received atomic.Int32
	handler := func(msg *relay.SyslogMessage) {
		received.Add(1)
	}

	rcv := NewSyslogReceiver("127.0.0.1", 0)
	if err := rcv.Start(handler); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rcv.Stop() })

	tcpAddr, ok := rcv.listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("listener addr is not *net.TCPAddr")
	}

	// 1. Send a 100 KB line with no trailing newline. The receiver uses
	//    a 64 KB read buffer and resets its message buffer when it hits
	//    MaxMessageSize without seeing a newline, so the oversize line
	//    is silently dropped. The TCP connection must not be closed by
	//    the server.
	conn1, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port))
	if err != nil {
		t.Fatalf("Dial 1: %v", err)
	}
	big := bytes.Repeat([]byte("A"), 100*1024)
	if _, err := conn1.Write(big); err != nil {
		t.Fatalf("Write oversize: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	conn1.Close()

	if n := received.Load(); n != 0 {
		t.Errorf("handler called %d times for oversize line, want 0", n)
	}

	// 2. Open a new connection and send a valid line. The receiver must
	//    still be alive and processing — i.e. the oversize input did
	//    not crash the goroutine or close the listener.
	conn2, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port))
	if err != nil {
		t.Fatalf("Dial 2: %v", err)
	}
	t.Cleanup(func() { conn2.Close() })

	good := []byte("<13>1 2025-04-10T05:01:53.000000-07:00 h a p m - - hello\n")
	if _, err := conn2.Write(good); err != nil {
		t.Fatalf("Write good: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if received.Load() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := received.Load(); n != 1 {
		t.Errorf("handler called %d times after valid line, want 1 (receiver must survive oversize input)", n)
	}
}

func TestParseRFC5424_EmptyInput(t *testing.T) {
	msg, err := ParseRFC5424(nil)
	if err != nil {
		t.Errorf("empty input should not error, got %v", err)
	}
	if msg != nil {
		t.Errorf("empty input should return nil message, got %+v", msg)
	}
}

func TestParseRFC5424_TooFewParts(t *testing.T) {
	cases := []string{
		"only-one-part",
		"two parts",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseRFC5424([]byte(in)); err == nil {
				t.Errorf("expected error for %q (too few parts)", in)
			}
		})
	}
}

func TestBytesToInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"0", 0},
		{"1", 1},
		{"189", 189},
		{"34Oct", 34},
		{"abc", 0},
		{"", 0},
		{"12a34", 1234},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := bytesToInt([]byte(tt.input)); got != tt.want {
				t.Errorf("bytesToInt(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestSyslogReceiver_DoubleStart(t *testing.T) {
	rcv := NewSyslogReceiver("127.0.0.1", 0)
	if err := rcv.Start(func(*relay.SyslogMessage) {}); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	t.Cleanup(func() { _ = rcv.Stop() })

	if err := rcv.Start(func(*relay.SyslogMessage) {}); err == nil {
		t.Error("second Start should error")
	}
}

func TestUDPSyslogReceiver_DoubleStart(t *testing.T) {
	rcv := NewUDPSyslogReceiver("127.0.0.1", 0)
	if err := rcv.Start(func(*relay.SyslogMessage) {}); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	t.Cleanup(func() { _ = rcv.Stop() })

	if err := rcv.Start(func(*relay.SyslogMessage) {}); err == nil {
		t.Error("second Start should error")
	}
}

func FuzzParseRFC5424(f *testing.F) {
	seeds := []string{
		`<189> 1 2025-04-10T05:01:53.000000-07:00 FGT-1000 fglog 1234 - [origin] msg`,
		`<34>Oct 11 22:14:15 fw-host sshd[123]: Failed password for invalid user admin from 10.0.0.1`,
		`<0>- - - - - - -`,
		``,
		`<>`,
		`<999>`,
		`garbage data with no spaces at all`,
		`<13>1 2025-04-10T05:01:53.000000-07:00 fw-host kernel: [1234.567] oops`,
		`<<<>>>`,
		`<-1> 1 2025-04-10T05:01:53.000000-07:00 h a p m - - msg`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		// Must not panic for any input. The parser runs on the inbound
		// syslog goroutine — a panic here would take it down and silently
		// break device-to-event association for the entire collector.
		_, _ = ParseRFC5424([]byte(data))
	})
}
