package syslog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// goldenNow is the injected clock for every fixture: the fallback timestamp
// of raw lines and the year source of RFC 3164 lines (whose Oct fixtures
// therefore resolve to 2025 without a rollover).
var goldenNow = time.Date(2025, 10, 12, 0, 0, 0, 0, time.UTC)

// goldenRecord is one parsed fixture line as stored in *.golden.json.
type goldenRecord struct {
	Line           string `json:"line"`
	Error          string `json:"error,omitempty"`
	Format         string `json:"format,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	AppName        string `json:"app_name,omitempty"`
	ProcessID      string `json:"process_id,omitempty"`
	MessageID      string `json:"message_id,omitempty"`
	StructuredData string `json:"structured_data,omitempty"`
	Message        string `json:"message,omitempty"`
	Priority       int    `json:"priority"`
	Facility       int    `json:"facility"`
	Severity       int    `json:"severity"`
	DeviceID       uint   `json:"device_id,omitempty"`
}

func recordOf(line string, msg *relay.SyslogMessage, err error) goldenRecord {
	rec := goldenRecord{Line: line}
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	rec.Format = msg.Format
	rec.Timestamp = msg.Timestamp.Format(time.RFC3339Nano)
	rec.Hostname = msg.Hostname
	rec.AppName = msg.AppName
	rec.ProcessID = msg.ProcessID
	rec.MessageID = msg.MessageID
	rec.StructuredData = msg.StructuredData
	rec.Message = msg.Message
	rec.Priority = msg.Priority
	rec.Facility = msg.Facility
	rec.Severity = msg.Severity
	rec.DeviceID = msg.DeviceID
	return rec
}

// fixtureLines returns the non-comment, non-empty lines of a *.log fixture.
func fixtureLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return lines
}

// TestParse_Golden parses every testdata/<format>/*.log fixture with the clock
// pinned to goldenNow and compares each line's columns with the *.golden.json
// next to it. UPDATE_GOLDEN=1 rewrites the golden files. Every line that
// parses must carry a non-empty Format and, unless it is a cef line, the
// Format of the directory it lives in.
func TestParse_Golden(t *testing.T) {
	logs, err := filepath.Glob(filepath.Join("testdata", "*", "*.log"))
	if err != nil || len(logs) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	for _, logPath := range logs {
		dirFormat := filepath.Base(filepath.Dir(logPath))
		goldenPath := strings.TrimSuffix(logPath, ".log") + ".golden.json"
		t.Run(dirFormat+"/"+filepath.Base(logPath), func(t *testing.T) {
			var got []goldenRecord
			for _, line := range fixtureLines(t, logPath) {
				msg, err := parseSyslog([]byte(line), goldenNow)
				got = append(got, recordOf(line, msg, err))
				if err != nil {
					continue
				}
				if msg.Format == "" {
					t.Errorf("%q: Format is empty — every dispatcher branch must label its row", line)
				}
				if dirFormat != "cef" && msg.Format != dirFormat {
					t.Errorf("%q: Format = %q, want %q (fixture directory)", line, msg.Format, dirFormat)
				}
			}

			if os.Getenv("UPDATE_GOLDEN") == "1" {
				data, err := json.MarshalIndent(got, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenPath, append(data, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("wrote %s", goldenPath)
				return
			}

			data, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (run with UPDATE_GOLDEN=1 to create): %v", err)
			}
			var want []goldenRecord
			if err := json.Unmarshal(data, &want); err != nil {
				t.Fatalf("decode %s: %v", goldenPath, err)
			}
			if len(want) != len(got) {
				t.Fatalf("%s: %d golden records, fixture has %d lines", goldenPath, len(want), len(got))
			}
			for i := range want {
				if !reflect.DeepEqual(want[i], got[i]) {
					t.Errorf("line %d differs from golden\n got: %+v\nwant: %+v", i+1, got[i], want[i])
				}
			}
		})
	}
}

func TestDetectFraming(t *testing.T) {
	tests := []struct {
		in        string
		want      Format
		wantStart int
	}{
		{`<189>date=2025-04-10 time=05:01:53 devname="fw-example-01"`, FormatFortiOSKV, 5},
		{`<13>1 2025-04-10T05:01:53Z fw-example-01 app 42 ID1 - body`, FormatRFC5424, 6},
		{`<189> 1 2025-04-10T05:01:53.000000-07:00 FGT-1000 fglog 1234 MSG-001 [origin] msg`, FormatRFC5424, 8},
		{`<134>1 1712725313.123456 fw-example-01 flows src=192.0.2.10`, FormatMeraki, 7},
		{`<134>1 1712725314 fw-example-03 events port 3 status changed`, FormatMeraki, 7},
		{`<34>Oct 11 22:14:15 fw-example-01 sshd[123]: Failed password`, FormatRFC3164, 4},
		{`<30>Oct  1 05:01:53 fw-example-01 dnsmasq[456]: query[A]`, FormatRFC3164, 4},
		{`<13>something without a recognised header`, FormatRaw, 4},
		{`<13>1 not-a-timestamp fw-example-01 app - - - body`, FormatRaw, 4},
		{`<13>1 12345678 fw-example-01 eight digits is not an epoch`, FormatRaw, 4},
		{`<13>1 1712725313. fw-example-01 bare dot`, FormatRaw, 4},
		{`<13>Foo 11 22:14:15 fw-example-01 not a month`, FormatRaw, 4},
		{`<13>Octo 11 22:14:15 fw-example-01`, FormatRaw, 4},
		{`<13>`, FormatRaw, 4},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			priEnd := strings.IndexByte(tt.in, '>') + 1
			got, start := detectFraming([]byte(tt.in), priEnd)
			if got != tt.want || start != tt.wantStart {
				t.Errorf("detectFraming = (%q, %d), want (%q, %d)", got, start, tt.want, tt.wantStart)
			}
		})
	}
}

// Conformant RFC 5424 has no space between `>` and the VERSION. The old
// positional parser was built for the lenient `<PRI> 1 ` spelling and shifted
// a conformant line one column: the TIMESTAMP landed in the VERSION slot and
// HOST was fed to parseTimestamp (failing to time.Now()).
func TestParse_RFC5424_Conformant_NoSpace(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	line := `<13>1 2025-04-10T05:01:53Z fw-example-01 app 42 ID1 - body`
	msg, err := parseSyslog([]byte(line), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2025, 4, 10, 5, 1, 53, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("Timestamp: got %v, want %v (the literal in the line, not now)", msg.Timestamp, want)
	}
	if msg.Hostname != "fw-example-01" {
		t.Errorf("Hostname: got %q, want %q", msg.Hostname, "fw-example-01")
	}
	if msg.AppName != "app" {
		t.Errorf("AppName: got %q, want %q", msg.AppName, "app")
	}
	if msg.ProcessID != "42" {
		t.Errorf("ProcessID: got %q, want %q", msg.ProcessID, "42")
	}
	if msg.MessageID != "ID1" {
		t.Errorf("MessageID: got %q, want %q", msg.MessageID, "ID1")
	}
	if msg.StructuredData != "" {
		t.Errorf("StructuredData: got %q, want empty for `-`", msg.StructuredData)
	}
	if msg.Message != "body" {
		t.Errorf("Message: got %q, want %q", msg.Message, "body")
	}
	if msg.Format != string(FormatRFC5424) {
		t.Errorf("Format: got %q, want %q", msg.Format, FormatRFC5424)
	}
}

// Meraki writes `<PRI>1 <epoch.frac> <device> <category> <body>`; the old
// parser had no epoch layout, so every Meraki row was stamped time.Now().
func TestParse_MerakiEpoch(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	line := `<134>1 1712725313.123456 fw-example-01 flows src=192.0.2.10 dst=198.51.100.7 mac=00:00:5E:00:53:0A protocol=udp sport=55719 dport=53 pattern: allow all`
	msg, err := parseSyslog([]byte(line), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2024, 4, 10, 5, 1, 53, 123456000, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("Timestamp: got %v, want %v (epoch field)", msg.Timestamp, want)
	}
	if msg.Hostname != "fw-example-01" {
		t.Errorf("Hostname: got %q, want %q", msg.Hostname, "fw-example-01")
	}
	if msg.AppName != "flows" {
		t.Errorf("AppName: got %q, want %q (the category token)", msg.AppName, "flows")
	}
	if !strings.HasPrefix(msg.Message, "src=192.0.2.10 ") || !strings.HasSuffix(msg.Message, "pattern: allow all") {
		t.Errorf("Message: got %q, want the body after the category", msg.Message)
	}
	if msg.Format != string(FormatMeraki) {
		t.Errorf("Format: got %q, want %q", msg.Format, FormatMeraki)
	}
}

// An RFC 3164 timestamp has no year. It is taken from now, minus one when the
// line would otherwise be more than 24 h in the future — a Dec 31 line read
// on Jan 1 belongs to the year that just ended. The old parser produced year 0.
func TestParse_BSD_YearRollover(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	line := `<13>Dec 31 23:59:00 fw-example-01 cron[7]: late`
	msg, err := parseSyslog([]byte(line), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2025, 12, 31, 23, 59, 0, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("Timestamp: got %v, want %v (previous year)", msg.Timestamp, want)
	}

	// Same clock, a line from a few minutes ago: current year, no rollover.
	msg, err = parseSyslog([]byte(`<13>Jan  1 00:01:00 fw-example-01 cron[7]: early`), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want = time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("Timestamp: got %v, want %v (current year)", msg.Timestamp, want)
	}

	// The slack is a week (bsdFutureSlack): a device clock 3 days fast keeps
	// the current year; 8 days ahead is taken as last year.
	msg, _ = parseSyslog([]byte(`<13>Jan  4 00:00:00 fw-example-01 cron[7]: fast clock`), now)
	want = time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("3 days ahead: got %v, want %v (within slack, current year)", msg.Timestamp, want)
	}
	msg, _ = parseSyslog([]byte(`<13>Jan  9 00:10:00 fw-example-01 cron[7]: too far`), now)
	want = time.Date(2025, 1, 9, 0, 10, 0, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("8 days ahead: got %v, want %v (beyond slack, previous year)", msg.Timestamp, want)
	}
}

// The FortiOS key=value stream is the dominant production input and must come
// out of the dispatcher exactly as it did before it. Columns pinned literally
// (not via the golden harness) so a regression names the field.
func TestParse_FortiOSKV_ByteForByteUnchanged(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	line := `<189>date=2025-04-10 time=05:01:53 devname="fw-example-01" devid="FGT60FTK00000000" eventtime=1744286513000000000 tz="-0700" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.10 srcport=51234 srcintf="port1" dstip=198.51.100.7 dstport=443 dstintf="port2" proto=6 action="accept" policyid=1 service="HTTPS"`
	msg, err := parseSyslog([]byte(line), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := &relay.SyslogMessage{
		Timestamp: time.Date(2025, 4, 10, 12, 1, 53, 0, time.UTC),
		Hostname:  "fw-example-01",
		AppName:   "traffic",
		MessageID: "0000000013",
		Message:   line[len("<189>"):],
		Priority:  189,
		Facility:  23,
		Severity:  5,
		Format:    string(FormatFortiOSKV),
	}
	got := *msg
	got.Timestamp = got.Timestamp.UTC()
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("FortiOS parse changed\n got: %+v\nwant: %+v", got, *want)
	}
}

// CEF is a body encoding carried by some syslog header (UniFi's SIEM stream
// sends it over plain syslog). The header family's columns are kept and the
// row is relabelled cef; the CEF record itself is passed through untouched.
func TestParse_CEF_Passthrough(t *testing.T) {
	now := time.Date(2025, 10, 12, 0, 0, 0, 0, time.UTC)
	cef := `CEF:0|Ubiquiti|UniFi Network|9.3.45|201|Threat Detected and Blocked|7|UNIFIcategory=Security src=203.0.113.5 dst=192.0.2.10 act=Blocked UNIFIutcTime=2025-10-11T22:14:15Z`
	line := `<14>Oct 11 22:14:15 fw-example-01 ` + cef
	msg, err := parseSyslog([]byte(line), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Format != string(FormatCEF) {
		t.Errorf("Format: got %q, want %q", msg.Format, FormatCEF)
	}
	if msg.Hostname != "fw-example-01" {
		t.Errorf("Hostname: got %q, want %q (BSD header columns kept)", msg.Hostname, "fw-example-01")
	}
	if msg.AppName != "" {
		t.Errorf("AppName: got %q, want empty (no TAG before the CEF record)", msg.AppName)
	}
	if msg.Message != cef {
		t.Errorf("Message: got %q, want the CEF record intact", msg.Message)
	}
	want := time.Date(2025, 10, 11, 22, 14, 15, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("Timestamp: got %v, want %v", msg.Timestamp, want)
	}

	// A FortiOS body that mentions CEF stays fortios_kv: the post-flag only
	// applies to the positional families.
	msg, err = parseSyslog([]byte(`<189>date=2025-04-10 time=05:01:53 devname="fw-example-01" logid="0100044547" type="event" msg="CEF: export enabled"`), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Format != string(FormatFortiOSKV) {
		t.Errorf("Format: got %q, want %q", msg.Format, FormatFortiOSKV)
	}
}

// Every message the dispatcher returns carries Format, including the raw
// fallback, so the server never has to re-sniff a row.
func TestParse_RawFallbackIsLabelled(t *testing.T) {
	now := time.Date(2025, 10, 12, 0, 0, 0, 0, time.UTC)
	line := `<13>something without a recognised header`
	msg, err := parseSyslog([]byte(line), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Format != string(FormatRaw) {
		t.Errorf("Format: got %q, want %q", msg.Format, FormatRaw)
	}
	if msg.Message != "something without a recognised header" {
		t.Errorf("Message: got %q, want the whole body", msg.Message)
	}
	if msg.Hostname != "" || msg.AppName != "" {
		t.Errorf("raw line must not guess header columns: Hostname=%q AppName=%q", msg.Hostname, msg.AppName)
	}
	if !msg.Timestamp.Equal(now) {
		t.Errorf("Timestamp: got %v, want now (%v)", msg.Timestamp, now)
	}

	if _, err := parseSyslog([]byte(`<13>`), now); err == nil {
		t.Error("a PRI with nothing after it must be rejected, not stored as an empty raw row")
	}
}

func TestParseTimestamp_Epoch(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		ts   string
		want time.Time
	}{
		{"1712725313", time.Date(2024, 4, 10, 5, 1, 53, 0, time.UTC)},
		{"1712725313.5", time.Date(2024, 4, 10, 5, 1, 53, 500000000, time.UTC)},
		{"1712725313.123456", time.Date(2024, 4, 10, 5, 1, 53, 123456000, time.UTC)},
		{"1712725313.1234567891", time.Date(2024, 4, 10, 5, 1, 53, 123456789, time.UTC)},
	}
	for _, tt := range tests {
		t.Run(tt.ts, func(t *testing.T) {
			got, err := parseTimestamp(now, tt.ts)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// The wire hint is omitted when empty so an older server (and any
// hand-built message) sees the exact pre-1.3.48 JSON.
func TestSyslogMessage_FormatOmittedWhenEmpty(t *testing.T) {
	data, err := json.Marshal(&relay.SyslogMessage{Hostname: "fw-example-01"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"format"`)) {
		t.Errorf("empty Format must be omitted from the wire: %s", data)
	}
	data, err = json.Marshal(&relay.SyslogMessage{Format: string(FormatRFC3164)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"format":"rfc3164"`)) {
		t.Errorf("Format must be sent as `format`: %s", data)
	}
}

// BSD and Meraki rows are bound to a device by source IP on the server. A
// DeviceID derived from the HOST column would be checked against the probe's
// own id there and, when it differs (any FortiGate-looking host name does),
// the row would be discarded — so these parsers must leave it 0.
func TestParse_BSDAndMeraki_DeviceIDNotDerived(t *testing.T) {
	now := time.Date(2025, 10, 12, 0, 0, 0, 0, time.UTC)
	lines := []string{
		`<34>Oct 11 22:14:15 FGT60FTK00000000 sshd[123]: x`,
		`<34>Oct 11 22:14:15 FGT-1000 sshd[123]: x`,
		`<134>1 1712725313.123456 FGT60FTK00000000 events x`,
		`<134>1 1712725313.123456 fgt-1000 flows src=192.0.2.10`,
	}
	for _, line := range lines {
		msg, err := parseSyslog([]byte(line), now)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", line, err)
		}
		if msg.DeviceID != 0 {
			t.Errorf("%q: DeviceID = %d, want 0 (bound by source IP; a body-derived id gets the row dropped)", line, msg.DeviceID)
		}
	}
}

// The month gate only looks at `Mmm d`; a line that then fails to carry a
// full timestamp followed by a space is stored raw, not half-parsed.
func TestParse_BSD_InvalidTimestampFallsBackToRaw(t *testing.T) {
	now := time.Date(2025, 10, 12, 0, 0, 0, 0, time.UTC)
	lines := []string{
		`<13>Oct 11 22:14`,
		`<13>Oct 11 22:14:15x fw-example-01 glued`,
		`<13>Oct 11 22:14:15fw-example-01`,
		`<13>Oct 32 22:14:15 fw-example-01 impossible day`,
		`<13>Oct 11 2025 22:14:15x asa-01 glued year form`,
	}
	for _, line := range lines {
		msg, err := parseSyslog([]byte(line), now)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", line, err)
		}
		if msg.Format != string(FormatRaw) {
			t.Errorf("%q: Format = %q, want raw", line, msg.Format)
		}
		if msg.Hostname != "" || msg.AppName != "" {
			t.Errorf("%q: columns guessed from a bad timestamp: Hostname=%q AppName=%q", line, msg.Hostname, msg.AppName)
		}
		if want := line[len("<13>"):]; msg.Message != want {
			t.Errorf("%q: Message = %q, want the whole body %q", line, msg.Message, want)
		}
		if !msg.Timestamp.Equal(now) {
			t.Errorf("%q: Timestamp = %v, want now", line, msg.Timestamp)
		}
	}
}

// Cisco ASA/IOS insert the year: `Mmm dd yyyy hh:mm:ss HOST : %ASA-...`.
func TestParse_CiscoASA_YearForm(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	line := `<166>Oct 11 2025 22:14:15 asa-01 : %ASA-6-302013: Built outbound TCP connection 12345 for outside:198.51.100.7/443 (198.51.100.7/443) to inside:192.0.2.10/51234 (203.0.113.2/51234)`
	msg, err := parseSyslog([]byte(line), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Format != string(FormatRFC3164) {
		t.Errorf("Format = %q, want rfc3164", msg.Format)
	}
	if msg.Hostname != "asa-01" {
		t.Errorf("Hostname = %q, want asa-01", msg.Hostname)
	}
	want := time.Date(2025, 10, 11, 22, 14, 15, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v (year from the line, not the clock)", msg.Timestamp, want)
	}
	if !strings.HasPrefix(msg.Message, "%ASA-6-302013: Built") {
		t.Errorf("Message = %q, want it to start at %%ASA-6-302013", msg.Message)
	}

	// Single-digit day, same form.
	msg, err = parseSyslog([]byte(`<166>Oct  1 2025 05:01:53 asa-01 : %ASA-6-106015: Deny TCP`), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want = time.Date(2025, 10, 1, 5, 1, 53, 0, time.UTC)
	if !msg.Timestamp.Equal(want) || msg.Hostname != "asa-01" {
		t.Errorf("single-digit day: Timestamp=%v Hostname=%q, want %v asa-01", msg.Timestamp, msg.Hostname, want)
	}
}

// Only a body that IS a CEF record (optionally behind one `TAG: `) is
// relabelled; a body that mentions `CEF:` further in is not.
func TestParse_CEF_RequiresPrefix(t *testing.T) {
	now := time.Date(2025, 10, 12, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		line string
		want Format
	}{
		{`<14>Oct 11 22:14:15 fw-example-01 CEF:0|Ubiquiti|UniFi Network|9.3.45|201|x|7|src=203.0.113.5`, FormatCEF},
		{`<14>Oct 11 22:14:16 fw-example-01 unifi: CEF:0|Ubiquiti|UniFi Network|9.3.45|400|x|1|`, FormatCEF},
		{`<14>1 2025-10-11T22:14:15Z fw-example-01 - - - - CEF:0|Ubiquiti|UniFi OS|4.1.13|1005|x|3|`, FormatCEF},
		{`<14>CEF:0|Ubiquiti|UniFi Network|9.3.45|512|x|5|`, FormatCEF},
		{`<13>Oct 11 22:14:20 fw-example-01 note: the CEF: token later in a body does not relabel the row`, FormatRFC3164},
		{`<13>Oct 11 22:14:20 fw-example-01 sshd[1]: user typed CEF:0|a|b|c|d|e|f|`, FormatRFC3164},
		{`<13>mentions CEF:0|a|b|c|d|e|f| after a word`, FormatRaw},
	}
	for _, tc := range cases {
		msg, err := parseSyslog([]byte(tc.line), now)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", tc.line, err)
		}
		if msg.Format != string(tc.want) {
			t.Errorf("%q: Format = %q, want %q", tc.line, msg.Format, tc.want)
		}
	}
}
