package syslog

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"firewall-collector/internal/relay"
)

// Format names the syslog framing a datagram was parsed with. It is sent to the
// server as the `format` hint on every syslog row so consumers can pick a body
// parser without re-sniffing the line. Shipped in 1.3.48 as an additive hint;
// relay schema v6 (1.3.50) makes it a contract: every row parseSyslog returns
// carries one of the values below, and a v6 server skips its re-framing
// fallback on that promise. Adding a value or leaving a branch unlabelled is a
// wire-format change (see relay.SchemaVersionMax).
type Format string

const (
	// FormatFortiOSKV is FortiOS key=value output: `<PRI>date=... time=...`.
	FormatFortiOSKV Format = "fortios_kv"
	// FormatRFC5424 is a conformant `<PRI>1 TIMESTAMP HOST APP PID MSGID SD MSG`
	// line (the lenient `<PRI> 1 ...` spelling is accepted too).
	FormatRFC5424 Format = "rfc5424"
	// FormatRFC3164 is the BSD form `<PRI>Mmm dd hh:mm:ss HOST TAG[pid]: MSG`.
	FormatRFC3164 Format = "rfc3164"
	// FormatMeraki is Cisco Meraki's `<PRI>1 <epoch.frac> HOST CATEGORY BODY`
	// (built from the documented format; untested on real hardware).
	FormatMeraki Format = "meraki"
	// FormatCEF is any of the header families above whose body is an ArcSight
	// CEF record (`CEF:0|vendor|product|...`), e.g. the UniFi SIEM stream.
	// The header columns are those of the framing that carried it.
	FormatCEF Format = "cef"
	// FormatRaw is a line with a valid PRI but no recognised header: the whole
	// body is the message and the timestamp is the receive time.
	FormatRaw Format = "raw"
)

// cefSniffLen bounds how long a leading `TAG: ` may be before a CEF record.
const cefSniffLen = 64

// detectFraming classifies a datagram by cheap byte gates on what follows the
// PRI and returns where that framing's payload starts:
//
//	fortios_kv  `date=` glued to the `>`            payload = after `>`
//	meraki      `1 ` + 9-10 digit epoch (+ `.frac`) payload = after `1 `
//	rfc5424     `1 ` + `YYYY-` or `- ` (NILVALUE)   payload = after `1 `
//	rfc3164     `Mmm ` + digit or space             payload = after `>`
//	raw         anything else                       payload = after `>`
//
// The gates are evaluated in that order. A single space between `>` and the
// VERSION is tolerated (the lenient `<PRI> 1 ...` spelling some senders use).
// Callers decode the PRI themselves; data is expected to start with a valid
// `<PRI>` and priEnd is the index just past its `>`.
func detectFraming(data []byte, priEnd int) (Format, int) {
	if priEnd >= len(data) {
		return FormatRaw, priEnd
	}
	body := data[priEnd:]
	if bytes.HasPrefix(body, []byte("date=")) {
		return FormatFortiOSKV, priEnd
	}

	start := priEnd
	if body[0] == ' ' {
		start++
		body = body[1:]
	}

	if len(body) > 2 && body[0] == '1' && body[1] == ' ' {
		rest := body[2:]
		switch {
		case isEpochPrefix(rest):
			return FormatMeraki, start + 2
		case isISODatePrefix(rest), bytes.HasPrefix(rest, []byte("- ")):
			// `- ` is the RFC 5424 NILVALUE timestamp.
			return FormatRFC5424, start + 2
		}
	}

	if isBSDTimestampPrefix(body) {
		return FormatRFC3164, start
	}
	return FormatRaw, priEnd
}

// isEpochPrefix reports whether b starts with a 9-10 digit Unix epoch, an
// optional `.fraction`, and then a space (or ends there).
func isEpochPrefix(b []byte) bool {
	i := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i < 9 || i > 10 {
		return false
	}
	if i < len(b) && b[i] == '.' {
		i++
		j := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == j {
			return false
		}
	}
	return i == len(b) || b[i] == ' '
}

// isISODatePrefix reports whether b starts with `YYYY-`.
func isISODatePrefix(b []byte) bool {
	if len(b) < 5 || b[4] != '-' {
		return false
	}
	for _, c := range b[:4] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isBSDTimestampPrefix reports whether b starts with an RFC 3164 month
// abbreviation followed by a space and a digit or the padding space of a
// single-digit day (`Oct 11`, `Oct  1`).
func isBSDTimestampPrefix(b []byte) bool {
	if len(b) < 5 || b[3] != ' ' || (b[4] != ' ' && (b[4] < '0' || b[4] > '9')) {
		return false
	}
	switch string(b[:3]) {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	}
	return false
}

// parseRFC5424Strict fills msg from the payload after `1 `:
//
//	TIMESTAMP HOST APP PID MSGID SD MSG
//
// Columns map one-to-one as before; STRUCTURED-DATA is the single token in
// its slot (a bracketed element containing spaces spills into MSG, as it
// always has) and DeviceID is derived from it as before.
func parseRFC5424Strict(msg *relay.SyslogMessage, body []byte, now time.Time) {
	parts := bytes.SplitN(body, []byte(" "), 7)

	if ts, err := parseTimestamp(now, string(parts[0])); err == nil {
		msg.Timestamp = ts
	}
	if len(parts) > 1 {
		msg.Hostname = string(parts[1])
	}
	if len(parts) > 2 {
		msg.AppName = string(parts[2])
	}
	if len(parts) > 3 {
		msg.ProcessID = string(parts[3])
	}
	if len(parts) > 4 {
		msg.MessageID = string(parts[4])
	}
	if len(parts) > 5 {
		structuredData := string(parts[5])
		if structuredData != "-" {
			msg.StructuredData = structuredData
			msg.DeviceID = extractDeviceID(msg.Hostname, structuredData)
		}
	}
	if len(parts) > 6 {
		msg.Message = string(parts[6])
	}
}

// bsdTimestampEnd returns the length of the BSD timestamp that opens body:
//
//	Mmm d[d] [yyyy] hh:mm:ss
//
// with any amount of padding before the day (`Oct  1`, `Oct 1` and `Oct 11`
// all occur in the wild), an optional 4-digit year (Cisco ASA/IOS), and the
// time followed by a space or the end of the line. It returns 0 when the bytes
// do not have that shape. The month itself was already checked by the gate.
func bsdTimestampEnd(body []byte) int {
	i := 3
	for i < len(body) && body[i] == ' ' {
		i++
	}
	day := i
	for i < len(body) && i-day < 2 && body[i] >= '0' && body[i] <= '9' {
		i++
	}
	if i == day || i >= len(body) || body[i] != ' ' {
		return 0
	}
	i++
	if j := i + 4; j < len(body) && body[j] == ' ' && allDigits(body[i:j]) {
		i = j + 1 // optional year
	}
	if len(body) < i+8 {
		return 0
	}
	for k, c := range body[i : i+8] {
		if k == 2 || k == 5 {
			if c != ':' {
				return 0
			}
		} else if c < '0' || c > '9' {
			return 0
		}
	}
	i += 8
	if i < len(body) && body[i] != ' ' {
		return 0
	}
	return i
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseBSD fills msg from an RFC 3164 payload:
//
//	Mmm dd hh:mm:ss HOST TAG[pid]: MSG
//	Mmm dd yyyy hh:mm:ss HOST TAG: MSG   (Cisco ASA/IOS spelling)
//
// It reports false — leaving msg untouched — when the bytes the month gate
// matched are not a complete timestamp (bsdTimestampEnd) that also decodes
// to a real date; the caller then stores the line raw rather than guessing
// columns.
//
// The RFC 3164 timestamp carries no year or zone: the year is taken from now
// (minus one when that would put the line more than bsdFutureSlack ahead,
// i.e. a line from late December read in early January) and the zone is the
// collector's. The TAG is the token after HOST only when it ends in `:`;
// otherwise the line has no tag and everything after HOST is the message
// (the UniFi SIEM stream, for one, writes `HOST CEF:0|...`). DeviceID is
// deliberately not derived from HOST: the server binds these rows by source
// IP, and a body-derived id that is not the probe's would get the row dropped.
func parseBSD(msg *relay.SyslogMessage, body []byte, now time.Time) bool {
	tsLen := bsdTimestampEnd(body)
	if tsLen == 0 {
		return false
	}
	ts, err := parseTimestamp(now, string(body[:tsLen]))
	if err != nil {
		return false
	}
	msg.Timestamp = ts
	rest := bytes.TrimLeft(body[tsLen:], " ")

	host, rest := nextToken(rest)
	msg.Hostname = host

	if i := bytes.IndexByte(rest, ' '); (i > 0 && rest[i-1] == ':') || (i < 0 && len(rest) > 0 && rest[len(rest)-1] == ':') {
		tag, after := nextToken(rest)
		tag = strings.TrimSuffix(tag, ":")
		if open := strings.IndexByte(tag, '['); open >= 0 && strings.HasSuffix(tag, "]") {
			msg.ProcessID = tag[open+1 : len(tag)-1]
			tag = tag[:open]
		}
		msg.AppName = tag
		rest = after
	}
	msg.Message = string(rest)
	return true
}

// parseMeraki fills msg from a Meraki payload after `1 `:
//
//	<epoch.frac> HOST CATEGORY BODY
//
// CATEGORY is the dashboard role token (flows, urls, security_event, events,
// ...) and lands in AppName so it can group like FortiOS `type` does.
// DeviceID stays 0 (bound by source IP on the server, as for parseBSD).
// Built from Meraki's documented samples; untested on real hardware.
func parseMeraki(msg *relay.SyslogMessage, body []byte, now time.Time) {
	epoch, rest := nextToken(body)
	if ts, err := parseTimestamp(now, epoch); err == nil {
		msg.Timestamp = ts
	}
	msg.Hostname, rest = nextToken(rest)
	msg.AppName, rest = nextToken(rest)
	msg.Message = string(rest)
}

// nextToken splits off the first space-delimited token and returns it with the
// remainder (leading spaces trimmed).
func nextToken(b []byte) (string, []byte) {
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		return string(b), nil
	}
	return string(b[:i]), bytes.TrimLeft(b[i+1:], " ")
}

// isCEFBody reports whether a message body is a CEF record: it starts with
// `CEF:`, optionally after one `TAG: ` token (a sender that keeps a syslog tag
// in front of the record). A body that merely mentions CEF further in is not
// one.
func isCEFBody(message string) bool {
	if strings.HasPrefix(message, "CEF:") {
		return true
	}
	if i := strings.IndexByte(message, ' '); i > 0 && i < cefSniffLen && message[i-1] == ':' {
		return strings.HasPrefix(message[i+1:], "CEF:")
	}
	return false
}

// Go reference forms of the BSD timestamps; the double space absorbs the
// padding of a single-digit day.
const (
	bsdTimestampLayout     = "Jan  2 15:04:05"
	bsdYearTimestampLayout = "Jan  2 2006 15:04:05"
)

// bsdFutureSlack is how far ahead of now a year-less RFC 3164 timestamp may
// land before it is taken to belong to the previous year. A week absorbs a
// device clock that runs days fast without misdating it by a year; a line
// from late December read in early January still rolls back.
const bsdFutureSlack = 7 * 24 * time.Hour

// parseTimestamp decodes a syslog TIMESTAMP field. Besides the RFC 5424 forms
// it accepts a Unix epoch with optional fraction (Meraki), the Cisco
// `Mmm dd yyyy hh:mm:ss` form and the RFC 3164 `Mmm dd hh:mm:ss` form, which
// has no year or zone: those are taken from now (year rolled back by one if
// the result would be more than bsdFutureSlack ahead of now). "-" and "" mean
// "no timestamp" and yield now.
func parseTimestamp(now time.Time, ts string) (time.Time, error) {
	ts = strings.TrimSpace(ts)
	if ts == "-" || ts == "" {
		return now, nil
	}

	if isEpochPrefix([]byte(ts)) {
		if t, ok := parseEpoch(ts); ok {
			return t, nil
		}
	}

	formats := []string{
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t, nil
		}
	}

	if t, err := time.ParseInLocation(bsdYearTimestampLayout, ts, now.Location()); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation(bsdTimestampLayout, ts, now.Location()); err == nil {
		t = t.AddDate(now.Year(), 0, 0)
		if t.After(now.Add(bsdFutureSlack)) {
			t = t.AddDate(-1, 0, 0)
		}
		return t, nil
	}

	return now, fmt.Errorf("failed to parse timestamp: %s", ts)
}

// parseEpoch converts `seconds[.fraction]` to a UTC time. The caller has
// already checked the digit shape; the fraction is truncated to nanoseconds.
func parseEpoch(ts string) (time.Time, bool) {
	secStr, fracStr, _ := strings.Cut(ts, ".")
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	var nsec int64
	if fracStr != "" {
		if len(fracStr) > 9 {
			fracStr = fracStr[:9]
		}
		n, err := strconv.ParseInt(fracStr, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		for i := len(fracStr); i < 9; i++ {
			n *= 10
		}
		nsec = n
	}
	return time.Unix(sec, nsec).UTC(), true
}
