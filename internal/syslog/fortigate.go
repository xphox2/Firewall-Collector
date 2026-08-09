package syslog

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"firewall-collector/internal/relay"
)

// FortiEvent is the structured form of FortiGate event-log syslog lines that
// we care about — primarily for config-change triggering. It is a
// collector-internal type and is never sent to the server (the resulting
// backup carries TriggerSource="syslog" instead).
type FortiEvent struct {
	Logid   string
	Type    string
	Subtype string
	Level   string
	VD      string
	User    string
	UI      string
	Action  string
	Cfgtid  string
	Cfgpath string
	Cfgobj  string
	Cfgattr string
	Devid   string
	Devname string
	Msg     string
}

// FortiOS event-log IDs that signal config changes. Stable across FortiOS
// 5.2 → 7.6 per Fortinet KB ta-p/387138 and the official log message reference.
const (
	LogidConfigAttr    = "0100044546" // attribute changed (e.g. system.global)
	LogidConfigObjAttr = "0100044547" // object attribute changed (e.g. firewall.policy 8)
)

// IsConfigChange reports whether this event indicates a config commit and
// should trigger a backup.
func (e *FortiEvent) IsConfigChange() bool {
	if e == nil {
		return false
	}
	return e.Logid == LogidConfigAttr || e.Logid == LogidConfigObjAttr
}

// ParseFortiEvent extracts a FortiEvent from a SyslogMessage if the message
// body looks like FortiOS key=value event-log output. Returns nil for
// non-FortiGate / non-event lines (no `logid=` token).
func ParseFortiEvent(msg *relay.SyslogMessage) *FortiEvent {
	if msg == nil || msg.Message == "" {
		return nil
	}
	// Cheap check first: if there's no `logid=` we're done. Avoids paying for
	// the full key=value scan on the bulk of non-FortiGate syslog traffic.
	if !strings.Contains(msg.Message, "logid=") {
		return nil
	}

	kv := parseKVPairs(msg.Message)
	if kv["logid"] == "" {
		return nil
	}

	return &FortiEvent{
		Logid:   kv["logid"],
		Type:    kv["type"],
		Subtype: kv["subtype"],
		Level:   kv["level"],
		VD:      kv["vd"],
		User:    kv["user"],
		UI:      kv["ui"],
		Action:  kv["action"],
		Cfgtid:  kv["cfgtid"],
		Cfgpath: kv["cfgpath"],
		Cfgobj:  kv["cfgobj"],
		Cfgattr: kv["cfgattr"],
		Devid:   kv["devid"],
		Devname: kv["devname"],
		Msg:     kv["msg"],
	}
}

// parseKVPairs walks `key=value` and `key="quoted value"` tokens out of a
// FortiOS-style log line. Tolerant of empty values, missing trailing space,
// and quoted strings containing spaces. Unknown keys are kept; the caller
// pulls out only what it needs.
//
// We deliberately avoid regex here — the line is ~500 bytes and called per
// syslog message, often >1000/sec under load.
func parseKVPairs(s string) map[string]string {
	out := map[string]string{}
	i := 0
	n := len(s)
	for i < n {
		// Skip whitespace between pairs.
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		// Read key up to '='.
		keyStart := i
		for i < n && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= n || s[i] != '=' {
			// Not a key=value token — skip the run we just consumed.
			continue
		}
		key := s[keyStart:i]
		i++ // consume '='
		if i >= n {
			out[strings.ToLower(key)] = ""
			break
		}
		// Read value: quoted or bare.
		var val string
		if s[i] == '"' {
			i++ // consume opening quote
			valStart := i
			for i < n && s[i] != '"' {
				i++
			}
			val = s[valStart:i]
			if i < n {
				i++ // consume closing quote
			}
		} else {
			valStart := i
			for i < n && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			val = s[valStart:i]
		}
		out[strings.ToLower(key)] = val
	}
	return out
}

// fortiOSBody reports whether a datagram is FortiOS key=value output and, if so,
// returns everything after the PRI.
//
// The discriminator is that FortiOS writes `date=` immediately after the closing
// `>` with no space, whereas RFC 5424 always has ` VERSION TIMESTAMP` there. It
// deliberately does NOT test for `logid=`: that token also appears inside the
// body of genuine RFC 5424 messages, so keying on it would misroute them.
func fortiOSBody(data []byte) (string, bool) {
	end := bytes.IndexByte(data, '>')
	if end < 0 || end+1 >= len(data) {
		return "", false
	}
	body := data[end+1:]
	if !bytes.HasPrefix(body, []byte("date=")) {
		return "", false
	}
	return string(body), true
}

// parseFortiOSKV fills a message from a FortiOS key=value record.
//
// Message keeps the WHOLE record rather than starting at `subtype=`, so
// logid/type/devname stop being lost to the header columns. That is additive for
// every server-side consumer: they scan for key=value tokens across the string
// (configdiff.ParseFortiAuditEvent) or use strings.Contains (the deny
// projection), and the fields they look for all sit after `subtype=` and are
// therefore already present today.
//
// The header columns take low-cardinality values, which is what they are for and
// what makes them usable as aggregation grouping keys:
//
//	Hostname   devname (else devid)
//	AppName    type — "traffic", "event", "utm"
//	MessageID  logid
//
// ProcessID and StructuredData are left empty rather than carrying `tz=` and
// `type=` fragments. Note the empty StructuredData means DeviceID is not derived
// here; the server attributes these rows by source IP (ResolveDevicesByIPs),
// which is what already happens in production because the fragment that landed
// in StructuredData never yielded an ID either.
func parseFortiOSKV(msg *relay.SyslogMessage, body string) {
	kv := parseKVPairs(body)

	msg.Message = body
	msg.Hostname = kv["devname"]
	if msg.Hostname == "" {
		msg.Hostname = kv["devid"]
	}
	msg.AppName = kv["type"]
	msg.MessageID = kv["logid"]
	msg.ProcessID = ""
	msg.StructuredData = ""

	// eventtime ONLY. FortiOS `date`/`time` are device-local with the offset in a
	// separate `tz="-0400"` key, so parsing them without it would silently shift
	// every row by the UTC offset. eventtime is an unambiguous epoch, and when it
	// is absent or unparseable the caller's time.Now() default stands — the same
	// behaviour these lines get today.
	if ts, ok := parseFortiEventTime(kv["eventtime"]); ok {
		msg.Timestamp = ts
	}
}

// parseFortiEventTime converts FortiOS `eventtime` to a time. FortiOS 6.x emits
// seconds and 7.x nanoseconds, so the unit is inferred from magnitude rather
// than assumed: anything at or above 1e15 is treated as nanoseconds. Values that
// are not plausible epochs are rejected so a malformed field cannot backdate a
// row into a partition or past a retention cutoff.
func parseFortiEventTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	var ts time.Time
	if n >= 1e15 {
		ts = time.Unix(0, n)
	} else {
		ts = time.Unix(n, 0)
	}
	// Guard against a garbage field producing an absurd timestamp.
	if ts.Year() < 2000 || ts.Year() > 2100 {
		return time.Time{}, false
	}
	return ts.UTC(), true
}
