package syslog

import (
	"strings"

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
