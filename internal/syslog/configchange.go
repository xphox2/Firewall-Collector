package syslog

import "firewall-collector/internal/relay"

// ConfigChangeEvent is the vendor-neutral form of a syslog line that reports a
// configuration commit on the sending device. The collector uses it to
// schedule a debounced config backup; it is never sent to the server (the
// resulting backup carries TriggerSource="syslog" instead).
type ConfigChangeEvent struct {
	// Format is the syslog framing the line arrived in.
	Format Format
	// EventID is the vendor's event identifier (FortiOS logid).
	EventID string
	// TxnID identifies the commit so the per-attribute flurry a single CLI
	// transaction emits collapses to one backup (FortiOS cfgtid). Empty when
	// the vendor has no such notion; the debounce then degrades to per-device.
	TxnID string
	// Path, Action and User describe what changed, for logging only.
	Path   string
	Action string
	User   string
}

// ConfigChangeDetector recognises the config-commit lines of one device
// vendor. Detect returns ok=false for every line that is not one.
type ConfigChangeDetector interface {
	Detect(msg *relay.SyslogMessage) (ConfigChangeEvent, bool)
}

// configChangeDetectors is keyed by the RESOLVED device vendor (the vendor of
// the device the collector bound the packet's source IP to), not by the
// syslog framing: a FortiGate emits the same key=value body whether it is
// configured for its native framing (`fortios_kv`), `set format rfc5424`, or
// a BSD-style relay, and all three must keep triggering backups. Keying on
// the vendor is also what stops a FortiOS event id inside a line from some
// other device — or a spoofed one — from scheduling a FortiOS backup: a device
// that is not a FortiGate has no FortiOS detector, and an unresolved source
// has no vendor at all. Vendors whose config-change lines are known only from
// documentation register nothing until a fixture from real hardware exists.
var configChangeDetectors = map[string]ConfigChangeDetector{
	"fortigate": fortiOSConfigChange{},
}

// DetectConfigChange reports whether msg is a config-commit line for a device
// of the given vendor. An empty or unknown vendor matches no detector.
func DetectConfigChange(vendor string, msg *relay.SyslogMessage) (ConfigChangeEvent, bool) {
	if msg == nil {
		return ConfigChangeEvent{}, false
	}
	d, ok := configChangeDetectors[vendor]
	if !ok {
		return ConfigChangeEvent{}, false
	}
	return d.Detect(msg)
}

// fortiOSConfigChange is the FortiGate detector: the FortiOS event-log ids
// that signal a config commit (LogidConfigAttr, LogidConfigObjAttr), read
// from the key=value body behind any of the framings FortiOS can be
// configured to emit — native (`fortios_kv`), `set format rfc5424` (framed
// `rfc5424`, including the lenient `<PRI> 1 …` spelling) or a BSD header
// (`rfc3164`). Meraki, CEF and raw framings are never FortiOS event logs.
type fortiOSConfigChange struct{}

// fortiOSFramings are the framings a FortiGate's event log can arrive in.
var fortiOSFramings = map[Format]bool{
	FormatFortiOSKV: true,
	FormatRFC5424:   true,
	FormatRFC3164:   true,
}

func (fortiOSConfigChange) Detect(msg *relay.SyslogMessage) (ConfigChangeEvent, bool) {
	if !fortiOSFramings[Format(msg.Format)] {
		return ConfigChangeEvent{}, false
	}
	ev := parseFortiEvent(msg)
	if !ev.IsConfigChange() {
		return ConfigChangeEvent{}, false
	}
	return ConfigChangeEvent{
		Format:  Format(msg.Format),
		EventID: ev.Logid,
		TxnID:   ev.Cfgtid,
		Path:    ev.Cfgpath,
		Action:  ev.Action,
		User:    ev.User,
	}, true
}
