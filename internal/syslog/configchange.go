package syslog

import "firewall-collector/internal/relay"

// ConfigChangeEvent is the vendor-neutral form of a syslog line that reports a
// configuration commit on the sending device. The collector uses it to
// schedule a debounced config backup; it is never sent to the server (the
// resulting backup carries TriggerSource="syslog" instead).
type ConfigChangeEvent struct {
	// Format is the syslog framing whose detector recognised the line.
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

// ConfigChangeDetector recognises the config-commit lines of one syslog
// framing. Detect returns ok=false for every line that is not one.
type ConfigChangeDetector interface {
	Detect(msg *relay.SyslogMessage) (ConfigChangeEvent, bool)
}

// configChangeDetectors is keyed by the framing the dispatcher labelled the
// row with (relay.SyslogMessage.Format). A detector only ever sees lines of
// its own framing, so a FortiOS event id appearing in the body of a BSD or
// RFC 5424 line from some other device cannot trigger a FortiOS backup
// against whatever box owns that source IP. Vendors whose config-change
// lines are known only from documentation register nothing until a fixture
// from real hardware exists.
var configChangeDetectors = map[Format]ConfigChangeDetector{
	FormatFortiOSKV: fortiOSConfigChange{},
}

// DetectConfigChange reports whether msg is a config-commit line, dispatching
// on msg.Format. A row without a format (an older collector's queue drained
// after an upgrade) matches no detector.
func DetectConfigChange(msg *relay.SyslogMessage) (ConfigChangeEvent, bool) {
	if msg == nil {
		return ConfigChangeEvent{}, false
	}
	d, ok := configChangeDetectors[Format(msg.Format)]
	if !ok {
		return ConfigChangeEvent{}, false
	}
	return d.Detect(msg)
}

// fortiOSConfigChange is the FortiOS key=value detector: the event-log ids
// that signal a config commit (LogidConfigAttr, LogidConfigObjAttr).
type fortiOSConfigChange struct{}

func (fortiOSConfigChange) Detect(msg *relay.SyslogMessage) (ConfigChangeEvent, bool) {
	ev := parseFortiEvent(msg)
	if !ev.IsConfigChange() {
		return ConfigChangeEvent{}, false
	}
	return ConfigChangeEvent{
		Format:  FormatFortiOSKV,
		EventID: ev.Logid,
		TxnID:   ev.Cfgtid,
		Path:    ev.Cfgpath,
		Action:  ev.Action,
		User:    ev.User,
	}, true
}
