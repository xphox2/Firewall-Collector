package ssh

import "fmt"

// ConfigBackupClient is the vendor-agnostic surface the collector's SSH poll
// path needs: connect, capture the running configuration (plus a cheap
// change-detection checksum), and report the observed host key. Vendor-specific
// diagnostics (FortiOS `diagnose`/`get` commands, etc.) stay on the concrete
// types and are reached via a type assertion by callers that need them.
type ConfigBackupClient interface {
	Connect() error
	Close()
	GetConfigChecksum() (string, error)
	GetConfig() (string, error)
	ObservedHostKey() string
}

// NewConfigBackupClient returns the SSH config-backup client for a device
// vendor. FortiGate drives the FortiOS CLI; OPNsense and pfSense read
// /conf/config.xml over a FreeBSD shell (differing only in the XML root element,
// which is why they are separate clients); Palo Alto (PAN-OS) captures
// `show config running` XML. An empty vendor defaults to FortiGate (legacy
// behavior, same as the SNMP vendor resolver). Unknown vendors return an error
// so the caller logs-and-skips rather than mis-driving a device with the wrong
// CLI dialect.
func NewConfigBackupClient(vendor, host string, port int, username, password string) (ConfigBackupClient, error) {
	switch vendor {
	case "fortigate", "":
		return NewFortiGateClient(host, port, username, password), nil
	case "opnsense":
		return NewOPNsenseClient(host, port, username, password), nil
	case "pfsense":
		return NewPfSenseClient(host, port, username, password), nil
	case "paloalto":
		return NewPaloAltoClient(host, port, username, password), nil
	default:
		return nil, fmt.Errorf("ssh config backup not supported for vendor %q", vendor)
	}
}
