package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// opnsenseConfigPath is the single XML file that holds an OPNsense firewall's
// entire configuration. A plain read of this file is the backup.
const opnsenseConfigPath = "/conf/config.xml"

// OPNsenseClient captures the running configuration from an OPNsense firewall
// over SSH. Unlike FortiOS — which wraps output in an interactive CLI/pager and
// needs prompt stripping — OPNsense exposes a normal FreeBSD shell and stores
// its whole configuration as one XML file, so the backup is a raw `cat` of that
// file (captured unfiltered to preserve exact bytes for change detection).
//
// The SSH login must have shell access and read permission on the config file:
// use root, or grant the account the "System: Shell account access" privilege.
// A non-shell OPNsense account drops into the console menu, where `cat` never
// runs and GetConfig returns an error rather than a valid config.
type OPNsenseClient struct {
	host            string
	port            int
	username        string
	password        string
	keyFile         string
	keyPassphrase   string
	client          *ssh.Client
	observedHostKey string
	// config caches the extracted config for the client's lifetime (one poll):
	// GetConfigChecksum and GetConfig then share a single network fetch, and the
	// checksum is always derived from the exact bytes that get sent.
	config        string
	configFetched bool
}

// NewOPNsenseClient builds a password-authenticated OPNsense SSH client.
func NewOPNsenseClient(host string, port int, username, password string) *OPNsenseClient {
	return NewOPNsenseClientWithKey(host, port, username, password, "", "")
}

// NewOPNsenseClientWithKey builds an OPNsense SSH client that authenticates with
// a private key (falling back to password when keyFile is empty).
func NewOPNsenseClientWithKey(host string, port int, username, password, keyFile, keyPassphrase string) *OPNsenseClient {
	if port == 0 {
		port = 22
	}
	return &OPNsenseClient{
		host:          host,
		port:          port,
		username:      username,
		password:      password,
		keyFile:       keyFile,
		keyPassphrase: keyPassphrase,
	}
}

// ObservedHostKey returns the SHA256 fingerprint of the host key presented on
// the most recent Connect, or "" if not yet connected.
func (c *OPNsenseClient) ObservedHostKey() string { return c.observedHostKey }

func (c *OPNsenseClient) Connect() error {
	client, hostKey, err := dialSSH(c.host, c.port, c.username, c.password, c.keyFile, c.keyPassphrase)
	c.observedHostKey = hostKey
	if err != nil {
		return err
	}
	c.client = client
	return nil
}

func (c *OPNsenseClient) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

// GetConfig reads /conf/config.xml and returns the XML document. The result is
// cached for the client's lifetime so a poll's checksum + backup share one
// fetch. extractOPNsenseConfig isolates the document from any shell/stderr noise
// and requires a complete <opnsense>…</opnsense>, so a permission error, console
// menu, or truncated capture is reported as a failure rather than stored as a
// bogus revision.
func (c *OPNsenseClient) GetConfig() (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	if c.configFetched {
		return c.config, nil
	}
	out, err := runCommandRaw(c.client, "cat "+opnsenseConfigPath, false, commandTimeout)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", opnsenseConfigPath, err)
	}
	cfg, err := extractOPNsenseConfig(out)
	if err != nil {
		return "", err
	}
	c.config = cfg
	c.configFetched = true
	return cfg, nil
}

// extractOPNsenseConfig isolates the XML document from raw command output. It
// tolerates any shell/stderr noise before the XML declaration or after the
// closing root tag (so a login banner or csh warning can't corrupt the stored
// config), and requires a complete <opnsense>…</opnsense> pair so a truncated
// capture is rejected rather than silently stored (the server has no OPNsense
// validator to catch it downstream).
func extractOPNsenseConfig(out string) (string, error) {
	start := strings.Index(out, "<?xml")
	if start < 0 {
		start = strings.Index(out, "<opnsense>")
	}
	if start < 0 {
		return "", fmt.Errorf("no OPNsense config in output from %s (missing <opnsense> root — check the SSH account has shell access and read permission)", opnsenseConfigPath)
	}
	const closeTag = "</opnsense>"
	end := strings.LastIndex(out, closeTag)
	if end < start {
		return "", fmt.Errorf("incomplete OPNsense config from %s (missing %s — capture may be truncated)", opnsenseConfigPath, closeTag)
	}
	return out[start : end+len(closeTag)], nil
}

// GetHardwareSensors returns the raw output of a single sysctl read covering
// temperature, per-rail power (INA2xx), and fan (EMC230x) trees. The `-i` flag
// is essential: FreeBSD `sysctl a b c` exits non-zero if ANY listed OID is
// unknown, which would make the caller discard the whole output — so on an x86
// OPNsense (none of these drivers) or a partial-tree box, `-i` still returns the
// trees that exist (exit 0) and a box with none simply yields empty output.
// Parsing is done by ssh.ParseOPNsenseSensors. Requires only shell access — the
// sysctls are world-readable (no root needed).
func (c *OPNsenseClient) GetHardwareSensors() (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	return runCommandRaw(c.client, "sysctl -iq hw.temperature dev.ina2xx dev.emc2302", false, commandTimeout)
}

// GetBridgeList returns the FreeBSD bridge interface names (`ifconfig -g
// bridge`) — the L2-topology FDB supplement for bridged OPNsense boxes. A
// routed-only box (no if_bridge) yields empty output, and FreeBSD's stock
// SNMP agents expose no BRIDGE-MIB, so SSH is the only source.
func (c *OPNsenseClient) GetBridgeList() (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	return runCommandRaw(c.client, "ifconfig -g bridge", false, commandTimeout)
}

// GetBridgeFDB returns one bridge's learned address table
// (`ifconfig <bridge> addr`) with per-member-interface attribution. The name
// is validated before command interpolation (same defense as the FortiGate
// path).
func (c *OPNsenseClient) GetBridgeFDB(bridge string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	if !bridgeNameRe.MatchString(bridge) {
		return "", fmt.Errorf("invalid bridge name %q", bridge)
	}
	return runCommandRaw(c.client, "ifconfig "+bridge+" addr", false, commandTimeout)
}

// GetConfigChecksum returns a change-detection token derived from the exact
// config bytes GetConfig will send, so the stored checksum always corresponds
// to the stored config. Backed by the same cached fetch as GetConfig.
func (c *OPNsenseClient) GetConfigChecksum() (string, error) {
	cfg, err := c.GetConfig()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(cfg))
	return hex.EncodeToString(sum[:]), nil
}
