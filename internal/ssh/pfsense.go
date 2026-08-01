package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// pfsenseConfigPath is the single XML file that holds a pfSense firewall's
// entire configuration — the same location OPNsense uses, since OPNsense forked
// from pfSense.
const pfsenseConfigPath = "/conf/config.xml"

// PfSenseClient captures the running configuration from a pfSense firewall over
// SSH. Like OPNsense it exposes a FreeBSD shell and keeps its whole
// configuration in one XML file, so the backup is a raw `cat` of that file.
//
// Deliberately a SEPARATE type from OPNsenseClient rather than a shared one with
// a different root element. The collector's poll path dispatches its extra SSH
// diagnostics by concrete client type, and an *OPNsenseClient additionally gets
// hardware-sensor and bridge-FDB probing. Those are plausible on pfSense — same
// FreeBSD underpinnings — but have never been run against one, and silently
// inheriting them would mean shipping unverified device commands. Config backup
// is what the server actually needs; the diagnostics can be added deliberately
// once there is a device to verify them on.
//
// The root element is <pfsense>, NOT <opnsense>: matching on the wrong one
// rejects every backup the device produces.
//
// The SSH login must have shell access and read permission on the config file.
// A pfSense account without shell access lands in the console menu, where `cat`
// never runs and GetConfig returns an error rather than a bogus config.
//
// UNVERIFIED against a real pfSense device — there was none available. The
// capture mechanism is byte-identical to the OPNsense path, which is verified in
// production; what is unverified is that pfSense's shell and file layout behave
// as documented.
type PfSenseClient struct {
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

// NewPfSenseClient builds a password-authenticated pfSense SSH client.
func NewPfSenseClient(host string, port int, username, password string) *PfSenseClient {
	return NewPfSenseClientWithKey(host, port, username, password, "", "")
}

// NewPfSenseClientWithKey builds a pfSense SSH client that authenticates with a
// private key (falling back to password when keyFile is empty).
func NewPfSenseClientWithKey(host string, port int, username, password, keyFile, keyPassphrase string) *PfSenseClient {
	if port == 0 {
		port = 22
	}
	return &PfSenseClient{
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
func (c *PfSenseClient) ObservedHostKey() string { return c.observedHostKey }

func (c *PfSenseClient) Connect() error {
	client, hostKey, err := dialSSH(c.host, c.port, c.username, c.password, c.keyFile, c.keyPassphrase)
	c.observedHostKey = hostKey
	if err != nil {
		return err
	}
	c.client = client
	return nil
}

func (c *PfSenseClient) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

// GetConfig reads /conf/config.xml and returns the XML document. The result is
// cached for the client's lifetime so a poll's checksum + backup share one
// fetch. extractXMLConfig isolates the document from any shell/stderr noise and
// requires a complete <pfsense>…</pfsense>, so a permission error, console menu,
// or truncated capture is reported as a failure rather than stored as a bogus
// revision.
func (c *PfSenseClient) GetConfig() (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	if c.configFetched {
		return c.config, nil
	}
	out, err := runCommandRaw(c.client, "cat "+pfsenseConfigPath, false, commandTimeout)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", pfsenseConfigPath, err)
	}
	cfg, err := extractXMLConfig(out, "pfsense", pfsenseConfigPath)
	if err != nil {
		return "", err
	}
	c.config = cfg
	c.configFetched = true
	return cfg, nil
}

// GetConfigChecksum returns a change-detection token derived from the exact
// config bytes GetConfig will send, so the stored checksum always corresponds to
// the stored config. Backed by the same cached fetch as GetConfig.
func (c *PfSenseClient) GetConfigChecksum() (string, error) {
	cfg, err := c.GetConfig()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(cfg))
	return hex.EncodeToString(sum[:]), nil
}
