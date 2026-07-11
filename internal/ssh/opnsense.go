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

// GetConfig reads /conf/config.xml and returns it verbatim. It validates that
// the content looks like an OPNsense config so a permission error or console
// menu (which would return unrelated text) is reported as a failure rather than
// stored as a bogus revision.
func (c *OPNsenseClient) GetConfig() (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	out, err := runCommandRaw(c.client, "cat "+opnsenseConfigPath, false, commandTimeout)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", opnsenseConfigPath, err)
	}
	cfg := strings.TrimSpace(out)
	if !strings.Contains(cfg, "<opnsense>") {
		return "", fmt.Errorf("unexpected content from %s (missing <opnsense> root — check that the SSH account has shell access and read permission)", opnsenseConfigPath)
	}
	return cfg, nil
}

// GetConfigChecksum returns a cheap change-detection token for the config. It
// prefers a remote `sha256 -q` (a tiny command that avoids transferring the
// whole file) and falls back to hashing the fetched config locally on images
// where that binary or its output differs.
func (c *OPNsenseClient) GetConfigChecksum() (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	if out, err := runCommandRaw(c.client, "sha256 -q "+opnsenseConfigPath, false, commandTimeout); err == nil {
		if h := parseHexHash(out); h != "" {
			return h, nil
		}
	}
	cfg, err := c.GetConfig()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(cfg))
	return hex.EncodeToString(sum[:]), nil
}

// parseHexHash extracts a 64-char hex SHA-256 from command output. It takes the
// last whitespace field so it handles both `sha256 -q` (bare hash) and the
// default `SHA256 (file) = <hash>` form.
func parseHexHash(out string) string {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return ""
	}
	cand := fields[len(fields)-1]
	if len(cand) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(cand); err != nil {
		return ""
	}
	return cand
}
