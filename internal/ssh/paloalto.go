package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// paloAltoShowConfigCmd captures the entire running configuration as XML. PAN-OS
// emits the running config as an XML document rooted at <config …> whose
// version/detail-version attributes drift per save — the server's `paloalto`
// config-diff normalizer masks exactly that root-attribute drift plus the
// encrypted <phash>/<secret>/<key>/<password>/<passphrase> elements, so an XML
// capture is what the drift pipeline expects. In a non-interactive SSH exec
// session PAN-OS disables the CLI pager automatically, so no `set cli pager off`
// pre-step is needed (each runCommandRaw call is a fresh, stateless session).
const paloAltoShowConfigCmd = "show config running"

// PaloAltoClient captures the running configuration from a Palo Alto (PAN-OS)
// firewall over SSH. Like OPNsense (a single XML document) rather than FortiGate
// (an interactive text CLI), the whole config is one XML tree, so the backup is
// a single command whose output is trimmed to the <config>…</config> document
// (captured unfiltered to preserve exact bytes for change detection).
//
// The SSH login must be a superuser or deviceadmin account: a non-superuser
// export replaces every secret with the literal `*****`, which the server flags
// as QualityMasked (the backup is not restorable). Model-agnostic across the
// PA-500 and newer platforms — `show config running` is standard PAN-OS.
type PaloAltoClient struct {
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

// NewPaloAltoClient builds a password-authenticated PAN-OS SSH client.
func NewPaloAltoClient(host string, port int, username, password string) *PaloAltoClient {
	return NewPaloAltoClientWithKey(host, port, username, password, "", "")
}

// NewPaloAltoClientWithKey builds a PAN-OS SSH client that authenticates with a
// private key (falling back to password when keyFile is empty).
func NewPaloAltoClientWithKey(host string, port int, username, password, keyFile, keyPassphrase string) *PaloAltoClient {
	if port == 0 {
		port = 22
	}
	return &PaloAltoClient{
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
func (c *PaloAltoClient) ObservedHostKey() string { return c.observedHostKey }

func (c *PaloAltoClient) Connect() error {
	client, hostKey, err := dialSSH(c.host, c.port, c.username, c.password, c.keyFile, c.keyPassphrase)
	c.observedHostKey = hostKey
	if err != nil {
		return err
	}
	c.client = client
	return nil
}

func (c *PaloAltoClient) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

// GetConfig captures `show config running` and returns the XML document. The
// result is cached for the client's lifetime so a poll's checksum + backup share
// one fetch. extractPaloAltoConfig isolates the document from any prompt/banner
// noise and requires a complete <config>…</config>, so a permission error,
// operational-mode error, or truncated capture is reported as a failure rather
// than stored as a bogus revision.
func (c *PaloAltoClient) GetConfig() (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}
	if c.configFetched {
		return c.config, nil
	}
	out, err := runCommandRaw(c.client, paloAltoShowConfigCmd, false, commandTimeout)
	if err != nil {
		return "", fmt.Errorf("run %q: %w", paloAltoShowConfigCmd, err)
	}
	cfg, err := extractPaloAltoConfig(out)
	if err != nil {
		return "", err
	}
	c.config = cfg
	c.configFetched = true
	return cfg, nil
}

// extractPaloAltoConfig isolates the PAN-OS running-config XML from raw command
// output. It tolerates any prompt/banner/stderr noise before the root element or
// after the closing tag (so an echoed command or login banner can't corrupt the
// stored config), and requires a complete <config …>…</config> pair so a
// truncated capture is rejected rather than silently stored (the server's
// paloalto normalizer only masks volatile fields — it has no completeness
// validator to catch a half-captured document downstream).
func extractPaloAltoConfig(out string) (string, error) {
	// The running config is rooted at `<config ` (with attributes) or a bare
	// `<config>`; match either without gobbling into a later element.
	start := strings.Index(out, "<config ")
	if bare := strings.Index(out, "<config>"); bare >= 0 && (start < 0 || bare < start) {
		start = bare
	}
	if start < 0 {
		return "", fmt.Errorf("no PAN-OS config in output (missing <config> root — check the SSH account has superuser/deviceadmin access and %q is valid)", paloAltoShowConfigCmd)
	}
	const closeTag = "</config>"
	end := strings.LastIndex(out, closeTag)
	if end < start {
		return "", fmt.Errorf("incomplete PAN-OS config (missing %s — capture may be truncated)", closeTag)
	}
	return out[start : end+len(closeTag)], nil
}

// GetConfigChecksum returns a change-detection token derived from the exact
// config bytes GetConfig will send, so the stored checksum always corresponds
// to the stored config. Backed by the same cached fetch as GetConfig.
func (c *PaloAltoClient) GetConfigChecksum() (string, error) {
	cfg, err := c.GetConfig()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(cfg))
	return hex.EncodeToString(sum[:]), nil
}
