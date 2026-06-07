package ssh

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	promptRegex         = regexp.MustCompile(`^(FW-|FGT-|FG-).*\s[\$#]\s*$`)
	promptWithVDOMRegex = regexp.MustCompile(`^(FW-|FGT-|FG-).*\((global|root)\)\s*[\$#]\s*$`)
	commandTimeout      = 10 * time.Minute
)

type FortiGateClient struct {
	host          string
	port          int
	username      string
	password      string
	keyFile       string
	keyPassphrase string
	client        *ssh.Client
}

func NewFortiGateClient(host string, port int, username, password string) *FortiGateClient {
	return NewFortiGateClientWithKey(host, port, username, password, "", "")
}

func NewFortiGateClientWithKey(host string, port int, username, password, keyFile, keyPassphrase string) *FortiGateClient {
	if port == 0 {
		port = 22
	}
	return &FortiGateClient{
		host:          host,
		port:          port,
		username:      username,
		password:      password,
		keyFile:       keyFile,
		keyPassphrase: keyPassphrase,
	}
}

func (c *FortiGateClient) Connect() error {
	auth, err := c.buildAuthMethods()
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            c.username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("ssh dial failed: %w", err)
	}
	c.client = client

	return nil
}

func (c *FortiGateClient) buildAuthMethods() ([]ssh.AuthMethod, error) {
	if c.keyFile != "" {
		signer, err := loadPrivateKey(c.keyFile, c.keyPassphrase)
		if err != nil {
			return nil, fmt.Errorf("load ssh key %q: %w", c.keyFile, err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	if c.password != "" {
		log.Printf("[SSH] WARNING: device %s using password auth (key file not configured) — password is sent plaintext during the SSH handshake before encryption (AUDIT-071)", c.host)
		return []ssh.AuthMethod{ssh.Password(c.password)}, nil
	}
	return nil, fmt.Errorf("ssh: no auth method configured for %s (set SSHKeyFile or SSHPassword)", c.host)
}

func loadPrivateKey(path, passphrase string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("parse encrypted key: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return signer, nil
}

func (c *FortiGateClient) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

func (c *FortiGateClient) Execute(command string) (string, error) {
	return c.executeWith(command, false, commandTimeout)
}

// ExecuteRaw runs a command and returns the unfiltered combined output. Useful
// when a caller needs to see exactly what FortiOS printed (e.g. TFTP backup
// diagnostics) without cleanOutput's prompt/empty-line stripping.
func (c *FortiGateClient) ExecuteRaw(command string, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = commandTimeout
	}
	return c.executeRaw(command, false, timeout)
}

// ExecuteWithPty runs a command in a session that has a PTY allocated. Some
// FortiOS builds drop non-PTY channels before completing side-effecting
// `execute` commands (notably TFTP backup), so this variant is used for those.
// Returns raw output without cleanOutput stripping.
func (c *FortiGateClient) ExecuteWithPty(command string, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = commandTimeout
	}
	return c.executeRaw(command, true, timeout)
}

func (c *FortiGateClient) executeWith(command string, requestPty bool, timeout time.Duration) (string, error) {
	raw, err := c.executeRaw(command, requestPty, timeout)
	if err != nil {
		return "", err
	}
	return cleanOutput(raw), nil
}

func (c *FortiGateClient) executeRaw(command string, requestPty bool, timeout time.Duration) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session failed: %w", err)
	}
	defer session.Close()

	if requestPty {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty("xterm", 80, 200, modes); err != nil {
			return "", fmt.Errorf("request pty failed: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan struct{})
	stopChan := make(chan struct{})
	var output []byte
	var execErr error

	go func() {
		output, execErr = session.CombinedOutput(command)
		close(done)
	}()

	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-stopChan:
		}
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("command timed out after %v: %s", timeout, command)
	case <-done:
		close(stopChan)
		if execErr != nil {
			return string(output), fmt.Errorf("execute failed: %w", execErr)
		}
		return string(output), nil
	}
}

func cleanOutput(output string) string {
	lines := strings.Split(output, "\n")
	cleaned := make([]string, 0, len(lines))

	for _, line := range lines {
		if strings.Contains(line, "--More--") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if isCLIPrompt(trimmed) {
			continue
		}
		cleaned = append(cleaned, trimmed)
	}
	return strings.Join(cleaned, "\n")
}

func isCLIPrompt(line string) bool {
	if strings.Contains(line, "--More--") {
		return false
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if isPromptLine(trimmed, "FW-") || isPromptLine(trimmed, "FGT-") || isPromptLine(trimmed, "FG-") {
		return true
	}
	return false
}

func isPromptLine(line, prefix string) bool {
	if !strings.HasPrefix(line, prefix) {
		return false
	}
	if promptWithVDOMRegex.MatchString(line) || promptRegex.MatchString(line) {
		return true
	}
	return false
}

func (c *FortiGateClient) GetConfigChecksum() (string, error) {
	output, err := c.Execute("diagnose sys csum")
	if err != nil {
		return "", err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "image:") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "image:" && i+16 <= len(parts) {
					var checksumBuilder strings.Builder
					for j := 0; j < 16; j++ {
						checksumBuilder.WriteString(strings.TrimSpace(parts[i+1+j]))
					}
					checksum := checksumBuilder.String()
					if len(checksum) == 32 {
						return checksum, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("could not parse checksum from output: %s", output)
}

func (c *FortiGateClient) GetConfig() (string, error) {
	return c.Execute("show full-configuration")
}

func (c *FortiGateClient) GetProcessTop() (string, error) {
	return c.Execute("diagnose sys top")
}

func (c *FortiGateClient) GetInterfaceList() (string, error) {
	return c.Execute("diagnose netlink interface list")
}

func (c *FortiGateClient) GetSensorInfo() (string, error) {
	return c.Execute("execute sensor list")
}

func (c *FortiGateClient) GetLicenseStatus() (string, error) {
	return c.Execute("get system status")
}

func (c *FortiGateClient) GetPerformanceStatus() (string, error) {
	return c.Execute("get system performance status")
}

func (c *FortiGateClient) GetVPNStatus() (string, string, error) {
	phase1, err := c.Execute("show vpn ipsec phase1-interface")
	if err != nil {
		return "", "", fmt.Errorf("phase1 failed: %w", err)
	}
	phase2, err := c.Execute("show vpn ipsec phase2-interface")
	if err != nil {
		return phase1, "", fmt.Errorf("phase2 failed: %w", err)
	}
	return phase1, phase2, nil
}

func (c *FortiGateClient) GetHAStatus() (string, error) {
	return c.Execute("get system ha status")
}

func (c *FortiGateClient) GetSystemSessionList() (string, error) {
	return c.Execute("get system session list")
}

func (c *FortiGateClient) BackupConfigTFTP(filename, tftpServerIP string) (string, error) {
	cmd := fmt.Sprintf("execute backup config tftp %s %s", filename, tftpServerIP)
	// Request a PTY: some FortiOS builds drop non-PTY channels before completing
	// the TFTP transfer side effect. 90s is enough for the firewall to either
	// finish or print a definitive failure (default TFTP retry budget is ~25s).
	return c.ExecuteWithPty(cmd, 90*time.Second)
}

func (c *FortiGateClient) BackupConfigSCP(filename, scpServerIP, username, password string) error {
	cmd := fmt.Sprintf("execute backup config scp %s %s %s %s", filename, scpServerIP, username, password)
	_, err := c.Execute(cmd)
	return err
}
