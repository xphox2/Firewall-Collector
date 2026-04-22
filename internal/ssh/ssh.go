package ssh

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	checksumRegex     = regexp.MustCompile(`(?i)is\s+([a-fA-F0-9]{32}|[a-fA-F0-9]{40})`)
	hexChecksumFinder = regexp.MustCompile(`([a-fA-F0-9]{32}|[a-fA-F0-9]{40})`)
)

type FortiGateClient struct {
	host     string
	port     int
	username string
	password string
	client   *ssh.Client
}

func NewFortiGateClient(host string, port int, username, password string) *FortiGateClient {
	if port == 0 {
		port = 22
	}
	return &FortiGateClient{
		host:     host,
		port:     port,
		username: username,
		password: password,
	}
}

func (c *FortiGateClient) Connect() error {
	config := &ssh.ClientConfig{
		User: c.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("ssh dial failed: %w", err)
	}
	c.client = client

	return nil
}

func (c *FortiGateClient) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

func (c *FortiGateClient) Execute(command string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session failed: %w", err)
	}
	defer session.Close()

	out, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("execute failed: %w", err)
	}

	return cleanOutput(string(out)), nil
}

func cleanOutput(output string) string {
	lines := strings.Split(output, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "--More--") {
			continue
		}
		if strings.Contains(line, " # ") {
			idx := strings.Index(line, " # ")
			line = line[idx+3:]
		}
		if strings.Contains(line, "# ") {
			idx := strings.Index(line, "# ")
			line = line[idx+2:]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}
	return strings.Join(cleaned, "\n")
}

func (c *FortiGateClient) GetConfigChecksum() (string, error) {
	output, err := c.Execute("diagnose sys checksum conf")
	if err != nil {
		return "", err
	}

	matches := checksumRegex.FindStringSubmatch(output)
	if len(matches) >= 2 {
		checksum := strings.ToLower(matches[1])
		if len(checksum) == 32 || len(checksum) == 40 {
			return checksum, nil
		}
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "is") {
			parts := strings.Fields(line)
			for i := len(parts) - 1; i >= 0; i-- {
				if parts[i] == "is" && i+1 < len(parts) {
					checksum := parts[i+1]
					if isHexString(checksum) {
						return checksum, nil
					}
				}
			}
		}
	}

	lines = strings.Split(output, "\n")
	for _, line := range lines {
		checksum := extractHexChecksum(line)
		if checksum != "" {
			return checksum, nil
		}
	}

	return "", fmt.Errorf("could not parse checksum from output")
}

func isHexString(s string) bool {
	if len(s) < 8 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func extractHexChecksum(line string) string {
	matches := hexChecksumFinder.FindStringSubmatch(line)
	if len(matches) >= 1 {
		return strings.ToLower(matches[1])
	}
	return ""
}

func (c *FortiGateClient) GetConfig() (string, error) {
	return c.Execute("show")
}

func (c *FortiGateClient) GetProcessTop() (string, error) {
	return c.Execute("diagnose sys top")
}

func (c *FortiGateClient) GetInterfaceList() (string, error) {
	return c.Execute("diagnose netlink interface list")
}

func (c *FortiGateClient) GetSensorInfo() (string, error) {
	return c.Execute("diagnose sys sensor info")
}

func (c *FortiGateClient) GetLicenseStatus() (string, error) {
	return c.Execute("diagnose license status")
}
