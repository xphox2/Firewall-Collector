package ssh

import (
	"fmt"
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
	promptPattern := "$ "

	for _, line := range lines {
		if strings.Contains(line, "--More--") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "FW-") && strings.Contains(trimmed, promptPattern) {
			continue
		}
		if strings.Contains(trimmed, "$") && !strings.Contains(trimmed, "config:") && !strings.Contains(trimmed, "image:") && !strings.Contains(trimmed, "Run Time:") && !strings.Contains(trimmed, "Temperature") {
			continue
		}
		cleaned = append(cleaned, trimmed)
	}
	return strings.Join(cleaned, "\n")
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
	return c.Execute("show")
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
