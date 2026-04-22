package ssh

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
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

	session.Stdout = nil
	session.Stderr = nil

	if err := session.RequestPty("vt100", 80, 40, nil); err != nil {
	}

	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("shell start failed: %w", err)
	}

	out, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("execute failed: %w", err)
	}

	return string(out), nil
}

func (c *FortiGateClient) GetConfigChecksum() (string, error) {
	output, err := c.Execute("diagnose sys checksum conf")
	if err != nil {
		return "", err
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

	checksum := strings.TrimSpace(output)
	if len(checksum) > 32 {
		checksum = checksum[len(checksum)-32:]
	}
	return checksum, nil
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

func (c *FortiGateClient) GetConfig() (string, error) {
	return c.Execute("show")
}

func (c *FortiGateClient) GetProcessTop() (string, error) {
	return c.Execute("diagnose sys top")
}

func (c *FortiGateClient) GetInterfaceList() (string, error) {
	return c.Execute("diagnose netlink interface list")
}
