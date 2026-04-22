package ssh

import (
	"bufio"
	"fmt"
	"io"
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

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe failed: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe failed: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
		return "", fmt.Errorf("pty request failed: %w", err)
	}

	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("shell start failed: %w", err)
	}

	time.Sleep(500 * time.Millisecond)

	reader := bufio.NewReader(stdout)

	_, err = stdin.Write([]byte(command + "\n"))
	if err != nil {
		return "", fmt.Errorf("write failed: %w", err)
	}

	var output []byte
	buf := make([]byte, 4096)
	done := time.After(5 * time.Second)

	for {
		select {
		case <-done:
			n, _ := reader.Read(buf)
			if n > 0 {
				output = append(output, buf[:n]...)
			}
			return cleanOutput(string(output)), nil
		default:
			n, err := reader.Read(buf)
			if n > 0 {
				output = append(output, buf[:n]...)
			}
			if err != nil {
				if err == io.EOF {
					return cleanOutput(string(output)), nil
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
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
		if strings.Contains(line, "$") {
			continue
		}
		line = strings.TrimSpace(line)
		if line != "" {
			cleaned = append(cleaned, line)
		}
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
