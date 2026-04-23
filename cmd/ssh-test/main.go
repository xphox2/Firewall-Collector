package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
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

type SensorDetailInfo struct {
	Name   string
	Value  float64
	Unit   string
	Status string
}

type ProcessInfo struct {
	Name    string
	PID     int
	CPU     float64
	Memory  float64
	Command string
}

type InterfaceErrorInfo struct {
	Name        string
	InErrors    uint64
	InDiscards  uint64
	OutErrors   uint64
	OutDiscards uint64
}

var (
	sensorNameRegex   = regexp.MustCompile(`(?i)^\s*Sensor\s+\d+:\s+(.+)$`)
	sensorValueRegex  = regexp.MustCompile(`(?i)^\s*Value:\s*([\d.]+)\s*(\w+)`)
	sensorStatusRegex = regexp.MustCompile(`(?i)^\s*Status:\s*(\w+)`)
	sensorLineRegex   = regexp.MustCompile(`(?i)^\s*(\d+)\s+(.+?)\s+\.+\s+([\d.]+)\s*(\w+)\s*(.*)$`)
)

func ParseSensorInfo(output string) []SensorDetailInfo {
	if len(output) == 0 {
		return nil
	}
	var sensors []SensorDetailInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	var currentName, currentUnit, currentStatus string
	var currentValue float64
	valueFound := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		nameMatch := sensorNameRegex.FindStringSubmatch(line)
		if len(nameMatch) >= 2 {
			if currentName != "" && valueFound {
				sensors = append(sensors, SensorDetailInfo{
					Name:   currentName,
					Value:  currentValue,
					Unit:   currentUnit,
					Status: currentStatus,
				})
			}
			currentName = strings.TrimSpace(nameMatch[1])
			currentUnit = ""
			currentStatus = "unknown"
			currentValue = 0
			valueFound = false
			continue
		}

		valueMatch := sensorValueRegex.FindStringSubmatch(line)
		if len(valueMatch) >= 3 {
			var v float64
			if _, err := fmt.Sscanf(valueMatch[1], "%f", &v); err == nil {
				currentValue = v
			}
			currentUnit = strings.TrimSpace(valueMatch[2])
			valueFound = true
			continue
		}

		statusMatch := sensorStatusRegex.FindStringSubmatch(line)
		if len(statusMatch) >= 2 {
			currentStatus = strings.TrimSpace(statusMatch[1])
			continue
		}

		lineMatch := sensorLineRegex.FindStringSubmatch(line)
		if len(lineMatch) >= 5 {
			currentName = strings.TrimSpace(lineMatch[2])
			var v float64
			if _, err := fmt.Sscanf(lineMatch[3], "%f", &v); err == nil {
				currentValue = v
			}
			currentUnit = strings.TrimSpace(lineMatch[4])
			statusPart := strings.TrimSpace(lineMatch[5])
			if statusPart != "" {
				currentStatus = statusPart
			} else {
				currentStatus = "normal"
			}
			valueFound = true
			if currentName != "" {
				sensors = append(sensors, SensorDetailInfo{
					Name:   currentName,
					Value:  currentValue,
					Unit:   currentUnit,
					Status: currentStatus,
				})
			}
			currentName = ""
			currentValue = 0
			currentUnit = ""
			currentStatus = ""
			valueFound = false
		}
	}

	if currentName != "" && valueFound {
		sensors = append(sensors, SensorDetailInfo{
			Name:   currentName,
			Value:  currentValue,
			Unit:   currentUnit,
			Status: currentStatus,
		})
	}

	return sensors
}

var processLineRegex = regexp.MustCompile(`^\s*(\S+)\s+(\d+)\s+(\S)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+)`)

func ParseProcessTop(output string) []ProcessInfo {
	var processes []ProcessInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	inProcessList := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "Run Time:") {
			inProcessList = true
			continue
		}

		if !inProcessList {
			if strings.Contains(line, "U,") && strings.Contains(line, "T,") {
				inProcessList = true
				continue
			}
		}

		if !inProcessList {
			continue
		}

		match := processLineRegex.FindStringSubmatch(line)
		if len(match) >= 6 {
			name := match[1]
			if name == "process" || name == "CPU" || name == "MEM" || name == "node" {
				continue
			}
			var pid int
			var cpu, mem float64
			fmt.Sscanf(match[2], "%d", &pid)
			fmt.Sscanf(match[4], "%f", &cpu)
			fmt.Sscanf(match[5], "%f", &mem)
			processes = append(processes, ProcessInfo{
				Name:    name,
				PID:     pid,
				CPU:     cpu,
				Memory:  mem,
				Command: match[6],
			})
		}
	}
	return processes
}

var ifaceLineRegex = regexp.MustCompile(`^\s*(\S+)\s+(?:[^|]+\|){3}\s*(\d+)\s+(?:[^|]+\|){3}\s*(\d+)\s+(?:[^|]+\|){3}\s*(\d+)\s+(?:[^|]+\|){3}\s*(\d+)`)

func ParseInterfaceList(output string) []InterfaceErrorInfo {
	var interfaces []InterfaceErrorInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") || strings.Contains(line, "flags=") {
			continue
		}

		match := ifaceLineRegex.FindStringSubmatch(line)
		if len(match) >= 6 {
			var inErr, inDisc, outErr, outDisc uint64
			fmt.Sscanf(match[2], "%d", &inErr)
			fmt.Sscanf(match[3], "%d", &inDisc)
			fmt.Sscanf(match[4], "%d", &outErr)
			fmt.Sscanf(match[5], "%d", &outDisc)
			interfaces = append(interfaces, InterfaceErrorInfo{
				Name:        match[1],
				InErrors:    inErr,
				InDiscards:  inDisc,
				OutErrors:   outErr,
				OutDiscards: outDisc,
			})
		}
	}
	return interfaces
}

func main() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: ssh-test <host> <port> <username> <password> [all|sensor|process|interface|license|performance|vpn|ha|checksum|config]")
		fmt.Println("")
		fmt.Println("Commands to test:")
		fmt.Println("  all        - Test all SSH commands")
		fmt.Println("  sensor     - Test 'execute sensor list' (Hardware Sensors)")
		fmt.Println("  process    - Test 'diagnose sys top' (Process Monitor)")
		fmt.Println("  interface  - Test 'diagnose netlink interface list' (Interface Errors)")
		fmt.Println("  license    - Test 'get system status' (License Info)")
		fmt.Println("  performance - Test 'get system performance status'")
		fmt.Println("  vpn        - Test 'show vpn ipsec phase1/phase2-interface' (VPN Status)")
		fmt.Println("  ha         - Test 'get system ha status' (HA Status)")
		fmt.Println("  checksum   - Test 'diagnose sys csum' (Config Checksum)")
		fmt.Println("  config     - Test 'show' (Full Config)")
		os.Exit(1)
	}

	host := os.Args[1]
	port := os.Args[2]
	username := os.Args[3]
	password := os.Args[4]
	testCmd := "all"
	if len(os.Args) > 5 {
		testCmd = os.Args[5]
	}

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)

	client := NewFortiGateClient(host, portNum, username, password)
	log.Printf("=== SSH FortiGate Test ===")
	log.Printf("Host: %s:%d", host, portNum)
	log.Printf("User: %s", username)
	log.Printf("Test: %s", testCmd)
	log.Printf("")

	if err := client.Connect(); err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer client.Close()
	log.Printf("Connected successfully!")
	log.Printf("")

	testAll := testCmd == "all"

	if testAll || testCmd == "checksum" {
		log.Printf("=== Testing GetConfigChecksum (diagnose sys csum) ===")
		checksum, err := client.GetConfigChecksum()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			log.Printf("OK: checksum=%s (len=%d)", checksum, len(checksum))
		}
		log.Printf("")
	}

	if testAll || testCmd == "config" {
		log.Printf("=== Testing GetConfig (show) ===")
		config, err := client.GetConfig()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			lines := strings.Split(config, "\n")
			log.Printf("OK: %d lines, first 3: %s", len(lines), strings.Join(lines[:3], " | "))
		}
		log.Printf("")
	}

	if testAll || testCmd == "process" {
		log.Printf("=== Testing GetProcessTop (diagnose sys top) ===")
		output, err := client.GetProcessTop()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			log.Printf("Raw output (%d bytes): %q", len(output), output)
			processes := ParseProcessTop(output)
			log.Printf("OK: parsed %d processes", len(processes))
			if len(processes) > 0 {
				log.Printf("Sample: %+v", processes[0])
			}
		}
		log.Printf("")
	}

	if testAll || testCmd == "interface" {
		log.Printf("=== Testing GetInterfaceList (diagnose netlink interface list) ===")
		output, err := client.GetInterfaceList()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			log.Printf("Raw output (%d bytes): %q", len(output), output)
			interfaces := ParseInterfaceList(output)
			log.Printf("OK: parsed %d interfaces", len(interfaces))
			if len(interfaces) > 0 {
				log.Printf("Sample: %+v", interfaces[0])
			}
		}
		log.Printf("")
	}

	if testAll || testCmd == "sensor" {
		log.Printf("=== Testing GetSensorInfo (execute sensor list) ===")
		output, err := client.GetSensorInfo()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			log.Printf("Raw output (%d bytes): %q", len(output), output)
			sensors := ParseSensorInfo(output)
			log.Printf("OK: parsed %d sensors", len(sensors))
			for i, s := range sensors {
				log.Printf("  [%d] %s = %.1f %s (status: %s)", i+1, s.Name, s.Value, s.Unit, s.Status)
			}
		}
		log.Printf("")
	}

	if testAll || testCmd == "license" {
		log.Printf("=== Testing GetLicenseStatus (get system status) ===")
		output, err := client.GetLicenseStatus()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			lines := strings.Split(output, "\n")
			log.Printf("OK: %d lines", len(lines))
			log.Printf("First 10 lines:")
			for i := 0; i < len(lines) && i < 10; i++ {
				log.Printf("  %s", lines[i])
			}
		}
		log.Printf("")
	}

	if testAll || testCmd == "performance" {
		log.Printf("=== Testing GetPerformanceStatus (get system performance status) ===")
		output, err := client.GetPerformanceStatus()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			lines := strings.Split(output, "\n")
			log.Printf("OK: %d lines", len(lines))
			for i := 0; i < len(lines) && i < 5; i++ {
				log.Printf("  %s", lines[i])
			}
		}
		log.Printf("")
	}

	if testAll || testCmd == "vpn" {
		log.Printf("=== Testing GetVPNStatus (show vpn ipsec phase1/phase2-interface) ===")
		phase1, phase2, err := client.GetVPNStatus()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			p1Lines := strings.Split(phase1, "\n")
			p2Lines := strings.Split(phase2, "\n")
			log.Printf("OK: phase1=%d lines, phase2=%d lines", len(p1Lines), len(p2Lines))
			log.Printf("Phase1 sample (first 3 non-empty):")
			count := 0
			for _, l := range p1Lines {
				if strings.TrimSpace(l) != "" {
					log.Printf("  %s", l)
					count++
					if count >= 3 {
						break
					}
				}
			}
		}
		log.Printf("")
	}

	if testAll || testCmd == "ha" {
		log.Printf("=== Testing GetHAStatus (get system ha status) ===")
		output, err := client.GetHAStatus()
		if err != nil {
			log.Printf("FAILED: %v", err)
		} else {
			lines := strings.Split(output, "\n")
			log.Printf("OK: %d lines", len(lines))
			for i := 0; i < len(lines) && i < 5; i++ {
				log.Printf("  %s", lines[i])
			}
		}
		log.Printf("")
	}

	log.Printf("=== All Tests Complete ===")
}
