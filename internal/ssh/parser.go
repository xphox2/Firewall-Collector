package ssh

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

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

type SensorDetailInfo struct {
	Name   string
	Value  float64
	Unit   string
	Status string
}

type LicenseDetailInfo struct {
	LicenseType string
	Status      string
	Expires     string
	Details     string
}

type PerformanceInfo struct {
	CPUUser    float64
	CPUSystem  float64
	CPUNice    float64
	CPUIdle    float64
	CPUIowait  float64
	CPUIrq     float64
	CPUSoftirq float64

	MemoryTotal           uint64
	MemoryUsed            uint64
	MemoryFree            uint64
	MemoryFreeable        uint64
	MemoryUsedPercent     float64
	MemoryFreePercent     float64
	MemoryFreeablePercent float64

	NetworkIn  float64
	NetworkOut float64

	SessionCount int
	SessionRate  int
	MaxSessions  int

	Uptime uint64
}

type VPNPhase1Info struct {
	Name          string
	Type          string
	Interface     string
	RemoteGateway string
	Mode          string
	Status        string
}

type VPNPhase2Info struct {
	Name          string
	Phase1Name    string
	RemoteGateway string
	Mode          string
	Status        string
}

var processTopRegex = regexp.MustCompile(`^\s*(\S+)\s+(\d+)\s+(\S)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+)`)

func ParseProcessTop(output string) []ProcessInfo {
	var processes []ProcessInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	inProcessList := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Run Time:") {
			inProcessList = true
			continue
		}
		if strings.Contains(line, "--More--") {
			continue
		}

		if !inProcessList {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := processTopRegex.FindStringSubmatch(line)
		if len(matches) >= 6 {
			name := matches[1]
			if name == "process" || name == "CPU" || name == "MEM" || name == "node" {
				continue
			}

			pid, err := strconv.Atoi(matches[2])
			if err != nil {
				continue
			}

			state := matches[3]

			cpu, err := strconv.ParseFloat(matches[4], 64)
			if err != nil {
				cpu = 0
			}

			mem, err := strconv.ParseFloat(matches[5], 64)
			if err != nil {
				mem = 0
			}

			processes = append(processes, ProcessInfo{
				Name:    name,
				PID:     pid,
				CPU:     cpu,
				Memory:  mem,
				Command: name + " (" + state + ")",
			})
		}
	}

	return processes
}

var (
	ifaceNameRegex  = regexp.MustCompile(`(?i)^name:\s*(\S+)`)
	ifaceStatsRegex = regexp.MustCompile(`(?i)(RX|TX)\s+bytes\s+(\d+).*?errors\s+(\d+).*?discards\s+(\d+)`)
	ifaceErrorRegex = regexp.MustCompile(`(?i)errors[:\s]+(\d+).*?discards[:\s]+(\d+)`)
)

func ParseInterfaceList(output string) []InterfaceErrorInfo {
	var interfaces []InterfaceErrorInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	var currentName string
	var currentInErrors, currentInDiscards, currentOutErrors, currentOutDiscards uint64

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		nameMatch := ifaceNameRegex.FindStringSubmatch(line)
		if len(nameMatch) >= 2 {
			if currentName != "" {
				interfaces = append(interfaces, InterfaceErrorInfo{
					Name:        currentName,
					InErrors:    currentInErrors,
					InDiscards:  currentInDiscards,
					OutErrors:   currentOutErrors,
					OutDiscards: currentOutDiscards,
				})
			}
			currentName = nameMatch[1]
			currentInErrors = 0
			currentInDiscards = 0
			currentOutErrors = 0
			currentOutDiscards = 0
			continue
		}

		line = strings.ToLower(line)
		if strings.Contains(line, "rx") && strings.Contains(line, "errors") {
			matches := ifaceErrorRegex.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				if len(m) >= 3 {
					if v, err := strconv.ParseUint(m[1], 10, 64); err == nil {
						if strings.Contains(line, "rx") {
							currentInErrors = v
						} else if strings.Contains(line, "tx") {
							currentOutErrors = v
						}
					}
					if v, err := strconv.ParseUint(m[2], 10, 64); err == nil {
						if strings.Contains(line, "rx") {
							currentInDiscards = v
						} else if strings.Contains(line, "tx") {
							currentOutDiscards = v
						}
					}
				}
			}
		}
	}

	if currentName != "" {
		interfaces = append(interfaces, InterfaceErrorInfo{
			Name:        currentName,
			InErrors:    currentInErrors,
			InDiscards:  currentInDiscards,
			OutErrors:   currentOutErrors,
			OutDiscards: currentOutDiscards,
		})
	}

	return interfaces
}

var (
	sensorNameRegex   = regexp.MustCompile(`(?i)^\s*Sensor\s+\d+:\s+(.+)$`)
	sensorValueRegex  = regexp.MustCompile(`(?i)^\s*Value:\s*([\d.]+)\s*(\w+)`)
	sensorStatusRegex = regexp.MustCompile(`(?i)^\s*Status:\s*(\w+)`)
)

func ParseSensorInfo(output string) []SensorDetailInfo {
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
			if v, err := strconv.ParseFloat(valueMatch[1], 64); err == nil {
				currentValue = v
			}
			currentUnit = strings.TrimSpace(valueMatch[2])
			valueFound = true
			continue
		}

		statusMatch := sensorStatusRegex.FindStringSubmatch(line)
		if len(statusMatch) >= 2 {
			currentStatus = strings.TrimSpace(statusMatch[1])
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

var (
	licenseStatusRegex = regexp.MustCompile(`(?i)^(?:License|VM License|SSL-VPN|SSLVPN|Explicit Proxy|FortiCare|FortiGuard|Antivirus|IPS|Web Filter|Email Filter|Application Control|Geo IP|IoT Detection|SD-WAN|Threat Feed|Virtual Domain)\s*[:.]*\s*(\w+)`)
	licenseDetailRegex = regexp.MustCompile(`(?i)^(License|VM License|SSL-VPN|SSLVPN|Explicit Proxy|FortiCare|FortiGuard|Antivirus|IPS|Web Filter|Email Filter|Application Control|Geo IP|IoT Detection|SD-WAN|Threat Feed|Virtual Domain)\s*[:.]*\s*(.+)`)
	versionRegex       = regexp.MustCompile(`(?i)^(?:Version|Firmware)\s*[:.]\s*(.+)`)
)

func ParseLicenseStatus(output string) []LicenseDetailInfo {
	var licenses []LicenseDetailInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		detailMatch := licenseDetailRegex.FindStringSubmatch(line)
		if len(detailMatch) >= 3 {
			desc := strings.TrimSpace(detailMatch[1])
			value := strings.TrimSpace(detailMatch[2])

			lic := LicenseDetailInfo{
				LicenseType: desc,
				Status:      "unknown",
				Expires:     "",
				Details:     value,
			}

			if strings.EqualFold(value, "valid") || strings.EqualFold(value, "enabled") {
				lic.Status = "licensed"
			} else if strings.EqualFold(value, "expired") || strings.EqualFold(value, "disabled") {
				lic.Status = "expired"
			} else if strings.Contains(strings.ToLower(value), "none") {
				lic.Status = "no_license"
			} else {
				lic.Status = value
			}

			licenses = append(licenses, lic)
			continue
		}

		statusMatch := licenseStatusRegex.FindStringSubmatch(line)
		if len(statusMatch) >= 2 && len(licenses) > 0 {
			status := strings.TrimSpace(statusMatch[1])
			if strings.EqualFold(status, "valid") || strings.EqualFold(status, "enabled") {
				licenses[len(licenses)-1].Status = "licensed"
			} else if strings.EqualFold(status, "expired") || strings.EqualFold(status, "disabled") {
				licenses[len(licenses)-1].Status = "expired"
			} else if strings.Contains(strings.ToLower(status), "none") {
				licenses[len(licenses)-1].Status = "no_license"
			}
		}
	}

	return licenses
}

var (
	cpuStatesRegex    = regexp.MustCompile(`CPU states:\s+(\d+)%\s+user\s+(\d+)%\s+system\s+(\d+)%\s+nice\s+(\d+)%\s+idle\s+(\d+)%\s+iowait\s+(\d+)%\s+irq\s+(\d+)%\s+softirq`)
	memoryRegex       = regexp.MustCompile(`Memory:\s+(\d+)k total,\s+(\d+)k used\s+\(([0-9.]+)%\),\s+(\d+)k free\s+\(([0-9.]+)%\),\s+(\d+)k freeable\s+\(([0-9.]+)%\)`)
	networkUsageRegex = regexp.MustCompile(`Average network usage:\s+([\d.]+)\s+/\s+([\d.]+)\s+kbps\s+in\s+(\d+)\s+minute`)
	sessionCountRegex = regexp.MustCompile(`Current sessions:\s+(\d+)`)
	sessionRateRegex  = regexp.MustCompile(`Maximal sessions:\s+(\d+)\s+sessions\s+in\s+(\d+)\s+minute`)
	uptimeRegex       = regexp.MustCompile(`Uptime:\s+(\d+)\s+days`)
)

func ParsePerformanceStatus(output string) *PerformanceInfo {
	info := &PerformanceInfo{}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		if cpuMatch := cpuStatesRegex.FindStringSubmatch(line); len(cpuMatch) >= 8 {
			info.CPUUser, _ = strconv.ParseFloat(cpuMatch[1], 64)
			info.CPUSystem, _ = strconv.ParseFloat(cpuMatch[2], 64)
			info.CPUNice, _ = strconv.ParseFloat(cpuMatch[3], 64)
			info.CPUIdle, _ = strconv.ParseFloat(cpuMatch[4], 64)
			info.CPUIowait, _ = strconv.ParseFloat(cpuMatch[5], 64)
			info.CPUIrq, _ = strconv.ParseFloat(cpuMatch[6], 64)
			info.CPUSoftirq, _ = strconv.ParseFloat(cpuMatch[7], 64)
			continue
		}

		if memMatch := memoryRegex.FindStringSubmatch(line); len(memMatch) >= 8 {
			info.MemoryTotal, _ = strconv.ParseUint(memMatch[1], 10, 64)
			info.MemoryUsed, _ = strconv.ParseUint(memMatch[2], 10, 64)
			info.MemoryFree, _ = strconv.ParseUint(memMatch[4], 10, 64)
			info.MemoryFreeable, _ = strconv.ParseUint(memMatch[6], 10, 64)
			info.MemoryUsedPercent, _ = strconv.ParseFloat(memMatch[3], 64)
			info.MemoryFreePercent, _ = strconv.ParseFloat(memMatch[5], 64)
			info.MemoryFreeablePercent, _ = strconv.ParseFloat(memMatch[7], 64)
			info.MemoryTotal *= 1024
			info.MemoryUsed *= 1024
			info.MemoryFree *= 1024
			info.MemoryFreeable *= 1024
			continue
		}

		if netMatch := networkUsageRegex.FindStringSubmatch(line); len(netMatch) >= 4 {
			info.NetworkIn, _ = strconv.ParseFloat(netMatch[1], 64)
			info.NetworkOut, _ = strconv.ParseFloat(netMatch[2], 64)
			continue
		}

		if sessMatch := sessionCountRegex.FindStringSubmatch(line); len(sessMatch) >= 2 {
			info.SessionCount, _ = strconv.Atoi(sessMatch[1])
			continue
		}

		if sessRateMatch := sessionRateRegex.FindStringSubmatch(line); len(sessRateMatch) >= 3 {
			info.MaxSessions, _ = strconv.Atoi(sessRateMatch[1])
			info.SessionRate, _ = strconv.Atoi(sessRateMatch[2])
			continue
		}

		if uptimeMatch := uptimeRegex.FindStringSubmatch(line); len(uptimeMatch) >= 2 {
			days, _ := strconv.ParseUint(uptimeMatch[1], 10, 64)
			info.Uptime = days * 86400
			continue
		}
	}

	return info
}

var (
	phase1NameRegex      = regexp.MustCompile(`(?i)edit\s+"([^"]+)"`)
	phase1TypeRegex      = regexp.MustCompile(`(?i)set\s+type\s+(\S+)`)
	phase1InterfaceRegex = regexp.MustCompile(`(?i)set\s+interface\s+(\S+)`)
	phase1RemoteRegex    = regexp.MustCompile(`(?i)set\s+remote-gw\s+(\S+)`)
	phase1ModeRegex      = regexp.MustCompile(`(?i)set\s+mode\s+(\S+)`)
	phase1StatusRegex    = regexp.MustCompile(`(?i)set\s+status\s+(\S+)`)

	phase2NameRegex   = regexp.MustCompile(`(?i)edit\s+"([^"]+)"`)
	phase2Phase1Regex = regexp.MustCompile(`(?i)set\s+phase1name\s+"([^"]+)"`)
	phase2RemoteRegex = regexp.MustCompile(`(?i)set\s+remote-gw\s+(\S+)`)
	phase2ModeRegex   = regexp.MustCompile(`(?i)set\s+mode\s+(\S+)`)
	phase2StatusRegex = regexp.MustCompile(`(?i)set\s+status\s+(\S+)`)
)

func ParseVPNPhase1(output string) []VPNPhase1Info {
	var tunnels []VPNPhase1Info
	scanner := bufio.NewScanner(strings.NewReader(output))

	var current VPNPhase1Info

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if nameMatch := phase1NameRegex.FindStringSubmatch(line); len(nameMatch) >= 2 {
			if current.Name != "" {
				tunnels = append(tunnels, current)
			}
			current = VPNPhase1Info{Name: nameMatch[1]}
			continue
		}

		if typeMatch := phase1TypeRegex.FindStringSubmatch(line); len(typeMatch) >= 2 {
			current.Type = typeMatch[1]
		}
		if intfMatch := phase1InterfaceRegex.FindStringSubmatch(line); len(intfMatch) >= 2 {
			current.Interface = intfMatch[1]
		}
		if remoteMatch := phase1RemoteRegex.FindStringSubmatch(line); len(remoteMatch) >= 2 {
			current.RemoteGateway = remoteMatch[1]
		}
		if modeMatch := phase1ModeRegex.FindStringSubmatch(line); len(modeMatch) >= 2 {
			current.Mode = modeMatch[1]
		}
		if statusMatch := phase1StatusRegex.FindStringSubmatch(line); len(statusMatch) >= 2 {
			current.Status = statusMatch[1]
		}
	}

	if current.Name != "" {
		tunnels = append(tunnels, current)
	}

	return tunnels
}

func ParseVPNPhase2(output string) []VPNPhase2Info {
	var tunnels []VPNPhase2Info
	scanner := bufio.NewScanner(strings.NewReader(output))

	var current VPNPhase2Info

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if nameMatch := phase2NameRegex.FindStringSubmatch(line); len(nameMatch) >= 2 {
			if current.Name != "" {
				tunnels = append(tunnels, current)
			}
			current = VPNPhase2Info{Name: nameMatch[1]}
			continue
		}

		if phase1Match := phase2Phase1Regex.FindStringSubmatch(line); len(phase1Match) >= 2 {
			current.Phase1Name = phase1Match[1]
		}
		if remoteMatch := phase2RemoteRegex.FindStringSubmatch(line); len(remoteMatch) >= 2 {
			current.RemoteGateway = remoteMatch[1]
		}
		if modeMatch := phase2ModeRegex.FindStringSubmatch(line); len(modeMatch) >= 2 {
			current.Mode = modeMatch[1]
		}
		if statusMatch := phase2StatusRegex.FindStringSubmatch(line); len(statusMatch) >= 2 {
			current.Status = statusMatch[1]
		}
	}

	if current.Name != "" {
		tunnels = append(tunnels, current)
	}

	return tunnels
}
