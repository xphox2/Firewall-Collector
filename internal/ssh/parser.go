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

var processTopRegex = regexp.MustCompile(`^\s*(\S+)\s+(\d+)\s+(\d+\.?\d*)%\s+(\d+\.?\d*)%\s+(.*)`)

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
			if name == "process" || name == "CPU" || name == "MEM" {
				continue
			}

			pid, err := strconv.Atoi(matches[2])
			if err != nil {
				continue
			}

			cpu, err := strconv.ParseFloat(matches[3], 64)
			if err != nil {
				cpu = 0
			}

			mem, err := strconv.ParseFloat(matches[4], 64)
			if err != nil {
				mem = 0
			}

			command := strings.TrimSpace(matches[5])
			if command == "" {
				command = name
			}

			processes = append(processes, ProcessInfo{
				Name:    name,
				PID:     pid,
				CPU:     cpu,
				Memory:  mem,
				Command: command,
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

func splitByWhitespace(s string) []string {
	var result []string
	var current strings.Builder
	inSpace := true

	for _, ch := range s {
		if ch == ' ' || ch == '\t' {
			if !inSpace && current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			inSpace = true
		} else {
			current.WriteRune(ch)
			inSpace = false
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
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
	licenseTypeRegex    = regexp.MustCompile(`(?i)^(\w[\w\s]+):\s*$`)
	licenseStatusRegex  = regexp.MustCompile(`(?i)^\s*Status:\s*(\w+)`)
	licenseExpiresRegex = regexp.MustCompile(`(?i)^\s*Expires?:\s*(.+)`)
	licenseDetailsRegex = regexp.MustCompile(`(?i)^\s*(Version|Account|Support|Support Level):\s*(.+)`)
)

func ParseLicenseStatus(output string) []LicenseDetailInfo {
	var licenses []LicenseDetailInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	var currentType, currentStatus, currentExpires, currentDetails string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "--More--") {
			continue
		}

		typeMatch := licenseTypeRegex.FindStringSubmatch(line)
		if len(typeMatch) >= 2 {
			if currentType != "" {
				licenses = append(licenses, LicenseDetailInfo{
					LicenseType: currentType,
					Status:      currentStatus,
					Expires:     currentExpires,
					Details:     currentDetails,
				})
			}
			currentType = strings.TrimSpace(typeMatch[1])
			currentStatus = "unknown"
			currentExpires = ""
			currentDetails = ""
			continue
		}

		statusMatch := licenseStatusRegex.FindStringSubmatch(line)
		if len(statusMatch) >= 2 {
			currentStatus = strings.TrimSpace(statusMatch[1])
			continue
		}

		expiresMatch := licenseExpiresRegex.FindStringSubmatch(line)
		if len(expiresMatch) >= 2 {
			currentExpires = strings.TrimSpace(expiresMatch[1])
			continue
		}

		detailsMatch := licenseDetailsRegex.FindStringSubmatch(line)
		if len(detailsMatch) >= 3 {
			if currentDetails != "" {
				currentDetails += "; "
			}
			currentDetails += detailsMatch[1] + ": " + strings.TrimSpace(detailsMatch[2])
		}
	}

	if currentType != "" {
		licenses = append(licenses, LicenseDetailInfo{
			LicenseType: currentType,
			Status:      currentStatus,
			Expires:     currentExpires,
			Details:     currentDetails,
		})
	}

	return licenses
}
