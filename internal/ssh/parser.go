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
