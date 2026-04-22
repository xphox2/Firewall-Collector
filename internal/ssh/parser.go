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

func ParseProcessTop(output string) []ProcessInfo {
	var processes []ProcessInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if lineNum < 5 {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := splitByWhitespace(line)
		if len(parts) < 6 {
			continue
		}

		name := parts[0]
		pid, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		cpuStr := strings.TrimSuffix(parts[2], "%")
		cpu, err := strconv.ParseFloat(cpuStr, 64)
		if err != nil {
			cpu = 0
		}

		memStr := strings.TrimSuffix(parts[3], "%")
		mem, err := strconv.ParseFloat(memStr, 64)
		if err != nil {
			mem = 0
		}

		command := strings.Join(parts[5:], " ")

		processes = append(processes, ProcessInfo{
			Name:    name,
			PID:     pid,
			CPU:     cpu,
			Memory:  mem,
			Command: command,
		})
	}

	return processes
}

func ParseInterfaceList(output string) []InterfaceErrorInfo {
	var interfaces []InterfaceErrorInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	var currentName string
	var currentInErrors, currentInDiscards, currentOutErrors, currentOutDiscards uint64

	inStats := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "==") || strings.HasPrefix(line, "name:") {
			if currentName != "" {
				interfaces = append(interfaces, InterfaceErrorInfo{
					Name:        currentName,
					InErrors:    currentInErrors,
					InDiscards:  currentInDiscards,
					OutErrors:   currentOutErrors,
					OutDiscards: currentOutDiscards,
				})
			}

			if strings.HasPrefix(line, "name:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					currentName = strings.TrimSpace(parts[1])
				}
				currentInErrors = 0
				currentInDiscards = 0
				currentOutErrors = 0
				currentOutDiscards = 0
				inStats = false
			}
			continue
		}

		if strings.Contains(line, "RX") || strings.Contains(line, "TX") || inStats {
			if strings.Contains(line, "errors:") {
				inStats = true
				re := regexp.MustCompile(`errors[:\s]+(\d+)`)
				matches := re.FindAllStringSubmatch(line, -1)
				if len(matches) >= 1 {
					if v, err := strconv.ParseUint(matches[0][1], 10, 64); err == nil {
						currentInErrors = v
					}
				}
				if len(matches) >= 2 {
					if v, err := strconv.ParseUint(matches[1][1], 10, 64); err == nil {
						currentOutErrors = v
					}
				}
			}
			if strings.Contains(line, "discards:") {
				re := regexp.MustCompile(`discards[:\s]+(\d+)`)
				matches := re.FindAllStringSubmatch(line, -1)
				if len(matches) >= 1 {
					if v, err := strconv.ParseUint(matches[0][1], 10, 64); err == nil {
						currentInDiscards = v
					}
				}
				if len(matches) >= 2 {
					if v, err := strconv.ParseUint(matches[1][1], 10, 64); err == nil {
						currentOutDiscards = v
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
