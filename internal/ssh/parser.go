package ssh

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
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

// OPNsenseSensor is one hardware/environmental reading parsed from a FreeBSD
// `sysctl` dump (temperature, per-rail voltage/current/power, fan speed).
// Values keep native FreeBSD units (°C / mV / mA / mW / RPM) — no conversion.
type OPNsenseSensor struct {
	Name   string
	Type   string // temperature | voltage | current | power | fan
	Value  float64
	Unit   string
	Status string // normal | alarm
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
	// LocalSubnet/RemoteSubnet are the phase2 traffic selectors, in CANONICAL
	// CIDR — not the "addr netmask" pair the device prints. See subnetToCIDR.
	LocalSubnet  string
	RemoteSubnet string
}

var processTopRegex = regexp.MustCompile(`^\s*(\S+)\s+(\d+)\s+(\S)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+)`)

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
	// Interface header: the "Name: wan1" block form AND the real FortiOS
	// `diagnose netlink interface list` header "if=wan1 family=00 ..."
	// (AUDIT-222). No verbatim device capture exists in either repo yet —
	// when one becomes available it should be turned into a fixture.
	ifaceNameRegex = regexp.MustCompile(`(?i)^(?:name:|if=)\s*(\S+)`)
	// Direction-tagged errors+discards pair. Direction comes from the MATCH
	// text, not the line, so a combined RX+TX line fills both directions
	// instead of TX overwriting RX (AUDIT-222). Matches both the block shape
	// "RX bytes 1000000  errors 5  discards 3" and netlink-style
	// "rx_errors=5 rx_dropped=3" tokens. Known hazard: the discards group is
	// undirected and pairs with the PRECEDING direction match, so a line
	// missing one direction's discards token (e.g. "RX errors 5 TX errors 7
	// discards 2") would cross-assign — no known real output has that shape;
	// every observed form pairs errors+discards per direction.
	ifaceErrPairRegex = regexp.MustCompile(`(?i)\b(rx|tx)(?:[_ ]?errors|[_ ]?bytes[^e]*errors)[=:\s]+(\d+).*?(?:discards|dropped)[=:\s]+(\d+)`)
	// Compact netlink stat tokens: "rxe=5 txe=7 rxd=3 txd=2".
	ifaceCompactErrRegex  = regexp.MustCompile(`(?i)\b(rx|tx)e[=:](\d+)`)
	ifaceCompactDiscRegex = regexp.MustCompile(`(?i)\b(rx|tx)d[=:](\d+)`)
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

		// The old gate required "rx" AND "errors" on the line and then chose
		// the direction from the LINE text, so TX-only lines never parsed and
		// combined lines overwrote RX with TX (AUDIT-222). The gate now admits
		// either direction with any error/discard token (including the compact
		// netlink "rxe=/txe=/rxd=/txd=" forms, which carry no "errors" word),
		// and every regex below carries its own direction capture.
		lower := strings.ToLower(line)
		// Real FortiOS netlink output follows the cumulative "stat:" line
		// with a "re:" RATE line carrying the SAME compact tokens
		// (near-always zeros) — parsing it would clobber the cumulative
		// counters with current rates. Firmware that omits it is unaffected.
		if strings.HasPrefix(strings.TrimSpace(lower), "re:") {
			continue
		}
		hasDirection := strings.Contains(lower, "rx") || strings.Contains(lower, "tx")
		hasErrorToken := strings.Contains(lower, "errors") || strings.Contains(lower, "dropped") ||
			strings.Contains(lower, "rxe=") || strings.Contains(lower, "txe=") ||
			strings.Contains(lower, "rxd=") || strings.Contains(lower, "txd=")
		if hasDirection && hasErrorToken {
			for _, m := range ifaceErrPairRegex.FindAllStringSubmatch(lower, -1) {
				if len(m) < 4 {
					continue
				}
				if v, err := strconv.ParseUint(m[2], 10, 64); err == nil {
					if m[1] == "rx" {
						currentInErrors = v
					} else {
						currentOutErrors = v
					}
				}
				if v, err := strconv.ParseUint(m[3], 10, 64); err == nil {
					if m[1] == "rx" {
						currentInDiscards = v
					} else {
						currentOutDiscards = v
					}
				}
			}
			for _, m := range ifaceCompactErrRegex.FindAllStringSubmatch(lower, -1) {
				if v, err := strconv.ParseUint(m[2], 10, 64); err == nil {
					if m[1] == "rx" {
						currentInErrors = v
					} else {
						currentOutErrors = v
					}
				}
			}
			for _, m := range ifaceCompactDiscRegex.FindAllStringSubmatch(lower, -1) {
				if v, err := strconv.ParseUint(m[2], 10, 64); err == nil {
					if m[1] == "rx" {
						currentInDiscards = v
					} else {
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

var (
	sensorNameRegex   = regexp.MustCompile(`(?i)^\s*Sensor\s+\d+:\s+(.+)$`)
	sensorValueRegex  = regexp.MustCompile(`(?i)^\s*Value:\s*([\d.]+)\s*(\w+)`)
	sensorStatusRegex = regexp.MustCompile(`(?i)^\s*Status:\s*(\w+)`)
	sensorLineRegex   = regexp.MustCompile(`(?i)^\s*(\d+)\s+(.+?)\s+\.+\s+([\d.]+)\s*(\S+)\s*(.*)$`)
)

func ParseSensorInfo(output string) []SensorDetailInfo {
	if len(output) == 0 {
		log.Printf("[SSH] ParseSensorInfo: empty output")
		return nil
	}
	log.Printf("[SSH] ParseSensorInfo: parsing %d bytes, first 500 chars: %s", len(output), output[:min(500, len(output))])
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
			continue
		}

		lineMatch := sensorLineRegex.FindStringSubmatch(line)
		if len(lineMatch) < 5 {
			continue
		}
		currentName = strings.TrimSpace(lineMatch[2])
		if v, err := strconv.ParseFloat(lineMatch[3], 64); err == nil {
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

	if currentName != "" && valueFound {
		sensors = append(sensors, SensorDetailInfo{
			Name:   currentName,
			Value:  currentValue,
			Unit:   currentUnit,
			Status: currentStatus,
		})
	}

	log.Printf("[SSH] ParseSensorInfo: parsed %d sensors", len(sensors))
	return sensors
}

var (
	licenseStatusRegex = regexp.MustCompile(`(?i)^(?:License|VM License|SSL-VPN|SSLVPN|Explicit Proxy|FortiCare|FortiGuard|Antivirus|IPS|Web Filter|Email Filter|Application Control|Geo IP|IoT Detection|SD-WAN|Threat Feed|Virtual Domain)\s*[:.]*\s*(\w+)`)
	licenseDetailRegex = regexp.MustCompile(`(?i)^(License|VM License|SSL-VPN|SSLVPN|Explicit Proxy|FortiCare|FortiGuard|Antivirus|IPS|Web Filter|Email Filter|Application Control|Geo IP|IoT Detection|SD-WAN|Threat Feed|Virtual Domain)\s*[:.]*\s*(.+)`)
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
	// FortiOS prints "Uptime: 20 days, 3 hours, 26 minutes" — the hours and
	// minutes segments are optional in the regex (and were formerly discarded
	// entirely, so a fresh-booted device reported Uptime=0 for a whole day —
	// AUDIT-303).
	uptimeRegex = regexp.MustCompile(`Uptime:\s+(\d+)\s+days?(?:,\s*(\d+)\s+hours?)?(?:,\s*(\d+)\s+minutes?)?`)
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
			// PerformanceInfo.Uptime is SECONDS. (The cross-source unit
			// mismatch with SNMP's TimeTicks hundredths is AUDIT-220's scope,
			// deliberately not touched here.) Unmatched optional groups scan
			// as "" → ParseUint error → 0, matching the old error handling.
			days, _ := strconv.ParseUint(uptimeMatch[1], 10, 64)
			var hours, mins uint64
			if len(uptimeMatch) >= 3 {
				hours, _ = strconv.ParseUint(uptimeMatch[2], 10, 64)
			}
			if len(uptimeMatch) >= 4 {
				mins, _ = strconv.ParseUint(uptimeMatch[3], 10, 64)
			}
			info.Uptime = days*86400 + hours*3600 + mins*60
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
	// FortiOS prints selectors as address + DOTTED NETMASK, e.g.
	//   set src-subnet 192.168.13.0 255.255.255.0
	phase2SrcSubnetRegex = regexp.MustCompile(`(?i)set\s+src-subnet\s+(\S+)\s+(\S+)`)
	phase2DstSubnetRegex = regexp.MustCompile(`(?i)set\s+dst-subnet\s+(\S+)\s+(\S+)`)
)

// subnetToCIDR converts FortiOS's "address netmask" selector form into the
// canonical CIDR the rest of the system speaks.
//
// Storing the device's own text would be useless downstream: netclass.SelectorIP
// parses CIDR, "a - b" ranges and bare IPs — never a space-separated netmask
// pair — so SelectorCovered would always return false and these rows could never
// be matched to a provisioned tunnel. The connection-detail phase2 matcher is
// exact string equality against the peer's selectors, and strongSwan reports
// canonical CIDR, so anything else silently fails to pair.
//
// Masking the address (rather than trusting it to already be a network address)
// is what makes both ends converge on the identical string.
func subnetToCIDR(addr, mask string) string {
	ip := net.ParseIP(strings.TrimSpace(addr)).To4()
	m := net.ParseIP(strings.TrimSpace(mask)).To4()
	if ip == nil || m == nil {
		return ""
	}
	ipMask := net.IPv4Mask(m[0], m[1], m[2], m[3])
	if _, bits := ipMask.Size(); bits == 0 {
		return "" // non-contiguous mask: not expressible as CIDR
	}
	return (&net.IPNet{IP: ip.Mask(ipMask), Mask: ipMask}).String()
}

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
		if srcMatch := phase2SrcSubnetRegex.FindStringSubmatch(line); len(srcMatch) >= 3 {
			current.LocalSubnet = subnetToCIDR(srcMatch[1], srcMatch[2])
		}
		if dstMatch := phase2DstSubnetRegex.FindStringSubmatch(line); len(dstMatch) >= 3 {
			current.RemoteSubnet = subnetToCIDR(dstMatch[1], dstMatch[2])
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

var (
	opnTempPrefix = "hw.temperature."
	// dev.ina2xx.<idx>.<field> — the INA2xx power monitors (one per PSU rail).
	opnInaRe = regexp.MustCompile(`^dev\.ina2xx\.(\d+)\.(bus_voltage|current|power|label)$`)
	// dev.emc2302.<unit>.fan<n>.<field> — the EMC230x fan controller. Capture the
	// controller unit too: an appliance with >2 fans has multiple 2-channel
	// controllers, so keying by channel alone would collide their fans.
	opnFanRe = regexp.MustCompile(`^dev\.emc2302\.(\d+)\.fan(\d+)\.(rpm|fault)$`)
)

// ParseOPNsenseSensors parses the output of
// `sysctl -iq hw.temperature dev.ina2xx dev.emc2302` into hardware sensors.
// Absent sysctl trees (e.g. on x86 OPNsense, which has none of these drivers)
// simply yield fewer sensors — the parser never errors. Values are kept in the
// device's native units (°C / mV / mA / mW / RPM); the device-detail UI renders
// the Unit string generically.
func ParseOPNsenseSensors(output string) []OPNsenseSensor {
	type rail struct {
		label            string
		volt, curr, powr string
		hasV, hasC, hasP bool
	}
	type fan struct {
		rpm, fault       string
		hasRPM, hasFault bool
	}
	type fanKey struct{ unit, ch int }
	rails := map[int]*rail{}
	fans := map[fanKey]*fan{}
	var sensors []OPNsenseSensor

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		key, val, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if name, found := strings.CutPrefix(key, opnTempPrefix); found {
			if f, err := parseTempC(val); err == nil {
				sensors = append(sensors, OPNsenseSensor{Name: name, Type: "temperature", Value: f, Unit: "°C", Status: "normal"})
			}
			continue
		}
		if m := opnInaRe.FindStringSubmatch(key); m != nil {
			idx, _ := strconv.Atoi(m[1])
			r := rails[idx]
			if r == nil {
				r = &rail{}
				rails[idx] = r
			}
			switch m[2] {
			case "label":
				r.label = val
			case "bus_voltage":
				r.volt, r.hasV = val, true
			case "current":
				r.curr, r.hasC = val, true
			case "power":
				r.powr, r.hasP = val, true
			}
			continue
		}
		if m := opnFanRe.FindStringSubmatch(key); m != nil {
			u, _ := strconv.Atoi(m[1])
			ch, _ := strconv.Atoi(m[2])
			k := fanKey{u, ch}
			fn := fans[k]
			if fn == nil {
				fn = &fan{}
				fans[k] = fn
			}
			switch m[3] {
			case "rpm":
				fn.rpm, fn.hasRPM = val, true
			case "fault":
				fn.fault, fn.hasFault = val, true
			}
			continue
		}
	}

	// Power rails, in index order. Skip rails with no label (can't name them);
	// emit only the electrical values actually present.
	for _, idx := range sortedIntKeys(rails) {
		r := rails[idx]
		if r.label == "" {
			continue
		}
		if r.hasV {
			if v, err := strconv.ParseFloat(r.volt, 64); err == nil {
				sensors = append(sensors, OPNsenseSensor{Name: r.label + " voltage", Type: "voltage", Value: v, Unit: "mV", Status: "normal"})
			}
		}
		if r.hasC {
			if v, err := strconv.ParseFloat(r.curr, 64); err == nil {
				sensors = append(sensors, OPNsenseSensor{Name: r.label + " current", Type: "current", Value: v, Unit: "mA", Status: "normal"})
			}
		}
		if r.hasP {
			if v, err := strconv.ParseFloat(r.powr, 64); err == nil {
				sensors = append(sensors, OPNsenseSensor{Name: r.label + " power", Type: "power", Value: v, Unit: "mW", Status: "normal"})
			}
		}
	}

	// Fans, ordered by controller then channel and numbered sequentially (stable
	// per position). A fan is emitted if it reports rpm OR a fault, so a fault
	// with no rpm still surfaces as an alarm (Value 0) rather than being dropped —
	// the fault is the higher-value signal. fault != 0 → alarm.
	fanKeys := make([]fanKey, 0, len(fans))
	for k := range fans {
		fanKeys = append(fanKeys, k)
	}
	sort.Slice(fanKeys, func(i, j int) bool {
		if fanKeys[i].unit != fanKeys[j].unit {
			return fanKeys[i].unit < fanKeys[j].unit
		}
		return fanKeys[i].ch < fanKeys[j].ch
	})
	for i, k := range fanKeys {
		fn := fans[k]
		var v float64
		if fn.hasRPM {
			if pv, err := strconv.ParseFloat(fn.rpm, 64); err == nil {
				v = pv
			} else if !fn.hasFault {
				continue // unparseable rpm and no fault signal → nothing useful
			}
		}
		status := "normal"
		if fn.hasFault && fn.fault != "0" {
			status = "alarm"
		}
		sensors = append(sensors, OPNsenseSensor{Name: fmt.Sprintf("System Fan %d", i+1), Type: "fan", Value: v, Unit: "RPM", Status: status})
	}

	return sensors
}

// parseTempC parses a FreeBSD temperature string like "46.0C" into 46.0.
func parseTempC(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(s), "C"), 64)
}

func sortedIntKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// ARPEntryInfo is one row parsed from FortiOS `get system arp`. Unlike the
// SNMP ARP walk it carries the interface NAME (FortiOS prints no ifIndex),
// which the server resolves against interface stats.
type ARPEntryInfo struct {
	IPAddress  string
	MACAddress string // canonical lowercase colon form
	Interface  string
}

// ParseARPTable parses FortiOS `get system arp` output:
//
//	Address           Age(min)   Hardware Addr      Interface
//	192.168.5.1       0          00:09:0f:09:00:02  internal
//
// Incomplete entries (MAC 00:00:00:00:00:00 or "Incomplete") and multicast
// MACs are dropped — they can't attribute a link.
func ParseARPTable(output string) []ARPEntryInfo {
	var out []ARPEntryInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue // header or noise
		}
		hw, err := net.ParseMAC(fields[2])
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			continue
		}
		allZero := true
		for _, o := range hw {
			if o != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}
		out = append(out, ARPEntryInfo{
			IPAddress:  ip,
			MACAddress: hw.String(),
			Interface:  fields[3],
		})
	}
	return out
}

// BridgeFDBEntryInfo is one learned MAC from a FortiOS bridge host table
// (`diagnose netlink brctl name host <bridge>`) — the member PORT NAME is the
// payload: it is the only per-physical-port MAC attribution a FortiGate
// offers (no BRIDGE-MIB over SNMP).
type BridgeFDBEntryInfo struct {
	Interface  string // member port name (devname column)
	MACAddress string // canonical lowercase colon form
}

// bridgeNameRe validates bridge names before they are interpolated into an
// SSH command line — defense in depth against a hostile name in device output.
var bridgeNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ParseBridgeList extracts bridge names from `diagnose netlink brctl list`:
//
//	list bridge information
//	1. name=internal ifindex=9 mac_entries=5
//
// Names failing the safety pattern are dropped.
func ParseBridgeList(output string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, "name=")
		if idx < 0 {
			continue
		}
		name := strings.Fields(line[idx+len("name="):])
		if len(name) == 0 {
			continue
		}
		n := strings.TrimSpace(name[0])
		if n == "" || !bridgeNameRe.MatchString(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// ParseBridgeFDB parses a FortiOS bridge host table:
//
//	show bridge control interface internal host.
//	fdb: size=256, used=6, num=6, depth=1
//	Bridge internal host table
//	port no  device  devname  mac addr                 ttl    attributes
//	  3      9       internal3    02:09:0f:78:69:01    88
//	  1      7       internal1    00:09:0f:09:00:07    0      Local Static
//
// Local/Static rows (the bridge's own MACs) and multicast/zero MACs are
// dropped — only dynamically learned unicast entries attribute a link.
func ParseBridgeFDB(output string) []BridgeFDBEntryInfo {
	var out []BridgeFDBEntryInfo
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Local") || strings.Contains(line, "Static") {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		// port-no and device must be numeric — filters headers/banners.
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		if _, err := strconv.Atoi(fields[1]); err != nil {
			continue
		}
		hw, err := net.ParseMAC(fields[3])
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			continue
		}
		allZero := true
		for _, o := range hw {
			if o != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}
		out = append(out, BridgeFDBEntryInfo{Interface: fields[2], MACAddress: hw.String()})
	}
	return out
}

// ParseFreeBSDBridgeList extracts bridge names from `ifconfig -g bridge`
// (one interface name per line; empty on a routed-only box).
func ParseFreeBSDBridgeList(output string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		n := strings.TrimSpace(line)
		if n == "" || !bridgeNameRe.MatchString(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// ParseFreeBSDBridgeFDB parses `ifconfig <bridge> addr` learned-address rows:
//
//	58:9c:fc:10:ff:a1 Vlan1 vtnet0 1141 flags=0<>
//
// Fields: MAC, VLAN tag, member interface, expiry, flags. STATIC/STICKY rows
// (the bridge's own or pinned MACs) and multicast/zero MACs are dropped.
func ParseFreeBSDBridgeFDB(output string) []BridgeFDBEntryInfo {
	var out []BridgeFDBEntryInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		hw, err := net.ParseMAC(fields[0])
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			continue
		}
		allZero := true
		for _, o := range hw {
			if o != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "STATIC") || strings.Contains(upper, "STICKY") {
			continue
		}
		// Field layout shifts by FreeBSD version (the Vlan column is absent
		// pre-13): the member interface is the first non-Vlan field after
		// the MAC.
		iface := fields[1]
		if strings.HasPrefix(iface, "Vlan") && len(fields) >= 3 {
			iface = fields[2]
		}
		if iface == "" {
			continue
		}
		out = append(out, BridgeFDBEntryInfo{Interface: iface, MACAddress: hw.String()})
	}
	return out
}
