package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// OPNsense SNMP OIDs — FreeBSD-based, uses bsnmpd or net-snmp plugin.
// Shares the same BEGEMOT-PF-MIB as pfSense for firewall state metrics.
// UCD-SNMP-MIB available with bsnmpd UCD module or net-snmp plugin.
var (
	// --- SNMPv2-MIB system scalars ---
	onsOIDSysDescr  = ".1.3.6.1.2.1.1.1.0"
	onsOIDSysUpTime = ".1.3.6.1.2.1.1.3.0"
	onsOIDSysName   = ".1.3.6.1.2.1.1.5.0"

	// --- UCD-SNMP-MIB CPU ---
	onsOIDCpuUser   = ".1.3.6.1.4.1.2021.11.9.0"
	onsOIDCpuSystem = ".1.3.6.1.4.1.2021.11.10.0"
	onsOIDCpuIdle   = ".1.3.6.1.4.1.2021.11.11.0"

	// --- UCD-SNMP-MIB Memory ---
	onsOIDMemTotalReal = ".1.3.6.1.4.1.2021.4.5.0"
	onsOIDMemAvailReal = ".1.3.6.1.4.1.2021.4.6.0"
	onsOIDMemBuffer    = ".1.3.6.1.4.1.2021.4.14.0"
	onsOIDMemCached    = ".1.3.6.1.4.1.2021.4.15.0"

	// --- BEGEMOT-PF-MIB ---
	onsOIDStateCount = ".1.3.6.1.4.1.12325.1.200.1.3.1.0" // pfStateTableCount
	onsOIDPfRunning  = ".1.3.6.1.4.1.12325.1.200.1.1.1.0" // PF enabled

	// --- HOST-RESOURCES-MIB Processor ---
	onsBaseOIDProcessor = ".1.3.6.1.2.1.25.3.3.1"
	onsOIDProcessorLoad = ".1.3.6.1.2.1.25.3.3.1.2"
)

// OPNsenseProfile implements VendorProfile for OPNsense firewalls.
type OPNsenseProfile struct{}

func init() {
	RegisterVendor(&OPNsenseProfile{})
}

func (o *OPNsenseProfile) Name() string { return "opnsense" }

func (o *OPNsenseProfile) SystemOIDs() []string {
	return []string{
		onsOIDSysName,
		onsOIDSysDescr,
		onsOIDSysUpTime,
		onsOIDCpuUser,
		onsOIDCpuSystem,
		onsOIDCpuIdle,
		onsOIDMemTotalReal,
		onsOIDMemAvailReal,
		onsOIDMemBuffer,
		onsOIDMemCached,
		onsOIDStateCount,
		onsOIDPfRunning,
	}
}

func (o *OPNsenseProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}
	var cpuUser, cpuSystem, cpuIdle int64
	var memTotalKB, memAvailKB, memBufferKB, memCachedKB int64

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case onsOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case onsOIDSysDescr:
			status.Version = extractOPNsenseVersion(safeString(pdu.Value))
		case onsOIDSysUpTime:
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks / 100
		case onsOIDCpuUser:
			cpuUser = gosnmp.ToBigInt(pdu.Value).Int64()
		case onsOIDCpuSystem:
			cpuSystem = gosnmp.ToBigInt(pdu.Value).Int64()
		case onsOIDCpuIdle:
			cpuIdle = gosnmp.ToBigInt(pdu.Value).Int64()
		case onsOIDMemTotalReal:
			memTotalKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case onsOIDMemAvailReal:
			memAvailKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case onsOIDMemBuffer:
			memBufferKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case onsOIDMemCached:
			memCachedKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case onsOIDStateCount:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		}
	}

	// CPU usage from UCD-SNMP-MIB
	total := cpuUser + cpuSystem + cpuIdle
	if total > 0 {
		status.CPUUsage = float64(cpuUser+cpuSystem) / float64(total) * 100
	} else if cpuIdle > 0 {
		status.CPUUsage = float64(100 - cpuIdle)
	}

	// Memory: used = total - available - buffers - cached
	if memTotalKB > 0 {
		status.MemoryTotal = uint64(memTotalKB / 1024)
		usedKB := memTotalKB - memAvailKB - memBufferKB - memCachedKB
		if usedKB < 0 {
			usedKB = memTotalKB - memAvailKB
		}
		status.MemoryUsage = float64(usedKB) / float64(memTotalKB) * 100
	}

	return status
}

// extractOPNsenseVersion parses the OPNsense version from sysDescr.
// Typical sysDescr: "OPNsense 24.1" or "FreeBSD 14.0-CURRENT ..."
func extractOPNsenseVersion(sysDescr string) string {
	if sysDescr == "" {
		return ""
	}
	lower := strings.ToLower(sysDescr)
	if idx := strings.Index(lower, "opnsense"); idx >= 0 {
		parts := strings.Fields(sysDescr[idx:])
		if len(parts) >= 2 {
			return "OPNsense " + parts[1]
		}
		return "OPNsense"
	}
	// Fallback: extract kernel version
	parts := strings.Fields(sysDescr)
	if len(parts) >= 3 {
		return parts[0] + " " + parts[2]
	}
	if len(sysDescr) > 80 {
		return sysDescr[:80]
	}
	return sysDescr
}

// VPN: Detected via IF-MIB interface name patterns.
// OpenVPN (ovpns*/ovpnc*), WireGuard (wg*/tun_wg*), and route-based IPSec
// (ipsec*) interfaces are real OS interfaces with status and traffic counters.

func (o *OPNsenseProfile) VPNBaseOID() string { return BaseOIDInterface }

func (o *OPNsenseProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	return parseBSDVPNFromInterfaces(pdus)
}

// Hardware sensors: not available via bsnmpd without extend scripts.

func (o *OPNsenseProfile) HWSensorBaseOID() string { return "" }

func (o *OPNsenseProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor {
	return nil
}

// Processors: HOST-RESOURCES-MIB hrProcessorTable.

func (o *OPNsenseProfile) ProcessorBaseOID() string { return onsBaseOIDProcessor }

func (o *OPNsenseProfile) ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats {
	now := time.Now()
	var result []relay.ProcessorStats
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, onsOIDProcessorLoad+".") {
			idx := getIndexFromOID(pdu.Name, onsOIDProcessorLoad)
			if idx < 0 {
				continue
			}
			result = append(result, relay.ProcessorStats{
				Timestamp: now,
				Index:     idx,
				Usage:     float64(gosnmp.ToBigInt(pdu.Value).Int64()),
			})
		}
	}
	return result
}

// Traps: OPNsense bsnmpd sends standard linkUp/linkDown traps only.

func (o *OPNsenseProfile) TrapOIDs() map[string]TrapDef {
	return nil
}
