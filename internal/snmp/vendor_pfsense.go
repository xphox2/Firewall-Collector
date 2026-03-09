package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// pfSense SNMP OIDs — FreeBSD-based, uses bsnmpd with standard + BEGEMOT-PF-MIB.
// UCD-SNMP-MIB available when the UCD module is enabled in Services > SNMP.
var (
	// --- SNMPv2-MIB system scalars ---
	pfOIDSysDescr  = ".1.3.6.1.2.1.1.1.0"
	pfOIDSysUpTime = ".1.3.6.1.2.1.1.3.0"
	pfOIDSysName   = ".1.3.6.1.2.1.1.5.0"

	// --- UCD-SNMP-MIB CPU (requires UCD module) ---
	pfOIDCpuUser   = ".1.3.6.1.4.1.2021.11.9.0"
	pfOIDCpuSystem = ".1.3.6.1.4.1.2021.11.10.0"
	pfOIDCpuIdle   = ".1.3.6.1.4.1.2021.11.11.0"

	// --- UCD-SNMP-MIB Memory ---
	pfOIDMemTotalReal = ".1.3.6.1.4.1.2021.4.5.0"
	pfOIDMemAvailReal = ".1.3.6.1.4.1.2021.4.6.0"
	pfOIDMemBuffer    = ".1.3.6.1.4.1.2021.4.14.0"
	pfOIDMemCached    = ".1.3.6.1.4.1.2021.4.15.0"

	// --- BEGEMOT-PF-MIB (enterprise 12325 = FreeBSD/Begemot) ---
	// PF state table — active sessions equivalent
	pfOIDStateCount   = ".1.3.6.1.4.1.12325.1.200.1.3.1.0" // pfStateTableCount
	pfOIDStateSearches = ".1.3.6.1.4.1.12325.1.200.1.3.2.0"
	pfOIDStateInserts  = ".1.3.6.1.4.1.12325.1.200.1.3.3.0"
	pfOIDStateRemovals = ".1.3.6.1.4.1.12325.1.200.1.3.4.0"
	// PF counters
	pfOIDCounterMatch  = ".1.3.6.1.4.1.12325.1.200.1.2.1.0" // Total rule matches
	pfOIDCounterMemDrop = ".1.3.6.1.4.1.12325.1.200.1.2.6.0" // Memory drops
	// PF status
	pfOIDPfRunning = ".1.3.6.1.4.1.12325.1.200.1.1.1.0" // PF enabled (1=yes)

	// --- HOST-RESOURCES-MIB Processor ---
	pfBaseOIDProcessor = ".1.3.6.1.2.1.25.3.3.1"
	pfOIDProcessorLoad = ".1.3.6.1.2.1.25.3.3.1.2"
)

// PfSenseProfile implements VendorProfile for pfSense firewalls.
type PfSenseProfile struct{}

func init() {
	RegisterVendor(&PfSenseProfile{})
}

func (p *PfSenseProfile) Name() string { return "pfsense" }

func (p *PfSenseProfile) SystemOIDs() []string {
	return []string{
		pfOIDSysName,
		pfOIDSysDescr,
		pfOIDSysUpTime,
		pfOIDCpuUser,
		pfOIDCpuSystem,
		pfOIDCpuIdle,
		pfOIDMemTotalReal,
		pfOIDMemAvailReal,
		pfOIDMemBuffer,
		pfOIDMemCached,
		pfOIDStateCount,
		pfOIDPfRunning,
	}
}

func (p *PfSenseProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}
	var cpuUser, cpuSystem, cpuIdle int64
	var memTotalKB, memAvailKB, memBufferKB, memCachedKB int64

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case pfOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case pfOIDSysDescr:
			status.Version = extractPfSenseVersion(safeString(pdu.Value))
		case pfOIDSysUpTime:
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks / 100
		case pfOIDCpuUser:
			cpuUser = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDCpuSystem:
			cpuSystem = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDCpuIdle:
			cpuIdle = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemTotalReal:
			memTotalKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemAvailReal:
			memAvailKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemBuffer:
			memBufferKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDMemCached:
			memCachedKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case pfOIDStateCount:
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

// extractPfSenseVersion parses the pfSense version from sysDescr.
// Typical sysDescr: "pfSense pfSense-CE-2.7.2-RELEASE pfSense" or
// "FreeBSD 14.0-CURRENT FreeBSD 14.0-CURRENT ..."
func extractPfSenseVersion(sysDescr string) string {
	if sysDescr == "" {
		return ""
	}
	// Look for pfSense version pattern
	lower := strings.ToLower(sysDescr)
	if idx := strings.Index(lower, "pfsense"); idx >= 0 {
		// Extract version substring after "pfSense"
		parts := strings.Fields(sysDescr[idx:])
		for _, part := range parts {
			if strings.Contains(part, "-CE-") || strings.Contains(part, "-RELEASE") ||
				strings.Contains(part, "2.") || strings.Contains(part, "24.") {
				return "pfSense " + part
			}
		}
		if len(parts) >= 2 {
			return "pfSense " + parts[1]
		}
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

// VPN: pfSense VPN tunnels (IPSec/OpenVPN/WireGuard) are not exposed via SNMP.
// OpenVPN/WireGuard tunnel interfaces appear in IF-MIB but without tunnel metadata.

func (p *PfSenseProfile) VPNBaseOID() string { return "" }

func (p *PfSenseProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	return nil
}

// Hardware sensors: not available via bsnmpd on FreeBSD without custom extend scripts.

func (p *PfSenseProfile) HWSensorBaseOID() string { return "" }

func (p *PfSenseProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor {
	return nil
}

// Processors: HOST-RESOURCES-MIB hrProcessorTable for per-CPU load.

func (p *PfSenseProfile) ProcessorBaseOID() string { return pfBaseOIDProcessor }

func (p *PfSenseProfile) ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats {
	now := time.Now()
	var result []relay.ProcessorStats
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, pfOIDProcessorLoad+".") {
			idx := getIndexFromOID(pdu.Name, pfOIDProcessorLoad)
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

// Traps: pfSense bsnmpd sends standard linkUp/linkDown traps only.

func (p *PfSenseProfile) TrapOIDs() map[string]TrapDef {
	return nil
}
