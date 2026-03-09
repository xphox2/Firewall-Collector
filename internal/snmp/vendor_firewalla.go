package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// Firewalla SNMP OIDs — standard Linux MIBs (Net-SNMP / UCD-SNMP-MIB / HOST-RESOURCES-MIB).
// Firewalla runs Ubuntu Linux; SNMP requires manual snmpd installation.
var (
	// --- SNMPv2-MIB system scalars ---
	fwOIDSysDescr  = ".1.3.6.1.2.1.1.1.0"
	fwOIDSysUpTime = ".1.3.6.1.2.1.1.3.0"
	fwOIDSysName   = ".1.3.6.1.2.1.1.5.0"

	// --- UCD-SNMP-MIB CPU (1.3.6.1.4.1.2021.11) ---
	fwOIDCpuUser   = ".1.3.6.1.4.1.2021.11.9.0"  // ssCpuRawUser (%)
	fwOIDCpuSystem = ".1.3.6.1.4.1.2021.11.10.0"  // ssCpuRawSystem (%)
	fwOIDCpuIdle   = ".1.3.6.1.4.1.2021.11.11.0"  // ssCpuRawIdle (%)

	// --- UCD-SNMP-MIB Memory (1.3.6.1.4.1.2021.4) ---
	fwOIDMemTotalReal = ".1.3.6.1.4.1.2021.4.5.0"  // memTotalReal (kB)
	fwOIDMemAvailReal = ".1.3.6.1.4.1.2021.4.6.0"  // memAvailReal (kB)
	fwOIDMemBuffer    = ".1.3.6.1.4.1.2021.4.14.0"  // memBuffer (kB)
	fwOIDMemCached    = ".1.3.6.1.4.1.2021.4.15.0"  // memCached (kB)
	fwOIDMemTotalSwap = ".1.3.6.1.4.1.2021.4.3.0"   // memTotalSwap (kB)

	// --- HOST-RESOURCES-MIB Disk (1.3.6.1.2.1.25.2.3.1) ---
	fwBaseOIDStorage      = ".1.3.6.1.2.1.25.2.3.1"
	fwOIDStorageDescr     = ".1.3.6.1.2.1.25.2.3.1.3"  // hrStorageDescr
	fwOIDStorageAllocUnit = ".1.3.6.1.2.1.25.2.3.1.4"  // hrStorageAllocationUnits (bytes)
	fwOIDStorageSize      = ".1.3.6.1.2.1.25.2.3.1.5"  // hrStorageSize (units)
	fwOIDStorageUsed      = ".1.3.6.1.2.1.25.2.3.1.6"  // hrStorageUsed (units)

	// --- HOST-RESOURCES-MIB Processor (1.3.6.1.2.1.25.3.3.1) ---
	fwBaseOIDProcessor  = ".1.3.6.1.2.1.25.3.3.1"
	fwOIDProcessorLoad  = ".1.3.6.1.2.1.25.3.3.1.2"  // hrProcessorLoad (%)

	// --- UCD-SNMP-MIB Load Averages (1.3.6.1.4.1.2021.10.1) ---
	fwOIDLaLoad1  = ".1.3.6.1.4.1.2021.10.1.3.1"  // laLoad 1-min (string)
	fwOIDLaLoad5  = ".1.3.6.1.4.1.2021.10.1.3.2"  // laLoad 5-min (string)
	fwOIDLaLoad15 = ".1.3.6.1.4.1.2021.10.1.3.3"  // laLoad 15-min (string)

	// --- lmSensors via NET-SNMP (1.3.6.1.4.1.2021.13.16) ---
	fwBaseOIDLmTempSensor = ".1.3.6.1.4.1.2021.13.16.2.1"
	fwOIDLmTempSensorDescr = ".1.3.6.1.4.1.2021.13.16.2.1.2"  // lmTempSensorsDevice
	fwOIDLmTempSensorValue = ".1.3.6.1.4.1.2021.13.16.2.1.3"  // lmTempSensorsValue (milli°C)

	fwBaseOIDLmFanSensor = ".1.3.6.1.4.1.2021.13.16.3.1"
	fwOIDLmFanSensorDescr = ".1.3.6.1.4.1.2021.13.16.3.1.2"  // lmFanSensorsDevice
	fwOIDLmFanSensorValue = ".1.3.6.1.4.1.2021.13.16.3.1.3"  // lmFanSensorsValue (RPM)
)

// FirewallaProfile implements VendorProfile for Firewalla devices.
// Firewalla runs Ubuntu Linux — all metrics come from standard Linux SNMP MIBs.
// VPN, HA, security stats, SD-WAN, and license info are not available via SNMP.
type FirewallaProfile struct{}

func init() {
	RegisterVendor(&FirewallaProfile{})
}

func (f *FirewallaProfile) Name() string { return "firewalla" }

func (f *FirewallaProfile) SystemOIDs() []string {
	return []string{
		fwOIDSysName,
		fwOIDSysDescr,
		fwOIDSysUpTime,
		fwOIDCpuUser,
		fwOIDCpuSystem,
		fwOIDCpuIdle,
		fwOIDMemTotalReal,
		fwOIDMemAvailReal,
		fwOIDMemBuffer,
		fwOIDMemCached,
		fwOIDMemTotalSwap,
		fwOIDLaLoad1,
		fwOIDLaLoad5,
		fwOIDLaLoad15,
	}
}

func (f *FirewallaProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}
	var cpuUser, cpuSystem, cpuIdle int64
	var memTotalKB, memAvailKB, memBufferKB, memCachedKB int64

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case fwOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case fwOIDSysDescr:
			status.Version = extractFirewallaVersion(safeString(pdu.Value))
		case fwOIDSysUpTime:
			// sysUpTime is in hundredths of a second; convert to seconds
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks / 100
		case fwOIDCpuUser:
			cpuUser = gosnmp.ToBigInt(pdu.Value).Int64()
		case fwOIDCpuSystem:
			cpuSystem = gosnmp.ToBigInt(pdu.Value).Int64()
		case fwOIDCpuIdle:
			cpuIdle = gosnmp.ToBigInt(pdu.Value).Int64()
		case fwOIDMemTotalReal:
			memTotalKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case fwOIDMemAvailReal:
			memAvailKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case fwOIDMemBuffer:
			memBufferKB = gosnmp.ToBigInt(pdu.Value).Int64()
		case fwOIDMemCached:
			memCachedKB = gosnmp.ToBigInt(pdu.Value).Int64()
		}
	}

	// CPU: compute usage from user+system, or from 100-idle as fallback
	total := cpuUser + cpuSystem + cpuIdle
	if total > 0 {
		status.CPUUsage = float64(cpuUser+cpuSystem) / float64(total) * 100
	} else if cpuIdle > 0 {
		status.CPUUsage = float64(100 - cpuIdle)
	}

	// Memory: Linux "used" = total - available - buffers - cached
	if memTotalKB > 0 {
		status.MemoryTotal = uint64(memTotalKB / 1024) // Convert kB to MB
		usedKB := memTotalKB - memAvailKB - memBufferKB - memCachedKB
		if usedKB < 0 {
			usedKB = memTotalKB - memAvailKB
		}
		status.MemoryUsage = float64(usedKB) / float64(memTotalKB) * 100
	}

	return status
}

// extractFirewallaVersion extracts a useful version string from sysDescr.
// sysDescr on Linux typically looks like "Linux hostname 5.4.0-xxx #1 SMP ..."
func extractFirewallaVersion(sysDescr string) string {
	if sysDescr == "" {
		return ""
	}
	// Try to extract kernel version from "Linux <hostname> <version> ..."
	parts := strings.Fields(sysDescr)
	if len(parts) >= 3 && strings.EqualFold(parts[0], "Linux") {
		return "Linux " + parts[2]
	}
	// Truncate if too long
	if len(sysDescr) > 80 {
		return sysDescr[:80]
	}
	return sysDescr
}

// VPN: Firewalla uses WireGuard/OpenVPN which don't expose SNMP data.
// Return empty OID and nil results — the polling loop gracefully skips.

func (f *FirewallaProfile) VPNBaseOID() string { return "" }

func (f *FirewallaProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	return nil
}

// Hardware sensors: use lm-sensors via NET-SNMP extension MIB.
// Only available if lm-sensors is installed and snmpd is configured to expose it.

func (f *FirewallaProfile) HWSensorBaseOID() string { return fwBaseOIDLmTempSensor }

func (f *FirewallaProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor {
	sensorMap := make(map[int]*relay.HardwareSensor)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name

		// Temperature sensors
		if strings.HasPrefix(name, fwOIDLmTempSensorDescr+".") {
			idx := getIndexFromOID(name, fwOIDLmTempSensorDescr)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			sensor.Name = safeString(pdu.Value)
			sensor.Type = "temperature"
			sensor.Unit = "°C"
		} else if strings.HasPrefix(name, fwOIDLmTempSensorValue+".") {
			idx := getIndexFromOID(name, fwOIDLmTempSensorValue)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			// lmTempSensorsValue is in milli-degrees C
			sensor.Value = float64(gosnmp.ToBigInt(pdu.Value).Int64()) / 1000.0
			sensor.Status = "normal"
		}

		// Fan sensors (if present in same walk — different subtree)
		if strings.HasPrefix(name, fwOIDLmFanSensorDescr+".") {
			idx := getIndexFromOID(name, fwOIDLmFanSensorDescr)
			if idx < 0 {
				continue
			}
			// Use offset to avoid collision with temp sensor indices
			sIdx := 1000 + idx
			sensor := getOrCreateSensor(sensorMap, sIdx)
			sensor.Name = safeString(pdu.Value)
			sensor.Type = "fan"
			sensor.Unit = "RPM"
		} else if strings.HasPrefix(name, fwOIDLmFanSensorValue+".") {
			idx := getIndexFromOID(name, fwOIDLmFanSensorValue)
			if idx < 0 {
				continue
			}
			sIdx := 1000 + idx
			sensor := getOrCreateSensor(sensorMap, sIdx)
			sensor.Value = float64(gosnmp.ToBigInt(pdu.Value).Int64())
			sensor.Status = "normal"
		}
	}

	now := time.Now()
	sensors := make([]relay.HardwareSensor, 0, len(sensorMap))
	for _, sensor := range sensorMap {
		sensor.Timestamp = now
		sensors = append(sensors, *sensor)
	}
	return sensors
}

// Processors: use HOST-RESOURCES-MIB hrProcessorTable for per-CPU load.

func (f *FirewallaProfile) ProcessorBaseOID() string { return fwBaseOIDProcessor }

func (f *FirewallaProfile) ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats {
	now := time.Now()
	var result []relay.ProcessorStats
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, fwOIDProcessorLoad+".") {
			idx := getIndexFromOID(pdu.Name, fwOIDProcessorLoad)
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

// Traps: Firewalla doesn't send enterprise-specific SNMP traps.
// Standard linkUp/linkDown traps may still be received via the generic trap handler.

func (f *FirewallaProfile) TrapOIDs() map[string]TrapDef {
	return nil
}
