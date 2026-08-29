package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// Generic SNMP OIDs — a standards-only profile for devices without a
// vendor-specific profile. Deliberately contains NO enterprise OIDs — not even
// UCD-SNMP-MIB (1.3.6.1.4.1.2021), which is the Net-SNMP enterprise subtree —
// so any RFC-compliant SNMP agent can answer these.
//
// Interface counters (ifTable/ifXTable) and ipAddrTable are polled
// vendor-neutrally by GetInterfaceStats/GetInterfaceAddresses, so generic
// devices get full interface telemetry without profile involvement.
var (
	// --- SNMPv2-MIB system scalars ---
	genOIDSysDescr  = ".1.3.6.1.2.1.1.1.0" // sysDescr
	genOIDSysUpTime = ".1.3.6.1.2.1.1.3.0" // sysUpTime (TimeTicks)
	genOIDSysName   = ".1.3.6.1.2.1.1.5.0" // sysName

	// --- HOST-RESOURCES-MIB ---
	// hrMemorySize: physical RAM in KBytes — the only standard memory scalar
	// that can be fetched with a plain Get. Memory *usage* would require a
	// walk of hrStorageTable, which the SystemOIDs Get contract does not
	// support, so MemoryUsage is deliberately left unset (0) rather than
	// guessed.
	genOIDHrMemorySize = ".1.3.6.1.2.1.25.2.2.0"

	// hrProcessorTable: per-CPU average load (%) over the last minute.
	genBaseOIDProcessor = ".1.3.6.1.2.1.25.3.3.1"
	genOIDProcessorLoad = ".1.3.6.1.2.1.25.3.3.1.2" // hrProcessorLoad (%)
)

// GenericProfile implements VendorProfile for unknown/unclassified devices
// using only standard MIB-II and HOST-RESOURCES-MIB objects.
//
// Vendor-specific metrics that firewall siblings populate — session counts,
// VPN tunnels, HA state, hardware sensors, security stats, enterprise traps —
// have no standards-based equivalent, so this profile signals them as
// unsupported (empty base OID / nil results) and does not implement any of
// the optional provider interfaces (HAProvider, SecurityStatsProvider, ...).
type GenericProfile struct{}

func init() {
	RegisterVendor(&GenericProfile{})
}

func (g *GenericProfile) Name() string { return "generic" }

func (g *GenericProfile) SystemOIDs() []string {
	return []string{
		genOIDSysName,
		genOIDSysDescr,
		genOIDSysUpTime,
		genOIDHrMemorySize,
	}
}

func (g *GenericProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case genOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case genOIDSysDescr:
			status.Version = extractGenericVersion(safeString(pdu.Value))
		case genOIDSysUpTime:
			// sysUpTime is in hundredths of a second; store it RAW (AUDIT-220)
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks // AUDIT-220: store RAW hundredths (the consumer FormatUptime divides by 100 once; pre-dividing here made non-FortiGate uptime render 100x too small).
		case genOIDHrMemorySize:
			// hrMemorySize is in KBytes; convert to MB
			status.MemoryTotal = gosnmp.ToBigInt(pdu.Value).Uint64() / 1024
		}
	}

	// CPUUsage/MemoryUsage: no standard scalar exists; aggregate CPU comes
	// from the hrProcessorTable walk (ProcessorBaseOID) instead.
	return status
}

// extractGenericVersion returns a display-safe version string from sysDescr.
func extractGenericVersion(sysDescr string) string {
	sysDescr = strings.TrimSpace(sysDescr)
	if len(sysDescr) > 80 {
		return sysDescr[:80]
	}
	return sysDescr
}

// VPN: no standards-based way to enumerate VPN tunnels on an unknown device.

func (g *GenericProfile) VPNBaseOID() string { return "" }

func (g *GenericProfile) ParseVPNStatus(_ []gosnmp.SnmpPDU) []relay.VPNStatus {
	return nil
}

// Hardware sensors: ENTITY-SENSOR-MIB support is too inconsistent across
// devices to be part of a standards-only profile; lmSensors lives under the
// Net-SNMP enterprise subtree. Not supported.

func (g *GenericProfile) HWSensorBaseOID() string { return "" }

func (g *GenericProfile) ParseHardwareSensors(_ []gosnmp.SnmpPDU) []relay.HardwareSensor {
	return nil
}

// Processors: HOST-RESOURCES-MIB hrProcessorTable per-CPU load.

func (g *GenericProfile) ProcessorBaseOID() string { return genBaseOIDProcessor }

func (g *GenericProfile) ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats {
	now := time.Now()
	var result []relay.ProcessorStats
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, genOIDProcessorLoad+".") {
			idx := getIndexFromOID(pdu.Name, genOIDProcessorLoad)
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

// Traps: no enterprise trap OIDs. Standard linkUp/linkDown/coldStart traps
// are handled by the generic trap path independent of vendor profiles.

func (g *GenericProfile) TrapOIDs() map[string]TrapDef {
	return nil
}
