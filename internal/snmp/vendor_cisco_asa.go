package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// Cisco ASA SNMP OIDs — MIB-II system scalars plus standard, well-documented
// Cisco enterprise MIBs (enterprise 9):
//
//	CPU:        CISCO-PROCESS-MIB      cpmCPUTotalTable       (1.3.6.1.4.1.9.9.109)
//	Memory:     CISCO-MEMORY-POOL-MIB  ciscoMemoryPoolTable   (1.3.6.1.4.1.9.9.48)
//	Sessions:   CISCO-FIREWALL-MIB     cfwConnectionStatTable (1.3.6.1.4.1.9.9.147)
//	Failover:   CISCO-FIREWALL-MIB     cfwHardwareStatusTable (1.3.6.1.4.1.9.9.147)
//
// Deliberately omitted (would be speculative across ASA/Firepower builds —
// smaller correct beats speculative):
//   - VPN tunnel enumeration (CISCO-IPSEC-FLOW-MONITOR-MIB /
//     CISCO-REMOTE-ACCESS-MONITOR-MIB): per-tunnel index semantics vary too
//     much between platforms and code trains to hard-code here.
//   - Hardware sensors (CISCO-ENVMON-MIB / ENTITY-SENSOR-MIB): availability
//     differs per ASA hardware generation.
//   - Enterprise trap OIDs: ASA failover/IPS notifications are not uniformly
//     enabled; standard linkUp/linkDown traps flow through the generic path.
//   - Security stats / SD-WAN / license optional providers: no equivalent
//     standard ASA MIB objects.
var (
	// --- SNMPv2-MIB system scalars ---
	asaOIDSysDescr  = ".1.3.6.1.2.1.1.1.0" // "Cisco Adaptive Security Appliance Version 9.x(y)"
	asaOIDSysUpTime = ".1.3.6.1.2.1.1.3.0"
	asaOIDSysName   = ".1.3.6.1.2.1.1.5.0"

	// --- CISCO-PROCESS-MIB cpmCPUTotalTable (indexed by cpmCPUTotalIndex) ---
	asaBaseOIDCpu    = ".1.3.6.1.4.1.9.9.109.1.1.1.1"   // cpmCPUTotalEntry
	asaOIDCpu1MinRev = ".1.3.6.1.4.1.9.9.109.1.1.1.1.7" // cpmCPUTotal1minRev (%)
	asaOIDCpu5MinRev = ".1.3.6.1.4.1.9.9.109.1.1.1.1.8" // cpmCPUTotal5minRev (%)
	// First CPU entry — index 1 on ASA. If an agent uses a different index,
	// the Get returns NoSuchInstance (skipped) and CPU still arrives via the
	// cpmCPUTotalTable walk in ParseProcessorStats.
	asaOIDCpu1MinFirst = ".1.3.6.1.4.1.9.9.109.1.1.1.1.7.1"

	// --- CISCO-MEMORY-POOL-MIB (pool 1 = System memory on ASA) ---
	asaOIDMemPoolUsed = ".1.3.6.1.4.1.9.9.48.1.1.1.5.1" // ciscoMemoryPoolUsed (bytes)
	asaOIDMemPoolFree = ".1.3.6.1.4.1.9.9.48.1.1.1.6.1" // ciscoMemoryPoolFree (bytes)

	// --- CISCO-FIREWALL-MIB connection statistics ---
	// cfwConnectionStatValue.protoIp(40).currentInUse(6): current firewall
	// connections in use — the standard ASA connection-count instance.
	asaOIDConnCurrent = ".1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6"

	// --- CISCO-FIREWALL-MIB cfwHardwareStatusTable (failover pair state) ---
	// Indexed by cfwHardwareType: primaryUnit(6), secondaryUnit(7). Other rows
	// (power supplies, network interfaces, ...) are not failover members.
	asaBaseOIDFailover   = ".1.3.6.1.4.1.9.9.147.1.2.1.1.1"
	asaOIDFailoverInfo   = ".1.3.6.1.4.1.9.9.147.1.2.1.1.1.2" // cfwHardwareInformation
	asaOIDFailoverValue  = ".1.3.6.1.4.1.9.9.147.1.2.1.1.1.3" // cfwHardwareStatusValue
	asaOIDFailoverDetail = ".1.3.6.1.4.1.9.9.147.1.2.1.1.1.4" // cfwHardwareStatusDetail
)

// cfwHardwareType indices for the failover units.
const (
	asaFailoverIdxPrimary   = 6
	asaFailoverIdxSecondary = 7
)

// CiscoASAProfile implements VendorProfile (plus the optional HAProvider
// interface for failover state) for Cisco ASA firewalls.
type CiscoASAProfile struct{}

func init() {
	RegisterVendor(&CiscoASAProfile{})
}

func (c *CiscoASAProfile) Name() string { return "cisco_asa" }

func (c *CiscoASAProfile) SystemOIDs() []string {
	return []string{
		asaOIDSysName,
		asaOIDSysDescr,
		asaOIDSysUpTime,
		asaOIDCpu1MinFirst,
		asaOIDMemPoolUsed,
		asaOIDMemPoolFree,
		asaOIDConnCurrent,
	}
}

func (c *CiscoASAProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}
	var memUsedBytes, memFreeBytes int64

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case asaOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case asaOIDSysDescr:
			status.Version = extractCiscoASAVersion(safeString(pdu.Value))
		case asaOIDSysUpTime:
			// sysUpTime is in hundredths of a second; convert to seconds
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks / 100
		case asaOIDMemPoolUsed:
			memUsedBytes = gosnmp.ToBigInt(pdu.Value).Int64()
		case asaOIDMemPoolFree:
			memFreeBytes = gosnmp.ToBigInt(pdu.Value).Int64()
		case asaOIDConnCurrent:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		default:
			// CPU: match by prefix so any cpmCPUTotalIndex answers.
			if strings.HasPrefix(pdu.Name, asaOIDCpu1MinRev+".") {
				status.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
			}
		}
	}

	if memTotal := memUsedBytes + memFreeBytes; memTotal > 0 {
		status.MemoryTotal = uint64(memTotal) / (1024 * 1024) // bytes → MB
		status.MemoryUsage = float64(memUsedBytes) / float64(memTotal) * 100
	}

	return status
}

// extractCiscoASAVersion parses the OS version out of the ASA sysDescr,
// e.g. "Cisco Adaptive Security Appliance Version 9.16(4)8" → "ASA 9.16(4)8".
func extractCiscoASAVersion(sysDescr string) string {
	sysDescr = strings.TrimSpace(sysDescr)
	if sysDescr == "" {
		return ""
	}
	fields := strings.Fields(sysDescr)
	for i, f := range fields {
		if strings.EqualFold(f, "Version") && i+1 < len(fields) {
			return "ASA " + fields[i+1]
		}
	}
	if len(sysDescr) > 80 {
		return sysDescr[:80]
	}
	return sysDescr
}

// VPN: deliberately unsupported — see the omission note in the OID block.

func (c *CiscoASAProfile) VPNBaseOID() string { return "" }

func (c *CiscoASAProfile) ParseVPNStatus(_ []gosnmp.SnmpPDU) []relay.VPNStatus {
	return nil
}

// Hardware sensors: deliberately unsupported — see the omission note above.

func (c *CiscoASAProfile) HWSensorBaseOID() string { return "" }

func (c *CiscoASAProfile) ParseHardwareSensors(_ []gosnmp.SnmpPDU) []relay.HardwareSensor {
	return nil
}

// Processors: CISCO-PROCESS-MIB cpmCPUTotalTable, one row per CPU.

func (c *CiscoASAProfile) ProcessorBaseOID() string { return asaBaseOIDCpu }

func (c *CiscoASAProfile) ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats {
	// Prefer the 1-minute revised average; fall back to the 5-minute average
	// for agents that only populate one of the two columns.
	rev1 := make(map[int]int64)
	rev5 := make(map[int]int64)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, asaOIDCpu1MinRev+".") {
			idx := getIndexFromOID(pdu.Name, asaOIDCpu1MinRev)
			if idx < 0 {
				continue
			}
			rev1[idx] = gosnmp.ToBigInt(pdu.Value).Int64()
		} else if strings.HasPrefix(pdu.Name, asaOIDCpu5MinRev+".") {
			idx := getIndexFromOID(pdu.Name, asaOIDCpu5MinRev)
			if idx < 0 {
				continue
			}
			rev5[idx] = gosnmp.ToBigInt(pdu.Value).Int64()
		}
	}

	now := time.Now()
	var result []relay.ProcessorStats
	for idx, usage := range rev1 {
		result = append(result, relay.ProcessorStats{Timestamp: now, Index: idx, Usage: float64(usage)})
	}
	for idx, usage := range rev5 {
		if _, ok := rev1[idx]; ok {
			continue
		}
		result = append(result, relay.ProcessorStats{Timestamp: now, Index: idx, Usage: float64(usage)})
	}
	return result
}

// Traps: deliberately unsupported — see the omission note above.

func (c *CiscoASAProfile) TrapOIDs() map[string]TrapDef {
	return nil
}

// --- HA Provider: CISCO-FIREWALL-MIB failover status ---
//
// The primary(6)/secondary(7) rows of cfwHardwareStatusTable describe the
// failover pair; on standalone units the rows are absent (NoSuchInstance on
// the scalar Gets) and no HA status is reported.

func (c *CiscoASAProfile) HAScalarOIDs() []string {
	return []string{
		asaOIDFailoverInfo + ".6",
		asaOIDFailoverInfo + ".7",
		asaOIDFailoverValue + ".6",
		asaOIDFailoverValue + ".7",
		asaOIDFailoverDetail + ".6",
		asaOIDFailoverDetail + ".7",
	}
}

func (c *CiscoASAProfile) HAStatsBaseOID() string { return asaBaseOIDFailover }

func (c *CiscoASAProfile) ParseHAStatus(scalars []gosnmp.SnmpPDU, members []gosnmp.SnmpPDU) []relay.HAStatus {
	info := make(map[int]string)
	value := make(map[int]int64)
	detail := make(map[int]string)

	parse := func(pdus []gosnmp.SnmpPDU) {
		for _, pdu := range pdus {
			if !isValidPDU(pdu) {
				continue
			}
			if strings.HasPrefix(pdu.Name, asaOIDFailoverInfo+".") {
				idx := getIndexFromOID(pdu.Name, asaOIDFailoverInfo)
				if idx >= 0 {
					info[idx] = safeString(pdu.Value)
				}
			} else if strings.HasPrefix(pdu.Name, asaOIDFailoverValue+".") {
				idx := getIndexFromOID(pdu.Name, asaOIDFailoverValue)
				if idx >= 0 {
					value[idx] = gosnmp.ToBigInt(pdu.Value).Int64()
				}
			} else if strings.HasPrefix(pdu.Name, asaOIDFailoverDetail+".") {
				idx := getIndexFromOID(pdu.Name, asaOIDFailoverDetail)
				if idx >= 0 {
					detail[idx] = safeString(pdu.Value)
				}
			}
		}
	}
	parse(scalars)
	parse(members)

	now := time.Now()
	var result []relay.HAStatus
	for _, idx := range []int{asaFailoverIdxPrimary, asaFailoverIdxSecondary} {
		statusVal, ok := value[idx]
		if !ok {
			continue // row absent → not a failover member / failover off
		}
		memberIndex := 1
		if idx == asaFailoverIdxSecondary {
			memberIndex = 2
		}
		sync := asaHardwareStatusText(statusVal)
		if d := detail[idx]; d != "" {
			sync = sync + " (" + d + ")"
		}
		result = append(result, relay.HAStatus{
			Timestamp:      now,
			SystemMode:     "failover",
			GroupName:      "failover",
			MemberIndex:    memberIndex,
			MemberHostname: info[idx],
			SyncStatus:     sync,
		})
	}
	return result
}

// asaHardwareStatusText maps the CISCO-FIREWALL-MIB HardwareStatus textual
// convention to a display string.
func asaHardwareStatusText(v int64) string {
	switch v {
	case 1:
		return "other"
	case 2:
		return "up"
	case 3:
		return "down"
	case 4:
		return "error"
	case 5:
		return "overTemp"
	case 6:
		return "busy"
	case 7:
		return "noMedia"
	case 8:
		return "backup"
	case 9:
		return "active"
	case 10:
		return "standby"
	default:
		return "unknown"
	}
}
