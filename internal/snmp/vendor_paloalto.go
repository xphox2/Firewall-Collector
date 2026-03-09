package snmp

import (
	"fmt"
	"math"
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// Palo Alto Networks SNMP OIDs — PAN-COMMON-MIB + standard MIBs.
// Enterprise OID: .1.3.6.1.4.1.25461
var (
	// --- SNMPv2-MIB system scalars ---
	paOIDSysName   = ".1.3.6.1.2.1.1.5.0"
	paOIDSysUpTime = ".1.3.6.1.2.1.1.3.0"

	// --- PAN-COMMON-MIB panSys (.1.3.6.1.4.1.25461.2.1.2.1) ---
	paOIDSwVersion     = ".1.3.6.1.4.1.25461.2.1.2.1.1.0"
	paOIDHwVersion     = ".1.3.6.1.4.1.25461.2.1.2.1.2.0"
	paOIDSerialNumber  = ".1.3.6.1.4.1.25461.2.1.2.1.3.0"
	paOIDAppVersion    = ".1.3.6.1.4.1.25461.2.1.2.1.7.0"
	paOIDAvVersion     = ".1.3.6.1.4.1.25461.2.1.2.1.8.0"
	paOIDThreatVersion = ".1.3.6.1.4.1.25461.2.1.2.1.9.0"
	paOIDWildfireVer   = ".1.3.6.1.4.1.25461.2.1.2.1.17.0"

	// --- PAN-COMMON-MIB HA ---
	paOIDHAState     = ".1.3.6.1.4.1.25461.2.1.2.1.11.0"
	paOIDHAPeerState = ".1.3.6.1.4.1.25461.2.1.2.1.12.0"
	paOIDHAMode      = ".1.3.6.1.4.1.25461.2.1.2.1.13.0"

	// --- PAN-COMMON-MIB panSession (.1.3.6.1.4.1.25461.2.1.2.3) ---
	paOIDSessionUtil   = ".1.3.6.1.4.1.25461.2.1.2.3.1.0"
	paOIDSessionMax    = ".1.3.6.1.4.1.25461.2.1.2.3.2.0"
	paOIDSessionActive = ".1.3.6.1.4.1.25461.2.1.2.3.3.0"

	// --- PAN-COMMON-MIB GlobalProtect gateway ---
	paOIDGPActiveTunnels = ".1.3.6.1.4.1.25461.2.1.2.5.1.3.0"
	paOIDGPMaxTunnels    = ".1.3.6.1.4.1.25461.2.1.2.5.1.2.0"

	// --- HOST-RESOURCES-MIB CPU ---
	paBaseOIDProcessor  = ".1.3.6.1.2.1.25.3.3.1"
	paOIDProcessorLoad  = ".1.3.6.1.2.1.25.3.3.1.2"
	paOIDProcessorLoad1 = ".1.3.6.1.2.1.25.3.3.1.2.1" // Management plane CPU

	// --- ENTITY-SENSOR-MIB ---
	paBaseOIDSensor      = ".1.3.6.1.2.1.99.1.1.1"
	paOIDSensorType      = ".1.3.6.1.2.1.99.1.1.1.1"
	paOIDSensorScale     = ".1.3.6.1.2.1.99.1.1.1.2"
	paOIDSensorPrecision = ".1.3.6.1.2.1.99.1.1.1.3"
	paOIDSensorValue     = ".1.3.6.1.2.1.99.1.1.1.4"
	paOIDSensorStatus    = ".1.3.6.1.2.1.99.1.1.1.5"

	// --- ENTITY-MIB (for sensor names) ---
	paOIDEntityName = ".1.3.6.1.2.1.47.1.1.1.1.7"

	// --- PAN-COMMON-MIB Panorama ---
	paOIDPanorama1Connected = ".1.3.6.1.4.1.25461.2.1.2.4.1.0"
	paOIDPanorama2Connected = ".1.3.6.1.4.1.25461.2.1.2.4.2.0"
)

// PaloAltoProfile implements VendorProfile for Palo Alto Networks firewalls.
type PaloAltoProfile struct{}

func init() {
	RegisterVendor(&PaloAltoProfile{})
}

func (p *PaloAltoProfile) Name() string { return "paloalto" }

func (p *PaloAltoProfile) SystemOIDs() []string {
	return []string{
		paOIDSysName,
		paOIDSysUpTime,
		paOIDSwVersion,
		paOIDHwVersion,
		paOIDSerialNumber,
		paOIDProcessorLoad1,
		paOIDSessionActive,
		paOIDSessionMax,
		paOIDSessionUtil,
		paOIDAvVersion,
		paOIDThreatVersion,
		paOIDGPActiveTunnels,
		paOIDGPMaxTunnels,
	}
}

func (p *PaloAltoProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case paOIDSysName:
			status.Hostname = safeString(pdu.Value)
		case paOIDSwVersion:
			status.Version = "PAN-OS " + safeString(pdu.Value)
		case paOIDSysUpTime:
			ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
			status.Uptime = ticks / 100
		case paOIDProcessorLoad1:
			status.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case paOIDSessionActive:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case paOIDAvVersion:
			status.AVVersion = safeString(pdu.Value)
		case paOIDThreatVersion:
			status.IPSVersion = safeString(pdu.Value)
		case paOIDGPActiveTunnels:
			status.SSLVPNTunnels = int(gosnmp.ToBigInt(pdu.Value).Int64())
		}
	}

	return status
}

// VPN: Palo Alto tunnel.* interfaces are IPSec VTI tunnels visible in IF-MIB.
// No pollable IPSec SA table exists — only SNMP traps for tunnel up/down.

func (p *PaloAltoProfile) VPNBaseOID() string { return BaseOIDInterface }

func (p *PaloAltoProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	return parsePaloAltoVPNFromInterfaces(pdus)
}

// parsePaloAltoVPNFromInterfaces extracts VPN tunnel status from IF-MIB
// by matching "tunnel.*" interface name pattern used by PAN-OS.
func parsePaloAltoVPNFromInterfaces(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	interfaces := make(map[int]*bsdIfData) // reuse bsdIfData struct

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name

		if strings.HasPrefix(name, OIDIfDescr+".") {
			idx := getIndexFromOID(name, OIDIfDescr)
			if idx < 0 {
				continue
			}
			ifd := getOrCreatePAIf(interfaces, idx)
			ifd.name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, OIDIfOperStatus+".") {
			idx := getIndexFromOID(name, OIDIfOperStatus)
			if idx < 0 {
				continue
			}
			ifd := getOrCreatePAIf(interfaces, idx)
			ifd.operUp = gosnmp.ToBigInt(pdu.Value).Int64() == 1
		} else if strings.HasPrefix(name, OIDIfInOctets+".") {
			idx := getIndexFromOID(name, OIDIfInOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreatePAIf(interfaces, idx)
			ifd.bytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDIfOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfOutOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreatePAIf(interfaces, idx)
			ifd.bytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
		// 64-bit counters from ifXTable
		if strings.HasPrefix(name, OIDIfHCInOctets+".") {
			idx := getIndexFromOID(name, OIDIfHCInOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreatePAIf(interfaces, idx)
			ifd.bytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDIfHCOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfHCOutOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreatePAIf(interfaces, idx)
			ifd.bytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	var result []relay.VPNStatus

	for _, ifd := range interfaces {
		lower := strings.ToLower(ifd.name)
		if !strings.HasPrefix(lower, "tunnel.") {
			continue
		}

		vpnStatus := "down"
		state := "inactive"
		if ifd.operUp {
			vpnStatus = "up"
			state = "active"
		}

		result = append(result, relay.VPNStatus{
			Timestamp:  now,
			TunnelName: ifd.name,
			TunnelType: "ipsec",
			Status:     vpnStatus,
			State:      state,
			BytesIn:    ifd.bytesIn,
			BytesOut:   ifd.bytesOut,
		})
	}

	return result
}

func getOrCreatePAIf(m map[int]*bsdIfData, idx int) *bsdIfData {
	if v, ok := m[idx]; ok {
		return v
	}
	v := &bsdIfData{}
	m[idx] = v
	return v
}

// Hardware sensors: ENTITY-SENSOR-MIB for temperature, fan, voltage, power.

func (p *PaloAltoProfile) HWSensorBaseOID() string { return paBaseOIDSensor }

func (p *PaloAltoProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor {
	sensors := make(map[int]*paSensorData)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name

		if strings.HasPrefix(name, paOIDSensorType+".") {
			idx := getIndexFromOID(name, paOIDSensorType)
			if idx < 0 {
				continue
			}
			sd := getOrCreatePASensor(sensors, idx)
			sd.sensorType = int(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, paOIDSensorScale+".") {
			idx := getIndexFromOID(name, paOIDSensorScale)
			if idx < 0 {
				continue
			}
			sd := getOrCreatePASensor(sensors, idx)
			sd.scale = int(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, paOIDSensorPrecision+".") {
			idx := getIndexFromOID(name, paOIDSensorPrecision)
			if idx < 0 {
				continue
			}
			sd := getOrCreatePASensor(sensors, idx)
			sd.precision = int(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, paOIDSensorValue+".") {
			idx := getIndexFromOID(name, paOIDSensorValue)
			if idx < 0 {
				continue
			}
			sd := getOrCreatePASensor(sensors, idx)
			sd.value = gosnmp.ToBigInt(pdu.Value).Int64()
		} else if strings.HasPrefix(name, paOIDSensorStatus+".") {
			idx := getIndexFromOID(name, paOIDSensorStatus)
			if idx < 0 {
				continue
			}
			sd := getOrCreatePASensor(sensors, idx)
			sd.status = int(gosnmp.ToBigInt(pdu.Value).Int64())
		}
	}

	now := time.Now()
	var result []relay.HardwareSensor

	for idx, sd := range sensors {
		if sd.status == 2 || sd.status == 3 { // unavailable or nonoperational
			continue
		}

		sensorName, sensorTypeName, unit := paSensorMeta(sd.sensorType, idx)
		if sensorTypeName == "" {
			continue
		}

		// Compute actual value: value / 10^precision * scale_factor
		actualValue := float64(sd.value)
		if sd.precision > 0 {
			actualValue = actualValue / math.Pow(10, float64(sd.precision))
		}
		// Apply scale factor (entPhySensorScale: 8=units, 9=kilo, 7=milli, etc.)
		actualValue = actualValue * paSensorScaleFactor(sd.scale)

		alarmStatus := "normal"
		if sd.status == 3 {
			alarmStatus = "alarm"
		}

		result = append(result, relay.HardwareSensor{
			Timestamp: now,
			Name:      sensorName,
			Type:      sensorTypeName,
			Value:     actualValue,
			Status:    alarmStatus,
			Unit:      unit,
		})
	}

	return result
}

// paSensorMeta returns name, type, and unit for ENTITY-SENSOR-MIB sensor types.
func paSensorMeta(sensorType, idx int) (string, string, string) {
	switch sensorType {
	case 8: // celsius
		return fmt.Sprintf("Temperature Sensor %d", idx), "temperature", "°C"
	case 10: // rpm
		return fmt.Sprintf("Fan %d", idx), "fan", "RPM"
	case 4: // voltsDC
		return fmt.Sprintf("Voltage Sensor %d", idx), "voltage", "V"
	case 3: // voltsAC
		return fmt.Sprintf("AC Voltage %d", idx), "voltage", "V"
	case 5: // amperes
		return fmt.Sprintf("Current Sensor %d", idx), "current", "A"
	case 6: // watts
		return fmt.Sprintf("Power Sensor %d", idx), "power", "W"
	default:
		return "", "", ""
	}
}

// paSensorScaleFactor converts ENTITY-SENSOR-MIB scale enum to multiplier.
func paSensorScaleFactor(scale int) float64 {
	switch scale {
	case 1: // yocto
		return 1e-24
	case 2: // zepto
		return 1e-21
	case 3: // atto
		return 1e-18
	case 4: // femto
		return 1e-15
	case 5: // pico
		return 1e-12
	case 6: // nano
		return 1e-9
	case 7: // micro
		return 1e-6
	case 8: // milli
		return 1e-3
	case 9: // units
		return 1
	case 10: // kilo
		return 1e3
	case 11: // mega
		return 1e6
	case 12: // giga
		return 1e9
	case 13: // tera
		return 1e12
	default:
		return 1
	}
}

// paSensorData holds per-sensor data from the ENTITY-SENSOR-MIB.
type paSensorData struct {
	sensorType int
	scale      int
	precision  int
	value      int64
	status     int
}

func getOrCreatePASensor(m map[int]*paSensorData, idx int) *paSensorData {
	if v, ok := m[idx]; ok {
		return v
	}
	v := &paSensorData{scale: 9} // default to units scale
	m[idx] = v
	return v
}

// Processors: HOST-RESOURCES-MIB hrProcessorLoad.
// Index 1 = management plane, 2 = data plane system, 3+ = data plane packet processors.

func (p *PaloAltoProfile) ProcessorBaseOID() string { return paBaseOIDProcessor }

func (p *PaloAltoProfile) ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats {
	now := time.Now()
	var result []relay.ProcessorStats
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, paOIDProcessorLoad+".") {
			idx := getIndexFromOID(pdu.Name, paOIDProcessorLoad)
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

// HA: Palo Alto exposes HA state as scalar OIDs in PAN-COMMON-MIB.

var _ HAProvider = (*PaloAltoProfile)(nil)

func (p *PaloAltoProfile) HAScalarOIDs() []string {
	return []string{
		paOIDHAState,
		paOIDHAPeerState,
		paOIDHAMode,
		paOIDSerialNumber,
	}
}

func (p *PaloAltoProfile) HAStatsBaseOID() string { return "" }

func (p *PaloAltoProfile) ParseHAStatus(scalars []gosnmp.SnmpPDU, _ []gosnmp.SnmpPDU) []relay.HAStatus {
	var haState, peerState, haMode, serial string

	for _, pdu := range scalars {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case paOIDHAState:
			haState = safeString(pdu.Value)
		case paOIDHAPeerState:
			peerState = safeString(pdu.Value)
		case paOIDHAMode:
			haMode = safeString(pdu.Value)
		case paOIDSerialNumber:
			serial = safeString(pdu.Value)
		}
	}

	if haMode == "" || haMode == "disabled" {
		return nil // standalone mode
	}

	syncStatus := "in-sync"
	if peerState == "" || peerState == "non-functional" || peerState == "suspended" {
		syncStatus = "out-of-sync"
	}

	return []relay.HAStatus{
		{
			Timestamp:      time.Now(),
			SystemMode:     haMode,
			GroupID:        1,
			GroupName:      "HA",
			MemberIndex:    0,
			MemberSerial:   serial,
			MemberHostname: haState,
			SyncStatus:     syncStatus,
		},
	}
}

// Traps: PAN-TRAPS-MIB notifications.

func (p *PaloAltoProfile) TrapOIDs() map[string]TrapDef {
	return map[string]TrapDef{
		// VPN tunnel events
		".1.3.6.1.4.1.25461.2.1.3.2.0.1746": {Type: "vpn-tunnel-up", Severity: "info"},
		".1.3.6.1.4.1.25461.2.1.3.2.0.1747": {Type: "vpn-tunnel-down", Severity: "critical"},
		// HA events
		".1.3.6.1.4.1.25461.2.1.3.2.0.801": {Type: "ha-state-change", Severity: "warning"},
		".1.3.6.1.4.1.25461.2.1.3.2.0.803": {Type: "ha-dataplane-down", Severity: "critical"},
		".1.3.6.1.4.1.25461.2.1.3.2.0.826": {Type: "ha-split-brain", Severity: "critical"},
		// Hardware events
		".1.3.6.1.4.1.25461.2.1.3.2.0.900": {Type: "hw-disk-error", Severity: "critical"},
		".1.3.6.1.4.1.25461.2.1.3.2.0.913": {Type: "hw-ps-failure", Severity: "critical"},
		".1.3.6.1.4.1.25461.2.1.3.2.0.916": {Type: "hw-fan-failure", Severity: "critical"},
		// GlobalProtect events
		".1.3.6.1.4.1.25461.2.1.3.2.0.700": {Type: "gp-login-success", Severity: "info"},
		".1.3.6.1.4.1.25461.2.1.3.2.0.701": {Type: "gp-login-failed", Severity: "warning"},
		".1.3.6.1.4.1.25461.2.1.3.2.0.702": {Type: "gp-logout", Severity: "info"},
		// System events
		".1.3.6.1.4.1.25461.2.1.3.2.0.600": {Type: "system-general", Severity: "info"},
		// Threat events
		".1.3.6.1.4.1.25461.2.1.3.2.0.4":   {Type: "threat-detected", Severity: "critical"},
	}
}
