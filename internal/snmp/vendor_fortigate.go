package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// FortiGate-specific SNMP OIDs (Fortinet enterprise MIB 1.3.6.1.4.1.12356)
var (
	fgOIDSystemCPU       = ".1.3.6.1.4.1.12356.101.4.1.3.0"
	fgOIDSystemMemory    = ".1.3.6.1.4.1.12356.101.4.1.4.0"
	fgOIDSystemMemoryCap = ".1.3.6.1.4.1.12356.101.4.1.5.0"
	fgOIDSystemDisk      = ".1.3.6.1.4.1.12356.101.4.1.6.0"
	fgOIDSystemDiskCap   = ".1.3.6.1.4.1.12356.101.4.1.7.0"
	fgOIDSystemSessions  = ".1.3.6.1.4.1.12356.101.4.1.8.0"
	fgOIDSystemUptime    = ".1.3.6.1.4.1.12356.101.4.1.20.0"
	fgOIDSystemVersion   = ".1.3.6.1.4.1.12356.101.4.1.1.0"
	fgOIDSystemHostname  = ".1.3.6.1.4.1.12356.101.4.1.2.0"

	fgBaseOIDVPNTunnel      = ".1.3.6.1.4.1.12356.101.12.2.2.1"
	fgOIDVPNTunnelName      = ".1.3.6.1.4.1.12356.101.12.2.2.1.3"
	fgOIDVPNTunnelRemoteGW  = ".1.3.6.1.4.1.12356.101.12.2.2.1.4"
	fgOIDVPNTunnelInOctets  = ".1.3.6.1.4.1.12356.101.12.2.2.1.18"
	fgOIDVPNTunnelOutOctets = ".1.3.6.1.4.1.12356.101.12.2.2.1.19"
	fgOIDVPNTunnelStatus    = ".1.3.6.1.4.1.12356.101.12.2.2.1.20"

	fgOIDHWSensorEntry = ".1.3.6.1.4.1.12356.101.4.3.2.1"
	fgOIDHWSensorName  = ".1.3.6.1.4.1.12356.101.4.3.2.1.2"
	fgOIDHWSensorValue = ".1.3.6.1.4.1.12356.101.4.3.2.1.3"
	fgOIDHWSensorAlarm = ".1.3.6.1.4.1.12356.101.4.3.2.1.4"

	fgTrapVPNTunnelUp   = ".1.3.6.1.4.1.12356.101.2.0.301"
	fgTrapVPNTunnelDown = ".1.3.6.1.4.1.12356.101.2.0.302"
	fgTrapHASwitch      = ".1.3.6.1.4.1.12356.101.2.0.401"
	fgTrapHAStateChange = ".1.3.6.1.4.1.12356.101.2.0.402"
	fgTrapHAHBFail      = ".1.3.6.1.4.1.12356.101.2.0.403"
	fgTrapHAMemberDown  = ".1.3.6.1.4.1.12356.101.2.0.404"
	fgTrapHAMemberUp    = ".1.3.6.1.4.1.12356.101.2.0.405"
	fgTrapIPSSignature  = ".1.3.6.1.4.1.12356.101.2.0.503"
	fgTrapIPSAnomaly    = ".1.3.6.1.4.1.12356.101.2.0.504"
	fgTrapAVVirus       = ".1.3.6.1.4.1.12356.101.2.0.601"
	fgTrapAVOversize    = ".1.3.6.1.4.1.12356.101.2.0.602"
)

// FortiGateProfile implements VendorProfile for FortiGate devices.
type FortiGateProfile struct{}

func init() {
	RegisterVendor(&FortiGateProfile{})
}

func (f *FortiGateProfile) Name() string { return "fortigate" }

func (f *FortiGateProfile) SystemOIDs() []string {
	return []string{
		fgOIDSystemHostname,
		fgOIDSystemVersion,
		fgOIDSystemCPU,
		fgOIDSystemMemory,
		fgOIDSystemMemoryCap,
		fgOIDSystemDisk,
		fgOIDSystemDiskCap,
		fgOIDSystemSessions,
		fgOIDSystemUptime,
	}
}

func (f *FortiGateProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}
	for _, pdu := range pdus {
		switch pdu.Name {
		case fgOIDSystemHostname:
			status.Hostname = safeString(pdu.Value)
		case fgOIDSystemVersion:
			status.Version = safeString(pdu.Value)
		case fgOIDSystemCPU:
			status.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemMemory:
			status.MemoryUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemMemoryCap:
			status.MemoryTotal = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case fgOIDSystemDisk:
			status.DiskUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemDiskCap:
			status.DiskTotal = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case fgOIDSystemSessions:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemUptime:
			status.Uptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}
	return status
}

func (f *FortiGateProfile) VPNBaseOID() string { return fgBaseOIDVPNTunnel }

func (f *FortiGateProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	tunnelMap := make(map[int]*relay.VPNStatus)
	for _, pdu := range pdus {
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDVPNTunnelName+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelName)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelName = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNTunnelRemoteGW+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelRemoteGW)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.RemoteIP = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNTunnelInOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelInOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNTunnelOutOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelOutOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNTunnelStatus+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelStatus)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			statusVal := gosnmp.ToBigInt(pdu.Value).Int64()
			if statusVal == 2 {
				t.Status = "up"
				t.State = "active"
			} else {
				t.Status = "down"
				t.State = "inactive"
			}
		}
	}

	now := time.Now()
	result := make([]relay.VPNStatus, 0, len(tunnelMap))
	for _, t := range tunnelMap {
		t.Timestamp = now
		result = append(result, *t)
	}
	return result
}

func (f *FortiGateProfile) HWSensorBaseOID() string { return fgOIDHWSensorEntry }

func (f *FortiGateProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor {
	sensorMap := make(map[int]*relay.HardwareSensor)
	for _, pdu := range pdus {
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDHWSensorName+".") {
			idx := getIndexFromOID(name, fgOIDHWSensorName)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			sensor.Name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDHWSensorValue+".") {
			idx := getIndexFromOID(name, fgOIDHWSensorValue)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			sensor.Value = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, fgOIDHWSensorAlarm+".") {
			idx := getIndexFromOID(name, fgOIDHWSensorAlarm)
			if idx < 0 {
				continue
			}
			sensor := getOrCreateSensor(sensorMap, idx)
			alarm := gosnmp.ToBigInt(pdu.Value).Int64()
			if alarm == 0 {
				sensor.Status = "normal"
			} else {
				sensor.Status = "alarm"
			}
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

func (f *FortiGateProfile) TrapOIDs() map[string]TrapDef {
	return map[string]TrapDef{
		fgTrapVPNTunnelUp:   {Type: "VPN_TUNNEL_UP", Severity: "info"},
		fgTrapVPNTunnelDown: {Type: "VPN_TUNNEL_DOWN", Severity: "critical"},
		fgTrapHASwitch:      {Type: "HA_SWITCH", Severity: "warning"},
		fgTrapHAStateChange: {Type: "HA_STATE_CHANGE", Severity: "warning"},
		fgTrapHAHBFail:      {Type: "HA_HEARTBEAT_FAIL", Severity: "critical"},
		fgTrapHAMemberDown:  {Type: "HA_MEMBER_DOWN", Severity: "critical"},
		fgTrapHAMemberUp:    {Type: "HA_MEMBER_UP", Severity: "info"},
		fgTrapIPSSignature:  {Type: "IPS_SIGNATURE", Severity: "critical"},
		fgTrapIPSAnomaly:    {Type: "IPS_ANOMALY", Severity: "critical"},
		fgTrapAVVirus:       {Type: "AV_VIRUS", Severity: "critical"},
		fgTrapAVOversize:    {Type: "AV_OVERSIZE", Severity: "info"},
	}
}
