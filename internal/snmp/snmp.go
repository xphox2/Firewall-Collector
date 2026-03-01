package snmp

import (
	"fmt"
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// FortiGate-specific SNMP OIDs (Fortinet enterprise MIB 1.3.6.1.4.1.12356)
var (
	OIDSystemCPU       = ".1.3.6.1.4.1.12356.101.4.1.3"
	OIDSystemMemory    = ".1.3.6.1.4.1.12356.101.4.1.4"
	OIDSystemMemoryCap = ".1.3.6.1.4.1.12356.101.4.1.5"
	OIDSystemDisk      = ".1.3.6.1.4.1.12356.101.4.1.6"
	OIDSystemDiskCap   = ".1.3.6.1.4.1.12356.101.4.1.7"
	OIDSystemSessions  = ".1.3.6.1.4.1.12356.101.4.1.8"
	OIDSystemUptime    = ".1.3.6.1.4.1.12356.101.4.1.20"
	OIDSystemVersion   = ".1.3.6.1.4.1.12356.101.4.1.1"
	OIDSystemHostname  = ".1.3.6.1.4.1.12356.101.4.1.2"

	BaseOIDInterface   = ".1.3.6.1.2.1.2.2.1"
	OIDIfDescr         = ".1.3.6.1.2.1.2.2.1.2"
	OIDIfType          = ".1.3.6.1.2.1.2.2.1.3"
	OIDIfSpeed         = ".1.3.6.1.2.1.2.2.1.5"
	OIDIfAdminStatus   = ".1.3.6.1.2.1.2.2.1.7"
	OIDIfOperStatus    = ".1.3.6.1.2.1.2.2.1.8"
	OIDIfInOctets      = ".1.3.6.1.2.1.2.2.1.10"
	OIDIfInUcastPkts   = ".1.3.6.1.2.1.2.2.1.11"
	OIDIfInDiscards    = ".1.3.6.1.2.1.2.2.1.13"
	OIDIfInErrors      = ".1.3.6.1.2.1.2.2.1.14"
	OIDIfOutOctets     = ".1.3.6.1.2.1.2.2.1.16"
	OIDIfOutUcastPkts  = ".1.3.6.1.2.1.2.2.1.17"
	OIDIfOutDiscards   = ".1.3.6.1.2.1.2.2.1.19"
	OIDIfOutErrors     = ".1.3.6.1.2.1.2.2.1.20"

	// Trap OIDs
	TrapVPNTunnelUp   = ".1.3.6.1.4.1.12356.101.2.0.301"
	TrapVPNTunnelDown = ".1.3.6.1.4.1.12356.101.2.0.302"
	TrapHASwitch      = ".1.3.6.1.4.1.12356.101.2.0.401"
	TrapHAStateChange = ".1.3.6.1.4.1.12356.101.2.0.402"
	TrapHAHBFail      = ".1.3.6.1.4.1.12356.101.2.0.403"
	TrapHAMemberDown  = ".1.3.6.1.4.1.12356.101.2.0.404"
	TrapHAMemberUp    = ".1.3.6.1.4.1.12356.101.2.0.405"
	TrapIPSSignature  = ".1.3.6.1.4.1.12356.101.2.0.503"
	TrapIPSanomaly    = ".1.3.6.1.4.1.12356.101.2.0.504"
	TrapAVVirus       = ".1.3.6.1.4.1.12356.101.2.0.601"
	TrapAVOversize    = ".1.3.6.1.4.1.12356.101.2.0.602"
)

func safeString(v interface{}) string {
	if s, ok := v.([]byte); ok {
		return string(s)
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

type SNMPClient struct {
	client *gosnmp.GoSNMP
}

func NewSNMPClient(host string, port int, community string, version string) (*SNMPClient, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port: %d", port)
	}

	snmpVersion := gosnmp.Version2c
	if version == "3" {
		snmpVersion = gosnmp.Version3
	} else if version == "1" {
		snmpVersion = gosnmp.Version1
	}

	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: community,
		Version:   snmpVersion,
		Timeout:   10 * time.Second,
		Retries:   1,
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to SNMP %s:%d: %w", host, port, err)
	}

	return &SNMPClient{client: client}, nil
}

func (s *SNMPClient) Close() error {
	if s.client != nil && s.client.Conn != nil {
		return s.client.Conn.Close()
	}
	return nil
}

func (s *SNMPClient) GetSystemStatus() (*relay.SystemStatus, error) {
	status := &relay.SystemStatus{
		Timestamp: time.Now(),
	}

	oids := []string{
		OIDSystemHostname,
		OIDSystemVersion,
		OIDSystemCPU,
		OIDSystemMemory,
		OIDSystemMemoryCap,
		OIDSystemDisk,
		OIDSystemDiskCap,
		OIDSystemSessions,
		OIDSystemUptime,
	}

	result, err := s.client.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("failed to get system status: %w", err)
	}

	for _, pdu := range result.Variables {
		switch pdu.Name {
		case OIDSystemHostname:
			status.Hostname = safeString(pdu.Value)
		case OIDSystemVersion:
			status.Version = safeString(pdu.Value)
		case OIDSystemCPU:
			status.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemMemory:
			status.MemoryUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemMemoryCap:
			status.MemoryTotal = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case OIDSystemDisk:
			status.DiskUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemDiskCap:
			status.DiskTotal = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case OIDSystemSessions:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case OIDSystemUptime:
			status.Uptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	return status, nil
}

func (s *SNMPClient) GetInterfaceStats() ([]relay.InterfaceStats, error) {
	pdus, err := s.client.WalkAll(BaseOIDInterface)
	if err != nil {
		return nil, fmt.Errorf("failed to walk interface stats: %w", err)
	}

	interfaces := make(map[int]relay.InterfaceStats)

	for _, pdu := range pdus {
		name := pdu.Name

		if strings.HasPrefix(name, OIDIfDescr+".") {
			idx := getIndexFromOID(name, OIDIfDescr)
			iface := getOrCreateInterface(interfaces, idx)
			iface.Name = safeString(pdu.Value)
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfType+".") {
			idx := getIndexFromOID(name, OIDIfType)
			iface := getOrCreateInterface(interfaces, idx)
			iface.Type = int(gosnmp.ToBigInt(pdu.Value).Int64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfSpeed+".") {
			idx := getIndexFromOID(name, OIDIfSpeed)
			iface := getOrCreateInterface(interfaces, idx)
			iface.Speed = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfOperStatus+".") {
			idx := getIndexFromOID(name, OIDIfOperStatus)
			iface := getOrCreateInterface(interfaces, idx)
			status := gosnmp.ToBigInt(pdu.Value).Int64()
			if status == 1 {
				iface.Status = "up"
			} else if status == 2 {
				iface.Status = "down"
			} else {
				iface.Status = "unknown"
			}
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfAdminStatus+".") {
			idx := getIndexFromOID(name, OIDIfAdminStatus)
			iface := getOrCreateInterface(interfaces, idx)
			status := gosnmp.ToBigInt(pdu.Value).Int64()
			if status == 1 {
				iface.AdminStatus = "up"
			} else {
				iface.AdminStatus = "down"
			}
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfInOctets+".") {
			idx := getIndexFromOID(name, OIDIfInOctets)
			iface := getOrCreateInterface(interfaces, idx)
			iface.InBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfInUcastPkts+".") {
			idx := getIndexFromOID(name, OIDIfInUcastPkts)
			iface := getOrCreateInterface(interfaces, idx)
			iface.InPackets = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfInErrors+".") {
			idx := getIndexFromOID(name, OIDIfInErrors)
			iface := getOrCreateInterface(interfaces, idx)
			iface.InErrors = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfInDiscards+".") {
			idx := getIndexFromOID(name, OIDIfInDiscards)
			iface := getOrCreateInterface(interfaces, idx)
			iface.InDiscards = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfOutOctets)
			iface := getOrCreateInterface(interfaces, idx)
			iface.OutBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfOutUcastPkts+".") {
			idx := getIndexFromOID(name, OIDIfOutUcastPkts)
			iface := getOrCreateInterface(interfaces, idx)
			iface.OutPackets = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfOutErrors+".") {
			idx := getIndexFromOID(name, OIDIfOutErrors)
			iface := getOrCreateInterface(interfaces, idx)
			iface.OutErrors = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfOutDiscards+".") {
			idx := getIndexFromOID(name, OIDIfOutDiscards)
			iface := getOrCreateInterface(interfaces, idx)
			iface.OutDiscards = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		}
	}

	result := make([]relay.InterfaceStats, 0, len(interfaces))
	for idx, iface := range interfaces {
		if idx < 0 {
			continue
		}
		iface.Timestamp = time.Now()
		result = append(result, iface)
	}

	return result, nil
}

func getIndexFromOID(oid, base string) int {
	partial := strings.TrimPrefix(oid, base+".")
	parts := strings.Split(partial, ".")
	if len(parts) > 0 {
		var index int
		if n, _ := fmt.Sscanf(parts[0], "%d", &index); n == 1 {
			return index
		}
	}
	return -1
}

func getOrCreateInterface(interfaces map[int]relay.InterfaceStats, index int) relay.InterfaceStats {
	if iface, exists := interfaces[index]; exists {
		return iface
	}
	return relay.InterfaceStats{Index: index}
}
