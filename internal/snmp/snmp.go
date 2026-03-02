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
	OIDSystemCPU       = ".1.3.6.1.4.1.12356.101.4.1.3.0"
	OIDSystemMemory    = ".1.3.6.1.4.1.12356.101.4.1.4.0"
	OIDSystemMemoryCap = ".1.3.6.1.4.1.12356.101.4.1.5.0"
	OIDSystemDisk      = ".1.3.6.1.4.1.12356.101.4.1.6.0"
	OIDSystemDiskCap   = ".1.3.6.1.4.1.12356.101.4.1.7.0"
	OIDSystemSessions  = ".1.3.6.1.4.1.12356.101.4.1.8.0"
	OIDSystemUptime    = ".1.3.6.1.4.1.12356.101.4.1.20.0"
	OIDSystemVersion   = ".1.3.6.1.4.1.12356.101.4.1.1.0"
	OIDSystemHostname  = ".1.3.6.1.4.1.12356.101.4.1.2.0"

	BaseOIDInterface   = ".1.3.6.1.2.1.2.2.1"
	OIDIfDescr         = ".1.3.6.1.2.1.2.2.1.2"
	OIDIfType          = ".1.3.6.1.2.1.2.2.1.3"
	OIDIfMtu           = ".1.3.6.1.2.1.2.2.1.4"
	OIDIfSpeed         = ".1.3.6.1.2.1.2.2.1.5"
	OIDIfPhysAddress   = ".1.3.6.1.2.1.2.2.1.6"
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

	// ifXTable (RFC 2863)
	BaseOIDIfXTable  = ".1.3.6.1.2.1.31.1.1.1"
	OIDIfHCInOctets  = ".1.3.6.1.2.1.31.1.1.1.6"
	OIDIfHCOutOctets = ".1.3.6.1.2.1.31.1.1.1.10"
	OIDIfHighSpeed   = ".1.3.6.1.2.1.31.1.1.1.15"
	OIDIfAlias       = ".1.3.6.1.2.1.31.1.1.1.18"

	// Q-BRIDGE-MIB (native VLAN)
	OIDdot1qPvid = ".1.3.6.1.2.1.17.7.1.4.5.1.1"

	// FortiGate VPN tunnel MIB
	BaseOIDVPNTunnel      = ".1.3.6.1.4.1.12356.101.12.2.2.1"
	OIDVPNTunnelName      = ".1.3.6.1.4.1.12356.101.12.2.2.1.3"
	OIDVPNTunnelRemoteGW  = ".1.3.6.1.4.1.12356.101.12.2.2.1.4"
	OIDVPNTunnelInOctets  = ".1.3.6.1.4.1.12356.101.12.2.2.1.18"
	OIDVPNTunnelOutOctets = ".1.3.6.1.4.1.12356.101.12.2.2.1.19"
	OIDVPNTunnelStatus    = ".1.3.6.1.4.1.12356.101.12.2.2.1.20"

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

// IfTypeNames maps IANA ifType values to human-readable names
var IfTypeNames = map[int]string{
	1:   "other",
	6:   "ethernet",
	24:  "loopback",
	53:  "propVirtual",
	131: "tunnel",
	135: "l2vlan",
	136: "l3ipvlan",
	150: "mplsTunnel",
	161: "lag",
	351: "vxlan",
}

// SNMPv3Config holds per-device v3 credentials
type SNMPv3Config struct {
	Username string
	AuthType string // MD5, SHA, SHA224, SHA256, SHA384, SHA512
	AuthPass string
	PrivType string // DES, AES, AES192, AES256
	PrivPass string
}

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

func NewSNMPClient(host string, port int, community string, version string, v3 *SNMPv3Config) (*SNMPClient, error) {
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

	if snmpVersion == gosnmp.Version3 && v3 != nil {
		client.SecurityModel = gosnmp.UserSecurityModel
		client.MsgFlags = v3MsgFlags(v3)
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 v3.Username,
			AuthenticationProtocol:   v3AuthProto(v3.AuthType),
			AuthenticationPassphrase: v3.AuthPass,
			PrivacyProtocol:          v3PrivProto(v3.PrivType),
			PrivacyPassphrase:        v3.PrivPass,
		}
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to SNMP %s:%d: %w", host, port, err)
	}

	return &SNMPClient{client: client}, nil
}

func v3MsgFlags(v3 *SNMPv3Config) gosnmp.SnmpV3MsgFlags {
	if v3.PrivPass != "" {
		return gosnmp.AuthPriv
	}
	if v3.AuthPass != "" {
		return gosnmp.AuthNoPriv
	}
	return gosnmp.NoAuthNoPriv
}

func v3AuthProto(authType string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(authType) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.SHA
	}
}

func v3PrivProto(privType string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(privType) {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.AES
	}
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
		} else if strings.HasPrefix(name, OIDIfMtu+".") {
			idx := getIndexFromOID(name, OIDIfMtu)
			iface := getOrCreateInterface(interfaces, idx)
			iface.MTU = int(gosnmp.ToBigInt(pdu.Value).Int64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfSpeed+".") {
			idx := getIndexFromOID(name, OIDIfSpeed)
			iface := getOrCreateInterface(interfaces, idx)
			iface.Speed = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
			interfaces[idx] = iface
		} else if strings.HasPrefix(name, OIDIfPhysAddress+".") {
			idx := getIndexFromOID(name, OIDIfPhysAddress)
			iface := getOrCreateInterface(interfaces, idx)
			iface.MACAddress = formatMAC(pdu.Value)
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

	// Walk ifXTable for extended counters and metadata
	if xPdus, err := s.client.WalkAll(BaseOIDIfXTable); err == nil {
		for _, pdu := range xPdus {
			name := pdu.Name
			if strings.HasPrefix(name, OIDIfAlias+".") {
				idx := getIndexFromOID(name, OIDIfAlias)
				if iface, ok := interfaces[idx]; ok {
					iface.Alias = safeString(pdu.Value)
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfHighSpeed+".") {
				idx := getIndexFromOID(name, OIDIfHighSpeed)
				if iface, ok := interfaces[idx]; ok {
					iface.HighSpeed = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfHCInOctets+".") {
				idx := getIndexFromOID(name, OIDIfHCInOctets)
				if iface, ok := interfaces[idx]; ok {
					iface.InBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfHCOutOctets+".") {
				idx := getIndexFromOID(name, OIDIfHCOutOctets)
				if iface, ok := interfaces[idx]; ok {
					iface.OutBytes = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
					interfaces[idx] = iface
				}
			}
		}
	}

	// Walk Q-BRIDGE-MIB for VLAN IDs (not all devices support this)
	if vlanPdus, err := s.client.WalkAll(OIDdot1qPvid); err == nil {
		for _, pdu := range vlanPdus {
			idx := getIndexFromOID(pdu.Name, OIDdot1qPvid)
			if iface, ok := interfaces[idx]; ok {
				iface.VLANID = int(gosnmp.ToBigInt(pdu.Value).Int64())
				interfaces[idx] = iface
			}
		}
	}

	// Resolve type names
	now := time.Now()
	result := make([]relay.InterfaceStats, 0, len(interfaces))
	for idx, iface := range interfaces {
		if idx < 0 {
			continue
		}
		if typeName, ok := IfTypeNames[iface.Type]; ok {
			iface.TypeName = typeName
		}
		iface.Timestamp = now
		result = append(result, iface)
	}

	return result, nil
}

func formatMAC(v interface{}) string {
	var b []byte
	switch val := v.(type) {
	case []byte:
		b = val
	case string:
		b = []byte(val)
	default:
		return ""
	}
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

func (s *SNMPClient) GetVPNStatus() ([]relay.VPNStatus, error) {
	pdus, err := s.client.WalkAll(BaseOIDVPNTunnel)
	if err != nil {
		return nil, fmt.Errorf("failed to walk VPN tunnel table: %w", err)
	}

	tunnelMap := make(map[int]*relay.VPNStatus)
	for _, pdu := range pdus {
		name := pdu.Name
		if strings.HasPrefix(name, OIDVPNTunnelName+".") {
			idx := getIndexFromOID(name, OIDVPNTunnelName)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelName = safeString(pdu.Value)
		} else if strings.HasPrefix(name, OIDVPNTunnelRemoteGW+".") {
			idx := getIndexFromOID(name, OIDVPNTunnelRemoteGW)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.RemoteIP = safeString(pdu.Value)
		} else if strings.HasPrefix(name, OIDVPNTunnelInOctets+".") {
			idx := getIndexFromOID(name, OIDVPNTunnelInOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDVPNTunnelOutOctets+".") {
			idx := getIndexFromOID(name, OIDVPNTunnelOutOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDVPNTunnelStatus+".") {
			idx := getIndexFromOID(name, OIDVPNTunnelStatus)
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
	return result, nil
}

func getOrCreateVPN(m map[int]*relay.VPNStatus, index int) *relay.VPNStatus {
	if v, exists := m[index]; exists {
		return v
	}
	v := &relay.VPNStatus{}
	m[index] = v
	return v
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
