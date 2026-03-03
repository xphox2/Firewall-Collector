package snmp

import (
	"fmt"
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// Standard MIB OIDs (vendor-neutral)
var (
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
	OIDIfName        = ".1.3.6.1.2.1.31.1.1.1.1"
	OIDIfHCInOctets  = ".1.3.6.1.2.1.31.1.1.1.6"
	OIDIfHCOutOctets = ".1.3.6.1.2.1.31.1.1.1.10"
	OIDIfHighSpeed   = ".1.3.6.1.2.1.31.1.1.1.15"
	OIDIfAlias       = ".1.3.6.1.2.1.31.1.1.1.18"

	// Q-BRIDGE-MIB (native VLAN)
	OIDdot1qPvid = ".1.3.6.1.2.1.17.7.1.4.5.1.1"
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

// GetRaw performs a raw SNMP GET and returns the first value as a string for diagnostics.
func (s *SNMPClient) GetRaw(oids []string) (string, error) {
	result, err := s.client.Get(oids)
	if err != nil {
		return "", err
	}
	if len(result.Variables) == 0 {
		return "(no variables returned)", nil
	}
	pdu := result.Variables[0]
	switch pdu.Type {
	case gosnmp.OctetString:
		return string(pdu.Value.([]byte)), nil
	case gosnmp.ObjectIdentifier:
		return pdu.Value.(string), nil
	default:
		return fmt.Sprintf("%v (type=%d)", pdu.Value, pdu.Type), nil
	}
}

func (s *SNMPClient) resolveVendor(vendor string) VendorProfile {
	if vendor == "" {
		vendor = "fortigate"
	}
	profile := GetVendorProfile(vendor)
	if profile == nil {
		profile = DefaultVendor()
	}
	return profile
}

func (s *SNMPClient) GetSystemStatus(vendor ...string) (*relay.SystemStatus, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, fmt.Errorf("no vendor profile available")
	}

	oids := profile.SystemOIDs()
	if len(oids) == 0 {
		return nil, fmt.Errorf("vendor %s does not support system status polling", v)
	}

	result, err := s.client.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("failed to get system status: %w", err)
	}

	return profile.ParseSystemStatus(result.Variables), nil
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
			if strings.HasPrefix(name, OIDIfName+".") {
				idx := getIndexFromOID(name, OIDIfName)
				if iface, ok := interfaces[idx]; ok {
					ifName := safeString(pdu.Value)
					if ifName != "" {
						iface.Name = ifName
					}
					interfaces[idx] = iface
				}
			} else if strings.HasPrefix(name, OIDIfAlias+".") {
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

func (s *SNMPClient) GetVPNStatus(vendor ...string) ([]relay.VPNStatus, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, fmt.Errorf("no vendor profile available")
	}

	var statuses []relay.VPNStatus

	// Walk site-to-site (non-dial-up) tunnel table
	baseOID := profile.VPNBaseOID()
	if baseOID != "" {
		pdus, err := s.client.WalkAll(baseOID)
		if err != nil {
			return nil, fmt.Errorf("failed to walk VPN tunnel table: %w", err)
		}
		statuses = profile.ParseVPNStatus(pdus)
	}

	// Walk dial-up tunnel table if vendor supports it (e.g. FortiGate hub-side IPSec)
	if dialupProvider, ok := profile.(DialupVPNProvider); ok {
		dialupOID := dialupProvider.DialupVPNBaseOID()
		if dialupOID != "" {
			pdus, err := s.client.WalkAll(dialupOID)
			if err == nil && len(pdus) > 0 {
				statuses = append(statuses, dialupProvider.ParseDialupVPNStatus(pdus)...)
			}
		}
	}

	// Walk SSL-VPN tunnel table if vendor supports it
	if sslProvider, ok := profile.(SSLVPNProvider); ok {
		sslOID := sslProvider.SSLVPNBaseOID()
		if sslOID != "" {
			pdus, err := s.client.WalkAll(sslOID)
			if err == nil && len(pdus) > 0 {
				statuses = append(statuses, sslProvider.ParseSSLVPNTunnels(pdus)...)
			}
		}
	}

	return statuses, nil
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

func (s *SNMPClient) GetProcessorStats(vendor ...string) ([]relay.ProcessorStats, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, fmt.Errorf("no vendor profile available")
	}

	baseOID := profile.ProcessorBaseOID()
	if baseOID == "" {
		return nil, nil
	}

	pdus, err := s.client.WalkAll(baseOID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk processor table: %w", err)
	}

	return profile.ParseProcessorStats(pdus), nil
}

func (s *SNMPClient) GetHardwareSensors(vendor ...string) ([]relay.HardwareSensor, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, fmt.Errorf("no vendor profile available")
	}

	baseOID := profile.HWSensorBaseOID()
	if baseOID == "" {
		return nil, nil
	}

	pdus, err := s.client.WalkAll(baseOID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk hardware sensor table: %w", err)
	}

	return profile.ParseHardwareSensors(pdus), nil
}

func getOrCreateSensor(sensors map[int]*relay.HardwareSensor, index int) *relay.HardwareSensor {
	if s, exists := sensors[index]; exists {
		return s
	}
	s := &relay.HardwareSensor{}
	sensors[index] = s
	return s
}

func (s *SNMPClient) GetHAStatus(vendor ...string) ([]relay.HAStatus, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, nil
	}
	haProvider, ok := profile.(HAProvider)
	if !ok {
		return nil, nil
	}

	scalarOIDs := haProvider.HAScalarOIDs()
	if len(scalarOIDs) == 0 {
		return nil, nil
	}

	scalarResult, err := s.client.Get(scalarOIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get HA scalars: %w", err)
	}

	memberPDUs, err := s.client.WalkAll(haProvider.HAStatsBaseOID())
	if err != nil {
		// HA table may not exist on standalone units
		memberPDUs = nil
	}

	return haProvider.ParseHAStatus(scalarResult.Variables, memberPDUs), nil
}

func (s *SNMPClient) GetSecurityStats(vendor ...string) (*relay.SecurityStats, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, nil
	}
	secProvider, ok := profile.(SecurityStatsProvider)
	if !ok {
		return nil, nil
	}

	oids := secProvider.SecurityStatsOIDs()
	if len(oids) == 0 {
		return nil, nil
	}

	result, err := s.client.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("failed to get security stats: %w", err)
	}

	return secProvider.ParseSecurityStats(result.Variables), nil
}

func (s *SNMPClient) GetSDWANHealth(vendor ...string) ([]relay.SDWANHealth, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, nil
	}
	sdwanProvider, ok := profile.(SDWANProvider)
	if !ok {
		return nil, nil
	}

	baseOID := sdwanProvider.SDWANHealthBaseOID()
	if baseOID == "" {
		return nil, nil
	}

	pdus, err := s.client.WalkAll(baseOID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk SD-WAN health table: %w", err)
	}

	return sdwanProvider.ParseSDWANHealth(pdus), nil
}

func (s *SNMPClient) GetLicenseInfo(vendor ...string) ([]relay.LicenseInfo, error) {
	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	profile := s.resolveVendor(v)
	if profile == nil {
		return nil, nil
	}
	licProvider, ok := profile.(LicenseProvider)
	if !ok {
		return nil, nil
	}

	baseOID := licProvider.LicenseBaseOID()
	if baseOID == "" {
		return nil, nil
	}

	pdus, err := s.client.WalkAll(baseOID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk license table: %w", err)
	}

	return licProvider.ParseLicenseInfo(pdus), nil
}
