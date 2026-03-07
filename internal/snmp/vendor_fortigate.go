package snmp

import (
	"fmt"
	"net"
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// FortiGate-specific SNMP OIDs (Fortinet enterprise MIB 1.3.6.1.4.1.12356)
var (
	// --- System scalars ---
	fgOIDSystemCPU       = ".1.3.6.1.4.1.12356.101.4.1.3.0"
	fgOIDSystemMemory    = ".1.3.6.1.4.1.12356.101.4.1.4.0"
	fgOIDSystemMemoryCap = ".1.3.6.1.4.1.12356.101.4.1.5.0"
	fgOIDSystemDisk      = ".1.3.6.1.4.1.12356.101.4.1.6.0"
	fgOIDSystemDiskCap   = ".1.3.6.1.4.1.12356.101.4.1.7.0"
	fgOIDSystemSessions  = ".1.3.6.1.4.1.12356.101.4.1.8.0"
	fgOIDSystemUptime    = ".1.3.6.1.4.1.12356.101.4.1.20.0"
	fgOIDSystemVersion   = ".1.3.6.1.4.1.12356.101.4.1.1.0"
	fgOIDSystemHostname  = ".1.3.6.1.4.1.12356.101.4.1.2.0"
	// Extended system (Part 1)
	fgOIDLowMemUsage  = ".1.3.6.1.4.1.12356.101.4.1.9.0"
	fgOIDLowMemCap    = ".1.3.6.1.4.1.12356.101.4.1.10.0"
	fgOIDSesRate1     = ".1.3.6.1.4.1.12356.101.4.1.11.0"
	fgOIDSesRate10    = ".1.3.6.1.4.1.12356.101.4.1.12.0"
	fgOIDSesRate30    = ".1.3.6.1.4.1.12356.101.4.1.13.0"
	fgOIDSesRate60    = ".1.3.6.1.4.1.12356.101.4.1.14.0"
	fgOIDSes6Count    = ".1.3.6.1.4.1.12356.101.4.1.15.0"
	fgOIDVersionAv    = ".1.3.6.1.4.1.12356.101.4.2.1.0"
	fgOIDVersionIps   = ".1.3.6.1.4.1.12356.101.4.2.2.0"
	fgOIDSSLVPNUsers  = ".1.3.6.1.4.1.12356.101.12.2.3.1.2.0"
	fgOIDSSLVPNActive = ".1.3.6.1.4.1.12356.101.12.2.3.1.6.0"

	// --- IPSec site-to-site VPN tunnel table ---
	fgBaseOIDVPNTunnel        = ".1.3.6.1.4.1.12356.101.12.2.2.1"
	fgOIDVPNTunnelPhase1Name = ".1.3.6.1.4.1.12356.101.12.2.2.1.2"
	fgOIDVPNTunnelName       = ".1.3.6.1.4.1.12356.101.12.2.2.1.3"
	fgOIDVPNTunnelRemoteGW   = ".1.3.6.1.4.1.12356.101.12.2.2.1.4"
	// Phase 2 selectors - source (local) subnet
	fgOIDVPNTunnelSrcBeginIP = ".1.3.6.1.4.1.12356.101.12.2.2.1.8"  // Source selector begin IP
	fgOIDVPNTunnelSrcEndIP   = ".1.3.6.1.4.1.12356.101.12.2.2.1.9"  // Source selector end IP
	// Phase 2 selectors - destination (remote) subnet
	fgOIDVPNTunnelDstBeginIP = ".1.3.6.1.4.1.12356.101.12.2.2.1.11" // Destination selector begin IP
	fgOIDVPNTunnelDstEndIP   = ".1.3.6.1.4.1.12356.101.12.2.2.1.12" // Destination selector end IP
	fgOIDVPNTunnelInOctets   = ".1.3.6.1.4.1.12356.101.12.2.2.1.18"
	fgOIDVPNTunnelOutOctets  = ".1.3.6.1.4.1.12356.101.12.2.2.1.19"
	fgOIDVPNTunnelStatus     = ".1.3.6.1.4.1.12356.101.12.2.2.1.20"
	fgOIDVPNTunnelUpTime     = ".1.3.6.1.4.1.12356.101.12.2.2.1.21"

	// fgVpnDialupTable — dial-up/dynamic VPN peers (hub-side of spoke/hub IPSec).
	fgBaseOIDVPNDialup       = ".1.3.6.1.4.1.12356.101.12.2.1.1"
	fgOIDVPNDialupGateway    = ".1.3.6.1.4.1.12356.101.12.2.1.1.2"
	fgOIDVPNDialupLifetime   = ".1.3.6.1.4.1.12356.101.12.2.1.1.3"
	fgOIDVPNDialupSrcBegin   = ".1.3.6.1.4.1.12356.101.12.2.1.1.5"
	fgOIDVPNDialupSrcEnd     = ".1.3.6.1.4.1.12356.101.12.2.1.1.6"
	fgOIDVPNDialupDstBegin   = ".1.3.6.1.4.1.12356.101.12.2.1.1.7"
	fgOIDVPNDialupDstEnd     = ".1.3.6.1.4.1.12356.101.12.2.1.1.8"
	fgOIDVPNDialupInOctets   = ".1.3.6.1.4.1.12356.101.12.2.1.1.9"
	fgOIDVPNDialupOutOctets  = ".1.3.6.1.4.1.12356.101.12.2.1.1.10"

	// --- SSL-VPN tunnel table (Part 2) ---
	fgBaseOIDSSLVPNTunnel      = ".1.3.6.1.4.1.12356.101.12.2.4.1"
	fgOIDSSLVPNTunnelUserName  = ".1.3.6.1.4.1.12356.101.12.2.4.1.3"
	fgOIDSSLVPNTunnelSrcIP     = ".1.3.6.1.4.1.12356.101.12.2.4.1.4"
	fgOIDSSLVPNTunnelBytesIn   = ".1.3.6.1.4.1.12356.101.12.2.4.1.7"
	fgOIDSSLVPNTunnelBytesOut  = ".1.3.6.1.4.1.12356.101.12.2.4.1.8"

	// --- Hardware sensors ---
	fgOIDHWSensorEntry = ".1.3.6.1.4.1.12356.101.4.3.2.1"
	fgOIDHWSensorName  = ".1.3.6.1.4.1.12356.101.4.3.2.1.2"
	fgOIDHWSensorValue = ".1.3.6.1.4.1.12356.101.4.3.2.1.3"
	fgOIDHWSensorAlarm = ".1.3.6.1.4.1.12356.101.4.3.2.1.4"

	// --- Processor table ---
	fgBaseOIDProcessor  = ".1.3.6.1.4.1.12356.101.4.4.2.1"
	fgOIDProcessorUsage = ".1.3.6.1.4.1.12356.101.4.4.2.1.2"

	// --- HA cluster (Part 3) ---
	fgOIDHASystemMode    = ".1.3.6.1.4.1.12356.101.13.1.1.0"
	fgOIDHAGroupId       = ".1.3.6.1.4.1.12356.101.13.1.2.0"
	fgOIDHAGroupName     = ".1.3.6.1.4.1.12356.101.13.1.7.0"
	fgBaseOIDHAStats     = ".1.3.6.1.4.1.12356.101.13.2.1"
	fgOIDHAStatsSerial   = ".1.3.6.1.4.1.12356.101.13.2.1.1.2"
	fgOIDHAStatsCPU      = ".1.3.6.1.4.1.12356.101.13.2.1.1.3"
	fgOIDHAStatsMem      = ".1.3.6.1.4.1.12356.101.13.2.1.1.4"
	fgOIDHAStatsNet      = ".1.3.6.1.4.1.12356.101.13.2.1.1.5"
	fgOIDHAStatsSes      = ".1.3.6.1.4.1.12356.101.13.2.1.1.6"
	fgOIDHAStatsPkt      = ".1.3.6.1.4.1.12356.101.13.2.1.1.7"
	fgOIDHAStatsByte     = ".1.3.6.1.4.1.12356.101.13.2.1.1.8"
	fgOIDHAStatsHostname = ".1.3.6.1.4.1.12356.101.13.2.1.1.11"
	fgOIDHAStatsSync     = ".1.3.6.1.4.1.12356.101.13.2.1.1.12"
	fgOIDHAStatsMaster   = ".1.3.6.1.4.1.12356.101.13.2.1.1.16"

	// --- Security stats (Part 4) ---
	// Antivirus (default VDOM index .1)
	fgOIDAVDetected     = ".1.3.6.1.4.1.12356.101.8.2.1.1.1.1"
	fgOIDAVBlocked      = ".1.3.6.1.4.1.12356.101.8.2.1.1.2.1"
	fgOIDAVHTTPDetected = ".1.3.6.1.4.1.12356.101.8.2.1.1.3.1"
	fgOIDAVHTTPBlocked  = ".1.3.6.1.4.1.12356.101.8.2.1.1.4.1"
	fgOIDAVSMTPDetected = ".1.3.6.1.4.1.12356.101.8.2.1.1.5.1"
	fgOIDAVSMTPBlocked  = ".1.3.6.1.4.1.12356.101.8.2.1.1.6.1"
	// IPS (default VDOM index .1)
	fgOIDIPSDetected = ".1.3.6.1.4.1.12356.101.9.2.1.1.1.1"
	fgOIDIPSBlocked  = ".1.3.6.1.4.1.12356.101.9.2.1.1.2.1"
	fgOIDIPSCritical = ".1.3.6.1.4.1.12356.101.9.2.1.1.3.1"
	fgOIDIPSHigh     = ".1.3.6.1.4.1.12356.101.9.2.1.1.4.1"
	fgOIDIPSMedium   = ".1.3.6.1.4.1.12356.101.9.2.1.1.5.1"
	fgOIDIPSLow      = ".1.3.6.1.4.1.12356.101.9.2.1.1.6.1"
	fgOIDIPSInfo     = ".1.3.6.1.4.1.12356.101.9.2.1.1.7.1"
	// Web Filter (default VDOM index .1)
	fgOIDWFHTTPBlocked  = ".1.3.6.1.4.1.12356.101.10.1.2.1.1.1.1"
	fgOIDWFHTTPSBlocked = ".1.3.6.1.4.1.12356.101.10.1.2.1.1.2.1"
	fgOIDWFURLBlocked   = ".1.3.6.1.4.1.12356.101.10.1.2.1.1.3.1"

	// --- SD-WAN health check (Part 5) ---
	fgBaseOIDSDWANHealth     = ".1.3.6.1.4.1.12356.101.4.9"
	fgOIDSDWANHealthName     = ".1.3.6.1.4.1.12356.101.4.9.2"
	fgOIDSDWANHealthState    = ".1.3.6.1.4.1.12356.101.4.9.4"
	fgOIDSDWANHealthLatency  = ".1.3.6.1.4.1.12356.101.4.9.5"
	fgOIDSDWANHealthPktSend  = ".1.3.6.1.4.1.12356.101.4.9.7"
	fgOIDSDWANHealthPktRecv  = ".1.3.6.1.4.1.12356.101.4.9.8"
	fgOIDSDWANHealthIfName   = ".1.3.6.1.4.1.12356.101.4.9.14"

	// --- License/contract table (Part 6) ---
	fgBaseOIDLicense     = ".1.3.6.1.4.1.12356.101.4.6.3.1.1"
	fgOIDLicenseDesc     = ".1.3.6.1.4.1.12356.101.4.6.3.1.1.1"
	fgOIDLicenseExpiry   = ".1.3.6.1.4.1.12356.101.4.6.3.1.1.2"

	// --- Traps ---
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
		fgOIDLowMemUsage,
		fgOIDLowMemCap,
		fgOIDSesRate1,
		fgOIDSesRate10,
		fgOIDSesRate30,
		fgOIDSesRate60,
		fgOIDSes6Count,
		fgOIDVersionAv,
		fgOIDVersionIps,
		fgOIDSSLVPNUsers,
		fgOIDSSLVPNActive,
	}
}

func (f *FortiGateProfile) ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus {
	status := &relay.SystemStatus{Timestamp: time.Now()}
	var rawDiskMB, rawDiskCapMB int64
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
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
			rawDiskMB = gosnmp.ToBigInt(pdu.Value).Int64()
		case fgOIDSystemDiskCap:
			rawDiskCapMB = gosnmp.ToBigInt(pdu.Value).Int64()
		case fgOIDSystemSessions:
			status.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSystemUptime:
			status.Uptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		case fgOIDLowMemUsage:
			status.LowMemUsage = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDLowMemCap:
			status.LowMemCap = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSesRate1:
			status.SessionRate1 = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSesRate10:
			status.SessionRate10 = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSesRate30:
			status.SessionRate30 = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSesRate60:
			status.SessionRate60 = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSes6Count:
			status.SessionCount6 = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDVersionAv:
			status.AVVersion = safeString(pdu.Value)
		case fgOIDVersionIps:
			status.IPSVersion = safeString(pdu.Value)
		case fgOIDSSLVPNUsers:
			status.SSLVPNUsers = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDSSLVPNActive:
			status.SSLVPNTunnels = int(gosnmp.ToBigInt(pdu.Value).Int64())
		}
	}
	// fgSysDiskUsage/fgSysDiskCapacity are in MB — compute percentage
	if rawDiskCapMB > 0 {
		status.DiskUsage = float64(rawDiskMB) / float64(rawDiskCapMB) * 100
	}
	status.DiskTotal = uint64(rawDiskCapMB)
	return status
}

func (f *FortiGateProfile) VPNBaseOID() string { return fgBaseOIDVPNTunnel }

func (f *FortiGateProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	tunnelMap := make(map[int]*relay.VPNStatus)
	// Temporary storage for Phase 2 subnet selectors (source=local, dest=remote)
	srcBeginIPs := make(map[int]string)
	srcEndIPs := make(map[int]string)
	dstBeginIPs := make(map[int]string)
	dstEndIPs := make(map[int]string)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDVPNTunnelPhase1Name+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelPhase1Name)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.Phase1Name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNTunnelName+".") {
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
		} else if strings.HasPrefix(name, fgOIDVPNTunnelSrcBeginIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelSrcBeginIP)
			if idx >= 0 {
				srcBeginIPs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelSrcEndIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelSrcEndIP)
			if idx >= 0 {
				srcEndIPs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelDstBeginIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelDstBeginIP)
			if idx >= 0 {
				dstBeginIPs[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNTunnelDstEndIP+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelDstEndIP)
			if idx >= 0 {
				dstEndIPs[idx] = safeString(pdu.Value)
			}
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
		} else if strings.HasPrefix(name, fgOIDVPNTunnelUpTime+".") {
			idx := getIndexFromOID(name, fgOIDVPNTunnelUpTime)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelUptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	result := make([]relay.VPNStatus, 0, len(tunnelMap))
	for idx, t := range tunnelMap {
		t.Timestamp = now
		t.TunnelType = "ipsec"
		// Build Local Subnet (Phase 2 source selector)
		srcBegin := srcBeginIPs[idx]
		srcEnd := srcEndIPs[idx]
		if srcBegin != "" && srcEnd != "" && srcBegin != srcEnd {
			t.LocalSubnet = srcBegin + " - " + srcEnd
		} else if srcBegin != "" {
			t.LocalSubnet = srcBegin
		}
		// Build Remote Subnet (Phase 2 destination selector)
		dstBegin := dstBeginIPs[idx]
		dstEnd := dstEndIPs[idx]
		if dstBegin != "" && dstEnd != "" && dstBegin != dstEnd {
			t.RemoteSubnet = dstBegin + " - " + dstEnd
		} else if dstBegin != "" {
			t.RemoteSubnet = dstBegin
		}
		result = append(result, *t)
	}
	return result
}

// buildCIDR combines an IP address and subnet mask into CIDR notation (e.g., "10.0.0.0/24").
func buildCIDR(addr, mask string) string {
	if addr == "" {
		return ""
	}
	// Wildcard selector: 0.0.0.0/0.0.0.0 → "0.0.0.0/0" (Phase 2 "any" selector)
	if addr == "0.0.0.0" {
		if mask == "" || mask == "0.0.0.0" {
			return "0.0.0.0/0"
		}
		return ""
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if mask == "" || mask == "0.0.0.0" {
		return addr
	}
	m := net.ParseIP(mask)
	if m == nil {
		return addr
	}
	ones, _ := net.IPMask(m.To4()).Size()
	return fmt.Sprintf("%s/%d", addr, ones)
}

func (f *FortiGateProfile) DialupVPNBaseOID() string { return fgBaseOIDVPNDialup }

func (f *FortiGateProfile) ParseDialupVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	tunnelMap := make(map[int]*relay.VPNStatus)
	srcBegin := make(map[int]string)
	srcEnd := make(map[int]string)
	dstBegin := make(map[int]string)
	dstEnd := make(map[int]string)

	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDVPNDialupGateway+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupGateway)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.RemoteIP = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDVPNDialupLifetime+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupLifetime)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelUptime = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNDialupSrcBegin+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupSrcBegin)
			if idx >= 0 {
				srcBegin[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNDialupSrcEnd+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupSrcEnd)
			if idx >= 0 {
				srcEnd[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNDialupDstBegin+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupDstBegin)
			if idx >= 0 {
				dstBegin[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNDialupDstEnd+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupDstEnd)
			if idx >= 0 {
				dstEnd[idx] = safeString(pdu.Value)
			}
		} else if strings.HasPrefix(name, fgOIDVPNDialupInOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupInOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDVPNDialupOutOctets+".") {
			idx := getIndexFromOID(name, fgOIDVPNDialupOutOctets)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	result := make([]relay.VPNStatus, 0, len(tunnelMap))
	for idx, t := range tunnelMap {
		t.Timestamp = now
		// Presence in the dialup table means the tunnel is active —
		// entries disappear when the peer disconnects.
		t.Status = "up"
		t.State = "active"
		t.TunnelType = "ipsec-dialup"
		// Dialup table uses IP range selectors (begin/end) instead of addr/mask.
		t.LocalSubnet = rangeToCIDR(srcBegin[idx], srcEnd[idx])
		t.RemoteSubnet = rangeToCIDR(dstBegin[idx], dstEnd[idx])
		// The gen1 dialup table has no tunnel name column; use remote gateway IP.
		if t.TunnelName == "" {
			if t.RemoteIP != "" {
				t.TunnelName = "dialup-" + t.RemoteIP
			} else {
				t.TunnelName = "dialup-unknown"
			}
		}
		result = append(result, *t)
	}
	return result
}

// rangeToCIDR converts an IP range (begin, end) to CIDR notation.
// FortiGate dialup VPN table uses range selectors instead of addr/mask.
// e.g. (10.0.0.0, 10.0.0.255) → "10.0.0.0/24"
func rangeToCIDR(begin, end string) string {
	if begin == "" {
		return ""
	}
	// Wildcard: 0.0.0.0 → 0.0.0.0 means "any"
	if begin == "0.0.0.0" {
		return "0.0.0.0/0"
	}
	bIP := net.ParseIP(begin).To4()
	if bIP == nil {
		return begin
	}
	if end == "" || end == begin {
		return begin + "/32"
	}
	eIP := net.ParseIP(end).To4()
	if eIP == nil {
		return begin
	}
	// XOR begin and end to find host portion
	xor := make([]byte, 4)
	for i := 0; i < 4; i++ {
		xor[i] = bIP[i] ^ eIP[i]
	}
	// Valid CIDR range: XOR should be 0...0 then 1...1 (contiguous host bits)
	// Count prefix bits (leading zeros in XOR)
	prefixLen := 0
	for i := 0; i < 4; i++ {
		for bit := 7; bit >= 0; bit-- {
			if xor[i]&(1<<uint(bit)) == 0 {
				prefixLen++
			} else {
				// Verify remaining bits are all 1s
				for j := i; j < 4; j++ {
					startBit := 0
					if j == i {
						startBit = bit
					} else {
						startBit = 7
					}
					for b := startBit; b >= 0; b-- {
						if xor[j]&(1<<uint(b)) == 0 {
							// Not a clean CIDR — return as range
							return begin + "-" + end
						}
					}
				}
				return fmt.Sprintf("%s/%d", begin, prefixLen)
			}
		}
	}
	return fmt.Sprintf("%s/%d", begin, prefixLen)
}

func (f *FortiGateProfile) HWSensorBaseOID() string { return fgOIDHWSensorEntry }

func (f *FortiGateProfile) ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor {
	sensorMap := make(map[int]*relay.HardwareSensor)
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
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
		inferSensorUnit(sensor)
		sensors = append(sensors, *sensor)
	}
	return sensors
}

// inferSensorUnit sets Type and Unit based on FortiGate sensor name patterns.
func inferSensorUnit(s *relay.HardwareSensor) {
	lower := strings.ToLower(s.Name)
	switch {
	case strings.Contains(lower, "temp") || strings.Contains(lower, "dts") || strings.Contains(lower, "lm75"):
		s.Type = "temperature"
		s.Unit = "°C"
	case strings.Contains(lower, "fan"):
		s.Type = "fan"
		s.Unit = "RPM"
	case strings.Contains(lower, "vcc") || strings.Contains(lower, "vdd") ||
		strings.Contains(lower, "+1.") || strings.Contains(lower, "+2.") ||
		strings.Contains(lower, "+3.") || strings.Contains(lower, "+5.") ||
		strings.Contains(lower, "+12") || strings.Contains(lower, "volt"):
		s.Type = "voltage"
		s.Unit = "mV"
	case strings.Contains(lower, "ps") && strings.Contains(lower, "status"):
		s.Type = "power"
		s.Unit = ""
	}
}

func (f *FortiGateProfile) ProcessorBaseOID() string { return fgBaseOIDProcessor }

func (f *FortiGateProfile) ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats {
	now := time.Now()
	var result []relay.ProcessorStats
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		if strings.HasPrefix(pdu.Name, fgOIDProcessorUsage+".") {
			idx := getIndexFromOID(pdu.Name, fgOIDProcessorUsage)
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

// --- SSL-VPN Provider (Part 2) ---

func (f *FortiGateProfile) SSLVPNBaseOID() string { return fgBaseOIDSSLVPNTunnel }

func (f *FortiGateProfile) ParseSSLVPNTunnels(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	tunnelMap := make(map[int]*relay.VPNStatus)
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDSSLVPNTunnelUserName+".") {
			idx := getIndexFromOID(name, fgOIDSSLVPNTunnelUserName)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.TunnelName = "sslvpn-" + safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDSSLVPNTunnelSrcIP+".") {
			idx := getIndexFromOID(name, fgOIDSSLVPNTunnelSrcIP)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.RemoteIP = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDSSLVPNTunnelBytesIn+".") {
			idx := getIndexFromOID(name, fgOIDSSLVPNTunnelBytesIn)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDSSLVPNTunnelBytesOut+".") {
			idx := getIndexFromOID(name, fgOIDSSLVPNTunnelBytesOut)
			if idx < 0 {
				continue
			}
			t := getOrCreateVPN(tunnelMap, idx)
			t.BytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	result := make([]relay.VPNStatus, 0, len(tunnelMap))
	for _, t := range tunnelMap {
		t.Timestamp = now
		t.TunnelType = "sslvpn"
		t.Status = "up"
		t.State = "active"
		result = append(result, *t)
	}
	return result
}

// --- HA Provider (Part 3) ---

func (f *FortiGateProfile) HAScalarOIDs() []string {
	return []string{fgOIDHASystemMode, fgOIDHAGroupId, fgOIDHAGroupName}
}

func (f *FortiGateProfile) HAStatsBaseOID() string { return fgBaseOIDHAStats }

func (f *FortiGateProfile) ParseHAStatus(scalars []gosnmp.SnmpPDU, members []gosnmp.SnmpPDU) []relay.HAStatus {
	var systemMode string
	var groupID int
	var groupName string

	for _, pdu := range scalars {
		if !isValidPDU(pdu) {
			continue
		}
		switch pdu.Name {
		case fgOIDHASystemMode:
			mode := gosnmp.ToBigInt(pdu.Value).Int64()
			switch mode {
			case 1:
				systemMode = "standalone"
			case 2:
				systemMode = "activeActive"
			case 3:
				systemMode = "activePassive"
			default:
				systemMode = "standalone"
			}
		case fgOIDHAGroupId:
			groupID = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case fgOIDHAGroupName:
			groupName = safeString(pdu.Value)
		}
	}

	if systemMode == "standalone" {
		return nil
	}

	memberMap := make(map[int]*relay.HAStatus)
	for _, pdu := range members {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDHAStatsSerial+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsSerial)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.MemberSerial = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDHAStatsCPU+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsCPU)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.CPUUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, fgOIDHAStatsMem+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsMem)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.MemoryUsage = float64(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, fgOIDHAStatsNet+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsNet)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.NetworkUsage = int(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, fgOIDHAStatsSes+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsSes)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.SessionCount = int(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, fgOIDHAStatsPkt+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsPkt)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.PacketCount = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDHAStatsByte+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsByte)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.ByteCount = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDHAStatsHostname+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsHostname)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.MemberHostname = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDHAStatsSync+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsSync)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			syncVal := gosnmp.ToBigInt(pdu.Value).Int64()
			if syncVal == 1 {
				m.SyncStatus = "in-sync"
			} else {
				m.SyncStatus = "out-of-sync"
			}
		} else if strings.HasPrefix(name, fgOIDHAStatsMaster+".") {
			idx := getIndexFromOID(name, fgOIDHAStatsMaster)
			if idx < 0 {
				continue
			}
			m := getOrCreateHA(memberMap, idx)
			m.MasterSerial = safeString(pdu.Value)
		}
	}

	now := time.Now()
	result := make([]relay.HAStatus, 0, len(memberMap))
	for idx, m := range memberMap {
		m.Timestamp = now
		m.SystemMode = systemMode
		m.GroupID = groupID
		m.GroupName = groupName
		m.MemberIndex = idx
		result = append(result, *m)
	}
	return result
}

func getOrCreateHA(m map[int]*relay.HAStatus, index int) *relay.HAStatus {
	if v, exists := m[index]; exists {
		return v
	}
	v := &relay.HAStatus{}
	m[index] = v
	return v
}

// --- Security Stats Provider (Part 4) ---

func (f *FortiGateProfile) SecurityStatsOIDs() []string {
	return []string{
		fgOIDAVDetected, fgOIDAVBlocked,
		fgOIDAVHTTPDetected, fgOIDAVHTTPBlocked,
		fgOIDAVSMTPDetected, fgOIDAVSMTPBlocked,
		fgOIDIPSDetected, fgOIDIPSBlocked,
		fgOIDIPSCritical, fgOIDIPSHigh, fgOIDIPSMedium, fgOIDIPSLow, fgOIDIPSInfo,
		fgOIDWFHTTPBlocked, fgOIDWFHTTPSBlocked, fgOIDWFURLBlocked,
	}
}

func (f *FortiGateProfile) ParseSecurityStats(pdus []gosnmp.SnmpPDU) *relay.SecurityStats {
	stats := &relay.SecurityStats{Timestamp: time.Now()}
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		v := uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		switch pdu.Name {
		case fgOIDAVDetected:
			stats.AVDetected = v
		case fgOIDAVBlocked:
			stats.AVBlocked = v
		case fgOIDAVHTTPDetected:
			stats.AVHTTPDetected = v
		case fgOIDAVHTTPBlocked:
			stats.AVHTTPBlocked = v
		case fgOIDAVSMTPDetected:
			stats.AVSMTPDetected = v
		case fgOIDAVSMTPBlocked:
			stats.AVSMTPBlocked = v
		case fgOIDIPSDetected:
			stats.IPSDetected = v
		case fgOIDIPSBlocked:
			stats.IPSBlocked = v
		case fgOIDIPSCritical:
			stats.IPSCritical = v
		case fgOIDIPSHigh:
			stats.IPSHigh = v
		case fgOIDIPSMedium:
			stats.IPSMedium = v
		case fgOIDIPSLow:
			stats.IPSLow = v
		case fgOIDIPSInfo:
			stats.IPSInfo = v
		case fgOIDWFHTTPBlocked:
			stats.WFHTTPBlocked = v
		case fgOIDWFHTTPSBlocked:
			stats.WFHTTPSBlocked = v
		case fgOIDWFURLBlocked:
			stats.WFURLBlocked = v
		}
	}
	return stats
}

// --- SD-WAN Provider (Part 5) ---

func (f *FortiGateProfile) SDWANHealthBaseOID() string { return fgBaseOIDSDWANHealth }

func (f *FortiGateProfile) ParseSDWANHealth(pdus []gosnmp.SnmpPDU) []relay.SDWANHealth {
	healthMap := make(map[int]*relay.SDWANHealth)
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDSDWANHealthName+".") {
			idx := getIndexFromOID(name, fgOIDSDWANHealthName)
			if idx < 0 {
				continue
			}
			h := getOrCreateSDWAN(healthMap, idx)
			h.Name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDSDWANHealthState+".") {
			idx := getIndexFromOID(name, fgOIDSDWANHealthState)
			if idx < 0 {
				continue
			}
			h := getOrCreateSDWAN(healthMap, idx)
			stateVal := gosnmp.ToBigInt(pdu.Value).Int64()
			if stateVal == 0 {
				h.State = "alive"
			} else {
				h.State = "dead"
			}
		} else if strings.HasPrefix(name, fgOIDSDWANHealthLatency+".") {
			idx := getIndexFromOID(name, fgOIDSDWANHealthLatency)
			if idx < 0 {
				continue
			}
			h := getOrCreateSDWAN(healthMap, idx)
			h.Latency = parseStringFloat(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDSDWANHealthPktSend+".") {
			idx := getIndexFromOID(name, fgOIDSDWANHealthPktSend)
			if idx < 0 {
				continue
			}
			h := getOrCreateSDWAN(healthMap, idx)
			h.PacketSend = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDSDWANHealthPktRecv+".") {
			idx := getIndexFromOID(name, fgOIDSDWANHealthPktRecv)
			if idx < 0 {
				continue
			}
			h := getOrCreateSDWAN(healthMap, idx)
			h.PacketRecv = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, fgOIDSDWANHealthIfName+".") {
			idx := getIndexFromOID(name, fgOIDSDWANHealthIfName)
			if idx < 0 {
				continue
			}
			h := getOrCreateSDWAN(healthMap, idx)
			h.Interface = safeString(pdu.Value)
		}
	}

	now := time.Now()
	result := make([]relay.SDWANHealth, 0, len(healthMap))
	for _, h := range healthMap {
		h.Timestamp = now
		// Compute packet loss from send/recv
		if h.PacketSend > 0 {
			lost := h.PacketSend - h.PacketRecv
			h.PacketLoss = float64(lost) / float64(h.PacketSend) * 100
		}
		result = append(result, *h)
	}
	return result
}

func getOrCreateSDWAN(m map[int]*relay.SDWANHealth, index int) *relay.SDWANHealth {
	if v, exists := m[index]; exists {
		return v
	}
	v := &relay.SDWANHealth{}
	m[index] = v
	return v
}

// parseStringFloat tries to parse an SNMP value as a float64.
// FortiGate returns some metrics as OctetString containing a decimal number.
func parseStringFloat(v interface{}) float64 {
	s := safeString(v)
	if s != "" {
		var f float64
		if _, err := fmt.Sscanf(s, "%f", &f); err == nil {
			return f
		}
	}
	// Fall back to integer conversion
	return float64(gosnmp.ToBigInt(v).Int64())
}

// --- License Provider (Part 6) ---

func (f *FortiGateProfile) LicenseBaseOID() string { return fgBaseOIDLicense }

func (f *FortiGateProfile) ParseLicenseInfo(pdus []gosnmp.SnmpPDU) []relay.LicenseInfo {
	licenseMap := make(map[int]*relay.LicenseInfo)
	for _, pdu := range pdus {
		if !isValidPDU(pdu) {
			continue
		}
		name := pdu.Name
		if strings.HasPrefix(name, fgOIDLicenseDesc+".") {
			idx := getIndexFromOID(name, fgOIDLicenseDesc)
			if idx < 0 {
				continue
			}
			l := getOrCreateLicense(licenseMap, idx)
			l.Description = safeString(pdu.Value)
		} else if strings.HasPrefix(name, fgOIDLicenseExpiry+".") {
			idx := getIndexFromOID(name, fgOIDLicenseExpiry)
			if idx < 0 {
				continue
			}
			l := getOrCreateLicense(licenseMap, idx)
			l.ExpiryDate = safeString(pdu.Value)
		}
	}

	now := time.Now()
	result := make([]relay.LicenseInfo, 0, len(licenseMap))
	for _, l := range licenseMap {
		l.Timestamp = now
		result = append(result, *l)
	}
	return result
}

func getOrCreateLicense(m map[int]*relay.LicenseInfo, index int) *relay.LicenseInfo {
	if v, exists := m[index]; exists {
		return v
	}
	v := &relay.LicenseInfo{}
	m[index] = v
	return v
}
