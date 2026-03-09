package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// linuxIfData holds interface data extracted from IF-MIB for VPN detection.
type linuxIfData struct {
	name     string
	ifType   int
	operUp   bool
	bytesIn  uint64
	bytesOut uint64
}

// parseLinuxVPNFromInterfaces extracts VPN tunnel status from IF-MIB PDUs by
// matching interface name and type patterns used on Linux-based firewalls
// (Firewalla, etc.):
//
//   - wg*       → WireGuard interfaces
//   - tun*      → OpenVPN TUN-mode tunnels (ifType 53/propVirtual on Linux)
//   - tap*      → OpenVPN TAP-mode tunnels
//   - vti*      → IPSec VTI (route-based) interfaces
//
// On Linux, OpenVPN uses generic "tun0/tun1" names. We use ifType to
// avoid false positives: only ifType 53 (propVirtual) or 131 (tunnel)
// interfaces named "tun*" are classified as VPN.
func parseLinuxVPNFromInterfaces(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	interfaces := make(map[int]*linuxIfData)

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
			ifd := getOrCreateLinuxIf(interfaces, idx)
			ifd.name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, OIDIfType+".") {
			idx := getIndexFromOID(name, OIDIfType)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateLinuxIf(interfaces, idx)
			ifd.ifType = int(gosnmp.ToBigInt(pdu.Value).Int64())
		} else if strings.HasPrefix(name, OIDIfOperStatus+".") {
			idx := getIndexFromOID(name, OIDIfOperStatus)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateLinuxIf(interfaces, idx)
			ifd.operUp = gosnmp.ToBigInt(pdu.Value).Int64() == 1
		} else if strings.HasPrefix(name, OIDIfInOctets+".") {
			idx := getIndexFromOID(name, OIDIfInOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateLinuxIf(interfaces, idx)
			ifd.bytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDIfOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfOutOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateLinuxIf(interfaces, idx)
			ifd.bytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	var result []relay.VPNStatus

	for _, ifd := range interfaces {
		tunnelType, tunnelName := classifyLinuxVPNInterface(ifd.name, ifd.ifType)
		if tunnelType == "" {
			continue
		}

		status := "down"
		state := "inactive"
		if ifd.operUp {
			status = "up"
			state = "active"
		}

		result = append(result, relay.VPNStatus{
			Timestamp:  now,
			TunnelName: tunnelName,
			TunnelType: tunnelType,
			Status:     status,
			State:      state,
			BytesIn:    ifd.bytesIn,
			BytesOut:   ifd.bytesOut,
		})
	}

	return result
}

// classifyLinuxVPNInterface returns (tunnelType, tunnelName) if the interface
// matches a known Linux VPN pattern. Uses ifType to avoid false positives
// for ambiguous names like "tun0".
func classifyLinuxVPNInterface(ifName string, ifType int) (string, string) {
	lower := strings.ToLower(ifName)

	// WireGuard: wg0, wg1
	if strings.HasPrefix(lower, "wg") {
		return "wireguard", ifName
	}

	// OpenVPN TUN-mode: tun0, tun1
	// ifType 53 (propVirtual) or 131 (tunnel) are point-to-point tunnel interfaces
	if strings.HasPrefix(lower, "tun") {
		if ifType == 53 || ifType == 131 || ifType == 1 {
			return "openvpn", ifName
		}
	}

	// OpenVPN TAP-mode: tap0, tap1
	if strings.HasPrefix(lower, "tap") {
		return "openvpn", ifName
	}

	// IPSec VTI (route-based): vti0, vti1
	if strings.HasPrefix(lower, "vti") {
		return "ipsec", ifName
	}

	return "", ""
}

func getOrCreateLinuxIf(m map[int]*linuxIfData, idx int) *linuxIfData {
	if v, ok := m[idx]; ok {
		return v
	}
	v := &linuxIfData{}
	m[idx] = v
	return v
}
