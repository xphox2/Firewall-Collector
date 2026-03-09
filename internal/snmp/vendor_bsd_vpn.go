package snmp

import (
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// bsdIfData holds interface data extracted from IF-MIB for VPN detection.
type bsdIfData struct {
	name     string
	operUp   bool
	bytesIn  uint64
	bytesOut uint64
}

// parseBSDVPNFromInterfaces extracts VPN tunnel status from IF-MIB PDUs by
// matching interface name patterns used by pfSense and OPNsense:
//
//   - ovpns*  → OpenVPN server instances
//   - ovpnc*  → OpenVPN client instances
//   - wg*     → WireGuard interfaces
//   - tun_wg* → WireGuard interfaces (pfSense naming)
//   - ipsec*  → IPSec VTI (route-based) interfaces
//
// This works with pure SNMP — no firewall-side configuration required.
func parseBSDVPNFromInterfaces(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	interfaces := make(map[int]*bsdIfData)

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
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.name = safeString(pdu.Value)
		} else if strings.HasPrefix(name, OIDIfOperStatus+".") {
			idx := getIndexFromOID(name, OIDIfOperStatus)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.operUp = gosnmp.ToBigInt(pdu.Value).Int64() == 1
		} else if strings.HasPrefix(name, OIDIfInOctets+".") {
			idx := getIndexFromOID(name, OIDIfInOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.bytesIn = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		} else if strings.HasPrefix(name, OIDIfOutOctets+".") {
			idx := getIndexFromOID(name, OIDIfOutOctets)
			if idx < 0 {
				continue
			}
			ifd := getOrCreateBSDIf(interfaces, idx)
			ifd.bytesOut = uint64(gosnmp.ToBigInt(pdu.Value).Uint64())
		}
	}

	now := time.Now()
	var result []relay.VPNStatus

	for _, ifd := range interfaces {
		tunnelType, tunnelName := classifyBSDVPNInterface(ifd.name)
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

// classifyBSDVPNInterface returns (tunnelType, tunnelName) if the interface
// name matches a known VPN pattern, or ("", "") if not a VPN interface.
func classifyBSDVPNInterface(ifName string) (string, string) {
	lower := strings.ToLower(ifName)

	// OpenVPN server: ovpns1, ovpns2, etc.
	if strings.HasPrefix(lower, "ovpns") {
		return "openvpn-server", ifName
	}
	// OpenVPN client: ovpnc1, ovpnc2, etc.
	if strings.HasPrefix(lower, "ovpnc") {
		return "openvpn-client", ifName
	}
	// WireGuard: wg0, wg1, tun_wg0, tun_wg1
	if strings.HasPrefix(lower, "wg") || strings.HasPrefix(lower, "tun_wg") {
		return "wireguard", ifName
	}
	// IPSec VTI (route-based): ipsec0, ipsec1 (NOT enc0 which is aggregate)
	if strings.HasPrefix(lower, "ipsec") {
		return "ipsec", ifName
	}

	return "", ""
}

func getOrCreateBSDIf(m map[int]*bsdIfData, idx int) *bsdIfData {
	if v, ok := m[idx]; ok {
		return v
	}
	v := &bsdIfData{}
	m[idx] = v
	return v
}
