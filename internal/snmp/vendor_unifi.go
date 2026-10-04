package snmp

import (
	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// UniFiProfile is the SNMP profile for Ubiquiti UniFi gateways (UDM / UXG /
// UCG lines) and USW switches — untested on real hardware, built from vendor
// docs. The UniFi Network app exposes SNMPv2-MIB, IF-MIB and HOST-RESOURCES
// (CPU / memory on Gen2 switches); the vendor UI-MIB is thin and not polled.
// That is the standards-only GenericProfile surface, so this profile embeds
// it under its own name: a device tagged `unifi` polls the same MIB-II scalars
// and interface tables, keeps its vendor for rules, capability profiles and
// the device form, and gains enterprise OIDs here the day a UI-MIB mapping is
// verified against real hardware.
//
// The one addition over generic is VPN: UniFi OS gateways are Linux, and
// their WireGuard (`wg*`), OpenVPN (`tun*`) and route-based IPsec (`vti*`)
// tunnels are real interfaces in IF-MIB with oper status and octet counters,
// so the Linux name/ifType matcher shared with Firewalla applies.
type UniFiProfile struct {
	GenericProfile
}

func init() {
	RegisterVendor(&UniFiProfile{})
}

func (u *UniFiProfile) Name() string { return "unifi" }

// VPN: detected via IF-MIB interface name patterns (see vendor_linux_vpn.go).

func (u *UniFiProfile) VPNBaseOID() string { return BaseOIDInterface }

func (u *UniFiProfile) ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus {
	return parseLinuxVPNFromInterfaces(pdus)
}
