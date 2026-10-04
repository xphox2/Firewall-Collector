package snmp

// MerakiProfile is the SNMP profile for Cisco Meraki MX / Z / MS devices —
// untested on real hardware, built from vendor docs. Meraki has two SNMP
// flavours: cloud SNMP (polling the Dashboard with MERAKI-CLOUD-CONTROLLER-MIB,
// which cannot be polled from the devices) and device-local SNMP, which is
// SNMPv2-MIB + IF-MIB on the appliance's LAN IP. The collector polls the
// device, so only the local flavour applies, and that is the standards-only
// GenericProfile surface: this profile embeds it under its own name. A device
// tagged `meraki` polls the MIB-II scalars and interface tables, keeps its
// vendor for rules, capability profiles and the device form, and gains a
// cloud-MIB mapping here if one is ever verified.
type MerakiProfile struct {
	GenericProfile
}

func init() {
	RegisterVendor(&MerakiProfile{})
}

func (m *MerakiProfile) Name() string { return "meraki" }
