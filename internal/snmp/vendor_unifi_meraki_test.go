package snmp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// TestUniFiMeraki_GenericSurface: both profiles (1.3.49, built from vendor
// docs and untested on real hardware) are registered under their own name and
// poll the generic, standards-only system surface — the same system OIDs, no
// sensor walk, no enterprise trap OIDs, none of the optional provider
// interfaces. The day either grows a verified vendor-specific OID this test is
// updated with it; until then it stops a copy-paste of an enterprise OID from
// another profile.
func TestUniFiMeraki_GenericSurface(t *testing.T) {
	generic := GetVendorProfile("generic")
	if generic == nil {
		t.Fatal("generic profile not registered")
	}
	for _, name := range []string{"unifi", "meraki"} {
		p := GetVendorProfile(name)
		if p == nil {
			t.Errorf("%s: not registered", name)
			continue
		}
		if p.Name() != name {
			t.Errorf("%s: Name() = %q", name, p.Name())
		}
		if !reflect.DeepEqual(p.SystemOIDs(), generic.SystemOIDs()) {
			t.Errorf("%s: SystemOIDs = %v, want the generic set %v", name, p.SystemOIDs(), generic.SystemOIDs())
		}
		for _, oid := range append(p.SystemOIDs(), p.ProcessorBaseOID(), p.VPNBaseOID()) {
			if oid != "" && !strings.HasPrefix(oid, ".1.3.6.1.2.1.") {
				t.Errorf("%s: OID %s is not under mib-2 — enterprise OIDs need hardware verification first", name, oid)
			}
		}
		if p.HWSensorBaseOID() != "" {
			t.Errorf("%s: HWSensorBaseOID = %q, want empty", name, p.HWSensorBaseOID())
		}
		if p.ProcessorBaseOID() != generic.ProcessorBaseOID() {
			t.Errorf("%s: ProcessorBaseOID = %q, want %q", name, p.ProcessorBaseOID(), generic.ProcessorBaseOID())
		}
		if len(p.TrapOIDs()) != 0 {
			t.Errorf("%s: TrapOIDs = %v, want none", name, p.TrapOIDs())
		}
		for iface, ok := range map[string]bool{
			"HAProvider":            implementsHA(p),
			"SecurityStatsProvider": implementsSecurityStats(p),
			"DialupVPNProvider":     implementsDialupVPN(p),
			"SSLVPNProvider":        implementsSSLVPN(p),
			"SDWANProvider":         implementsSDWAN(p),
			"LicenseProvider":       implementsLicense(p),
		} {
			if ok {
				t.Errorf("%s must not implement %s", name, iface)
			}
		}
		// resolveVendor must hand back the profile, not fall through to
		// generic: the vendor name is what rules and capability profiles key on.
		if got := (&SNMPClient{}).resolveVendor(name).Name(); got != name {
			t.Errorf("resolveVendor(%s) = %q", name, got)
		}
	}
}

func implementsHA(p VendorProfile) bool            { _, ok := p.(HAProvider); return ok }
func implementsSecurityStats(p VendorProfile) bool { _, ok := p.(SecurityStatsProvider); return ok }
func implementsDialupVPN(p VendorProfile) bool     { _, ok := p.(DialupVPNProvider); return ok }
func implementsSSLVPN(p VendorProfile) bool        { _, ok := p.(SSLVPNProvider); return ok }
func implementsSDWAN(p VendorProfile) bool         { _, ok := p.(SDWANProvider); return ok }
func implementsLicense(p VendorProfile) bool       { _, ok := p.(LicenseProvider); return ok }

// TestMeraki_NoVPNWalk: device-local Meraki SNMP has no tunnel table and the
// MX's AutoVPN peers are not IF-MIB interfaces, so the profile keeps the
// generic "unsupported" signal rather than walking ifTable for nothing.
func TestMeraki_NoVPNWalk(t *testing.T) {
	p := GetVendorProfile("meraki")
	if p == nil {
		t.Fatal("meraki profile not registered")
	}
	if p.VPNBaseOID() != "" {
		t.Errorf("meraki VPNBaseOID = %q, want empty", p.VPNBaseOID())
	}
	if got := p.ParseVPNStatus(nil); got != nil {
		t.Errorf("meraki ParseVPNStatus(nil) = %v, want nil", got)
	}
}

// TestUniFi_VPNFromIFMIB: a UniFi gateway's VPN tunnels are Linux interfaces,
// so the profile walks IF-MIB and classifies `wg*` / `tun*` (ifType 53) /
// `vti*` names the way the Firewalla profile does. Synthetic PDUs: one
// WireGuard interface up with counters, one OpenVPN tun down, one LAN port
// that must not be reported as a tunnel.
func TestUniFi_VPNFromIFMIB(t *testing.T) {
	p := GetVendorProfile("unifi")
	if p == nil {
		t.Fatal("unifi profile not registered")
	}
	if p.VPNBaseOID() != BaseOIDInterface {
		t.Fatalf("unifi VPNBaseOID = %q, want the IF-MIB ifTable %q", p.VPNBaseOID(), BaseOIDInterface)
	}
	pdus := []gosnmp.SnmpPDU{
		{Name: OIDIfDescr + ".2", Type: gosnmp.OctetString, Value: []byte("eth0")},
		{Name: OIDIfType + ".2", Type: gosnmp.Integer, Value: 6},
		{Name: OIDIfOperStatus + ".2", Type: gosnmp.Integer, Value: 1},
		{Name: OIDIfDescr + ".7", Type: gosnmp.OctetString, Value: []byte("wgsrv1")},
		{Name: OIDIfType + ".7", Type: gosnmp.Integer, Value: 53},
		{Name: OIDIfOperStatus + ".7", Type: gosnmp.Integer, Value: 1},
		{Name: OIDIfInOctets + ".7", Type: gosnmp.Counter32, Value: uint(1500)},
		{Name: OIDIfOutOctets + ".7", Type: gosnmp.Counter32, Value: uint(2500)},
		{Name: OIDIfDescr + ".9", Type: gosnmp.OctetString, Value: []byte("tun0")},
		{Name: OIDIfType + ".9", Type: gosnmp.Integer, Value: 53},
		{Name: OIDIfOperStatus + ".9", Type: gosnmp.Integer, Value: 2},
	}
	got := p.ParseVPNStatus(pdus)
	byName := map[string]struct{ typ, status string }{}
	for _, v := range got {
		byName[v.TunnelName] = struct{ typ, status string }{v.TunnelType, v.Status}
	}
	if len(got) != 2 {
		t.Fatalf("ParseVPNStatus returned %d tunnels (%v), want 2 (wgsrv1, tun0)", len(got), byName)
	}
	if wg := byName["wgsrv1"]; wg.typ != "wireguard" || wg.status != "up" {
		t.Errorf("wgsrv1 = %+v, want wireguard/up", wg)
	}
	if tun := byName["tun0"]; tun.typ != "openvpn" || tun.status != "down" {
		t.Errorf("tun0 = %+v, want openvpn/down", tun)
	}
	for _, v := range got {
		if v.TunnelName == "wgsrv1" && (v.BytesIn != 1500 || v.BytesOut != 2500) {
			t.Errorf("wgsrv1 counters = %d/%d, want 1500/2500", v.BytesIn, v.BytesOut)
		}
	}
}
