package snmp

import (
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// TestFirewalla_HWSensorBaseOID_CoversFanSubtree is the AUDIT-298 regression:
// the sensor walk base OID must be the common lm-sensors parent so a single
// WalkAll covers BOTH the temperature (.2.1) and fan (.3.1) subtrees. Returning
// the temp-only subtree left the fan parse branches dead.
func TestFirewalla_HWSensorBaseOID_CoversFanSubtree(t *testing.T) {
	f := &FirewallaProfile{}
	base := f.HWSensorBaseOID()
	if base != fwBaseOIDLmSensor {
		t.Fatalf("HWSensorBaseOID = %q; want the common parent %q", base, fwBaseOIDLmSensor)
	}
	// The fan subtree must sit UNDER the walked base, else the walk can't reach it.
	if !strings.HasPrefix(fwOIDLmFanSensorDescr, base+".") {
		t.Errorf("fan subtree %q is not under the walk base %q", fwOIDLmFanSensorDescr, base)
	}
	if !strings.HasPrefix(fwOIDLmTempSensorDescr, base+".") {
		t.Errorf("temp subtree %q is not under the walk base %q", fwOIDLmTempSensorDescr, base)
	}
}

// TestFirewalla_ParseHardwareSensors_TempAndFan verifies both sensor families
// are parsed when the (now correctly-scoped) walk returns temp AND fan PDUs.
func TestFirewalla_ParseHardwareSensors_TempAndFan(t *testing.T) {
	f := &FirewallaProfile{}
	pdus := []gosnmp.SnmpPDU{
		// Temperature sensor idx 1: 45.0 °C (value is milli-°C).
		{Name: fwOIDLmTempSensorDescr + ".1", Type: gosnmp.OctetString, Value: []byte("Core 0")},
		{Name: fwOIDLmTempSensorValue + ".1", Type: gosnmp.Integer, Value: 45000},
		// Fan sensor idx 1: 3200 RPM (different subtree, previously never walked).
		{Name: fwOIDLmFanSensorDescr + ".1", Type: gosnmp.OctetString, Value: []byte("Chassis Fan")},
		{Name: fwOIDLmFanSensorValue + ".1", Type: gosnmp.Integer, Value: 3200},
	}

	byType := map[string]float64{}
	for _, s := range f.ParseHardwareSensors(pdus) {
		byType[s.Type] = s.Value
	}

	if len(byType) != 2 {
		t.Fatalf("got %d sensor types; want temperature + fan: %v", len(byType), byType)
	}
	if got := byType["temperature"]; got != 45.0 {
		t.Errorf("temperature value = %v; want 45.0", got)
	}
	if got := byType["fan"]; got != 3200 {
		t.Errorf("fan value = %v; want 3200", got)
	}
}
