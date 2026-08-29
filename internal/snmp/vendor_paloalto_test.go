package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// TestPaloAltoVPN_UsesHC64BitOctets is the AUDIT-221 regression: when both the
// 32-bit ifTable octet counters and the 64-bit ifXTable HC counters are present
// for a tunnel interface, the parsed VPN byte totals must use the HC values.
// Before the fix GetVPNStatus never walked ifXTable, so the HC branch was dead
// and busy tunnels reported byte counts wrapped at 4 GiB.
func TestPaloAltoVPN_UsesHC64BitOctets(t *testing.T) {
	const idx = "7"
	// HC values that cannot be represented in 32 bits (> 4 GiB).
	const hcIn = uint64(9_000_000_000)
	const hcOut = uint64(12_000_000_000)

	// ifTable PDUs first, then ifXTable — the same merge order GetVPNStatus uses
	// so the HC assignment overwrites the 32-bit one.
	pdus := []gosnmp.SnmpPDU{
		{Name: OIDIfDescr + "." + idx, Type: gosnmp.OctetString, Value: []byte("tunnel.1")},
		{Name: OIDIfOperStatus + "." + idx, Type: gosnmp.Integer, Value: 1},
		{Name: OIDIfInOctets + "." + idx, Type: gosnmp.Counter32, Value: uint(704_982_704)},    // 32-bit wrapped remnant
		{Name: OIDIfOutOctets + "." + idx, Type: gosnmp.Counter32, Value: uint(3_115_098_112)}, // 32-bit wrapped remnant
		{Name: OIDIfHCInOctets + "." + idx, Type: gosnmp.Counter64, Value: hcIn},
		{Name: OIDIfHCOutOctets + "." + idx, Type: gosnmp.Counter64, Value: hcOut},
	}

	result := parsePaloAltoVPNFromInterfaces(pdus)
	if len(result) != 1 {
		t.Fatalf("got %d VPN statuses; want 1", len(result))
	}
	v := result[0]
	if v.BytesIn != hcIn {
		t.Errorf("BytesIn = %d; want the 64-bit HC value %d", v.BytesIn, hcIn)
	}
	if v.BytesOut != hcOut {
		t.Errorf("BytesOut = %d; want the 64-bit HC value %d", v.BytesOut, hcOut)
	}
	if v.Status != "up" {
		t.Errorf("Status = %q; want up", v.Status)
	}
}

// TestPaloAltoSensor_Status3ReportsAlarm is the AUDIT-302 regression: a
// nonoperational sensor (entPhySensorOperStatus = 3) must surface as an "alarm",
// not be silently dropped as if healthy. status 1 is normal; status 2
// (unavailable) is still dropped.
func TestPaloAltoSensor_Status3ReportsAlarm(t *testing.T) {
	p := &PaloAltoProfile{}
	// sensorType 8 = celsius → temperature (paSensorMeta returns non-empty, so a
	// status-3 sensor is not re-dropped for lack of a type).
	sensor := func(idx string, status int) []gosnmp.SnmpPDU {
		return []gosnmp.SnmpPDU{
			{Name: paOIDSensorType + "." + idx, Type: gosnmp.Integer, Value: 8},
			{Name: paOIDSensorValue + "." + idx, Type: gosnmp.Integer, Value: 42},
			{Name: paOIDSensorStatus + "." + idx, Type: gosnmp.Integer, Value: status},
		}
	}

	var pdus []gosnmp.SnmpPDU
	pdus = append(pdus, sensor("1", 1)...) // normal
	pdus = append(pdus, sensor("2", 2)...) // unavailable → dropped
	pdus = append(pdus, sensor("3", 3)...) // nonoperational → alarm

	byName := map[string]string{}
	for _, s := range p.ParseHardwareSensors(pdus) {
		byName[s.Name] = s.Status
	}

	if len(byName) != 2 {
		t.Fatalf("got %d sensors; want 2 (status-2 dropped): %v", len(byName), byName)
	}
	if got := byName["Temperature Sensor 1"]; got != "normal" {
		t.Errorf("status-1 sensor Status = %q; want normal", got)
	}
	if got := byName["Temperature Sensor 3"]; got != "alarm" {
		t.Errorf("status-3 sensor Status = %q; want alarm", got)
	}
	if _, ok := byName["Temperature Sensor 2"]; ok {
		t.Errorf("status-2 sensor should have been dropped, got Status=%q", byName["Temperature Sensor 2"])
	}
}
