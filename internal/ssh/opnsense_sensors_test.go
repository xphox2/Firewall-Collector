package ssh

import "testing"

// realistic slice of `sysctl -iq hw.temperature dev.ina2xx dev.emc2302` output
// from the live NXP box, including the noise lines that must be ignored.
const opnSensorFixture = `hw.temperature.network-board-local: 43.1C
hw.temperature.cpu-board-remote: 46.6C
dev.ina2xx.7.power: 2320
dev.ina2xx.7.current: 720
dev.ina2xx.7.shunt_voltage: 720
dev.ina2xx.7.bus_voltage: 3302
dev.ina2xx.7.label: 3.3V PSU
dev.ina2xx.7.%driver: ina2xx
dev.ina2xx.7.%desc: INA2xx Power Monitor (3.3V PSU)
dev.emc2302.0.fan1.fault: 0
dev.emc2302.0.fan1.rpm: 0
dev.emc2302.0.fan1.pwm: 81
dev.emc2302.0.fan0.fault: 0
dev.emc2302.0.fan0.rpm: 2732
dev.emc2302.0.fan0.pwm: 81`

func findSensor(sensors []OPNsenseSensor, name string) (OPNsenseSensor, bool) {
	for _, s := range sensors {
		if s.Name == name {
			return s, true
		}
	}
	return OPNsenseSensor{}, false
}

func TestParseOPNsenseSensors_Full(t *testing.T) {
	got := ParseOPNsenseSensors(opnSensorFixture)

	// 2 temps + 1 rail*3 electrical + 2 fans = 7.
	if len(got) != 7 {
		t.Fatalf("expected 7 sensors, got %d: %+v", len(got), got)
	}

	checks := []struct {
		name      string
		typ, unit string
		value     float64
		status    string
	}{
		{"cpu-board-remote", "temperature", "°C", 46.6, "normal"},
		{"3.3V PSU voltage", "voltage", "mV", 3302, "normal"},
		{"3.3V PSU current", "current", "mA", 720, "normal"},
		{"3.3V PSU power", "power", "mW", 2320, "normal"},
		{"System Fan 1", "fan", "RPM", 2732, "normal"}, // fan0 -> Fan 1
		{"System Fan 2", "fan", "RPM", 0, "normal"},    // fan1 present, 0 rpm, fault 0
	}
	for _, c := range checks {
		s, ok := findSensor(got, c.name)
		if !ok {
			t.Errorf("missing sensor %q", c.name)
			continue
		}
		if s.Type != c.typ || s.Unit != c.unit || s.Value != c.value || s.Status != c.status {
			t.Errorf("sensor %q = %+v, want type=%s unit=%s value=%v status=%s",
				c.name, s, c.typ, c.unit, c.value, c.status)
		}
	}

	// Noise lines must never become sensors.
	for _, bad := range []string{"3.3V PSU shunt_voltage", "3.3V PSU pwm", "3.3V PSU %driver"} {
		if _, ok := findSensor(got, bad); ok {
			t.Errorf("noise line leaked into a sensor: %q", bad)
		}
	}
}

func TestParseOPNsenseSensors_FanFault(t *testing.T) {
	got := ParseOPNsenseSensors("dev.emc2302.0.fan0.rpm: 0\ndev.emc2302.0.fan0.fault: 1")
	if len(got) != 1 || got[0].Status != "alarm" {
		t.Fatalf("expected one fan in alarm, got %+v", got)
	}
}

func TestParseOPNsenseSensors_PartialAndEmpty(t *testing.T) {
	// x86 OPNsense: only hw.temperature exists (no INA/EMC drivers). `sysctl -iq`
	// returns just that tree — must parse the temps and not choke.
	temps := ParseOPNsenseSensors("hw.temperature.cpu0: 51.0C\nhw.temperature.cpu1: 52.5C")
	if len(temps) != 2 {
		t.Fatalf("partial (temps only): expected 2, got %d: %+v", len(temps), temps)
	}

	// A box with none of the trees yields empty output → zero sensors, no panic.
	if got := ParseOPNsenseSensors(""); len(got) != 0 {
		t.Fatalf("empty input: expected 0 sensors, got %d", len(got))
	}
	// Garbage / unrelated lines are ignored.
	if got := ParseOPNsenseSensors("sysctl: unknown oid 'dev.ina2xx'\nfoo bar baz"); len(got) != 0 {
		t.Fatalf("garbage input: expected 0 sensors, got %d: %+v", len(got), got)
	}
}

func TestParseOPNsenseSensors_IncompleteRailSkipped(t *testing.T) {
	// A rail with electrical values but no label can't be named → skipped.
	got := ParseOPNsenseSensors("dev.ina2xx.3.bus_voltage: 1177\ndev.ina2xx.3.current: 344")
	if len(got) != 0 {
		t.Fatalf("unlabeled rail should be skipped, got %+v", got)
	}
}
