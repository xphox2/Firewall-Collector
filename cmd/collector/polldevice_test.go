package main

import (
	"errors"
	"testing"
	"time"

	"firewall-collector/internal/observability"
	"firewall-collector/internal/relay"
	"firewall-collector/internal/snmp"
)

// fakeSNMP is a deviceSNMP that returns one canned record per metric type, so a
// successful poll exercises every collect→stamp→send block in pollDevice.
type fakeSNMP struct{}

func (fakeSNMP) GetSystemStatus(...string) (*relay.SystemStatus, error) {
	return &relay.SystemStatus{CPUUsage: 12.5}, nil
}
func (fakeSNMP) GetInterfaceStats() ([]relay.InterfaceStats, error) {
	return []relay.InterfaceStats{{Name: "port1"}}, nil
}
func (fakeSNMP) GetInterfaceAddresses() ([]relay.InterfaceAddress, error) {
	return []relay.InterfaceAddress{{IPAddress: "10.0.0.1"}}, nil
}
func (fakeSNMP) GetVPNStatus(...string) ([]relay.VPNStatus, error) {
	return []relay.VPNStatus{{}}, nil
}
func (fakeSNMP) GetHardwareSensors(...string) ([]relay.HardwareSensor, error) {
	return []relay.HardwareSensor{{}}, nil
}
func (fakeSNMP) GetProcessorStats(...string) ([]relay.ProcessorStats, error) {
	return []relay.ProcessorStats{{}}, nil
}
func (fakeSNMP) GetHAStatus(...string) ([]relay.HAStatus, error) {
	return []relay.HAStatus{{}}, nil
}
func (fakeSNMP) GetSecurityStats(...string) (*relay.SecurityStats, error) {
	return &relay.SecurityStats{}, nil
}
func (fakeSNMP) GetSDWANHealth(...string) ([]relay.SDWANHealth, error) {
	return []relay.SDWANHealth{{}}, nil
}
func (fakeSNMP) GetLicenseInfo(...string) ([]relay.LicenseInfo, error) {
	return []relay.LicenseInfo{{}}, nil
}
func (fakeSNMP) Close() error { return nil }

// fakeSink is a metricSink that records everything pollDevice would send.
type fakeSink struct {
	systemStatuses []relay.SystemStatus
	interfaceStats []relay.InterfaceStats
	interfaceAddrs []relay.InterfaceAddress
	vpnStatuses    []relay.VPNStatus
	sensors        []relay.HardwareSensor
	procStats      []relay.ProcessorStats
	haStatuses     []relay.HAStatus
	secStats       []relay.SecurityStats
	sdwan          []relay.SDWANHealth
	licenses       []relay.LicenseInfo
}

func (f *fakeSink) SendSystemStatuses(s []relay.SystemStatus) error {
	f.systemStatuses = append(f.systemStatuses, s...)
	return nil
}
func (f *fakeSink) SendInterfaceStats(s []relay.InterfaceStats) error {
	f.interfaceStats = append(f.interfaceStats, s...)
	return nil
}
func (f *fakeSink) SendInterfaceAddresses(s []relay.InterfaceAddress) error {
	f.interfaceAddrs = append(f.interfaceAddrs, s...)
	return nil
}
func (f *fakeSink) SendVPNStatuses(s []relay.VPNStatus) error {
	f.vpnStatuses = append(f.vpnStatuses, s...)
	return nil
}
func (f *fakeSink) SendHardwareSensors(s []relay.HardwareSensor) error {
	f.sensors = append(f.sensors, s...)
	return nil
}
func (f *fakeSink) SendProcessorStats(s []relay.ProcessorStats) error {
	f.procStats = append(f.procStats, s...)
	return nil
}
func (f *fakeSink) SendHAStatuses(s []relay.HAStatus) error {
	f.haStatuses = append(f.haStatuses, s...)
	return nil
}
func (f *fakeSink) SendSecurityStats(s []relay.SecurityStats) error {
	f.secStats = append(f.secStats, s...)
	return nil
}
func (f *fakeSink) SendSDWANHealth(s []relay.SDWANHealth) error {
	f.sdwan = append(f.sdwan, s...)
	return nil
}
func (f *fakeSink) SendLicenseInfo(s []relay.LicenseInfo) error {
	f.licenses = append(f.licenses, s...)
	return nil
}

// newTestCollector builds a Collector wired to the given SNMP dialer and sink,
// with the maps and metrics pollDevice touches initialized.
func newTestCollector(sink metricSink, dial snmpDialer) *Collector {
	return &Collector{
		failCount:          make(map[uint]int),
		lastSuccessfulPoll: make(map[uint]time.Time),
		metrics:            observability.New(observability.Config{}),
		sink:               sink,
		newSNMP:            dial,
	}
}

func validDevice() relay.DeviceInfo {
	return relay.DeviceInfo{
		ID: 1, Name: "test", IPAddress: "1.2.3.4",
		SNMPPort: 161, SNMPCommunity: "public", SNMPVersion: "2c", Vendor: "fortigate",
	}
}

// TestPollDevice_CollectsStampsAndSends characterizes the happy path: every
// metric type is collected, stamped with the device ID and a timestamp, and
// forwarded to the sink, and a successful poll is recorded.
func TestPollDevice_CollectsStampsAndSends(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, func(string, int, string, string, *snmp.SNMPv3Config) (deviceSNMP, error) {
		return fakeSNMP{}, nil
	})

	c.pollDevice(validDevice())

	// Every metric type reached the sink exactly once.
	checks := []struct {
		name string
		got  int
	}{
		{"systemStatuses", len(sink.systemStatuses)},
		{"interfaceStats", len(sink.interfaceStats)},
		{"interfaceAddrs", len(sink.interfaceAddrs)},
		{"vpnStatuses", len(sink.vpnStatuses)},
		{"sensors", len(sink.sensors)},
		{"procStats", len(sink.procStats)},
		{"haStatuses", len(sink.haStatuses)},
		{"secStats", len(sink.secStats)},
		{"sdwan", len(sink.sdwan)},
		{"licenses", len(sink.licenses)},
	}
	for _, c := range checks {
		if c.got != 1 {
			t.Errorf("%s: got %d, want 1", c.name, c.got)
		}
	}

	// Stamping: DeviceID comes from the device, Timestamp is populated.
	if sink.systemStatuses[0].DeviceID != 1 || sink.systemStatuses[0].Timestamp.IsZero() {
		t.Errorf("system status not stamped: DeviceID=%d zeroTS=%v", sink.systemStatuses[0].DeviceID, sink.systemStatuses[0].Timestamp.IsZero())
	}
	if sink.interfaceStats[0].DeviceID != 1 || sink.interfaceStats[0].Timestamp.IsZero() {
		t.Errorf("interface stats not stamped: DeviceID=%d zeroTS=%v", sink.interfaceStats[0].DeviceID, sink.interfaceStats[0].Timestamp.IsZero())
	}

	// A successful poll resets the circuit breaker and records the device.
	if _, ok := c.lastSuccessfulPoll[1]; !ok {
		t.Error("recordPollSuccess did not record device 1")
	}
}

// TestPollDevice_SkipsInvalidCredentials characterizes the credential guard:
// a non-v3 device with an empty community is skipped before dialing.
func TestPollDevice_SkipsInvalidCredentials(t *testing.T) {
	sink := &fakeSink{}
	dialed := false
	c := newTestCollector(sink, func(string, int, string, string, *snmp.SNMPv3Config) (deviceSNMP, error) {
		dialed = true
		return fakeSNMP{}, nil
	})

	dev := validDevice()
	dev.SNMPCommunity = ""
	c.pollDevice(dev)

	if dialed {
		t.Error("newSNMP must not be called for a device with an empty community")
	}
	if len(sink.systemStatuses) != 0 {
		t.Errorf("skipped device sent %d system statuses, want 0", len(sink.systemStatuses))
	}
}

// TestPollDevice_ConnectFailure characterizes the connect-error path: nothing is
// sent and the circuit-breaker failure count increments.
func TestPollDevice_ConnectFailure(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, func(string, int, string, string, *snmp.SNMPv3Config) (deviceSNMP, error) {
		return nil, errors.New("connect refused")
	})

	c.pollDevice(validDevice())

	if len(sink.systemStatuses) != 0 {
		t.Errorf("connect failure sent %d system statuses, want 0", len(sink.systemStatuses))
	}
	if c.failCount[1] != 1 {
		t.Errorf("failCount[1] = %d after connect failure, want 1", c.failCount[1])
	}
}
