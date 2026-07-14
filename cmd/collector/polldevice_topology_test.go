package main

import (
	"testing"

	"firewall-collector/internal/relay"
	"firewall-collector/internal/snmp"
)

func topoDialer() snmpDialer {
	return func(string, int, string, string, *snmp.SNMPv3Config) (deviceSNMP, error) {
		return fakeSNMP{}, nil
	}
}

// TestPollDevice_TopologyGatedOnFlag: topology is collected only when the
// cycle flag is set — the slow-cadence gate lives in runPollCycle, pollDevice
// just honors the flag.
func TestPollDevice_TopologyGatedOnFlag(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, topoDialer())

	c.pollDevice(validDevice(), false)
	if len(sink.topoEntries) != 0 || len(sink.topoNeighbors) != 0 {
		t.Fatalf("topology sent on a non-topology cycle: entries=%d neighbors=%d",
			len(sink.topoEntries), len(sink.topoNeighbors))
	}

	c.pollDevice(validDevice(), true)
	if len(sink.topoEntries) == 0 || len(sink.topoNeighbors) == 0 {
		t.Fatalf("topology missing on a topology cycle: entries=%d neighbors=%d",
			len(sink.topoEntries), len(sink.topoNeighbors))
	}
}

// TestPollDevice_TopologySnapshotAtomicAndStamped: ARP and FDB ride ONE
// SendTopologyEntries call (the server treats each batch as the device's
// complete snapshot), and every row is stamped with device/timestamp/source.
func TestPollDevice_TopologySnapshotAtomicAndStamped(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, topoDialer())

	c.pollDevice(validDevice(), true)

	if sink.topoSendCount != 1 {
		t.Fatalf("ARP+FDB must be one atomic send, got %d sends", sink.topoSendCount)
	}
	if len(sink.topoEntries) != 2 {
		t.Fatalf("expected 2 topology entries (1 arp + 1 fdb), got %d", len(sink.topoEntries))
	}
	types := map[string]bool{}
	for _, e := range sink.topoEntries {
		types[e.EntryType] = true
		if e.DeviceID != 1 || e.Timestamp.IsZero() || e.Source != "snmp" {
			t.Errorf("entry %+v not stamped (want DeviceID=1, non-zero ts, source=snmp)", e)
		}
	}
	if !types["arp"] || !types["fdb"] {
		t.Errorf("combined snapshot missing a type: %v", types)
	}
	if sink.topoNeighbors[0].DeviceID != 1 || sink.topoNeighbors[0].Timestamp.IsZero() {
		t.Errorf("neighbor not stamped: %+v", sink.topoNeighbors[0])
	}
}

// fakeSNMPEmptyARP returns no ARP rows — exercises the snmpARPEmpty flag that
// gates the SSH ARP supplement.
type fakeSNMPEmptyARP struct{ fakeSNMP }

func (fakeSNMPEmptyARP) GetARPTable() ([]relay.TopologyEntry, error) { return nil, nil }

// TestPollDevice_SNMPARPEmptyFlag: the SSH loop may only send its ARP
// supplement when the last SNMP topology cycle AFFIRMATIVELY returned an
// empty ARP table; a populated table (or no topology cycle at all) means no.
func TestPollDevice_SNMPARPEmptyFlag(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, topoDialer())

	if c.snmpARPWasEmpty(1) {
		t.Fatal("flag must default to false before any topology cycle")
	}

	c.pollDevice(validDevice(), true) // fakeSNMP returns a populated ARP table
	if c.snmpARPWasEmpty(1) {
		t.Fatal("flag must be false after a populated SNMP ARP snapshot")
	}

	c2 := newTestCollector(sink, func(string, int, string, string, *snmp.SNMPv3Config) (deviceSNMP, error) {
		return fakeSNMPEmptyARP{}, nil
	})
	c2.pollDevice(validDevice(), true)
	if !c2.snmpARPWasEmpty(1) {
		t.Fatal("flag must be true after an affirmatively empty SNMP ARP snapshot")
	}
}

// TestRunPollCycle_TopologyCadence: cycles 1 and 1+topologyCycleInterval
// collect topology, the cycles in between don't.
func TestRunPollCycle_TopologyCadence(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, topoDialer())
	dev := validDevice()
	dev.Enabled = true
	c.devices = []relay.DeviceInfo{dev}

	wantSends := 0
	for cycle := 0; cycle < topologyCycleInterval+1; cycle++ {
		c.runPollCycle()
		c.pollWg.Wait()
		if cycle%topologyCycleInterval == 0 {
			wantSends++
		}
		if sink.topoSendCount != wantSends {
			t.Fatalf("after cycle %d: topology sends = %d, want %d", cycle+1, sink.topoSendCount, wantSends)
		}
	}
}
