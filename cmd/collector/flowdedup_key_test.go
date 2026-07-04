package main

import (
	"testing"
	"time"

	"firewall-collector/internal/flowdedup"
	"firewall-collector/internal/relay"
)

// TestFlowDedupKey_CrossAddressSameDevice is the regression for LC-00: a
// FortiGate exporting sFlow with an in-band agent-address (its management IP)
// and NetFlow from a different egress-interface source IP must land on the
// SAME dedup key once both addresses resolve to the device — keyed by raw
// address the tracker saw two unrelated "exporters" and suppression silently
// no-oped, double-counting every byte server-side. Mirrors the main.go call
// sites: resolveDeviceByIP first, then flowdedup.Key(deviceID, samplerAddr).
func TestFlowDedupKey_CrossAddressSameDevice(t *testing.T) {
	const (
		agentAddr = "192.168.1.99" // sFlow agent-address = management IP
		exportIP  = "203.0.113.5"  // NetFlow UDP source = egress interface IP
	)
	c := &Collector{
		devices: []relay.DeviceInfo{{ID: 42, IPAddress: agentAddr}},
	}
	// The egress IP is only known via the interface-address cache.
	c.cacheInterfaceAddresses(42, []relay.InterfaceAddress{{IPAddress: exportIP}})

	sflowKey := flowdedup.Key(c.resolveDeviceByIP(agentAddr), agentAddr)
	netflowKey := flowdedup.Key(c.resolveDeviceByIP(exportIP), exportIP)
	if sflowKey != netflowKey {
		t.Fatalf("dedup keys diverged for one device: sFlow %q vs NetFlow %q", sflowKey, netflowKey)
	}

	// And the tracker actually suppresses across the two families.
	tr := flowdedup.NewTracker(flowdedup.PolicyPreferNetFlow, nil)
	t0 := time.Now()
	tr.SuppressNetFlow(netflowKey, t0)
	if !tr.SuppressSFlowFlow(sflowKey, t0.Add(time.Second)) {
		t.Fatal("sFlow flow not suppressed while NetFlow live from the same device")
	}
}

// TestFlowDedupKey_UnresolvedFallsBackToAddress pins the fallback: with no
// matching device, the key degrades to the prefixed raw sampler address —
// different addresses stay independent (never cross-suppress strangers),
// while a single dual-exporting unresolved address still dedups.
func TestFlowDedupKey_UnresolvedFallsBackToAddress(t *testing.T) {
	c := &Collector{} // no devices, no interface cache

	kA := flowdedup.Key(c.resolveDeviceByIP("198.51.100.1"), "198.51.100.1")
	kB := flowdedup.Key(c.resolveDeviceByIP("198.51.100.2"), "198.51.100.2")
	if kA == kB {
		t.Fatalf("unresolved keys collided: %q", kA)
	}
	if kA != "ip:198.51.100.1" {
		t.Fatalf("unresolved key = %q, want ip:198.51.100.1", kA)
	}

	tr := flowdedup.NewTracker(flowdedup.PolicyPreferNetFlow, nil)
	t0 := time.Now()
	tr.SuppressNetFlow(kA, t0)
	if tr.SuppressSFlowFlow(kB, t0.Add(time.Second)) {
		t.Fatal("suppression leaked between two unresolved exporters")
	}
	if !tr.SuppressSFlowFlow(kA, t0.Add(2*time.Second)) {
		t.Fatal("same unresolved address must still dedup across families")
	}
}
