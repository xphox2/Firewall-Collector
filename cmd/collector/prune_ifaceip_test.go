package main

import (
	"testing"

	"firewall-collector/internal/relay"
)

// TestPruneIfaceIPMap_AUDIT237 verifies the interface-IP→device-ID cache is
// pruned on a device-list refresh that drops a device. Without the prune, a
// decommissioned device's IP — reassigned to a NEW device — keeps resolving to
// the STALE device via resolveDeviceByIP until overwritten or restart. On a
// reverted fix the stale entry survives and resolveDeviceByIP still returns the
// old device, failing this test.
func TestPruneIfaceIPMap_AUDIT237(t *testing.T) {
	c := &Collector{}

	// Device 1 has interface IP 10.0.0.5 cached.
	c.cacheInterfaceAddresses(1, []relay.InterfaceAddress{{IPAddress: "10.0.0.5"}})
	c.deviceMu.Lock()
	c.devices = []relay.DeviceInfo{{ID: 1}}
	c.deviceMu.Unlock()

	if got := c.resolveDeviceByIP("10.0.0.5"); got != 1 {
		t.Fatalf("precondition: resolveDeviceByIP(10.0.0.5) = %d, want 1", got)
	}

	// Device 1 decommissioned; the refresh now returns only device 2.
	newDevices := []relay.DeviceInfo{{ID: 2}}
	c.deviceMu.Lock()
	c.devices = newDevices
	c.deviceMu.Unlock()
	c.pruneIfaceIPMap(newDevices)

	if got := c.resolveDeviceByIP("10.0.0.5"); got != 0 {
		t.Errorf("stale ifaceIPMap entry not pruned: resolveDeviceByIP(10.0.0.5) = %d, want 0", got)
	}
}

// TestPruneIfaceIPMap_KeepsAssigned confirms the prune does not drop entries for
// devices still in the assigned list.
func TestPruneIfaceIPMap_KeepsAssigned(t *testing.T) {
	c := &Collector{}
	c.cacheInterfaceAddresses(1, []relay.InterfaceAddress{{IPAddress: "10.0.0.5"}})
	c.cacheInterfaceAddresses(2, []relay.InterfaceAddress{{IPAddress: "10.0.0.6"}})

	devices := []relay.DeviceInfo{{ID: 1}, {ID: 2}}
	c.deviceMu.Lock()
	c.devices = devices
	c.deviceMu.Unlock()
	c.pruneIfaceIPMap(devices)

	if got := c.resolveDeviceByIP("10.0.0.5"); got != 1 {
		t.Errorf("assigned device 1 entry wrongly pruned: got %d, want 1", got)
	}
	if got := c.resolveDeviceByIP("10.0.0.6"); got != 2 {
		t.Errorf("assigned device 2 entry wrongly pruned: got %d, want 2", got)
	}
}
