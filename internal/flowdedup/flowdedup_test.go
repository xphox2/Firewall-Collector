package flowdedup

import (
	"fmt"
	"testing"
	"time"
)

// TestPreferNetFlow_SuppressionAndFailover pins the core dual-export
// contract: sFlow flow samples are suppressed while NetFlow is live from the
// same exporter, and resume automatically once NetFlow goes quiet past the
// activity window (the failover property).
func TestPreferNetFlow_SuppressionAndFailover(t *testing.T) {
	tr := NewTracker(PolicyPreferNetFlow, nil)
	t0 := time.Now()
	const exp = "192.0.2.1"

	// sFlow alone: never suppressed.
	if tr.SuppressSFlowFlow(exp, t0) {
		t.Fatal("sFlow suppressed with no NetFlow activity")
	}
	// NetFlow appears: subsequent sFlow suppressed.
	if tr.SuppressNetFlow(exp, t0.Add(time.Second)) {
		t.Fatal("preferred family must never be suppressed under prefer-netflow")
	}
	if !tr.SuppressSFlowFlow(exp, t0.Add(2*time.Second)) {
		t.Fatal("sFlow not suppressed while NetFlow live")
	}
	// Within the window: still suppressed.
	if !tr.SuppressSFlowFlow(exp, t0.Add(activityWindow-time.Second)) {
		t.Fatal("sFlow resumed before the activity window elapsed")
	}
	// NetFlow quiet past the window: failover — sFlow resumes.
	if tr.SuppressSFlowFlow(exp, t0.Add(time.Second+activityWindow+time.Second)) {
		t.Fatal("sFlow still suppressed after NetFlow went quiet (failover broken)")
	}
}

// TestPolicies pins prefer-sflow mirroring and off/unknown behaving as off.
func TestPolicies(t *testing.T) {
	t0 := time.Now()

	ps := NewTracker(PolicyPreferSFlow, nil)
	ps.SuppressSFlowFlow("x", t0)
	if !ps.SuppressNetFlow("x", t0.Add(time.Second)) {
		t.Error("prefer-sflow: NetFlow not suppressed while sFlow live")
	}
	if ps.SuppressSFlowFlow("x", t0.Add(2*time.Second)) {
		t.Error("prefer-sflow: sFlow must never be suppressed")
	}

	for _, pol := range []string{PolicyOff, "bogus", ""} {
		off := NewTracker(pol, nil)
		off.SuppressNetFlow("x", t0)
		if off.SuppressSFlowFlow("x", t0.Add(time.Second)) {
			t.Errorf("policy %q: suppression active, want fail-open", pol)
		}
		if off.Policy() != PolicyOff {
			t.Errorf("policy %q normalized to %q, want off", pol, off.Policy())
		}
	}
}

// TestExportersAreIndependent: NetFlow from one exporter must not suppress
// another exporter's sFlow.
func TestExportersAreIndependent(t *testing.T) {
	tr := NewTracker(PolicyPreferNetFlow, nil)
	t0 := time.Now()
	tr.SuppressNetFlow("192.0.2.1", t0)
	if tr.SuppressSFlowFlow("192.0.2.2", t0.Add(time.Second)) {
		t.Fatal("suppression leaked across exporters")
	}
}

// TestOnChangeFiresOncePerTransition pins the announce contract: the hook
// fires on state CHANGES only, never per packet.
func TestOnChangeFiresOncePerTransition(t *testing.T) {
	var events []string
	tr := NewTracker(PolicyPreferNetFlow, func(exp, fam string, active bool) {
		events = append(events, fmt.Sprintf("%s/%s=%v", exp, fam, active))
	})
	t0 := time.Now()
	tr.SuppressNetFlow("e", t0)
	tr.SuppressSFlowFlow("e", t0.Add(1*time.Second)) // → suppressed (change)
	tr.SuppressSFlowFlow("e", t0.Add(2*time.Second)) // still suppressed (no event)
	tr.SuppressSFlowFlow("e", t0.Add(3*time.Second))
	tr.SuppressSFlowFlow("e", t0.Add(activityWindow+2*time.Second)) // resumed (change)

	// No event for the initial not-suppressed states (announce fires on
	// CHANGES only, and the zero state is "not suppressed").
	want := []string{"e/sflow=true", "e/sflow=false"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events[%d] = %q, want %q", i, events[i], want[i])
		}
	}
}

// TestKey_DeviceIdentityUnifiesFamilies pins the LC-00 fix: on FortiGate the
// sFlow SamplerAddress (in-band agent address) and the NetFlow SamplerAddress
// (UDP source IP) commonly DIFFER, so the tracker must be keyed by the
// resolved device identity — otherwise the two families never meet and
// suppression silently no-ops.
func TestKey_DeviceIdentityUnifiesFamilies(t *testing.T) {
	tr := NewTracker(PolicyPreferNetFlow, nil)
	t0 := time.Now()
	const (
		devID     = uint(7)
		agentAddr = "10.255.1.1"  // sFlow in-band agent-address (loopback/mgmt)
		exportIP  = "203.0.113.9" // NetFlow UDP source (egress interface)
	)

	// NetFlow arrives from the egress IP, sFlow from the agent address —
	// both resolve to device 7, so the sFlow flow must be suppressed.
	tr.SuppressNetFlow(Key(devID, exportIP), t0)
	if !tr.SuppressSFlowFlow(Key(devID, agentAddr), t0.Add(time.Second)) {
		t.Fatal("sFlow not suppressed despite NetFlow live from the same device (dedup keyed by address, not device)")
	}

	// Regression shape of the original bug: keyed by RAW addresses (device
	// unresolved), the same traffic pattern must NOT cross-suppress — the
	// fallback keeps unrelated exporters independent.
	tr2 := NewTracker(PolicyPreferNetFlow, nil)
	tr2.SuppressNetFlow(Key(0, exportIP), t0)
	if tr2.SuppressSFlowFlow(Key(0, agentAddr), t0.Add(time.Second)) {
		t.Fatal("unresolved exporters with different addresses must stay independent")
	}
	// Same unresolved address across families still dedups (fallback works).
	if !tr2.SuppressSFlowFlow(Key(0, exportIP), t0.Add(2*time.Second)) {
		t.Fatal("unresolved fallback: same sampler address must still dedup across families")
	}
}

// TestKey pins the key derivation: device identity when resolved, prefixed
// raw address otherwise, with namespaces that can never collide.
func TestKey(t *testing.T) {
	if got := Key(7, "10.0.0.1"); got != "dev:7" {
		t.Errorf("Key(7, ...) = %q, want dev:7", got)
	}
	if got := Key(0, "10.0.0.1"); got != "ip:10.0.0.1" {
		t.Errorf("Key(0, 10.0.0.1) = %q, want ip:10.0.0.1", got)
	}
	// A hostile sampler address can't forge its way into the device namespace.
	if Key(0, "dev:7") == Key(7, "anything") {
		t.Error("ip namespace collided with dev namespace")
	}
}

// TestExporterCapFailsOpen: past the map cap with nothing prunable, unknown
// exporters are untracked and never suppressed (losing dedup, never data).
func TestExporterCapFailsOpen(t *testing.T) {
	tr := NewTracker(PolicyPreferNetFlow, nil)
	now := time.Now()
	for i := 0; i < maxExporters; i++ {
		tr.SuppressNetFlow(fmt.Sprintf("10.0.%d.%d", i/256, i%256), now)
	}
	if got := len(tr.byIP); got != maxExporters {
		t.Fatalf("tracker holds %d exporters, want %d", got, maxExporters)
	}
	// A brand-new exporter beyond the cap (nothing idle to prune yet).
	if tr.SuppressSFlowFlow("203.0.113.99", now) {
		t.Fatal("untracked exporter suppressed — cap must fail open")
	}
	// After everything goes idle, the prune frees room again.
	later := now.Add(3 * activityWindow)
	tr.SuppressNetFlow("203.0.113.100", later)
	if !tr.SuppressSFlowFlow("203.0.113.100", later.Add(time.Second)) {
		t.Fatal("post-prune exporter not tracked")
	}
}
