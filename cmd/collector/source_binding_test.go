package main

import (
	"net"
	"testing"
	"time"

	"firewall-collector/internal/config"
	"firewall-collector/internal/flowdedup"
	"firewall-collector/internal/relay"
)

// newBindingCollector builds a Collector that monitors two devices (IDs 1 and
// 2) with the given strict-binding mode, for the source-attribution tests.
func newBindingCollector(strict bool) *Collector {
	return &Collector{
		cfg: &config.ProbeConfig{StrictSourceBinding: strict},
		devices: []relay.DeviceInfo{
			{ID: 1, IPAddress: "192.0.2.1"},
			{ID: 2, IPAddress: "192.0.2.2"},
		},
		// A per-device-unique interface IP for device 1 (a multi-homed egress),
		// used to prove the multi-homed FortiGate case resolves to the SAME
		// device and is therefore accepted, never rejected.
		ifaceIPMap: map[string]uint{"192.0.2.11": 1},
	}
}

// TestAcceptBoundSource_AUDIT186 exercises the asymmetric sFlow source binding
// gate directly.
func TestAcceptBoundSource_AUDIT186(t *testing.T) {
	strict := newBindingCollector(true)
	warn := newBindingCollector(false)

	// (a) STRICT: a KNOWN source (device 1) claiming a DIFFERENT known device
	// (2) is the detectable mismatch — reject.
	if strict.acceptBoundSource("sFlow", 1, 2, "192.0.2.1", "192.0.2.2") {
		t.Error("strict: known source device 1 claiming device 2 must be REJECTED")
	}
	// (b) source UNRESOLVABLE/ambiguous (0) while claiming device 2 — can't
	// enforce, so accept and fall back to the claim.
	if !strict.acceptBoundSource("sFlow", 0, 2, "198.51.100.9", "192.0.2.2") {
		t.Error("strict: unresolvable source must be ACCEPTED (warn+fallback), not dropped")
	}
	// (c) source == claim — the normal case — accept.
	if !strict.acceptBoundSource("sFlow", 1, 1, "192.0.2.1", "192.0.2.1") {
		t.Error("strict: source==claim must be accepted")
	}
	// claim unknown (0): no known-vs-known conflict — accept.
	if !strict.acceptBoundSource("sFlow", 1, 0, "192.0.2.1", "203.0.113.5") {
		t.Error("strict: a known source with an unresolved claim is not a mismatch — accept")
	}
	// (d) WARN mode: the same mismatch as (a) is attributed-by-claim, NOT
	// dropped — only logged.
	if !warn.acceptBoundSource("sFlow", 1, 2, "192.0.2.1", "192.0.2.2") {
		t.Error("warn mode: a source/claim mismatch must be ACCEPTED (attribute by claim), not rejected")
	}
}

// TestSFlowBindDecision_AUDIT186 replays the sFlow handler's resolve-then-bind
// logic through bindSFlowSample: it proves the multi-homed FortiGate egress case
// is accepted while a genuine cross-device forgery is rejected.
func TestSFlowBindDecision_AUDIT186(t *testing.T) {
	c := newBindingCollector(true)

	accepted := func(agentIP, srcIP string) bool {
		_, ok := c.bindSFlowSample("sFlow", agentIP, srcIP)
		return ok
	}

	// Forgery: datagram from device 1's mgmt IP claims agent_address = device 2.
	if accepted("192.0.2.2", "192.0.2.1") {
		t.Error("forged sample (source device 1, agent claims device 2) must be rejected")
	}
	// Multi-homed FortiGate: agent_address = device 1's mgmt IP, UDP source =
	// device 1's cached interface IP (192.0.2.11). Both resolve to device 1 →
	// accepted (NOT a false reject).
	if !accepted("192.0.2.1", "192.0.2.11") {
		t.Error("multi-homed FortiGate (agent+source both device 1) must be accepted")
	}
	// Multi-homed with an UNCACHED egress IP: source unresolvable → warn+accept.
	if !accepted("192.0.2.1", "198.51.100.77") {
		t.Error("multi-homed FortiGate with an uncached egress IP must be accepted (warn+fallback)")
	}
	// Attribution on accept: the sample is attributed to the claim's device.
	if id, ok := c.bindSFlowSample("sFlow", "192.0.2.1", "192.0.2.11"); !ok || id != 1 {
		t.Errorf("accepted sample must attribute to the claimed device 1; got id=%d ok=%v", id, ok)
	}
}

// TestSFlowBinding_HASharedInterface_AUDIT186_F1 is the HA/CARP false-reject
// regression (blocking review finding F1). An interface IP that the cache has
// seen from TWO different devices (an OPNsense CARP VIP, a FortiGate A-P synced
// interface) is ambiguous: binding must NOT reject a healthy member that exports
// with that shared IP as its agent_address, whichever device polled the cache
// last. A per-device-unique mgmt IP must still resolve authoritatively, and a
// genuine cross-device forgery (unique source vs unique claim) must still reject.
func TestSFlowBinding_HASharedInterface_AUDIT186_F1(t *testing.T) {
	c := newBindingCollector(true)
	const sharedVIP = "192.0.2.100"

	// Both HA members report the shared VIP in their interface tables. After the
	// second device's poll the cache flags it ambiguous (and last-writer-wins
	// points it at device 2).
	c.cacheInterfaceAddresses(1, []relay.InterfaceAddress{{IPAddress: sharedVIP}})
	c.cacheInterfaceAddresses(2, []relay.InterfaceAddress{{IPAddress: sharedVIP}})

	if id, amb := c.resolveDeviceByIPForBinding(sharedVIP); !amb {
		t.Fatalf("shared VIP must be flagged ambiguous for binding; got id=%d ambiguous=%v", id, amb)
	}

	// Member A (device 1) exports sFlow FROM its mgmt IP with agent_address =
	// the shared VIP. fromSource=1 (authoritative mgmt), claim=VIP=ambiguous →
	// must NOT reject even though the VIP's last-writer is device 2.
	if _, ok := c.bindSFlowSample("sFlow", sharedVIP, "192.0.2.1"); !ok {
		t.Error("healthy HA member A exporting with the shared VIP as agent_address must be ACCEPTED, not rejected")
	}
	// Member B likewise.
	if _, ok := c.bindSFlowSample("sFlow", sharedVIP, "192.0.2.2"); !ok {
		t.Error("healthy HA member B exporting with the shared VIP as agent_address must be ACCEPTED, not rejected")
	}
	// The reverse split (source is the shared VIP, claim is a unique mgmt IP):
	// source ambiguous → cannot enforce → accept.
	if _, ok := c.bindSFlowSample("sFlow", "192.0.2.2", sharedVIP); !ok {
		t.Error("an ambiguous SOURCE must not drive a reject either")
	}

	// A genuine cross-device forgery on UNIQUE IPs still rejects.
	if _, ok := c.bindSFlowSample("sFlow", "192.0.2.2", "192.0.2.1"); ok {
		t.Error("a genuine cross-device forgery (unique source vs unique claim) must STILL reject")
	}
	// And a unique mgmt IP still resolves authoritatively (not ambiguous).
	if id, amb := c.resolveDeviceByIPForBinding("192.0.2.1"); amb || id != 1 {
		t.Errorf("unique mgmt IP must resolve authoritatively; got id=%d ambiguous=%v", id, amb)
	}
}

// TestSFlowGateBeforeDedup_AUDIT186 proves the binding gate runs BEFORE the
// dual-export dedup gate: a rejected (forged) flow sample must never reach
// SuppressSFlowFlow, or it could poison the victim device's dedup state and
// suppress its genuine flows. Under prefer-sflow, marking the victim's sFlow
// active would suppress its NetFlow — so we assert the victim's NetFlow is NOT
// suppressed after the forged sample is dropped.
func TestSFlowGateBeforeDedup_AUDIT186(t *testing.T) {
	c := newBindingCollector(true)
	tr := flowdedup.NewTracker(flowdedup.PolicyPreferSFlow, nil)
	c.flowDedup = tr
	t0 := time.Now()

	// Forged: UDP source = device 1, agent_address claims device 2.
	forged := &relay.FlowSample{SamplerAddress: "192.0.2.2", SourceIP: "192.0.2.1", SrcAddr: "10.0.0.9"}
	if c.sflowFlowSendDecision(forged, t0) {
		t.Fatal("forged sample must be dropped by the binding gate")
	}
	// Victim (device 2) dedup state must be pristine: its NetFlow is NOT
	// suppressed, which can only hold if the forged sample never called
	// SuppressSFlowFlow for device 2.
	if tr.SuppressNetFlow(flowdedup.Key(2, "192.0.2.2"), t0.Add(time.Second)) {
		t.Fatal("forged sample poisoned device 2's dedup state — binding must gate BEFORE dedup")
	}

	// A legitimate sample for device 1 is accepted and passes to dedup.
	legit := &relay.FlowSample{SamplerAddress: "192.0.2.1", SourceIP: "192.0.2.1", SrcAddr: "10.0.0.1"}
	if !c.sflowFlowSendDecision(legit, t0.Add(2*time.Second)) {
		t.Error("a legitimate sample (source==claim==device 1) must be sent")
	}
}

// TestTFTPUploadAllowed_PendingTrigger_AUDIT187_F2 covers the expectation-based
// TFTP binding: an upload is recorded only when the collector has a live pending
// trigger for the claimed device — regardless of the WRQ source IP, so a branch
// device SNATing through a monitored NAT/hub is not false-rejected (blocking
// review finding F2). An unsolicited upload (no pending trigger) is rejected in
// strict mode and recorded+logged in warn mode, and a stale upload past the
// window is treated as unsolicited.
func TestTFTPUploadAllowed_PendingTrigger_AUDIT187_F2(t *testing.T) {
	// A NAT/hub source IP that is a DIFFERENT monitored device than the claim —
	// exactly the case the old source-based check false-rejected.
	hub := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000} // device 1 = the hub

	// (a) pending trigger for device 2 (a branch behind the hub) → recorded,
	// even though the WRQ source resolves to device 1.
	strict := newBindingCollector(true)
	strict.registerPendingTFTP(2)
	if id, trig, ok := strict.tftpUploadAllowed("fgt_2_poll_config", hub); !ok || id != 2 || trig != "poll" {
		t.Errorf("NATed upload with a pending trigger must be RECORDED; got id=%d trig=%q ok=%v", id, trig, ok)
	}
	// The trigger is single-use: a second upload for device 2 is now unsolicited.
	if _, _, ok := strict.tftpUploadAllowed("fgt_2_poll_config", hub); ok {
		t.Error("a consumed pending trigger must not authorize a second upload")
	}

	// (b) STRICT: unsolicited upload (no pending trigger) → NOT recorded.
	if _, _, ok := strict.tftpUploadAllowed("fgt_2_manual_config", hub); ok {
		t.Error("strict: an unsolicited upload with no pending trigger must be REJECTED")
	}
	// unparseable filename → not recorded regardless.
	if _, _, ok := strict.tftpUploadAllowed("garbage", hub); ok {
		t.Error("strict: unparseable filename must not be recorded")
	}

	// (c) expiry: a pending trigger past its deadline is treated as unsolicited.
	strict.pendingTFTPMu.Lock()
	if strict.pendingTFTP == nil {
		strict.pendingTFTP = map[uint]time.Time{}
	}
	strict.pendingTFTP[2] = time.Now().Add(-time.Minute) // already expired
	strict.pendingTFTPMu.Unlock()
	if _, _, ok := strict.tftpUploadAllowed("fgt_2_poll_config", hub); ok {
		t.Error("strict: a stale upload past the trigger deadline must be treated as unsolicited (rejected)")
	}

	// (d) WARN mode: an unsolicited upload is recorded + logged, not dropped.
	warn := newBindingCollector(false)
	if _, _, ok := warn.tftpUploadAllowed("fgt_2_manual_config", hub); !ok {
		t.Error("warn mode: an unsolicited upload must be RECORDED (attribute by filename), not dropped")
	}
}

// TestResolveDeviceByIP_EmptyIsUnknown pins the explicit empty=unknown contract
// (review nit 3): an empty IP never matches a device, even one whose IPAddress
// is somehow empty.
func TestResolveDeviceByIP_EmptyIsUnknown(t *testing.T) {
	c := &Collector{devices: []relay.DeviceInfo{{ID: 7, IPAddress: ""}}}
	if id := c.resolveDeviceByIP(""); id != 0 {
		t.Errorf("resolveDeviceByIP(\"\") = %d, want 0 (empty is unknown)", id)
	}
	if id, amb := c.resolveDeviceByIPForBinding(""); id != 0 || amb {
		t.Errorf("resolveDeviceByIPForBinding(\"\") = (%d, %v), want (0, false)", id, amb)
	}
}
