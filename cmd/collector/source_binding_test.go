package main

import (
	"net"
	"testing"

	"firewall-collector/internal/config"
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
		// An interface IP for device 1 (a multi-homed egress, say), used to
		// prove the FortiGate multi-homed case resolves to the SAME device and
		// is therefore accepted, never rejected.
		ifaceIPMap: map[string]uint{"192.0.2.11": 1},
	}
}

// TestAcceptBoundSource_AUDIT186 exercises the asymmetric sFlow/TFTP source
// binding gate directly (the shared decision both ingestion paths call).
func TestAcceptBoundSource_AUDIT186(t *testing.T) {
	strict := newBindingCollector(true)
	warn := newBindingCollector(false)

	// (a) STRICT: a KNOWN source (device 1) claiming a DIFFERENT known device
	// (2) is the detectable forgery — reject.
	if strict.acceptBoundSource("sFlow", 1, 2, "192.0.2.1", "192.0.2.2") {
		t.Error("strict: known source device 1 claiming device 2 must be REJECTED (forgery)")
	}
	// (b) source UNRESOLVABLE (0) while claiming device 2 — multi-homed/NAT:
	// can't enforce, so accept and fall back to the claim.
	if !strict.acceptBoundSource("sFlow", 0, 2, "198.51.100.9", "192.0.2.2") {
		t.Error("strict: unresolvable source must be ACCEPTED (warn+fallback), not dropped")
	}
	// (c) source == claim — the normal case — accept.
	if !strict.acceptBoundSource("sFlow", 1, 1, "192.0.2.1", "192.0.2.1") {
		t.Error("strict: source==claim must be accepted")
	}
	// claim unknown (0): no known-vs-known conflict — accept.
	if !strict.acceptBoundSource("sFlow", 1, 0, "192.0.2.1", "203.0.113.5") {
		t.Error("strict: a known source with an unresolved claim is not a forgery — accept")
	}
	// (d) WARN mode: the same mismatch as (a) is attributed-by-claim, NOT
	// dropped — only logged.
	if !warn.acceptBoundSource("sFlow", 1, 2, "192.0.2.1", "192.0.2.2") {
		t.Error("warn mode: a source/claim mismatch must be ACCEPTED (attribute by claim), not rejected")
	}
}

// TestSFlowAttributionDecision_AUDIT186 replays the sFlow handler's resolve-then
// -bind logic end to end: resolve deviceFromClaim (agent_address) and
// deviceFromSource (UDP source) through resolveDeviceByIP, then gate on
// acceptBoundSource. This proves the FortiGate multi-homed egress case is
// accepted while a genuine cross-device forgery is rejected.
func TestSFlowAttributionDecision_AUDIT186(t *testing.T) {
	c := newBindingCollector(true)

	decide := func(agentIP, srcIP string) bool {
		fromClaim := c.resolveDeviceByIP(agentIP)
		fromSource := c.resolveDeviceByIP(srcIP)
		return c.acceptBoundSource("sFlow", fromSource, fromClaim, srcIP, agentIP)
	}

	// Forgery: datagram from device 1's mgmt IP claims agent_address = device 2.
	if decide("192.0.2.2", "192.0.2.1") {
		t.Error("forged sample (source device 1, agent claims device 2) must be rejected")
	}
	// Multi-homed FortiGate: agent_address = device 1's mgmt IP, UDP source =
	// device 1's cached interface IP (192.0.2.11). Both resolve to device 1 →
	// accepted (NOT a false reject).
	if !decide("192.0.2.1", "192.0.2.11") {
		t.Error("multi-homed FortiGate (agent+source both device 1) must be accepted")
	}
	// Multi-homed with an UNCACHED egress IP: source unresolvable → warn+accept.
	if !decide("192.0.2.1", "198.51.100.77") {
		t.Error("multi-homed FortiGate with an uncached egress IP must be accepted (warn+fallback)")
	}
}

// TestTFTPUploadAllowed_AUDIT187 covers the TFTP client-address binding: the
// device ID is derived from the WRQ filename, so a KNOWN client uploading a
// config for a DIFFERENT device is a forgery and must NOT be recorded.
func TestTFTPUploadAllowed_AUDIT187(t *testing.T) {
	addr := func(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5000} }

	// (a) STRICT: client = device 1, filename claims device 2 → not recorded.
	strict := newBindingCollector(true)
	if _, _, ok := strict.tftpUploadAllowed("fgt_2_manual_config", addr("192.0.2.1")); ok {
		t.Error("strict: device 1 uploading fgt_2_..._config must be REJECTED (no ConfigRevision recorded)")
	}
	// (b) client UNRESOLVABLE (NAT'd/jump-host), filename claims device 2 →
	// recorded (warn+fallback).
	if _, _, ok := strict.tftpUploadAllowed("fgt_2_manual_config", addr("198.51.100.9")); !ok {
		t.Error("strict: a NAT'd upload from an unknown client must be recorded, not dropped")
	}
	// (c) match: client = device 1, filename claims device 1 → recorded.
	if id, trig, ok := strict.tftpUploadAllowed("fgt_1_manual_config", addr("192.0.2.1")); !ok || id != 1 || trig != "manual" {
		t.Errorf("strict: matching client/filename must be recorded; got id=%d trig=%q ok=%v", id, trig, ok)
	}
	// unparseable filename → not recorded regardless of source.
	if _, _, ok := strict.tftpUploadAllowed("garbage", addr("192.0.2.1")); ok {
		t.Error("strict: unparseable filename must not be recorded")
	}

	// (d) WARN mode: same mismatch as (a) is recorded (attributed by filename),
	// only logged.
	warn := newBindingCollector(false)
	if _, _, ok := warn.tftpUploadAllowed("fgt_2_manual_config", addr("192.0.2.1")); !ok {
		t.Error("warn mode: a client/filename mismatch must be RECORDED (attribute by filename), not dropped")
	}
}
