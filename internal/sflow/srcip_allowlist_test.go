package sflow

import (
	"net"
	"testing"
)

// TestSFlowSourceAllowlist pins the 2026-07-02 audit M2 fix: the receiver's
// source-IP allowlist follows the same nil/empty/set semantics as the TFTP one.
// sFlow attributes samples by the datagram's agent_address (spoofable), so
// dropping datagrams from non-fleet source IPs is the primary mitigation.
func TestSFlowSourceAllowlist(t *testing.T) {
	r := NewSFlowReceiver("0.0.0.0", 6343)

	// Default (nil policy): allow any source (back-compat).
	if !r.isSourceAllowed(net.ParseIP("203.0.113.9")) {
		t.Fatal("nil policy should allow any source")
	}

	// Explicit allowlist: only listed IPs pass.
	r.SetAllowedSourceIPs([]string{"192.0.2.1", "192.0.2.2"}, nil)
	if !r.isSourceAllowed(net.ParseIP("192.0.2.1")) {
		t.Error("192.0.2.1 should be allowed")
	}
	if r.isSourceAllowed(net.ParseIP("203.0.113.9")) {
		t.Error("203.0.113.9 must be denied when not in the allowlist")
	}

	// IPv4-mapped normalization: an entry given as ::ffff:v4 matches a plain v4.
	r.SetAllowedSourceIPs([]string{"::ffff:198.51.100.7"}, nil)
	if !r.isSourceAllowed(net.ParseIP("198.51.100.7")) {
		t.Error("IPv4-mapped allowlist entry should match the plain IPv4 source")
	}

	// Non-nil empty list: deny all (secure default while no devices are known).
	r.SetAllowedSourceIPs([]string{}, nil)
	if r.isSourceAllowed(net.ParseIP("192.0.2.1")) {
		t.Error("empty (non-nil) allowlist must deny every source")
	}

	// Back to nil: allow any again.
	r.SetAllowedSourceIPs(nil, nil)
	if !r.isSourceAllowed(net.ParseIP("192.0.2.1")) {
		t.Error("nil policy should allow any source again")
	}
}
