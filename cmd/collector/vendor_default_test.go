package main

import "testing"

// TestIsFortiGateVendor_EmptyFalse: an empty vendor is NOT FortiGate. Until
// 1.3.48 it was (a legacy alias for device records created before the vendor
// column), which routed an unclassified device onto the FortiGate-only paths:
// TFTP capture driven by FortiOS CLI over SSH, and a server-inferred backup
// quality. Since 1.3.49 (server 0.11.290, which backfilled every empty vendor)
// only the literal "fortigate" is.
func TestIsFortiGateVendor_EmptyFalse(t *testing.T) {
	for vendor, want := range map[string]bool{
		"":          false,
		"fortigate": true,
		"generic":   false,
		"opnsense":  false,
		"FortiGate": false, // the server lower-cases on save; no case folding here
	} {
		if got := isFortiGateVendor(vendor); got != want {
			t.Errorf("isFortiGateVendor(%q) = %v, want %v", vendor, got, want)
		}
	}
}
