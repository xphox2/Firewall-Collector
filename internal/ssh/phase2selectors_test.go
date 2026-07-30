package ssh

import "testing"

// FortiOS prints phase2 selectors as address + DOTTED NETMASK. Storing that text
// verbatim is useless downstream: netclass.SelectorIP parses CIDR, "a - b"
// ranges and bare IPs — never a space-separated pair — so SelectorCovered would
// always be false and the row could never be matched to a provisioned tunnel.
// The connection-detail phase2 matcher is exact string equality against the
// peer's selectors, and strongSwan reports canonical CIDR, so any other form
// silently fails to pair while still LOOKING fixed on the panel (which only
// needs non-empty text). That is why the conversion is the load-bearing part,
// not the regexes.
func TestParseVPNPhase2_SelectorsAreCanonicalCIDR(t *testing.T) {
	cfg := `
config vpn ipsec phase2-interface
    edit "fwm-t12"
        set phase1name "fwm-t12"
        set src-subnet 192.168.13.0 255.255.255.0
        set dst-subnet 192.168.50.0 255.255.255.0
    next
    edit "fwm-t12-1"
        set phase1name "fwm-t12"
        set src-subnet 192.168.25.0 255.255.255.0
        set dst-subnet 192.168.12.0 255.255.255.0
    next
end`
	got := ParseVPNPhase2(cfg)
	if len(got) != 2 {
		t.Fatalf("expected 2 phase2 entries, got %d", len(got))
	}
	want := []struct{ local, remote string }{
		{"192.168.13.0/24", "192.168.50.0/24"},
		{"192.168.25.0/24", "192.168.12.0/24"},
	}
	for i, w := range want {
		if got[i].LocalSubnet != w.local || got[i].RemoteSubnet != w.remote {
			t.Errorf("entry %d selectors = %q/%q, want %q/%q — the map cannot pair a row "+
				"whose selectors are not canonical CIDR",
				i, got[i].LocalSubnet, got[i].RemoteSubnet, w.local, w.remote)
		}
	}
}

// A host address with a /24 mask must still canonicalise to the NETWORK, or the
// two ends produce different strings for the same selector and the exact-match
// pairing fails.
func TestSubnetToCIDR_MasksTheAddress(t *testing.T) {
	cases := []struct{ addr, mask, want string }{
		{"192.168.13.0", "255.255.255.0", "192.168.13.0/24"},
		{"192.168.13.7", "255.255.255.0", "192.168.13.0/24"}, // host form → network
		{"10.0.0.0", "255.0.0.0", "10.0.0.0/8"},
		{"192.168.1.5", "255.255.255.255", "192.168.1.5/32"},
		{"0.0.0.0", "0.0.0.0", "0.0.0.0/0"},
		{"192.168.1.0", "255.255.0.255", ""}, // non-contiguous: not CIDR-expressible
		{"notanip", "255.255.255.0", ""},
		{"192.168.1.0", "notamask", ""},
	}
	for _, c := range cases {
		if got := subnetToCIDR(c.addr, c.mask); got != c.want {
			t.Errorf("subnetToCIDR(%q, %q) = %q, want %q", c.addr, c.mask, got, c.want)
		}
	}
}

// Older FortiOS, or an address-type selector (src-name / src-start-ip), emits no
// src-subnet at all. That must parse cleanly with empty selectors — exactly
// today's behaviour — rather than failing the whole document.
func TestParseVPNPhase2_NoSelectorsStillParses(t *testing.T) {
	cfg := `
config vpn ipsec phase2-interface
    edit "legacy"
        set phase1name "legacy-p1"
        set src-name "some-addr-object"
    next
end`
	got := ParseVPNPhase2(cfg)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].Name != "legacy" || got[0].Phase1Name != "legacy-p1" {
		t.Errorf("basic fields lost: %+v", got[0])
	}
	if got[0].LocalSubnet != "" || got[0].RemoteSubnet != "" {
		t.Errorf("expected empty selectors, got %q/%q", got[0].LocalSubnet, got[0].RemoteSubnet)
	}
}
