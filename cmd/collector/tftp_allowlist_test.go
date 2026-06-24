package main

import (
	"testing"

	"firewall-collector/internal/relay"
)

// TestDeviceSourceIPs is the regression for the 2026-06-23 audit H2 finding:
// the TFTP write server's source-IP allowlist was never populated from the
// device list, so it accepted forged config uploads from any host. The allowlist
// is now derived from the monitored devices' management IPs via this helper.
func TestDeviceSourceIPs(t *testing.T) {
	devices := []relay.DeviceInfo{
		{ID: 1, IPAddress: "192.168.1.10"},
		{ID: 2, IPAddress: ""}, // no IP — skipped
		{ID: 3, IPAddress: "192.168.1.20"},
	}
	got := deviceSourceIPs(devices)
	want := map[string]bool{"192.168.1.10": true, "192.168.1.20": true}
	if len(got) != len(want) {
		t.Fatalf("deviceSourceIPs = %v, want the 2 non-empty IPs", got)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("unexpected IP in allowlist: %q", ip)
		}
	}
}

// TestDeviceSourceIPs_EmptyIsNonNil verifies the deny-all default: an empty
// device list yields a non-nil empty slice, so SetAllowedSourceIPs denies every
// source (rather than nil = allow-all).
func TestDeviceSourceIPs_EmptyIsNonNil(t *testing.T) {
	got := deviceSourceIPs(nil)
	if got == nil {
		t.Fatal("deviceSourceIPs(nil) returned nil (allow-all); want non-nil empty (deny-all)")
	}
	if len(got) != 0 {
		t.Errorf("deviceSourceIPs(nil) = %v, want empty", got)
	}
}

// TestApplyTFTPAllowlist_NilServerNoPanic guards the startup ordering: the
// helper may run before the TFTP server is constructed and must be a safe no-op.
func TestApplyTFTPAllowlist_NilServerNoPanic(t *testing.T) {
	c := &Collector{} // tftpServer is nil
	c.applyTFTPAllowlist()
}
