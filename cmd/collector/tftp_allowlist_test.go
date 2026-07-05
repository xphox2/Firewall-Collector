package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"firewall-collector/internal/netflow"
	"firewall-collector/internal/relay"
	"firewall-collector/internal/sflow"
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

// TestApplyTFTPAllowlist_ReceiversAllowlistedWithoutTFTP is the LC-41
// regression (2026-07-04 audit): applyTFTPAllowlist began with an
// `if c.tftpServer == nil { return }` guard from its TFTP-only days, so with
// PROBE_TFTP_CONFIG_ENABLED=false (tftpServer never constructed) the sFlow and
// NetFlow SetAllowedSourceIPs blocks appended later were silently skipped on
// every call — both flow receivers stayed at their nil = allow-any default
// forever, accepting spoofed flow datagrams from any source.
//
// The receivers' allowlist state is unexported outside their packages, so the
// wiring is asserted via the log lines emitted from INSIDE each receiver's
// apply block, immediately after its SetAllowedSourceIPs call — they can only
// appear if the block executed.
func TestApplyTFTPAllowlist_ReceiversAllowlistedWithoutTFTP(t *testing.T) {
	c := &Collector{
		// tftpServer deliberately nil = TFTP config backup disabled.
		sflowReceiver:   sflow.NewSFlowReceiver("127.0.0.1", 6343),
		netflowReceiver: netflow.New("127.0.0.1", 2055, 4739),
		devices:         []relay.DeviceInfo{{ID: 1, IPAddress: "192.0.2.10"}},
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	c.applyTFTPAllowlist()

	out := buf.String()
	if !strings.Contains(out, "[sFlow] Source-IP allowlist applied: 1 device IP(s)") {
		t.Errorf("sFlow allowlist not applied with TFTP disabled — receiver left at allow-any; log:\n%s", out)
	}
	if !strings.Contains(out, "[NetFlow] Source-IP allowlist applied: 1 device IP(s)") {
		t.Errorf("NetFlow allowlist not applied with TFTP disabled — receiver left at allow-any; log:\n%s", out)
	}
	if strings.Contains(out, "[TFTP] Source-IP allowlist applied") {
		t.Errorf("TFTP allowlist log emitted with no TFTP server; log:\n%s", out)
	}
}
