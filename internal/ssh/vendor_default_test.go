package ssh

import (
	"strings"
	"testing"
)

// TestNewConfigBackupClient_EmptyVendorErrors: the SSH config-backup factory
// fails closed on an empty vendor, the same as on an unknown one. Until 1.3.48
// "" built a FortiGate client, so an unclassified device was driven with
// FortiOS CLI. An unclassified device is generic now (server 0.11.290), and
// there is no generic CLI; the caller logs and skips the device.
func TestNewConfigBackupClient_EmptyVendorErrors(t *testing.T) {
	c, err := NewConfigBackupClient("", "192.0.2.10", 22, "alice", "pw")
	if err == nil {
		t.Fatalf("NewConfigBackupClient(\"\") returned %T, want an error (an empty vendor must not be driven with FortiOS CLI)", c)
	}
	if !strings.Contains(err.Error(), `vendor ""`) {
		t.Errorf("error %q should name the empty vendor", err)
	}
}
