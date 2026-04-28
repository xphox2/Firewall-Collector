package main

import (
	"crypto/md5"
	"fmt"
	"testing"
)

func TestDevIDFromFilename_ValidFormat(t *testing.T) {
	tests := []struct {
		filename string
		wantID   uint
	}{
		{"fgt_42_config", 42},
		{"fgt_1_config", 1},
		{"fgt_999_config", 999},
	}
	for _, tt := range tests {
		got := devIDFromFilename(tt.filename)
		if got != tt.wantID {
			t.Errorf("devIDFromFilename(%q) = %d, want %d", tt.filename, got, tt.wantID)
		}
	}
}

func TestDevIDFromFilename_InvalidFormat(t *testing.T) {
	invalid := []string{
		"nounderscores",
		"fgt_notanumber_config",
		"",
		"_",
	}
	for _, fname := range invalid {
		got := devIDFromFilename(fname)
		if got != 0 {
			t.Errorf("devIDFromFilename(%q) = %d, want 0 for invalid input", fname, got)
		}
	}
}

func TestChecksumFromData_MD5Format(t *testing.T) {
	data := []byte("hello world")
	got := checksumFromData(data)
	if len(got) != 32 {
		t.Errorf("checksumFromData returned %d-char string, want 32 (MD5 hex)", len(got))
	}
	// Verify it's valid hex
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("checksum contains non-hex character %q", c)
		}
	}
}

func TestChecksumFromData_Deterministic(t *testing.T) {
	data := []byte("test config data")
	a := checksumFromData(data)
	b := checksumFromData(data)
	if a != b {
		t.Errorf("checksumFromData not deterministic: %q != %q", a, b)
	}
}

func TestChecksumFromData_MatchesMD5(t *testing.T) {
	data := []byte("FortiGate config backup")
	got := checksumFromData(data)
	h := md5.Sum(data)
	want := fmt.Sprintf("%x", h)
	if got != want {
		t.Errorf("checksumFromData = %q, want %q", got, want)
	}
}

func TestParseUploadFilename(t *testing.T) {
	tests := []struct {
		filename    string
		wantID      uint
		wantTrigger string
	}{
		// New 4-part format with embedded trigger
		{"fgt_42_syslog_config", 42, "syslog"},
		{"fgt_42_poll_config", 42, "poll"},
		{"fgt_42_manual_config", 42, "manual"},
		// Legacy 3-part format defaults to "poll"
		{"fgt_42_config", 42, "poll"},
		// Unknown trigger token: fall back to "poll" rather than trust arbitrary input
		{"fgt_42_garbage_config", 42, "poll"},
		// Invalid: empty / no underscores / non-numeric
		{"nounderscores", 0, "poll"},
		{"fgt_notanumber_syslog_config", 0, "poll"},
		{"", 0, "poll"},
	}
	for _, tt := range tests {
		gotID, gotTrigger := parseUploadFilename(tt.filename)
		if gotID != tt.wantID || gotTrigger != tt.wantTrigger {
			t.Errorf("parseUploadFilename(%q) = (%d, %q), want (%d, %q)",
				tt.filename, gotID, gotTrigger, tt.wantID, tt.wantTrigger)
		}
	}
}

func TestDetectBackupQuality(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"normal full backup", "config system global\n    set hostname \"FW\"\nend\n", "full"},
		{"masked via config_masked_password", "set foo bar\nconfig_masked_password\nset baz qux\n", "masked"},
		{"masked via ENC <removed>", "set password ENC <removed>\n", "masked"},
		{"empty", "", "full"},
	}
	for _, tt := range tests {
		got := detectBackupQuality([]byte(tt.data))
		if got != tt.want {
			t.Errorf("detectBackupQuality(%s) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
