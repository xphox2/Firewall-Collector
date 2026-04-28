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
