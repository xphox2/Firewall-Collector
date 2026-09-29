package main

import (
	"os"
	"strings"
	"testing"

	"firewall-collector/internal/config"
)

func TestValidateServerURL(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"https://fwmon.example.com", true},
		{"http://192.0.2.10:8080", true},
		{"https://fwmon.example.com/base/", true},
		{"  https://fwmon.example.com  ", true},
		{"", false},
		{"   ", false},
		{"fwmon.example.com", false},
		{"ftp://fwmon.example.com", false},
		{"https://", false},
		{"://bad", false},
	}
	for _, c := range cases {
		err := validateServerURL(c.in)
		if (err == nil) != c.ok {
			t.Errorf("validateServerURL(%q) err=%v, want ok=%v", c.in, err, c.ok)
		}
	}
}

// TestServerURLHasNoDefault pins that PROBE_SERVER_URL has no built-in
// default: with the variable unset, config.Load returns an empty ServerURL
// and the startup validator rejects it, so the collector refuses to start.
func TestServerURLHasNoDefault(t *testing.T) {
	t.Setenv("PROBE_SERVER_URL", "")
	os.Unsetenv("PROBE_SERVER_URL")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Probe.ServerURL != "" {
		t.Fatalf("ServerURL default = %q, want empty (no built-in default)", cfg.Probe.ServerURL)
	}
	err = validateServerURL(cfg.Probe.ServerURL)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("validateServerURL(unset) = %v, want a 'required' error", err)
	}
}

// TestMainValidatesServerURLAfterSSHTool pins the placement of the startup
// check: after the ssh-test early return (which never loads config) and
// next to the registration-key check.
func TestMainValidatesServerURLAfterSSHTool(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "\nfunc main() {")
	if start < 0 {
		t.Fatal("func main not found")
	}
	body = body[start:]
	ssh := strings.Index(body, "isSSHToolSubcommand(os.Args[1:])")
	key := strings.Index(body, `"PROBE_REGISTRATION_KEY environment variable is required"`)
	val := strings.Index(body, "validateServerURL(probeCfg.ServerURL)")
	if ssh < 0 || key < 0 || val < 0 {
		t.Fatalf("main() markers missing: ssh=%d key=%d validate=%d", ssh, key, val)
	}
	if !(ssh < key && key < val) {
		t.Fatalf("validateServerURL must run after the ssh-test return and the registration-key check (ssh=%d key=%d validate=%d)", ssh, key, val)
	}
}
