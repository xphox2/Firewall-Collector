package main

import (
	"os"
	"strings"
	"testing"

	"firewall-collector/internal/config"
)

func TestNormalizeServerURL(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want string
	}{
		{"https://fwmon.example.com", true, "https://fwmon.example.com"},
		{"http://192.0.2.10:8080", true, "http://192.0.2.10:8080"},
		{"https://fwmon.example.com/base/", true, "https://fwmon.example.com/base"},
		{"  https://fwmon.example.com  ", true, "https://fwmon.example.com"},
		{" https://fwmon.example.com// \t", true, "https://fwmon.example.com"},
		{"https://fwmon.example.com/", true, "https://fwmon.example.com"},
		{"", false, ""},
		{"   ", false, ""},
		{"/", false, ""},
		{"fwmon.example.com", false, ""},
		{"ftp://fwmon.example.com", false, ""},
		{"https://", false, ""},
		{"://bad", false, ""},
	}
	for _, c := range cases {
		got, err := normalizeServerURL(c.in)
		if (err == nil) != c.ok {
			t.Errorf("normalizeServerURL(%q) err=%v, want ok=%v", c.in, err, c.ok)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeServerURL(%q) = %q, want %q", c.in, got, c.want)
		}
		// The relay appends "/api/..." to this value: a trailing slash would
		// double it.
		if strings.HasSuffix(got, "/") {
			t.Errorf("normalizeServerURL(%q) = %q ends in a slash", c.in, got)
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
	_, err = normalizeServerURL(cfg.Probe.ServerURL)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("normalizeServerURL(unset) = %v, want a 'required' error", err)
	}
}

// TestMainValidatesServerURLAfterSSHTool pins the placement of the startup
// check: after the ssh-test early return (which never loads config) and
// next to the registration-key check. It also pins that the normalised value
// is written back to the config before the relay client is built from it.
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
	val := strings.Index(body, "normalizeServerURL(probeCfg.ServerURL)")
	assign := strings.Index(body, "probeCfg.ServerURL = serverURL")
	relayUse := strings.Index(body, "ServerURL:          probeCfg.ServerURL,")
	if ssh < 0 || key < 0 || val < 0 || assign < 0 || relayUse < 0 {
		t.Fatalf("main() markers missing: ssh=%d key=%d validate=%d assign=%d relay=%d", ssh, key, val, assign, relayUse)
	}
	if !(ssh < key && key < val) {
		t.Fatalf("normalizeServerURL must run after the ssh-test return and the registration-key check (ssh=%d key=%d validate=%d)", ssh, key, val)
	}
	if !(val < assign && assign < relayUse) {
		t.Fatalf("the normalised server URL must be assigned back before the relay client is built (validate=%d assign=%d relay=%d)", val, assign, relayUse)
	}
}
