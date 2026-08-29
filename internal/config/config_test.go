package config

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// TestParseBool_CaseInsensitiveAndDefault_AUDIT263 pins the hardened parseBool:
// the true/false sets are matched case-insensitively (and trimmed), a value
// matching NEITHER set falls back to defaultVal WITH a warning, and an empty
// value returns defaultVal silently. Before the fix the compare was
// case-sensitive and anything but "true"/"1"/"yes" read as false — so
// "PROBE_SYSLOG_ENABLED: True" silently disabled a listener that defaults on.
func TestParseBool_CaseInsensitiveAndDefault_AUDIT263(t *testing.T) {
	const key = "PROBE_TEST_BOOL_AUDIT263"
	defer os.Unsetenv(key)

	for _, v := range []string{"true", "TRUE", "True", "1", "yes", "YES", "Yes", "  true  "} {
		os.Setenv(key, v)
		if !parseBool(key, false) {
			t.Errorf("parseBool(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"false", "FALSE", "False", "0", "no", "NO"} {
		os.Setenv(key, v)
		if parseBool(key, true) {
			t.Errorf("parseBool(%q) = true, want false", v)
		}
	}

	// Garbage falls back to defaultVal in BOTH directions.
	os.Setenv(key, "maybe")
	if !parseBool(key, true) {
		t.Errorf("garbage value should fall back to default true")
	}
	if parseBool(key, false) {
		t.Errorf("garbage value should fall back to default false")
	}

	// ...and warns.
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	os.Setenv(key, "maybe")
	_ = parseBool(key, true)
	log.SetOutput(prev)
	if !strings.Contains(buf.String(), "unrecognized boolean") {
		t.Errorf("expected a warning for a garbage boolean, got: %q", buf.String())
	}

	// Empty (unset) → default, silently.
	os.Unsetenv(key)
	if !parseBool(key, true) {
		t.Errorf("unset should return default true")
	}
	if parseBool(key, false) {
		t.Errorf("unset should return default false")
	}
}

var envKeys = []string{
	"PROBE_REGISTRATION_KEY",
	"PROBE_SERVER_URL",
	"PROBE_TLS_CERT",
	"PROBE_TLS_KEY",
	"PROBE_CA_CERT",
	"PROBE_INSECURE_SKIP_VERIFY",
	"PROBE_HEARTBEAT_INTERVAL",
	"PROBE_SYNC_INTERVAL",
	"PROBE_POLL_INTERVAL",
	"PROBE_DEVICE_REFRESH_INTERVAL",
	"PROBE_PING_INTERVAL",
	"PROBE_PING_TIMEOUT",
	"PROBE_PING_COUNT",
	"PROBE_LISTEN_ADDR",
	"PROBE_SNMP_TRAP_PORT",
	"PROBE_SYSLOG_PORT",
	"PROBE_SFLOW_PORT",
	"PROBE_SNMP_TRAP_COMMUNITY",
	"PROBE_TFTP_CONFIG_ENABLED",
	"PROBE_TFTP_PORT",
	"PROBE_MAX_QUEUE_SIZE",
	"PROBE_MAX_BATCH_SIZE",
	"PROBE_QUEUE_DISK_PATH",
	"PROBE_SNMP_TRAP_ENABLED",
	"PROBE_SYSLOG_ENABLED",
	"PROBE_SFLOW_ENABLED",
	"PROBE_PING_ENABLED",
	"PROBE_NETFLOW_SAMPLING_OVERRIDES",
}

func withClearedEnv(t *testing.T) func() {
	t.Helper()
	saved := make(map[string]string, len(envKeys))
	for _, k := range envKeys {
		if v, ok := os.LookupEnv(k); ok {
			saved[k] = v
		}
		os.Unsetenv(k)
	}
	return func() {
		for _, k := range envKeys {
			if v, ok := saved[k]; ok {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}
}

func TestConfigLoad_SNMPTrapEnabled_EmptyCommunity_OK(t *testing.T) {
	defer withClearedEnv(t)()
	// PROBE_SNMP_TRAP_COMMUNITY is an OPTIONAL allowlist filter. With traps
	// enabled (the default) and no community set, Load() must succeed —
	// community filtering is simply disabled and the receiver accepts traps
	// from any community (communities are per-device on the server).
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error for empty community: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil cfg with no error")
	}
	if !cfg.Probe.SNMPTrapEnabled {
		t.Errorf("SNMPTrapEnabled = false, want true (default)")
	}
	if cfg.Probe.TrapCommunity != "" {
		t.Errorf("TrapCommunity = %q, want empty", cfg.Probe.TrapCommunity)
	}
}

func TestConfigLoad_SNMPTrapEnabled_WithCommunity_OK(t *testing.T) {
	defer withClearedEnv(t)()
	os.Setenv("PROBE_SNMP_TRAP_COMMUNITY", "public")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil cfg with no error")
	}
	if cfg.Probe.TrapCommunity != "public" {
		t.Errorf("TrapCommunity = %q, want %q", cfg.Probe.TrapCommunity, "public")
	}
	if !cfg.Probe.SNMPTrapEnabled {
		t.Errorf("SNMPTrapEnabled = false, want true (default)")
	}
}

func TestConfigLoad_QueueDiskPath(t *testing.T) {
	defer withClearedEnv(t)()

	// Default is empty at the library level (spillover is opt-in for bare
	// binaries; the Docker image sets PROBE_QUEUE_DISK_PATH=/queue to enable
	// it for the standard deployment).
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Probe.QueueDiskPath != "" {
		t.Errorf("default QueueDiskPath = %q, want empty", cfg.Probe.QueueDiskPath)
	}

	// An explicit value is read through to the config.
	os.Setenv("PROBE_QUEUE_DISK_PATH", "/queue")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Probe.QueueDiskPath != "/queue" {
		t.Errorf("QueueDiskPath = %q, want %q", cfg.Probe.QueueDiskPath, "/queue")
	}
}

// TestConfigLoad_NetFlowSamplingOverrides pins the PROBE_NETFLOW_SAMPLING_OVERRIDES
// format: comma-separated exporterIP=rate pairs, IPs normalized through
// net.ParseIP().String() (so they match the NetFlow receiver's exporter keys),
// malformed entries skipped without discarding the valid ones.
func TestConfigLoad_NetFlowSamplingOverrides(t *testing.T) {
	defer withClearedEnv(t)()

	// Default: unset → nil (no overrides).
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Probe.NetFlowSamplingOverrides != nil {
		t.Errorf("default NetFlowSamplingOverrides = %v, want nil", cfg.Probe.NetFlowSamplingOverrides)
	}

	// Valid pairs parse; whitespace tolerated; the IPv6 form normalizes
	// (0::1 → ::1) so lookups by net.IP.String() hit.
	os.Setenv("PROBE_NETFLOW_SAMPLING_OVERRIDES", "192.0.2.1=1000, 0::1 = 512")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	ov := cfg.Probe.NetFlowSamplingOverrides
	if len(ov) != 2 || ov["192.0.2.1"] != 1000 || ov["::1"] != 512 {
		t.Errorf("NetFlowSamplingOverrides = %v, want {192.0.2.1:1000 ::1:512}", ov)
	}

	// Malformed entries (bad IP, missing =, rate 0, rate overflow, junk) are
	// skipped individually — the valid entry still lands.
	os.Setenv("PROBE_NETFLOW_SAMPLING_OVERRIDES",
		"not-an-ip=10,192.0.2.9,192.0.2.9=0,192.0.2.9=4294967296,garbage,192.0.2.7=64")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	ov = cfg.Probe.NetFlowSamplingOverrides
	if len(ov) != 1 || ov["192.0.2.7"] != 64 {
		t.Errorf("NetFlowSamplingOverrides = %v, want only {192.0.2.7:64}", ov)
	}

	// All-invalid input collapses to nil, not an empty map.
	os.Setenv("PROBE_NETFLOW_SAMPLING_OVERRIDES", "bogus")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Probe.NetFlowSamplingOverrides != nil {
		t.Errorf("all-invalid NetFlowSamplingOverrides = %v, want nil", cfg.Probe.NetFlowSamplingOverrides)
	}
}

func TestConfigLoad_SNMPTrapDisabled_EmptyCommunity_OK(t *testing.T) {
	defer withClearedEnv(t)()
	os.Setenv("PROBE_SNMP_TRAP_ENABLED", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil cfg with no error")
	}
	if cfg.Probe.SNMPTrapEnabled {
		t.Errorf("SNMPTrapEnabled = true, want false")
	}
	if cfg.Probe.TrapCommunity != "" {
		t.Errorf("TrapCommunity = %q, want empty", cfg.Probe.TrapCommunity)
	}
}
