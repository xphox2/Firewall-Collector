package config

import (
	"os"
	"testing"
)

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
