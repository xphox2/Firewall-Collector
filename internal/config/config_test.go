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
	"PROBE_SNMP_TRAP_ENABLED",
	"PROBE_SYSLOG_ENABLED",
	"PROBE_SFLOW_ENABLED",
	"PROBE_PING_ENABLED",
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
