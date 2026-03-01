package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Probe ProbeConfig
}

type ProbeConfig struct {
	// Server connection
	RegistrationKey    string
	ServerURL          string
	TLSCertFile        string
	TLSKeyFile         string
	CACertFile         string
	InsecureSkipVerify bool

	// Intervals
	HeartbeatInterval      time.Duration
	SyncInterval           time.Duration
	PollInterval           time.Duration
	DeviceRefreshInterval  time.Duration
	PingInterval           time.Duration
	PingTimeout            time.Duration
	PingCount              int

	// Listener config
	ListenAddr    string
	SNMPTrapPort  int
	SyslogPort    int
	SFlowPort     int
	TrapCommunity string

	// Feature toggles
	SNMPTrapEnabled bool
	SyslogEnabled   bool
	SFlowEnabled    bool
	PingEnabled     bool
}

func Load() *Config {
	return &Config{
		Probe: ProbeConfig{
			// Server connection
			RegistrationKey:    os.Getenv("PROBE_REGISTRATION_KEY"),
			ServerURL:          getEnv("PROBE_SERVER_URL", "https://stats.technicallabs.org"),
			TLSCertFile:        os.Getenv("PROBE_TLS_CERT"),
			TLSKeyFile:         os.Getenv("PROBE_TLS_KEY"),
			CACertFile:         os.Getenv("PROBE_CA_CERT"),
			InsecureSkipVerify: os.Getenv("PROBE_INSECURE_SKIP_VERIFY") == "true",

			// Intervals
			HeartbeatInterval:     parseDurationSeconds("PROBE_HEARTBEAT_INTERVAL", 60),
			SyncInterval:          parseDurationSeconds("PROBE_SYNC_INTERVAL", 30),
			PollInterval:          parseDurationSeconds("PROBE_POLL_INTERVAL", 60),
			DeviceRefreshInterval: parseDurationSeconds("PROBE_DEVICE_REFRESH_INTERVAL", 300),
			PingInterval:          parseDurationSeconds("PROBE_PING_INTERVAL", 60),
			PingTimeout:           parseDurationSeconds("PROBE_PING_TIMEOUT", 5),
			PingCount:             parseInt("PROBE_PING_COUNT", 4),

			// Listener config
			ListenAddr:    getEnv("PROBE_LISTEN_ADDR", "0.0.0.0"),
			SNMPTrapPort:  parseInt("PROBE_SNMP_TRAP_PORT", 162),
			SyslogPort:    parseInt("PROBE_SYSLOG_PORT", 514),
			SFlowPort:     parseInt("PROBE_SFLOW_PORT", 6343),
			TrapCommunity: os.Getenv("PROBE_SNMP_TRAP_COMMUNITY"),

			// Feature toggles (default enabled)
			SNMPTrapEnabled: parseBool("PROBE_SNMP_TRAP_ENABLED", true),
			SyslogEnabled:   parseBool("PROBE_SYSLOG_ENABLED", true),
			SFlowEnabled:    parseBool("PROBE_SFLOW_ENABLED", true),
			PingEnabled:     parseBool("PROBE_PING_ENABLED", true),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func parseDurationSeconds(envKey string, defaultSeconds int) time.Duration {
	if v := os.Getenv(envKey); v != "" {
		if seconds, err := strconv.Atoi(v); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return time.Duration(defaultSeconds) * time.Second
}

func parseInt(envKey string, defaultVal int) int {
	if v := os.Getenv(envKey); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			return parsed
		}
	}
	return defaultVal
}

func parseBool(envKey string, defaultVal bool) bool {
	v := os.Getenv(envKey)
	if v == "" {
		return defaultVal
	}
	return v == "true" || v == "1" || v == "yes"
}
