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
	RegistrationKey    string
	ServerURL          string
	TLSCertFile        string
	TLSKeyFile         string
	CACertFile         string
	InsecureSkipVerify bool

	HeartbeatInterval     time.Duration
	SyncInterval          time.Duration
	PollInterval          time.Duration
	DeviceRefreshInterval time.Duration
	PingInterval          time.Duration
	PingTimeout           time.Duration
	PingCount             int

	ListenAddr    string
	SNMPTrapPort  int
	SyslogPort    int
	SFlowPort     int
	TrapCommunity string

	TFTPConfigEnabled bool
	TFTPListenAddr    string

	MaxQueueSize int
	MaxBatchSize int

	// QueueDiskPath is the directory for the disk-spillover queues (AUDIT-058).
	// Empty disables spillover — telemetry is dropped (not buffered) while the
	// central server is unreachable. Set it to a writable, persistent directory
	// to survive server outages and restarts. The Docker image defaults it to
	// /queue (created and chowned to the rootless uid; mount a volume there).
	QueueDiskPath string

	SNMPTrapEnabled bool
	SyslogEnabled   bool
	SFlowEnabled    bool
	PingEnabled     bool
}

func Load() (*Config, error) {
	cfg := &Config{
		Probe: ProbeConfig{
			RegistrationKey:    os.Getenv("PROBE_REGISTRATION_KEY"),
			ServerURL:          GetEnv("PROBE_SERVER_URL", "https://stats.technicallabs.org"),
			TLSCertFile:        os.Getenv("PROBE_TLS_CERT"),
			TLSKeyFile:         os.Getenv("PROBE_TLS_KEY"),
			CACertFile:         os.Getenv("PROBE_CA_CERT"),
			InsecureSkipVerify: os.Getenv("PROBE_INSECURE_SKIP_VERIFY") == "true",

			HeartbeatInterval:     parseDurationSeconds("PROBE_HEARTBEAT_INTERVAL", 60),
			SyncInterval:          parseDurationSeconds("PROBE_SYNC_INTERVAL", 30),
			PollInterval:          parseDurationSeconds("PROBE_POLL_INTERVAL", 60),
			DeviceRefreshInterval: parseDurationSeconds("PROBE_DEVICE_REFRESH_INTERVAL", 300),
			PingInterval:          parseDurationSeconds("PROBE_PING_INTERVAL", 60),
			PingTimeout:           parseDurationSeconds("PROBE_PING_TIMEOUT", 5),
			PingCount:             parseInt("PROBE_PING_COUNT", 4),

			ListenAddr:    GetEnv("PROBE_LISTEN_ADDR", "0.0.0.0"),
			SNMPTrapPort:  parseInt("PROBE_SNMP_TRAP_PORT", 162),
			SyslogPort:    parseInt("PROBE_SYSLOG_PORT", 514),
			SFlowPort:     parseInt("PROBE_SFLOW_PORT", 6343),
			TrapCommunity: os.Getenv("PROBE_SNMP_TRAP_COMMUNITY"),

			TFTPConfigEnabled: parseBool("PROBE_TFTP_CONFIG_ENABLED", true),
			TFTPListenAddr:    GetEnv("PROBE_LISTEN_ADDR", "0.0.0.0") + ":" + GetEnv("PROBE_TFTP_PORT", "69"),

			MaxQueueSize: parseInt("PROBE_MAX_QUEUE_SIZE", 10000),
			MaxBatchSize: parseInt("PROBE_MAX_BATCH_SIZE", 1000),

			QueueDiskPath: os.Getenv("PROBE_QUEUE_DISK_PATH"),

			SNMPTrapEnabled: parseBool("PROBE_SNMP_TRAP_ENABLED", true),
			SyslogEnabled:   parseBool("PROBE_SYSLOG_ENABLED", true),
			SFlowEnabled:    parseBool("PROBE_SFLOW_ENABLED", true),
			PingEnabled:     parseBool("PROBE_PING_ENABLED", true),
		},
	}

	// PROBE_SNMP_TRAP_COMMUNITY is an OPTIONAL allowlist filter, not a
	// requirement. SNMP communities are configured per-device on the server,
	// so there is rarely a single shared trap community. Leave it empty to
	// accept traps from any community (the snmptrapd default); set it only to
	// restrict the receiver to one community. The trap receiver logs a warning
	// at startup when filtering is disabled (see snmp.TrapReceiver.Start).

	return cfg, nil
}

// GetEnv returns the value of the named environment variable, or defaultValue
// when it is unset or empty. Exported so callers outside this package (e.g.
// cmd/collector) share one implementation instead of duplicating it (L16).
func GetEnv(key, defaultValue string) string {
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
