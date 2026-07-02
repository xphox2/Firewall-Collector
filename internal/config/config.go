package config

import (
	"log"
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

	// Per-source-IP UDP rate limiting for the sFlow/syslog/trap receivers. Each
	// listener has its OWN limiter with per-listener limits, because their normal
	// volumes differ by orders of magnitude: one FortiGate's traffic logging over
	// syslog can be thousands of msgs/sec, while sFlow datagrams and SNMP traps
	// are low-rate. A single collector serving dozens of firewalls therefore gets
	// a high syslog ceiling (so legitimate logs are never dropped) but tight
	// sFlow/trap limits (where a flood is abnormal). Each firewall is a distinct
	// source IP, so it gets its own per-source bucket — one chatty or hostile
	// firewall can't consume another's budget. Burst is auto-set to 2× the
	// per-source rate. On by default with headroom well above real-world rates.
	RateLimitEnabled    bool
	RateLimitMaxSources int // max distinct source IPs tracked per listener (memory bound)

	// UDPWorkers is the number of parallel receive sockets/goroutines per
	// high-volume UDP listener (sFlow, syslog) via SO_REUSEPORT. Default 1 (single
	// socket, current behavior). Set >1 to spread receive+parse across cores when
	// the receive goroutine is CPU-bound — Linux only (clamped to 1 elsewhere).
	UDPWorkers int

	SFlowRateLimitPPS        int // per-source datagrams/sec (sFlow)
	SFlowRateLimitGlobalPPS  int // aggregate ceiling across all sFlow sources
	SyslogRateLimitPPS       int // per-source msgs/sec (syslog — high: traffic logs)
	SyslogRateLimitGlobalPPS int // aggregate ceiling across all syslog sources
	TrapRateLimitPPS         int // per-source traps/sec
	TrapRateLimitGlobalPPS   int // aggregate ceiling across all trap sources
}

func Load() (*Config, error) {
	cfg := &Config{
		Probe: ProbeConfig{
			RegistrationKey: os.Getenv("PROBE_REGISTRATION_KEY"),
			ServerURL:       GetEnv("PROBE_SERVER_URL", "https://stats.technicallabs.org"),
			TLSCertFile:     os.Getenv("PROBE_TLS_CERT"),
			TLSKeyFile:      os.Getenv("PROBE_TLS_KEY"),
			CACertFile:      os.Getenv("PROBE_CA_CERT"),
			// M23 of the 2026-07-01 audit: use parseBool so the documented
			// `1`/`yes` forms work (the raw `== "true"` silently ignored them,
			// leaving TLS verification ON for an operator who wrote `=1`).
			InsecureSkipVerify: parseBool("PROBE_INSECURE_SKIP_VERIFY", false),

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
			// M1 of the 2026-07-01 audit: the server hard-caps ingestion
			// batches at 1000 items (100 for system-status) and, pre-fix,
			// TRUNCATED the tail silently — so any operator-raised value
			// above 1000 lost the tail of every batch permanently (the
			// batch ID was marked processed, defeating retry). Clamp here
			// so a misconfigured value can never cause loss; clampBatchSize
			// logs when it engages.
			MaxBatchSize: clampBatchSize(parseInt("PROBE_MAX_BATCH_SIZE", 1000)),

			QueueDiskPath: os.Getenv("PROBE_QUEUE_DISK_PATH"),

			SNMPTrapEnabled: parseBool("PROBE_SNMP_TRAP_ENABLED", true),
			SyslogEnabled:   parseBool("PROBE_SYSLOG_ENABLED", true),
			SFlowEnabled:    parseBool("PROBE_SFLOW_ENABLED", true),
			PingEnabled:     parseBool("PROBE_PING_ENABLED", true),

			RateLimitEnabled:    parseBool("PROBE_RATE_LIMIT_ENABLED", true),
			RateLimitMaxSources: parseInt("PROBE_RATE_LIMIT_MAX_SOURCES", 8192),

			UDPWorkers: parseInt("PROBE_UDP_WORKERS", 1),

			// sFlow: per-agent datagram rate is low even at high sampling, so a
			// flood is abnormal — keep it tight.
			SFlowRateLimitPPS:       parseInt("PROBE_SFLOW_RATE_LIMIT_PPS", 1000),
			SFlowRateLimitGlobalPPS: parseInt("PROBE_SFLOW_RATE_LIMIT_GLOBAL_PPS", 30000),
			// Syslog: FortiGate traffic logging can emit thousands of msgs/sec per
			// firewall; a collector serving dozens needs a high ceiling so real
			// logs are never dropped.
			SyslogRateLimitPPS:       parseInt("PROBE_SYSLOG_RATE_LIMIT_PPS", 5000),
			SyslogRateLimitGlobalPPS: parseInt("PROBE_SYSLOG_RATE_LIMIT_GLOBAL_PPS", 100000),
			// Traps: event-driven, low-rate.
			TrapRateLimitPPS:       parseInt("PROBE_TRAP_RATE_LIMIT_PPS", 500),
			TrapRateLimitGlobalPPS: parseInt("PROBE_TRAP_RATE_LIMIT_GLOBAL_PPS", 10000),
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

// serverMaxBatchItems is the central server's hard per-request ingestion cap
// (Firewall-Mon handlers_data.go). Batches above it are truncated server-side,
// so sending more than this per request can only lose data.
const serverMaxBatchItems = 1000

// clampBatchSize bounds PROBE_MAX_BATCH_SIZE to the server's ingestion cap
// (M1 of the 2026-07-01 audit — see the call site).
func clampBatchSize(v int) int {
	if v > serverMaxBatchItems {
		log.Printf("PROBE_MAX_BATCH_SIZE=%d exceeds the server's %d-item ingestion cap; clamping to %d (larger batches would be truncated server-side)", v, serverMaxBatchItems, serverMaxBatchItems)
		return serverMaxBatchItems
	}
	return v
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
