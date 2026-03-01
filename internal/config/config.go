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
	HeartbeatInterval  time.Duration
	SyncInterval       time.Duration
}

func Load() *Config {
	return &Config{
		Probe: ProbeConfig{
			RegistrationKey: os.Getenv("PROBE_REGISTRATION_KEY"),
			ServerURL:       getEnv("PROBE_SERVER_URL", "https://stats.technicallabs.org"),
			TLSCertFile:     os.Getenv("PROBE_TLS_CERT"),
			TLSKeyFile:      os.Getenv("PROBE_TLS_KEY"),
			CACertFile:         os.Getenv("PROBE_CA_CERT"),
			InsecureSkipVerify: os.Getenv("PROBE_INSECURE_SKIP_VERIFY") == "true",
			HeartbeatInterval:  parseDurationSeconds("PROBE_HEARTBEAT_INTERVAL", 60),
			SyncInterval:       parseDurationSeconds("PROBE_SYNC_INTERVAL", 30),
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
