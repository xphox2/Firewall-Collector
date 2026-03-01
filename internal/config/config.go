package config

import (
	"os"
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
		},
	}
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
