package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"firewall-collector/internal/config"
	"firewall-collector/internal/relay"
)

func main() {
	log.Println("=== Firewall Collector Starting ===")
	log.Printf("Version: 1.0.0")

	cfg := config.Load()

	registrationKey := cfg.Probe.RegistrationKey
	if registrationKey == "" {
		log.Fatal("PROBE_REGISTRATION_KEY environment variable is required")
	}

	log.Printf("Server URL: %s", cfg.Probe.ServerURL)

	relayClient := relay.NewClient(relay.Config{
		ServerURL:          cfg.Probe.ServerURL,
		RegistrationKey:    registrationKey,
		SyncInterval:       cfg.Probe.SyncInterval,
		HeartbeatInterval:  cfg.Probe.HeartbeatInterval,
		TLSCertFile:        cfg.Probe.TLSCertFile,
		TLSKeyFile:         cfg.Probe.TLSKeyFile,
		CACertFile:         cfg.Probe.CACertFile,
		InsecureSkipVerify: cfg.Probe.InsecureSkipVerify,
	})

	if err := relayClient.Register(); err != nil {
		log.Fatalf("Failed to register probe: %v", err)
	}
	log.Printf("Probe registered with ID: %d (Name: %s)", relayClient.GetProbeID(), relayClient.GetProbeName())

	go func() {
		if err := relayClient.HeartbeatLoop(); err != nil {
			log.Printf("Heartbeat error: %v", err)
		}
	}()

	go func() {
		if err := relayClient.DataSendLoop(); err != nil {
			log.Printf("Data send loop error: %v", err)
		}
	}()

	log.Println("Collector running. Map this collector to sites in the admin panel.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	relayClient.Stop()
	time.Sleep(2 * time.Second)
	log.Println("Collector stopped")
}
