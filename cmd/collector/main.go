package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"firewall-collector/internal/config"
	"firewall-collector/internal/ping"
	"firewall-collector/internal/relay"
	"firewall-collector/internal/sflow"
	"firewall-collector/internal/snmp"
	"firewall-collector/internal/syslog"
)

const version = "1.1.8"

type Collector struct {
	cfg           *config.ProbeConfig
	relayClient   *relay.Client
	trapReceiver  *snmp.TrapReceiver
	syslogTCP     *syslog.SyslogReceiver
	syslogUDP     *syslog.UDPSyslogReceiver
	sflowReceiver *sflow.SFlowReceiver
	pingCollector *ping.PingCollector
	devices       []relay.DeviceInfo
	deviceMu      sync.RWMutex
	stopChan      chan struct{}
	pollWg        sync.WaitGroup
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg := config.Load()
	probeCfg := &cfg.Probe

	if probeCfg.RegistrationKey == "" {
		log.Fatal("PROBE_REGISTRATION_KEY environment variable is required")
	}

	fmt.Println("========================================")
	fmt.Println("  Firewall Collector Starting")
	fmt.Printf("  Version: %s\n", version)
	fmt.Println("========================================")
	fmt.Printf("  Server URL:      %s\n", probeCfg.ServerURL)
	fmt.Printf("  Poll Interval:   %v\n", probeCfg.PollInterval)
	fmt.Printf("  Sync Interval:   %v\n", probeCfg.SyncInterval)
	fmt.Printf("  SNMP Trap:       %v (port %d)\n", probeCfg.SNMPTrapEnabled, probeCfg.SNMPTrapPort)
	fmt.Printf("  Syslog:          %v (port %d)\n", probeCfg.SyslogEnabled, probeCfg.SyslogPort)
	fmt.Printf("  sFlow:           %v (port %d)\n", probeCfg.SFlowEnabled, probeCfg.SFlowPort)
	fmt.Printf("  Ping:            %v (interval %v)\n", probeCfg.PingEnabled, probeCfg.PingInterval)
	fmt.Println("========================================")
	fmt.Println()

	relayClient := relay.NewClient(relay.Config{
		ServerURL:          probeCfg.ServerURL,
		RegistrationKey:    probeCfg.RegistrationKey,
		SyncInterval:       probeCfg.SyncInterval,
		HeartbeatInterval:  probeCfg.HeartbeatInterval,
		TLSCertFile:        probeCfg.TLSCertFile,
		TLSKeyFile:         probeCfg.TLSKeyFile,
		CACertFile:         probeCfg.CACertFile,
		InsecureSkipVerify: probeCfg.InsecureSkipVerify,
	})

	// Register with server
	fmt.Println("[1/6] Registering with server...")
	if err := relayClient.Register(); err != nil {
		log.Fatalf("Failed to register: %v", err)
	}
	fmt.Printf("  -> Registered as '%s' (ID: %d)\n\n", relayClient.GetProbeName(), relayClient.GetProbeID())

	c := &Collector{
		cfg:         probeCfg,
		relayClient: relayClient,
		stopChan:    make(chan struct{}),
	}

	// Start heartbeat + data sync loops
	fmt.Println("[2/6] Starting heartbeat and data sync loops...")
	go func() {
		if err := relayClient.HeartbeatLoop(); err != nil {
			log.Printf("Heartbeat loop error: %v", err)
		}
	}()
	go func() {
		if err := relayClient.DataSendLoop(); err != nil {
			log.Printf("Data send loop error: %v", err)
		}
	}()
	fmt.Printf("  -> Heartbeat every %v, sync every %v\n\n", probeCfg.HeartbeatInterval, probeCfg.SyncInterval)

	// Fetch initial device list
	fmt.Println("[3/6] Fetching device list...")
	if devices, err := relayClient.FetchDevices(); err != nil {
		log.Printf("  -> Initial device fetch failed: %v", err)
	} else {
		c.deviceMu.Lock()
		c.devices = devices
		c.deviceMu.Unlock()
		fmt.Printf("  -> %d devices assigned\n", len(devices))
	}
	fmt.Println()

	// Start SNMP polling + device refresh
	fmt.Println("[4/6] Starting SNMP polling...")
	go c.snmpPollingLoop()
	go c.deviceRefreshLoop()
	fmt.Printf("  -> Polling every %v, device refresh every %v\n\n", probeCfg.PollInterval, probeCfg.DeviceRefreshInterval)

	// Conditionally start receivers
	fmt.Println("[5/6] Starting receivers...")
	probeID := relayClient.GetProbeID()

	if probeCfg.SNMPTrapEnabled {
		trapReceiver := snmp.NewTrapReceiver(probeCfg.ListenAddr, probeCfg.SNMPTrapPort, probeCfg.TrapCommunity)
		if err := trapReceiver.Start(func(trap *relay.TrapEvent) {
			trap.ProbeID = probeID
			if trap.DeviceID == 0 {
				trap.DeviceID = c.resolveDeviceByIP(trap.SourceIP)
			}
			relayClient.SendTrap(trap)
		}); err != nil {
			log.Printf("  -> SNMP Trap failed to start: %v", err)
		} else {
			c.trapReceiver = trapReceiver
			fmt.Printf("  -> SNMP Trap on %s:%d\n", probeCfg.ListenAddr, probeCfg.SNMPTrapPort)
		}
	}

	if probeCfg.SyslogEnabled {
		syslogTCP := syslog.NewSyslogReceiver(probeCfg.ListenAddr, probeCfg.SyslogPort)
		if err := syslogTCP.Start(func(msg *relay.SyslogMessage) {
			msg.ProbeID = probeID
			relayClient.SendSyslogMessage(msg)
		}); err != nil {
			log.Printf("  -> Syslog TCP failed to start: %v", err)
		} else {
			c.syslogTCP = syslogTCP
		}

		syslogUDP := syslog.NewUDPSyslogReceiver(probeCfg.ListenAddr, probeCfg.SyslogPort)
		if err := syslogUDP.Start(func(msg *relay.SyslogMessage) {
			msg.ProbeID = probeID
			relayClient.SendSyslogMessage(msg)
		}); err != nil {
			log.Printf("  -> Syslog UDP failed to start: %v", err)
		} else {
			c.syslogUDP = syslogUDP
			fmt.Printf("  -> Syslog TCP+UDP on %s:%d\n", probeCfg.ListenAddr, probeCfg.SyslogPort)
		}
	}

	if probeCfg.SFlowEnabled {
		sflowReceiver := sflow.NewSFlowReceiver(probeCfg.ListenAddr, probeCfg.SFlowPort)
		if err := sflowReceiver.Start(func(sample *relay.FlowSample) {
			sample.ProbeID = probeID
			if sample.DeviceID == 0 {
				sample.DeviceID = c.resolveDeviceByIP(sample.SamplerAddress)
			}
			relayClient.SendFlowSample(sample)
		}); err != nil {
			log.Printf("  -> sFlow failed to start: %v", err)
		} else {
			c.sflowReceiver = sflowReceiver
			fmt.Printf("  -> sFlow on %s:%d\n", probeCfg.ListenAddr, probeCfg.SFlowPort)
		}
	}

	if probeCfg.PingEnabled {
		c.deviceMu.RLock()
		devices := make([]relay.DeviceInfo, len(c.devices))
		copy(devices, c.devices)
		c.deviceMu.RUnlock()

		pingCollector := ping.NewPingCollector(probeCfg.PingInterval, probeCfg.PingTimeout, probeCfg.PingCount)
		pingCollector.Start(devices, probeID, func(result *relay.PingResult) {
			relayClient.SendPingResult(result)
		})
		c.pingCollector = pingCollector
		fmt.Printf("  -> Ping every %v\n", probeCfg.PingInterval)
	}
	fmt.Println()

	fmt.Println("[6/6] Collector is running")
	fmt.Println("========================================")
	fmt.Println()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println()
	fmt.Println("Shutting down collector...")
	c.stop()
	fmt.Println("Collector stopped")
}

func (c *Collector) snmpPollingLoop() {
	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	sem := make(chan struct{}, 10) // Limit concurrent SNMP polls

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.deviceMu.RLock()
			devices := make([]relay.DeviceInfo, len(c.devices))
			copy(devices, c.devices)
			c.deviceMu.RUnlock()

			for _, dev := range devices {
				if !dev.Enabled {
					continue
				}
				c.pollWg.Add(1)
				sem <- struct{}{} // Acquire semaphore slot
				go func(d relay.DeviceInfo) {
					defer c.pollWg.Done()
					defer func() { <-sem }() // Release semaphore slot
					c.pollDevice(d)
				}(dev)
			}
		}
	}
}

func (c *Collector) pollDevice(dev relay.DeviceInfo) {
	var v3 *snmp.SNMPv3Config
	if dev.SNMPVersion == "3" {
		v3 = &snmp.SNMPv3Config{
			Username: dev.SNMPV3Username,
			AuthType: dev.SNMPV3AuthType,
			AuthPass: dev.SNMPV3AuthPass,
			PrivType: dev.SNMPV3PrivType,
			PrivPass: dev.SNMPV3PrivPass,
		}
	}

	client, err := snmp.NewSNMPClient(dev.IPAddress, dev.SNMPPort, dev.SNMPCommunity, dev.SNMPVersion, v3)
	if err != nil {
		log.Printf("[SNMP] Connect failed for %s (%s): %v", dev.Name, dev.IPAddress, err)
		return
	}
	defer client.Close()

	// Poll system status
	status, err := client.GetSystemStatus()
	if err != nil {
		log.Printf("[SNMP] Poll failed for %s (%s): %v", dev.Name, dev.IPAddress, err)
		return
	}

	status.DeviceID = dev.ID
	status.Timestamp = time.Now()
	if err := c.relayClient.SendSystemStatuses([]relay.SystemStatus{*status}); err != nil {
		log.Printf("[SNMP] Failed to send system status for %s: %v", dev.Name, err)
	}

	// Poll interface stats
	ifaces, err := client.GetInterfaceStats()
	if err != nil {
		log.Printf("[SNMP] Interface poll failed for %s: %v", dev.Name, err)
		return
	}

	now := time.Now()
	for i := range ifaces {
		ifaces[i].DeviceID = dev.ID
		ifaces[i].Timestamp = now
	}
	if err := c.relayClient.SendInterfaceStats(ifaces); err != nil {
		log.Printf("[SNMP] Failed to send interface stats for %s: %v", dev.Name, err)
	}

	// Collect VPN tunnel status (silently skip if device has no VPN)
	vpnStatuses, vpnErr := client.GetVPNStatus()
	if vpnErr == nil && len(vpnStatuses) > 0 {
		for i := range vpnStatuses {
			vpnStatuses[i].DeviceID = dev.ID
			vpnStatuses[i].Timestamp = now
		}
		if err := c.relayClient.SendVPNStatuses(vpnStatuses); err != nil {
			log.Printf("[SNMP] Failed to send VPN statuses for %s: %v", dev.Name, err)
		}
	}
}

func (c *Collector) deviceRefreshLoop() {
	ticker := time.NewTicker(c.cfg.DeviceRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			devices, err := c.relayClient.FetchDevices()
			if err != nil {
				log.Printf("[Devices] Refresh failed: %v", err)
				continue
			}

			c.deviceMu.Lock()
			c.devices = devices
			c.deviceMu.Unlock()

			log.Printf("[Devices] Refreshed: %d devices", len(devices))

			if c.pingCollector != nil {
				c.pingCollector.UpdateDevices(devices)
			}
		}
	}
}

// resolveDeviceByIP maps an sFlow agent IP to a device ID from the known device list.
func (c *Collector) resolveDeviceByIP(ip string) uint {
	c.deviceMu.RLock()
	defer c.deviceMu.RUnlock()
	for _, d := range c.devices {
		if d.IPAddress == ip {
			return d.ID
		}
	}
	return 0
}

func (c *Collector) stop() {
	close(c.stopChan)

	// Wait for in-flight SNMP polls to finish
	c.pollWg.Wait()

	if c.trapReceiver != nil {
		c.trapReceiver.Stop()
	}
	if c.syslogTCP != nil {
		c.syslogTCP.Stop()
	}
	if c.syslogUDP != nil {
		c.syslogUDP.Stop()
	}
	if c.sflowReceiver != nil {
		c.sflowReceiver.Stop()
	}
	if c.pingCollector != nil {
		c.pingCollector.Stop()
	}

	c.relayClient.Stop()
}
