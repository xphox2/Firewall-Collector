package main

import (
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"firewall-collector/internal/config"
	"firewall-collector/internal/ping"
	"firewall-collector/internal/relay"
	"firewall-collector/internal/sflow"
	"firewall-collector/internal/snmp"
	"firewall-collector/internal/ssh"
	"firewall-collector/internal/syslog"
	"firewall-collector/internal/tftp"
)

const version = "1.2.32"

type Collector struct {
	cfg           *config.ProbeConfig
	relayClient   *relay.Client
	trapReceiver  *snmp.TrapReceiver
	syslogTCP     *syslog.SyslogReceiver
	syslogUDP     *syslog.UDPSyslogReceiver
	sflowReceiver *sflow.SFlowReceiver
	pingCollector *ping.PingCollector
	tftpServer    *tftp.Server
	tftpListenIP  string
	devices       []relay.DeviceInfo
	deviceMu      sync.RWMutex
	ifaceIPMap    map[string]uint // interface IP → device ID cache
	ifaceIPMu     sync.RWMutex
	stopChan      chan struct{}
	pollWg        sync.WaitGroup
	// Circuit breaker: consecutive failure counts per device
	failCount   map[uint]int
	failCountMu sync.Mutex
	// SSH polling: last poll time per device ID
	sshLastPoll   map[uint]time.Time
	sshLastPollMu sync.Mutex
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

	relay.ConfigureLimits(probeCfg.MaxQueueSize, probeCfg.MaxBatchSize)

	relayClient := relay.NewClient(relay.Config{
		ServerURL:          probeCfg.ServerURL,
		RegistrationKey:    probeCfg.RegistrationKey,
		SyncInterval:       probeCfg.SyncInterval,
		HeartbeatInterval:  probeCfg.HeartbeatInterval,
		TLSCertFile:        probeCfg.TLSCertFile,
		TLSKeyFile:         probeCfg.TLSKeyFile,
		CACertFile:         probeCfg.CACertFile,
		InsecureSkipVerify: probeCfg.InsecureSkipVerify,
		MaxBatchSize:       probeCfg.MaxBatchSize,
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
		failCount:   make(map[uint]int),
	}

	// Start TFTP server for config fetch if enabled
	if probeCfg.TFTPConfigEnabled {
		fmt.Println("[TFTP] TFTP config backup enabled - starting TFTP server...")
		c.startTFTPServer()
	} else {
		fmt.Println("[TFTP] TFTP config backup disabled")
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
		for _, d := range devices {
			community := d.SNMPCommunity
			if len(community) > 2 {
				community = community[:2] + "****"
			}
			enabledStr := "enabled"
			if !d.Enabled {
				enabledStr = "DISABLED"
			}
			fmt.Printf("     %s (id=%d) %s:%d v%s community=%s vendor=%s [%s]\n",
				d.Name, d.ID, d.IPAddress, d.SNMPPort, d.SNMPVersion, community, d.Vendor, enabledStr)
			if d.SSHPollEnabled {
				log.Printf("[SSH] TFTP candidate: device id=%d name=%s ip=%s ssh_port=%d", d.ID, d.Name, d.IPAddress, d.SSHPort)
			}
		}
	}
	fmt.Println()

	// Run SNMP connectivity diagnostic on first enabled device
	c.runStartupDiagnostic()

	// Start SNMP polling + device refresh
	fmt.Println("[4/6] Starting SNMP polling...")
	go c.snmpPollingLoop()
	c.pollWg.Add(1)
	go func() {
		defer c.pollWg.Done()
		c.deviceRefreshLoop()
	}()
	fmt.Printf("  -> Polling every %v, device refresh every %v\n\n", probeCfg.PollInterval, probeCfg.DeviceRefreshInterval)

	// Start SSH polling for FortiGate devices
	fmt.Println("[5/6] Starting SSH polling...")
	go c.sshPollingLoop()
	fmt.Printf("  -> SSH polling every %v\n\n", 5*time.Minute)

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
			log.Printf("[Collector] Ping result: device=%d target=%s latency=%.2f loss=%.0f%% success=%v",
				result.DeviceID, result.TargetIP, result.Latency, result.PacketLoss, result.Success)
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

func (c *Collector) runStartupDiagnostic() {
	c.deviceMu.RLock()
	devices := make([]relay.DeviceInfo, len(c.devices))
	copy(devices, c.devices)
	c.deviceMu.RUnlock()

	var target *relay.DeviceInfo
	for i := range devices {
		if devices[i].Enabled {
			target = &devices[i]
			break
		}
	}

	if target == nil {
		fmt.Println("  [Diagnostic] No enabled devices — skipping SNMP connectivity test")
		return
	}

	// Credential validation
	fmt.Println("  [Diagnostic] === SNMP Credential Check ===")
	fmt.Printf("  [Diagnostic] Target: %s (id=%d)\n", target.Name, target.ID)
	fmt.Printf("  [Diagnostic] IP: %s  Port: %d  Version: %s\n", target.IPAddress, target.SNMPPort, target.SNMPVersion)
	fmt.Printf("  [Diagnostic] Community length: %d chars\n", len(target.SNMPCommunity))
	if target.SNMPCommunity == "" && target.SNMPVersion != "3" {
		fmt.Println("  [Diagnostic] *** WARNING: SNMP community string is EMPTY! Device will not respond. ***")
		fmt.Println("  [Diagnostic] *** Check device SNMP settings in the server admin panel. ***")
		return
	}
	if target.SNMPPort == 0 {
		fmt.Println("  [Diagnostic] *** WARNING: SNMP port is 0! Must be 161 (or valid port). ***")
		return
	}
	if target.SNMPVersion == "" {
		fmt.Println("  [Diagnostic] *** WARNING: SNMP version is empty! Defaulting to v2c. ***")
	}
	if target.SNMPVersion == "3" {
		fmt.Printf("  [Diagnostic] V3 Username: %q  AuthType: %s  PrivType: %s\n",
			target.SNMPV3Username, target.SNMPV3AuthType, target.SNMPV3PrivType)
		if target.SNMPV3Username == "" {
			fmt.Println("  [Diagnostic] *** WARNING: SNMPv3 username is EMPTY! ***")
		}
	}
	fmt.Printf("  [Diagnostic] Vendor from server: %q\n", target.Vendor)

	var v3 *snmp.SNMPv3Config
	if target.SNMPVersion == "3" {
		v3 = &snmp.SNMPv3Config{
			Username: target.SNMPV3Username,
			AuthType: target.SNMPV3AuthType,
			AuthPass: target.SNMPV3AuthPass,
			PrivType: target.SNMPV3PrivType,
			PrivPass: target.SNMPV3PrivPass,
		}
	}

	fmt.Println()
	fmt.Println("  [Diagnostic] === SNMP Connection Test ===")
	client, err := snmp.NewSNMPClient(target.IPAddress, target.SNMPPort, target.SNMPCommunity, target.SNMPVersion, v3)
	if err != nil {
		fmt.Printf("  [Diagnostic] CONNECT FAILED: %v\n", err)
		return
	}
	defer client.Close()
	fmt.Println("  [Diagnostic] UDP socket opened OK")

	// Test 1: Vendor-neutral sysObjectID GET (works on ANY SNMP device)
	fmt.Println()
	fmt.Println("  [Diagnostic] === Test 1: Basic SNMP (sysObjectID — works on any device) ===")
	start := time.Now()
	basicResult, basicErr := client.GetRaw([]string{".1.3.6.1.2.1.1.2.0"})
	elapsed := time.Since(start)
	if basicErr != nil {
		fmt.Printf("  [Diagnostic] BASIC SNMP FAILED (%v): %v\n", elapsed.Round(time.Millisecond), basicErr)
		fmt.Println("  [Diagnostic] >>> Device is NOT responding to ANY SNMP request.")
		fmt.Println("  [Diagnostic] >>> This means: wrong community string, SNMP disabled on device,")
		fmt.Println("  [Diagnostic] >>> firewall blocking UDP 161, or device unreachable.")
		if elapsed >= 10*time.Second {
			fmt.Println("  [Diagnostic] >>> Timeout = no response. Packets sent but nothing came back.")
		}
	} else {
		fmt.Printf("  [Diagnostic] BASIC SNMP OK (%v): sysObjectID = %v\n", elapsed.Round(time.Millisecond), basicResult)
	}

	// Test 2: Vendor-specific system status
	vendor := target.Vendor
	if vendor == "" {
		vendor = "fortigate"
	}
	fmt.Println()
	fmt.Printf("  [Diagnostic] === Test 2: Vendor-specific poll (vendor=%s) ===\n", vendor)
	start = time.Now()
	status, err := client.GetSystemStatus(vendor)
	elapsed = time.Since(start)
	if err != nil {
		fmt.Printf("  [Diagnostic] VENDOR POLL FAILED (%v): %v\n", elapsed.Round(time.Millisecond), err)
		if basicErr == nil {
			fmt.Println("  [Diagnostic] >>> Basic SNMP works but vendor OIDs fail!")
			fmt.Println("  [Diagnostic] >>> This device may not be a FortiGate, or FortiGate MIB is not enabled.")
		}
	} else {
		fmt.Printf("  [Diagnostic] VENDOR POLL OK (%v): %s — CPU=%.1f%% Mem=%.1f%% Sessions=%d\n",
			elapsed.Round(time.Millisecond), status.Hostname, status.CPUUsage, status.MemoryUsage, status.SessionCount)
	}
	fmt.Println()
}

func (c *Collector) snmpPollingLoop() {
	// Poll immediately on startup (don't wait for first ticker)
	c.runPollCycle()

	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.runPollCycle()
		}
	}
}

func (c *Collector) runPollCycle() {
	c.deviceMu.RLock()
	devices := make([]relay.DeviceInfo, len(c.devices))
	copy(devices, c.devices)
	c.deviceMu.RUnlock()

	sem := make(chan struct{}, 10) // Limit concurrent SNMP polls
	enabledCount := 0
	skippedCount := 0
	for _, dev := range devices {
		if !dev.Enabled {
			continue
		}
		// Circuit breaker: skip devices with 3+ consecutive failures (backoff for 4 cycles)
		c.failCountMu.Lock()
		failures := c.failCount[dev.ID]
		c.failCountMu.Unlock()
		if failures >= 3 {
			// Poll every 5th cycle (skip 4 cycles) when in failure state
			if failures%5 != 0 {
				c.failCountMu.Lock()
				c.failCount[dev.ID]++
				c.failCountMu.Unlock()
				skippedCount++
				continue
			}
		}
		enabledCount++
		c.pollWg.Add(1)
		sem <- struct{}{} // Acquire semaphore slot
		go func(d relay.DeviceInfo) {
			defer c.pollWg.Done()
			defer func() { <-sem }() // Release semaphore slot
			c.pollDevice(d)
		}(dev)
	}
	if skippedCount > 0 {
		log.Printf("[SNMP] Poll cycle: %d/%d devices enabled, %d skipped (backoff)", enabledCount, len(devices), skippedCount)
	} else {
		log.Printf("[SNMP] Poll cycle: %d/%d devices enabled", enabledCount, len(devices))
	}
}

func (c *Collector) sshPollingLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.runSSHPollCycle()
		}
	}
}

func (c *Collector) runSSHPollCycle() {
	c.deviceMu.RLock()
	devices := make([]relay.DeviceInfo, len(c.devices))
	copy(devices, c.devices)
	c.deviceMu.RUnlock()

	now := time.Now()
	c.sshLastPollMu.Lock()
	if c.sshLastPoll == nil {
		c.sshLastPoll = make(map[uint]time.Time)
	}
	c.sshLastPollMu.Unlock()

	sem := make(chan struct{}, 5) // Limit concurrent SSH polls (lower than SNMP due to connection overhead)
	var wg sync.WaitGroup

	for _, dev := range devices {
		if !dev.Enabled || !dev.SSHPollEnabled || dev.SSHUsername == "" || dev.SSHPassword == "" {
			continue
		}

		interval := time.Duration(dev.SSHPollInterval) * time.Second
		if interval <= 0 {
			interval = 15 * time.Minute
		}

		c.sshLastPollMu.Lock()
		lastPoll, exists := c.sshLastPoll[dev.ID]
		if exists && now.Sub(lastPoll) < interval {
			c.sshLastPollMu.Unlock()
			continue
		}
		c.sshLastPoll[dev.ID] = now
		c.sshLastPollMu.Unlock()

		wg.Add(1)
		sem <- struct{}{}
		go func(d relay.DeviceInfo) {
			defer wg.Done()
			defer func() { <-sem }()
			c.sshPollDevice(d)
		}(dev)
	}
	wg.Wait()
}

func (c *Collector) sshPollDevice(dev relay.DeviceInfo) {
	sshClient := ssh.NewFortiGateClient(dev.IPAddress, dev.SSHPort, dev.SSHUsername, dev.SSHPassword)
	if err := sshClient.Connect(); err != nil {
		log.Printf("[SSH] Connect failed for %s (%s): %v", dev.Name, dev.IPAddress, err)
		return
	}
	defer sshClient.Close()

	checksum, err := sshClient.GetConfigChecksum()
	if err != nil {
		log.Printf("[SSH] Config checksum failed for %s: %v", dev.Name, err)
	} else {
		c.checkAndSendConfigRevision(dev, checksum, sshClient)
	}

	processOutput, err := sshClient.GetProcessTop()
	if err == nil {
		c.sendProcessSnapshot(dev, processOutput)
	}

	interfaceOutput, err := sshClient.GetInterfaceList()
	if err == nil {
		c.sendInterfaceErrors(dev, interfaceOutput)
	}

	sensorOutput, err := sshClient.GetSensorInfo()
	if err == nil {
		c.sendSensorDetails(dev, sensorOutput)
	}

	licenseOutput, err := sshClient.GetLicenseStatus()
	if err == nil {
		c.sendLicenseDetails(dev, licenseOutput)
	}

	perfOutput, err := sshClient.GetPerformanceStatus()
	if err == nil {
		c.sendPerformanceStatus(dev, perfOutput)
	}

	phase1Output, phase2Output, err := sshClient.GetVPNStatus()
	if err == nil {
		c.sendVPNStatuses(dev, phase1Output, phase2Output)
	}
}

func (c *Collector) checkAndSendConfigRevision(dev relay.DeviceInfo, checksum string, client *ssh.FortiGateClient) {
	if c.cfg.TFTPConfigEnabled && c.tftpServer != nil {
		c.fetchConfigViaTFTP(dev, checksum)
		return
	}

	config, err := client.GetConfig()
	if err != nil {
		log.Printf("[SSH] Get config failed for %s: %v", dev.Name, err)
		return
	}

	rev := relay.ConfigRevision{
		DeviceID:   dev.ID,
		Timestamp:  time.Now(),
		Checksum:   checksum,
		ConfigText: config,
		Length:     len(config),
	}
	if err := c.relayClient.SendConfigRevision(&rev); err != nil {
		log.Printf("[SSH] Failed to send config revision for %s: %v", dev.Name, err)
	}
}

func devIDFromFilename(filename string) uint {
	parts := strings.Split(filename, "_")
	if len(parts) >= 2 {
		id, err := strconv.ParseUint(parts[1], 10, 32)
		if err == nil {
			return uint(id)
		}
	}
	return 0
}

func (c *Collector) startTFTPServer() {
	addr := c.cfg.TFTPListenAddr
	log.Printf("[TFTP] Starting TFTP server on %s (enabled=%v)", addr, c.cfg.TFTPConfigEnabled)

	tftpServer := tftp.NewServer(&tftp.Config{
		Addr:    addr,
		Timeout: 60 * time.Second,
	})

	tftpServer.SetWriteHandler(func(filename string, data []byte, clientAddr net.Addr) error {
		log.Printf("[TFTP] Received WRQ from %s for file: %s (%d bytes)", clientAddr.String(), filename, len(data))

		deviceID := devIDFromFilename(filename)
		if deviceID == 0 {
			log.Printf("[TFTP] Invalid filename %s - could not parse device ID", filename)
			return nil
		}
		log.Printf("[TFTP] Parsed device ID: %d", deviceID)

		checksum := checksumFromData(data)
		log.Printf("[TFTP] Config checksum: %s", checksum)

		rev := relay.ConfigRevision{
			DeviceID:   deviceID,
			Timestamp:  time.Now(),
			Checksum:   checksum,
			ConfigText: string(data),
			Length:     len(data),
		}

		log.Printf("[TFTP] Sending config revision to server for device %d...", deviceID)
		if err := c.relayClient.SendConfigRevision(&rev); err != nil {
			log.Printf("[TFTP] ERROR - Failed to send config revision for device %d: %v", deviceID, err)
		} else {
			log.Printf("[TFTP] SUCCESS - Received and sent config for device %d (len=%d, checksum=%s)", deviceID, len(data), checksum)
		}
		return nil
	})

	if err := tftpServer.ListenAndServe(); err != nil {
		log.Printf("[TFTP] ERROR - Failed to start TFTP server: %v", err)
		return
	}

	c.tftpServer = tftpServer
	c.tftpListenIP = c.cfg.TFTPListenAddr
	log.Printf("[TFTP] Server started successfully on %s", addr)
}

func checksumFromData(data []byte) string {
	h := md5.Sum(data)
	return fmt.Sprintf("%x", h)
}

func (c *Collector) fetchConfigViaTFTP(dev relay.DeviceInfo, checksum string) {
	if c.tftpServer == nil {
		log.Printf("[TFTP] TFTP server not available for device %d (%s)", dev.ID, dev.Name)
		return
	}

	filename := fmt.Sprintf("fgt_%d_config", dev.ID)
	log.Printf("[TFTP] Initiating TFTP config backup for device %d (%s) - filename: %s, target: %s",
		dev.ID, dev.Name, filename, c.tftpListenIP)

	err := c.sendConfigRevisionViaTFTP(dev, checksum, filename)
	if err != nil {
		log.Printf("[TFTP] ERROR - TFTP config backup failed for %s: %v", dev.Name, err)
	} else {
		log.Printf("[TFTP] TFTP config backup initiated for %s - waiting for upload...", dev.Name)
	}
}

func (c *Collector) sendConfigRevisionViaTFTP(dev relay.DeviceInfo, checksum string, filename string) error {
	log.Printf("[TFTP] Connecting to device %s via SSH to send TFTP backup command...", dev.IPAddress)
	sshClient := ssh.NewFortiGateClient(dev.IPAddress, dev.SSHPort, dev.SSHUsername, dev.SSHPassword)
	if err := sshClient.Connect(); err != nil {
		return fmt.Errorf("SSH connect failed: %w", err)
	}
	defer sshClient.Close()

	log.Printf("[TFTP] Sending 'execute backup config tftp %s %s' to %s", filename, c.tftpListenIP, dev.Name)
	if err := sshClient.BackupConfigTFTP(filename, c.tftpListenIP); err != nil {
		return fmt.Errorf("TFTP backup command failed: %w", err)
	}
	log.Printf("[TFTP] TFTP backup command sent successfully to %s", dev.Name)

	return nil
}

func (c *Collector) sendProcessSnapshot(dev relay.DeviceInfo, output string) {
	processes := ssh.ParseProcessTop(output)
	if len(processes) == 0 {
		return
	}
	relayProcesses := make([]relay.ProcessInfo, len(processes))
	for i, p := range processes {
		relayProcesses[i] = relay.ProcessInfo{
			Name:    p.Name,
			PID:     p.PID,
			CPU:     p.CPU,
			Memory:  p.Memory,
			Command: p.Command,
		}
	}
	snap := relay.ProcessSnapshot{
		DeviceID:  dev.ID,
		Timestamp: time.Now(),
		Processes: relayProcesses,
	}
	if err := c.relayClient.SendProcessSnapshot(&snap); err != nil {
		log.Printf("[SSH] Failed to send process snapshot for %s: %v", dev.Name, err)
	}
}

func (c *Collector) sendInterfaceErrors(dev relay.DeviceInfo, output string) {
	interfaces := ssh.ParseInterfaceList(output)
	if len(interfaces) == 0 {
		return
	}
	now := time.Now()
	snaps := make([]relay.InterfaceErrorSnapshot, 0, len(interfaces))
	for _, iface := range interfaces {
		snaps = append(snaps, relay.InterfaceErrorSnapshot{
			DeviceID:    dev.ID,
			Timestamp:   now,
			Interface:   iface.Name,
			InErrors:    iface.InErrors,
			InDiscards:  iface.InDiscards,
			OutErrors:   iface.OutErrors,
			OutDiscards: iface.OutDiscards,
		})
	}
	if err := c.relayClient.SendInterfaceErrorSnapshots(snaps); err != nil {
		log.Printf("[SSH] Failed to send interface errors for %s: %v", dev.Name, err)
	}
}

func (c *Collector) sendSensorDetails(dev relay.DeviceInfo, output string) {
	sensors := ssh.ParseSensorInfo(output)
	if len(sensors) == 0 {
		log.Printf("[SSH] No sensors parsed from %s, raw output length: %d", dev.Name, len(output))
		return
	}
	log.Printf("[SSH] Sending %d sensor details for %s", len(sensors), dev.Name)
	now := time.Now()
	details := make([]relay.SensorDetail, 0, len(sensors))
	for _, s := range sensors {
		details = append(details, relay.SensorDetail{
			DeviceID:  dev.ID,
			Timestamp: now,
			Name:      s.Name,
			Value:     s.Value,
			Unit:      s.Unit,
			Status:    s.Status,
		})
	}
	if err := c.relayClient.SendSensorDetails(details); err != nil {
		log.Printf("[SSH] Failed to send sensor details for %s: %v", dev.Name, err)
	}
}

func (c *Collector) sendLicenseDetails(dev relay.DeviceInfo, output string) {
	licenses := ssh.ParseLicenseStatus(output)
	if len(licenses) == 0 {
		return
	}
	now := time.Now()
	details := make([]relay.LicenseDetail, 0, len(licenses))
	for _, l := range licenses {
		details = append(details, relay.LicenseDetail{
			DeviceID:    dev.ID,
			Timestamp:   now,
			Description: l.LicenseType,
			ExpiryDate:  l.Expires,
			Status:      l.Status,
			Details:     l.Details,
		})
	}
	if err := c.relayClient.SendLicenseDetails(details); err != nil {
		log.Printf("[SSH] Failed to send license details for %s: %v", dev.Name, err)
	}
}

func (c *Collector) sendPerformanceStatus(dev relay.DeviceInfo, output string) {
	perf := ssh.ParsePerformanceStatus(output)
	if perf == nil {
		return
	}

	activeCPU := perf.CPUUser + perf.CPUSystem + perf.CPUNice + perf.CPUIowait + perf.CPUIrq + perf.CPUSoftirq
	status := relay.SystemStatus{
		DeviceID:       dev.ID,
		Timestamp:      time.Now(),
		CPUUsage:       activeCPU,
		MemoryUsage:    perf.MemoryUsedPercent,
		MemoryTotal:    perf.MemoryTotal,
		MemoryFree:     perf.MemoryFree,
		MemoryFreeable: perf.MemoryFreeable,
		SessionCount:   perf.SessionCount,
		Uptime:         perf.Uptime,
		NetworkInKbps:  perf.NetworkIn,
		NetworkOutKbps: perf.NetworkOut,
		CPUUser:        perf.CPUUser,
		CPUSystem:      perf.CPUSystem,
		CPUNice:        perf.CPUNice,
		CPUIdle:        perf.CPUIdle,
		CPUIowait:      perf.CPUIowait,
		CPUIrq:         perf.CPUIrq,
		CPUSoftirq:     perf.CPUSoftirq,
	}
	if err := c.relayClient.SendSystemStatuses([]relay.SystemStatus{status}); err != nil {
		log.Printf("[SSH] Failed to send performance status for %s: %v", dev.Name, err)
	}

	if perf.SessionRate > 0 || perf.MaxSessions > 0 {
		procStats := []relay.ProcessorStats{}
		if perf.SessionRate > 0 {
			procStats = append(procStats, relay.ProcessorStats{
				DeviceID:  dev.ID,
				Timestamp: time.Now(),
				Index:     -1,
				Usage:     float64(perf.SessionRate),
			})
		}
		if perf.MaxSessions > 0 {
			procStats = append(procStats, relay.ProcessorStats{
				DeviceID:  dev.ID,
				Timestamp: time.Now(),
				Index:     -2,
				Usage:     float64(perf.MaxSessions),
			})
		}
		if err := c.relayClient.SendProcessorStats(procStats); err != nil {
			log.Printf("[SSH] Failed to send processor stats for %s: %v", dev.Name, err)
		}
	}
}

func (c *Collector) sendVPNStatuses(dev relay.DeviceInfo, phase1Output, phase2Output string) {
	phase1Tunnels := ssh.ParseVPNPhase1(phase1Output)
	phase2Tunnels := ssh.ParseVPNPhase2(phase2Output)

	phase1Map := make(map[string]ssh.VPNPhase1Info)
	for _, p1 := range phase1Tunnels {
		if _, exists := phase1Map[p1.Name]; exists {
			log.Printf("[SSH] WARNING: Duplicate Phase1 tunnel name '%s' on device %s, using first occurrence", p1.Name, dev.Name)
		}
		phase1Map[p1.Name] = p1
	}

	var statuses []relay.VPNStatus
	for _, p2 := range phase2Tunnels {
		status := relay.VPNStatus{
			DeviceID:   dev.ID,
			Timestamp:  time.Now(),
			TunnelName: p2.Name,
			TunnelType: "ipsec",
			Phase1Name: p2.Phase1Name,
		}
		if p1, ok := phase1Map[p2.Phase1Name]; ok {
			status.RemoteIP = p1.RemoteGateway
			status.Status = p1.Status
			status.InterfaceName = p1.Interface
			status.Mode = p1.Mode
		}
		if status.RemoteIP == "" {
			status.RemoteIP = p2.RemoteGateway
		}
		if status.Status == "" {
			status.Status = "unknown"
		}
		statuses = append(statuses, status)
	}

	if len(statuses) > 0 {
		if err := c.relayClient.SendVPNStatuses(statuses); err != nil {
			log.Printf("[SSH] Failed to send VPN statuses for %s: %v", dev.Name, err)
		}
	}
}

func (c *Collector) pollDevice(dev relay.DeviceInfo) {
	// Credential guard: skip devices with obviously invalid SNMP settings
	if dev.SNMPVersion != "3" && dev.SNMPCommunity == "" {
		log.Printf("[SNMP] SKIP %s (%s): community string is EMPTY (check server device settings)", dev.Name, dev.IPAddress)
		return
	}
	if dev.SNMPPort == 0 {
		log.Printf("[SNMP] SKIP %s (%s): SNMP port is 0 (check server device settings)", dev.Name, dev.IPAddress)
		return
	}

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
		log.Printf("[SNMP] Connect failed for %s (%s:%d v%s community_len=%d): %v",
			dev.Name, dev.IPAddress, dev.SNMPPort, dev.SNMPVersion, len(dev.SNMPCommunity), err)
		c.recordPollFailure(dev.ID)
		return
	}
	defer client.Close()

	vendor := dev.Vendor
	if vendor == "" {
		vendor = "fortigate"
	}

	// Poll system status
	status, err := client.GetSystemStatus(vendor)
	if err != nil {
		log.Printf("[SNMP] Poll failed for %s (%s:%d v%s community_len=%d vendor=%s): %v",
			dev.Name, dev.IPAddress, dev.SNMPPort, dev.SNMPVersion, len(dev.SNMPCommunity), vendor, err)
		c.recordPollFailure(dev.ID)
		return
	}

	// Success — reset circuit breaker
	c.recordPollSuccess(dev.ID)
	status.DeviceID = dev.ID
	status.Timestamp = time.Now()
	log.Printf("[SNMP] %s (%s) [device_id=%d]: CPU=%.1f%% Mem=%.1f%% Disk=%.1f%%/%dMB Sessions=%d",
		dev.Name, dev.IPAddress, dev.ID, status.CPUUsage, status.MemoryUsage, status.DiskUsage, status.DiskTotal, status.SessionCount)
	if err := c.relayClient.SendSystemStatuses([]relay.SystemStatus{*status}); err != nil {
		log.Printf("[SNMP] Failed to send system status for %s (device_id=%d): %v", dev.Name, dev.ID, err)
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

	// Collect interface IP addresses (standard IP-MIB, vendor-neutral)
	ifAddrs, ifAddrErr := client.GetInterfaceAddresses()
	if ifAddrErr == nil && len(ifAddrs) > 0 {
		for i := range ifAddrs {
			ifAddrs[i].DeviceID = dev.ID
			ifAddrs[i].Timestamp = now
		}
		if err := c.relayClient.SendInterfaceAddresses(ifAddrs); err != nil {
			log.Printf("[SNMP] Failed to send interface addresses for %s: %v", dev.Name, err)
		}
		// Cache interface IPs for sFlow device resolution
		c.cacheInterfaceAddresses(dev.ID, ifAddrs)
	}

	// Collect VPN tunnel status (silently skip if device has no VPN)
	vpnStatuses, vpnErr := client.GetVPNStatus(vendor)
	if vpnErr == nil && len(vpnStatuses) > 0 {
		for i := range vpnStatuses {
			vpnStatuses[i].DeviceID = dev.ID
			vpnStatuses[i].Timestamp = now
		}
		if err := c.relayClient.SendVPNStatuses(vpnStatuses); err != nil {
			log.Printf("[SNMP] Failed to send VPN statuses for %s: %v", dev.Name, err)
		}
	}

	// Collect hardware sensors (silently skip if device doesn't support it)
	sensors, sensorErr := client.GetHardwareSensors(vendor)
	if sensorErr == nil && len(sensors) > 0 {
		for i := range sensors {
			sensors[i].DeviceID = dev.ID
			sensors[i].Timestamp = now
		}
		if err := c.relayClient.SendHardwareSensors(sensors); err != nil {
			log.Printf("[SNMP] Failed to send hardware sensors for %s: %v", dev.Name, err)
		}
	}

	// Collect processor stats (CPU cores, NP/SPU ASICs)
	procStats, procErr := client.GetProcessorStats(vendor)
	if procErr == nil && len(procStats) > 0 {
		for i := range procStats {
			procStats[i].DeviceID = dev.ID
			procStats[i].Timestamp = now
		}
		if err := c.relayClient.SendProcessorStats(procStats); err != nil {
			log.Printf("[SNMP] Failed to send processor stats for %s: %v", dev.Name, err)
		}
	}

	// Collect HA cluster status (silently skip if standalone or unsupported)
	haStatuses, haErr := client.GetHAStatus(vendor)
	if haErr == nil && len(haStatuses) > 0 {
		for i := range haStatuses {
			haStatuses[i].DeviceID = dev.ID
			haStatuses[i].Timestamp = now
		}
		if err := c.relayClient.SendHAStatuses(haStatuses); err != nil {
			log.Printf("[SNMP] Failed to send HA status for %s: %v", dev.Name, err)
		}
	}

	// Collect security stats (AV/IPS/WebFilter counters)
	secStats, secErr := client.GetSecurityStats(vendor)
	if secErr == nil && secStats != nil {
		secStats.DeviceID = dev.ID
		secStats.Timestamp = now
		if err := c.relayClient.SendSecurityStats([]relay.SecurityStats{*secStats}); err != nil {
			log.Printf("[SNMP] Failed to send security stats for %s: %v", dev.Name, err)
		}
	}

	// Collect SD-WAN health checks (silently skip if no SD-WAN configured)
	sdwanHealth, sdwanErr := client.GetSDWANHealth(vendor)
	if sdwanErr == nil && len(sdwanHealth) > 0 {
		for i := range sdwanHealth {
			sdwanHealth[i].DeviceID = dev.ID
			sdwanHealth[i].Timestamp = now
		}
		if err := c.relayClient.SendSDWANHealth(sdwanHealth); err != nil {
			log.Printf("[SNMP] Failed to send SD-WAN health for %s: %v", dev.Name, err)
		}
	}

	// Collect license/contract info (silently skip if unsupported)
	licenses, licErr := client.GetLicenseInfo(vendor)
	if licErr == nil && len(licenses) > 0 {
		for i := range licenses {
			licenses[i].DeviceID = dev.ID
			licenses[i].Timestamp = now
		}
		if err := c.relayClient.SendLicenseInfo(licenses); err != nil {
			log.Printf("[SNMP] Failed to send license info for %s: %v", dev.Name, err)
		}
	}
}

func (c *Collector) recordPollFailure(deviceID uint) {
	c.failCountMu.Lock()
	c.failCount[deviceID]++
	count := c.failCount[deviceID]
	c.failCountMu.Unlock()
	if count == 3 {
		log.Printf("[SNMP] Device %d: 3 consecutive failures — entering backoff mode", deviceID)
	}
}

func (c *Collector) recordPollSuccess(deviceID uint) {
	c.failCountMu.Lock()
	if c.failCount[deviceID] > 0 {
		c.failCount[deviceID] = 0
	}
	c.failCountMu.Unlock()
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

			names := make([]string, len(devices))
			for i, d := range devices {
				names[i] = fmt.Sprintf("%s(id=%d)", d.Name, d.ID)
			}
			log.Printf("[Devices] Refreshed: %d devices: %v", len(devices), names)

			if c.pingCollector != nil {
				c.pingCollector.UpdateDevices(devices)
			}
		}
	}
}

// resolveDeviceByIP maps an sFlow agent IP to a device ID from the known device list
// and interface address cache.
func (c *Collector) resolveDeviceByIP(ip string) uint {
	// Check management IPs first
	c.deviceMu.RLock()
	for _, d := range c.devices {
		if d.IPAddress == ip {
			c.deviceMu.RUnlock()
			return d.ID
		}
	}
	c.deviceMu.RUnlock()

	// Check interface IP cache
	c.ifaceIPMu.RLock()
	defer c.ifaceIPMu.RUnlock()
	if id, ok := c.ifaceIPMap[ip]; ok {
		return id
	}
	return 0
}

// cacheInterfaceAddresses stores interface IPs for device resolution.
func (c *Collector) cacheInterfaceAddresses(deviceID uint, addrs []relay.InterfaceAddress) {
	c.ifaceIPMu.Lock()
	defer c.ifaceIPMu.Unlock()
	if c.ifaceIPMap == nil {
		c.ifaceIPMap = make(map[string]uint)
	}
	for _, a := range addrs {
		if a.IPAddress != "" && a.IPAddress != "0.0.0.0" && a.IPAddress != "127.0.0.1" {
			c.ifaceIPMap[a.IPAddress] = deviceID
		}
	}
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
