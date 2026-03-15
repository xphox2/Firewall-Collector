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

const version = "1.2.15"

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
	ifaceIPMap    map[string]uint // interface IP → device ID cache
	ifaceIPMu    sync.RWMutex
	stopChan      chan struct{}
	pollWg        sync.WaitGroup
	// Circuit breaker: consecutive failure counts per device
	failCount     map[uint]int
	failCountMu   sync.Mutex
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
		failCount:   make(map[uint]int),
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
