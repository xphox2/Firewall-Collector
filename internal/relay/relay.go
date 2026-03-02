package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxReregisterAttempts = 5
const maxQueueSize = 10000

// --- DTOs matching server JSON tags ---

type SystemStatus struct {
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     uint      `json:"device_id"`
	Hostname     string    `json:"hostname"`
	Version      string    `json:"version"`
	CPUUsage     float64   `json:"cpu_usage"`
	MemoryUsage  float64   `json:"memory_usage"`
	MemoryTotal  uint64    `json:"memory_total"`
	DiskUsage    float64   `json:"disk_usage"`
	DiskTotal    uint64    `json:"disk_total"`
	SessionCount int       `json:"session_count"`
	Uptime       uint64    `json:"uptime"`
}

type InterfaceStats struct {
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id"`
	Index       int       `json:"index"`
	Name        string    `json:"name"`
	Type        int       `json:"type"`
	Speed       uint64    `json:"speed"`
	Status      string    `json:"status"`
	AdminStatus string    `json:"admin_status"`
	InBytes     uint64    `json:"in_bytes"`
	InPackets   uint64    `json:"in_packets"`
	InErrors    uint64    `json:"in_errors"`
	InDiscards  uint64    `json:"in_discards"`
	OutBytes    uint64    `json:"out_bytes"`
	OutPackets  uint64    `json:"out_packets"`
	OutErrors   uint64    `json:"out_errors"`
	OutDiscards uint64    `json:"out_discards"`
	Alias       string    `json:"alias"`
	MTU         int       `json:"mtu"`
	MACAddress  string    `json:"mac_address"`
	TypeName    string    `json:"type_name"`
	HighSpeed   uint64    `json:"high_speed"`
	VLANID      int       `json:"vlan_id"`
}

type VPNStatus struct {
	Timestamp  time.Time `json:"timestamp"`
	DeviceID   uint      `json:"device_id"`
	TunnelName string    `json:"tunnel_name"`
	RemoteIP   string    `json:"remote_ip"`
	Status     string    `json:"status"`
	BytesIn    uint64    `json:"bytes_in"`
	BytesOut   uint64    `json:"bytes_out"`
	PacketsIn  uint64    `json:"packets_in"`
	PacketsOut uint64    `json:"packets_out"`
	State      string    `json:"state"`
}

type TrapEvent struct {
	Timestamp time.Time `json:"timestamp"`
	DeviceID  uint      `json:"device_id"`
	ProbeID   uint      `json:"probe_id"`
	SourceIP  string    `json:"source_ip"`
	TrapOID   string    `json:"trap_oid"`
	TrapType  string    `json:"trap_type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
}

type PingResult struct {
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     uint      `json:"device_id"`
	ProbeID      uint      `json:"probe_id"`
	TargetIP     string    `json:"target_ip"`
	Success      bool      `json:"success"`
	Latency      float64   `json:"latency"`
	PacketLoss   float64   `json:"packet_loss"`
	TTL          int       `json:"ttl"`
	ErrorMessage string    `json:"error_message"`
}

type SyslogMessage struct {
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	ProbeID        uint      `json:"probe_id"`
	Hostname       string    `json:"hostname"`
	AppName        string    `json:"app_name"`
	ProcessID      string    `json:"process_id"`
	MessageID      string    `json:"message_id"`
	StructuredData string    `json:"structured_data"`
	Message        string    `json:"message"`
	Priority       int       `json:"priority"`
	Facility       int       `json:"facility"`
	Severity       int       `json:"severity"`
	SourceIP       string    `json:"source_ip"`
}

type FlowSample struct {
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	ProbeID        uint      `json:"probe_id"`
	SamplerAddress string    `json:"sampler_address"`
	SequenceNumber uint32    `json:"sequence_number"`
	SamplingRate   uint32    `json:"sampling_rate"`
	SrcAddr        string    `json:"src_addr"`
	DstAddr        string    `json:"dst_addr"`
	SrcPort        uint16    `json:"src_port"`
	DstPort        uint16    `json:"dst_port"`
	Protocol       uint8     `json:"protocol"`
	Bytes          uint64    `json:"bytes"`
	Packets        uint64    `json:"packets"`
	InputIfIndex   uint32    `json:"input_if_index"`
	OutputIfIndex  uint32    `json:"output_if_index"`
	TCPFlags       uint8     `json:"tcp_flags"`
}

type HardwareSensor struct {
	Timestamp time.Time `json:"timestamp"`
	DeviceID  uint      `json:"device_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Value     float64   `json:"value"`
	Status    string    `json:"status"`
	Unit      string    `json:"unit"`
}

type ProcessorStats struct {
	Timestamp time.Time `json:"timestamp"`
	DeviceID  uint      `json:"device_id"`
	Index     int       `json:"index"`
	Usage     float64   `json:"usage"`
}

type DeviceInfo struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	IPAddress      string `json:"ip_address"`
	SNMPPort       int    `json:"snmp_port"`
	SNMPCommunity  string `json:"snmp_community"`
	SNMPVersion    string `json:"snmp_version"`
	SNMPV3Username string `json:"snmpv3_username"`
	SNMPV3AuthType string `json:"snmpv3_auth_type"`
	SNMPV3AuthPass string `json:"snmpv3_auth_pass"`
	SNMPV3PrivType string `json:"snmpv3_priv_type"`
	SNMPV3PrivPass string `json:"snmpv3_priv_pass"`
	Enabled        bool   `json:"enabled"`
	Vendor         string `json:"vendor"`
}

type DevicesResponse struct {
	Success bool         `json:"success"`
	Data    []DeviceInfo `json:"data"`
}

// --- Config & Client ---

type Config struct {
	ServerURL          string
	RegistrationKey    string
	TLSCertFile        string
	TLSKeyFile         string
	CACertFile         string
	SyncInterval       time.Duration
	HeartbeatInterval  time.Duration
	InsecureSkipVerify bool
}

type RegisterRequest struct {
	RegistrationKey string `json:"registration_key"`
}

type RegisterResponse struct {
	Success   bool   `json:"success"`
	ProbeID   uint   `json:"probe_id"`
	ProbeName string `json:"probe_name"`
	Message   string `json:"message"`
	Approved  bool   `json:"approved"`
}

type Client struct {
	Config             Config
	httpClient         *http.Client
	approved           atomic.Bool
	mu                 sync.Mutex
	stopChan           chan struct{}
	done               chan struct{}
	stopOnce           sync.Once
	probeID            uint
	probeName          string
	reregisterAttempts int

	// Data queues
	trapQueue   []*TrapEvent
	pingQueue   []*PingResult
	syslogQueue []*SyslogMessage
	flowQueue   []*FlowSample
}

func NewClient(cfg Config) *Client {
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 60 * time.Second
	}

	tlsConfig := &tls.Config{}

	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			log.Fatalf("Failed to read CA certificate file %s: %v", cfg.CACertFile, err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			log.Fatalf("Failed to parse CA certificate from %s", cfg.CACertFile)
		}
		tlsConfig.RootCAs = caPool
	}

	if cfg.InsecureSkipVerify {
		log.Println("WARNING: TLS certificate verification is disabled — do not use in production")
		tlsConfig.InsecureSkipVerify = true
	}

	return &Client{
		Config: cfg,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		stopChan: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func generateRandomName() string {
	adjectives := []string{"swift", "bright", "eager", "keen", "active", "bold", "calm", "sharp", "lively", "noble"}
	nouns := []string{"falcon", "eagle", "hawk", "owl", "raven", "wolf", "bear", "lion", "tiger", "dragon"}

	adj := adjectives[randInt(len(adjectives))]
	noun := nouns[randInt(len(nouns))]
	suffix := hex.EncodeToString(randBytes(4))

	return fmt.Sprintf("%s-%s-%s", adj, noun, suffix)
}

func randInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		log.Printf("Failed to generate random int: %v", err)
		return 0
	}
	return int(n.Int64())
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Printf("Failed to generate random bytes: %v", err)
	}
	return b
}

func (c *Client) doAuthenticatedRequest(method, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Config.RegistrationKey)
	return c.httpClient.Do(req)
}

// --- Registration ---

func (c *Client) Register() error {
	data := RegisterRequest{
		RegistrationKey: c.Config.RegistrationKey,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", c.Config.ServerURL+"/api/probes/register", jsonData)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with HTTP status %d", resp.StatusCode)
	}

	var result RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !result.Success {
		if strings.Contains(result.Message, "unknown") || strings.Contains(result.Message, "invalid") {
			return fmt.Errorf("registration failed: %s - please check your registration key", result.Message)
		}
		return fmt.Errorf("registration failed: %s", result.Message)
	}

	c.mu.Lock()
	c.probeID = result.ProbeID
	c.probeName = result.ProbeName
	c.reregisterAttempts = 0
	c.mu.Unlock()

	c.approved.Store(result.Approved)

	if !result.Approved {
		log.Println("Probe registered but waiting for approval in admin panel...")
	} else {
		log.Println("Probe registered and approved!")
	}

	return nil
}

func (c *Client) GetProbeID() uint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probeID
}

func (c *Client) GetProbeName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probeName
}

func (c *Client) IsApproved() bool {
	return c.approved.Load()
}

// --- Heartbeat ---

func (c *Client) HeartbeatLoop() error {
	if err := c.SendHeartbeat(); err != nil {
		log.Printf("Initial heartbeat error: %v", err)
	}

	ticker := time.NewTicker(c.Config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.SendHeartbeat(); err != nil {
				log.Printf("Heartbeat error: %v", err)
			}
		case <-c.stopChan:
			return nil
		}
	}
}

func (c *Client) SendHeartbeat() error {
	return c.sendHeartbeatWithStatus("online")
}

func (c *Client) sendHeartbeatWithStatus(status string) error {
	c.mu.Lock()
	probeID := c.probeID
	c.mu.Unlock()

	data := map[string]interface{}{
		"probe_id":  probeID,
		"status":    status,
		"timestamp": time.Now().Unix(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat data: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", c.Config.ServerURL+"/api/probes/heartbeat", jsonData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		c.mu.Lock()
		attempts := c.reregisterAttempts
		c.reregisterAttempts++
		c.mu.Unlock()

		if attempts >= maxReregisterAttempts {
			return fmt.Errorf("max re-registration attempts (%d) reached, giving up", maxReregisterAttempts)
		}

		backoff := time.Duration(1<<uint(attempts)) * 10 * time.Second
		log.Printf("Probe unauthorized (attempt %d/%d), retrying registration in %v...",
			attempts+1, maxReregisterAttempts, backoff)
		time.Sleep(backoff)
		return c.Register()
	}

	return nil
}

// --- Queue methods (append to queue for batch sending) ---

func (c *Client) SendTrap(trap *TrapEvent) {
	c.mu.Lock()
	if len(c.trapQueue) >= maxQueueSize {
		c.trapQueue = c.trapQueue[1:]
		log.Println("[Relay] Trap queue full, dropping oldest entry")
	}
	c.trapQueue = append(c.trapQueue, trap)
	c.mu.Unlock()
}

func (c *Client) SendPingResult(result *PingResult) {
	c.mu.Lock()
	if len(c.pingQueue) >= maxQueueSize {
		c.pingQueue = c.pingQueue[1:]
		log.Println("[Relay] Ping queue full, dropping oldest entry")
	}
	c.pingQueue = append(c.pingQueue, result)
	c.mu.Unlock()
}

func (c *Client) SendSyslogMessage(msg *SyslogMessage) {
	c.mu.Lock()
	if len(c.syslogQueue) >= maxQueueSize {
		c.syslogQueue = c.syslogQueue[1:]
		log.Println("[Relay] Syslog queue full, dropping oldest entry")
	}
	c.syslogQueue = append(c.syslogQueue, msg)
	c.mu.Unlock()
}

func (c *Client) SendFlowSample(sample *FlowSample) {
	c.mu.Lock()
	if len(c.flowQueue) >= maxQueueSize {
		c.flowQueue = c.flowQueue[1:]
		log.Println("[Relay] Flow queue full, dropping oldest entry")
	}
	c.flowQueue = append(c.flowQueue, sample)
	c.mu.Unlock()
}

// --- Direct send (SNMP poll results sent immediately) ---

func (c *Client) SendSystemStatuses(statuses []SystemStatus) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	jsonData, err := json.Marshal(statuses)
	if err != nil {
		return fmt.Errorf("failed to marshal system statuses: %w", err)
	}

	url := fmt.Sprintf("%s/api/probes/%d/system-status", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send system statuses: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send system statuses returned status %d", resp.StatusCode)
}

func (c *Client) SendInterfaceStats(stats []InterfaceStats) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	jsonData, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("failed to marshal interface stats: %w", err)
	}

	url := fmt.Sprintf("%s/api/probes/%d/interface-stats", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send interface stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send interface stats returned status %d", resp.StatusCode)
}

func (c *Client) SendVPNStatuses(statuses []VPNStatus) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	jsonData, err := json.Marshal(statuses)
	if err != nil {
		return fmt.Errorf("failed to marshal VPN statuses: %w", err)
	}

	url := fmt.Sprintf("%s/api/probes/%d/vpn-status", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send VPN statuses: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send VPN statuses returned status %d", resp.StatusCode)
}

func (c *Client) SendHardwareSensors(sensors []HardwareSensor) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	jsonData, err := json.Marshal(sensors)
	if err != nil {
		return fmt.Errorf("failed to marshal hardware sensors: %w", err)
	}

	url := fmt.Sprintf("%s/api/probes/%d/hardware-sensors", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send hardware sensors: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send hardware sensors returned status %d", resp.StatusCode)
}

func (c *Client) SendProcessorStats(stats []ProcessorStats) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	jsonData, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("failed to marshal processor stats: %w", err)
	}

	url := fmt.Sprintf("%s/api/probes/%d/processor-stats", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send processor stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send processor stats returned status %d", resp.StatusCode)
}

// --- FetchDevices ---

func (c *Client) FetchDevices() ([]DeviceInfo, error) {
	if !c.approved.Load() {
		return nil, fmt.Errorf("probe not approved")
	}

	url := fmt.Sprintf("%s/api/probes/%d/devices", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch devices: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch devices returned status %d", resp.StatusCode)
	}

	var result DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode devices response: %w", err)
	}

	return result.Data, nil
}

// --- Data sync loop (replaces empty DataSendLoop) ---

func (c *Client) DataSendLoop() error {
	defer close(c.done)

	ticker := time.NewTicker(c.Config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.syncData()
		case <-c.stopChan:
			c.syncData() // Final flush
			return nil
		}
	}
}

func (c *Client) syncData() {
	c.mu.Lock()

	traps := c.trapQueue
	c.trapQueue = nil

	pings := c.pingQueue
	c.pingQueue = nil

	syslogs := c.syslogQueue
	c.syslogQueue = nil

	flows := c.flowQueue
	c.flowQueue = nil

	c.mu.Unlock()

	if !c.approved.Load() {
		return
	}

	probeID := c.GetProbeID()
	baseURL := fmt.Sprintf("%s/api/probes/%d", c.Config.ServerURL, probeID)

	if len(traps) > 0 {
		c.sendBatch(baseURL+"/traps", "traps", traps)
	}
	if len(pings) > 0 {
		c.sendBatch(baseURL+"/pings", "pings", pings)
	}
	if len(syslogs) > 0 {
		c.sendBatch(baseURL+"/syslog", "syslog", syslogs)
	}
	if len(flows) > 0 {
		c.sendBatch(baseURL+"/flows", "flows", flows)
	}
}

func (c *Client) sendBatch(url, name string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("[Relay] Failed to marshal %s batch: %v", name, err)
		return
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
		if err != nil {
			log.Printf("[Relay] Failed to send %s batch (attempt %d/3): %v", name, attempt+1, err)
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[Relay] Sent %s batch to server", name)
			return
		}

		if resp.StatusCode == 404 {
			c.approved.Store(false)
			log.Printf("[Relay] Probe no longer approved (404 on %s)", name)
			return
		}

		log.Printf("[Relay] Failed to send %s batch: status %d (attempt %d/3)", name, resp.StatusCode, attempt+1)
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
}

// --- Shutdown ---

func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopChan)

		// Wait for DataSendLoop to finish its final flush
		select {
		case <-c.done:
			log.Println("[Relay] Final data flush completed")
		case <-time.After(15 * time.Second):
			log.Println("[Relay] Timed out waiting for final data flush")
		}

		if err := c.sendHeartbeatWithStatus("offline"); err != nil {
			log.Printf("Failed to send offline heartbeat: %v", err)
		}
	})
}
