package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxReregisterAttempts = 5

var (
	maxQueueSize = 10000
	maxBatchSize = 1000
)

func ConfigureLimits(queueSize, batchSize int) {
	if queueSize > 0 {
		maxQueueSize = queueSize
	}
	if batchSize > 0 {
		maxBatchSize = batchSize
	}
}

type BatchLimitError struct {
	BatchSize int
	MaxSize   int
}

func (e *BatchLimitError) Error() string {
	return fmt.Sprintf("batch size %d exceeds max %d", e.BatchSize, e.MaxSize)
}

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
	// Extended session/memory/signature telemetry (Part 1)
	SessionRate1  int    `json:"session_rate_1"`
	SessionRate10 int    `json:"session_rate_10"`
	SessionRate30 int    `json:"session_rate_30"`
	SessionRate60 int    `json:"session_rate_60"`
	SessionCount6 int    `json:"session_count_6"`
	LowMemUsage   int    `json:"low_mem_usage"`
	LowMemCap     int    `json:"low_mem_cap"`
	AVVersion     string `json:"av_version"`
	IPSVersion    string `json:"ips_version"`
	SSLVPNUsers   int    `json:"sslvpn_users"`
	SSLVPNTunnels int    `json:"sslvpn_tunnels"`
	// Network throughput (kbps) from SSH performance status
	NetworkInKbps  float64 `json:"network_in_kbps"`
	NetworkOutKbps float64 `json:"network_out_kbps"`
	// CPU breakdown from SSH performance status
	CPUUser    float64 `json:"cpu_user"`
	CPUSystem  float64 `json:"cpu_system"`
	CPUNice    float64 `json:"cpu_nice"`
	CPUIdle    float64 `json:"cpu_idle"`
	CPUIowait  float64 `json:"cpu_iowait"`
	CPUIrq     float64 `json:"cpu_irq"`
	CPUSoftirq float64 `json:"cpu_softirq"`
	// Memory breakdown
	MemoryFree     uint64 `json:"memory_free"`
	MemoryFreeable uint64 `json:"memory_freeable"`
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
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     uint      `json:"device_id"`
	TunnelName   string    `json:"tunnel_name"`
	TunnelType   string    `json:"tunnel_type"` // "ipsec", "ipsec-dialup", "sslvpn"
	RemoteIP     string    `json:"remote_ip"`
	Status       string    `json:"status"`
	BytesIn      uint64    `json:"bytes_in"`
	BytesOut     uint64    `json:"bytes_out"`
	PacketsIn    uint64    `json:"packets_in"`
	PacketsOut   uint64    `json:"packets_out"`
	State        string    `json:"state"`
	Phase1Name   string    `json:"phase1_name"`
	LocalSubnet  string    `json:"local_subnet"`
	RemoteSubnet string    `json:"remote_subnet"`
	TunnelUptime uint64    `json:"tunnel_uptime"`
	// Phase1 details from SSH
	InterfaceName string `json:"interface_name"`
	Mode          string `json:"mode"`
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

type HAStatus struct {
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	SystemMode     string    `json:"system_mode"`
	GroupID        int       `json:"group_id"`
	GroupName      string    `json:"group_name"`
	MemberIndex    int       `json:"member_index"`
	MemberSerial   string    `json:"member_serial"`
	MemberHostname string    `json:"member_hostname"`
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    float64   `json:"memory_usage"`
	NetworkUsage   int       `json:"network_usage"`
	SessionCount   int       `json:"session_count"`
	PacketCount    uint64    `json:"packet_count"`
	ByteCount      uint64    `json:"byte_count"`
	SyncStatus     string    `json:"sync_status"`
	MasterSerial   string    `json:"master_serial"`
}

type SecurityStats struct {
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	AVDetected     uint64    `json:"av_detected"`
	AVBlocked      uint64    `json:"av_blocked"`
	AVHTTPDetected uint64    `json:"av_http_detected"`
	AVHTTPBlocked  uint64    `json:"av_http_blocked"`
	AVSMTPDetected uint64    `json:"av_smtp_detected"`
	AVSMTPBlocked  uint64    `json:"av_smtp_blocked"`
	IPSDetected    uint64    `json:"ips_detected"`
	IPSBlocked     uint64    `json:"ips_blocked"`
	IPSCritical    uint64    `json:"ips_critical"`
	IPSHigh        uint64    `json:"ips_high"`
	IPSMedium      uint64    `json:"ips_medium"`
	IPSLow         uint64    `json:"ips_low"`
	IPSInfo        uint64    `json:"ips_info"`
	WFHTTPBlocked  uint64    `json:"wf_http_blocked"`
	WFHTTPSBlocked uint64    `json:"wf_https_blocked"`
	WFURLBlocked   uint64    `json:"wf_url_blocked"`
}

type SDWANHealth struct {
	Timestamp  time.Time `json:"timestamp"`
	DeviceID   uint      `json:"device_id"`
	Name       string    `json:"name"`
	Interface  string    `json:"interface"`
	State      string    `json:"state"`
	Latency    float64   `json:"latency"`
	PacketLoss float64   `json:"packet_loss"`
	PacketSend uint64    `json:"packet_send"`
	PacketRecv uint64    `json:"packet_recv"`
}

type LicenseInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id"`
	Description string    `json:"description"`
	ExpiryDate  string    `json:"expiry_date"`
}

type InterfaceAddress struct {
	Timestamp time.Time `json:"timestamp"`
	DeviceID  uint      `json:"device_id"`
	IfIndex   int       `json:"if_index"`
	IPAddress string    `json:"ip_address"`
	NetMask   string    `json:"net_mask"`
}

type DeviceInfo struct {
	ID              uint   `json:"id"`
	Name            string `json:"name"`
	IPAddress       string `json:"ip_address"`
	SNMPPort        int    `json:"snmp_port"`
	SNMPCommunity   string `json:"snmp_community"`
	SNMPVersion     string `json:"snmp_version"`
	SNMPV3Username  string `json:"snmpv3_username"`
	SNMPV3AuthType  string `json:"snmpv3_auth_type"`
	SNMPV3AuthPass  string `json:"snmpv3_auth_pass"`
	SNMPV3PrivType  string `json:"snmpv3_priv_type"`
	SNMPV3PrivPass  string `json:"snmpv3_priv_pass"`
	Enabled         bool   `json:"enabled"`
	Vendor          string `json:"vendor"`
	SSHUsername     string `json:"ssh_username"`
	SSHPassword     string `json:"ssh_password"`
	SSHPort         int    `json:"ssh_port"`
	SSHPollEnabled  bool   `json:"ssh_poll_enabled"`
	SSHPollInterval int    `json:"ssh_poll_interval"`
}

type DevicesResponse struct {
	Success      bool         `json:"success"`
	Data         []DeviceInfo `json:"data"`
	TFTPServerIP string       `json:"tftp_server_ip"`
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
	MaxBatchSize       int
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
	Config                Config
	httpClient            *http.Client
	approved              atomic.Bool
	mu                    sync.Mutex
	stopChan              chan struct{}
	done                  chan struct{}
	stopOnce              sync.Once
	probeID               uint
	probeName             string
	reregisterAttempts    int
	lastReregisterAttempt time.Time

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
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     tlsConfig,
				MaxIdleConns:        25,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
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

// tryReregister attempts to re-register with the server when approval is lost.
// Rate-limited to once per 60 seconds to avoid spamming the server.
// After maxReregisterAttempts failures, enters a 10-minute cooldown before
// resetting the counter and trying again — so the probe can recover from
// extended outages without manual restart.
func (c *Client) tryReregister() bool {
	c.mu.Lock()
	elapsed := time.Since(c.lastReregisterAttempt)
	attempts := c.reregisterAttempts

	if attempts >= maxReregisterAttempts {
		// After exhausting all attempts, wait 10 minutes then reset and try again
		if elapsed < 10*time.Minute {
			c.mu.Unlock()
			return false
		}
		log.Println("[Relay] Re-registration cooldown expired, resetting attempt counter")
		c.reregisterAttempts = 0
		attempts = 0
	} else if elapsed < 60*time.Second {
		c.mu.Unlock()
		return false
	}

	c.lastReregisterAttempt = time.Now()
	c.reregisterAttempts++
	c.mu.Unlock()

	backoff := time.Duration(1<<uint(attempts))*10*time.Second + time.Duration(mrand.Intn(5000))*time.Millisecond
	log.Printf("[Relay] Probe lost approval, attempting re-registration (attempt %d/%d) in %v...",
		attempts+1, maxReregisterAttempts, backoff)
	time.Sleep(backoff)

	if err := c.Register(); err != nil {
		log.Printf("[Relay] Re-registration failed: %v", err)
		return false
	}

	log.Println("[Relay] Re-registration successful, probe approved again")
	return true
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

		backoff := time.Duration(1<<uint(attempts))*10*time.Second + time.Duration(mrand.Intn(5000))*time.Millisecond
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
		c.trapQueue = append(c.trapQueue[:0], c.trapQueue[1:]...)
		log.Println("[Relay] Trap queue full, dropping oldest entry")
	}
	c.trapQueue = append(c.trapQueue, trap)
	c.mu.Unlock()
}

func (c *Client) SendPingResult(result *PingResult) {
	c.mu.Lock()
	if len(c.pingQueue) >= maxQueueSize {
		c.pingQueue = append(c.pingQueue[:0], c.pingQueue[1:]...)
		log.Println("[Relay] Ping queue full, dropping oldest entry")
	}
	c.pingQueue = append(c.pingQueue, result)
	c.mu.Unlock()
}

func (c *Client) SendSyslogMessage(msg *SyslogMessage) {
	c.mu.Lock()
	if len(c.syslogQueue) >= maxQueueSize {
		c.syslogQueue = append(c.syslogQueue[:0], c.syslogQueue[1:]...)
		log.Println("[Relay] Syslog queue full, dropping oldest entry")
	}
	c.syslogQueue = append(c.syslogQueue, msg)
	c.mu.Unlock()
}

func (c *Client) SendFlowSample(sample *FlowSample) {
	c.mu.Lock()
	if len(c.flowQueue) >= maxQueueSize {
		c.flowQueue = append(c.flowQueue[:0], c.flowQueue[1:]...)
		log.Println("[Relay] Flow queue full, dropping oldest entry")
	}
	c.flowQueue = append(c.flowQueue, sample)
	c.mu.Unlock()
}

// --- Direct send (SNMP poll results sent immediately) ---

// doDirectSend is a helper for direct Send methods with retry and approval-revocation handling.
func (c *Client) doDirectSend(endpoint string, name string, payload interface{}) error {
	if !c.approved.Load() {
		if !c.tryReregister() {
			return fmt.Errorf("probe not approved")
		}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", name, err)
	}

	url := fmt.Sprintf("%s/api/probes/%d/%s", c.Config.ServerURL, c.GetProbeID(), endpoint)

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
		if err != nil {
			if attempt < 2 {
				time.Sleep(2 * time.Second)
				continue
			}
			return fmt.Errorf("failed to send %s: %w", name, err)
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// Attempt re-registration on auth/not-found errors
		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
			log.Printf("[Relay] Probe rejected (%d on %s), attempting re-registration...", resp.StatusCode, name)
			c.approved.Store(false)
			if c.tryReregister() {
				continue // retry the send after successful re-registration
			}
			return fmt.Errorf("probe no longer approved (%d on %s)", resp.StatusCode, name)
		}

		if attempt < 2 {
			time.Sleep(2 * time.Second)
			continue
		}
		return fmt.Errorf("send %s returned status %d", name, resp.StatusCode)
	}
	return nil
}

func (c *Client) SendSystemStatuses(statuses []SystemStatus) error {
	return c.doDirectSend("system-status", "system statuses", statuses)
}

func (c *Client) SendInterfaceStats(stats []InterfaceStats) error {
	return c.doDirectSend("interface-stats", "interface stats", stats)
}

func (c *Client) SendVPNStatuses(statuses []VPNStatus) error {
	return c.doDirectSend("vpn-status", "VPN statuses", statuses)
}

func (c *Client) SendHardwareSensors(sensors []HardwareSensor) error {
	return c.doDirectSend("hardware-sensors", "hardware sensors", sensors)
}

func (c *Client) SendProcessorStats(stats []ProcessorStats) error {
	return c.doDirectSend("processor-stats", "processor stats", stats)
}

func (c *Client) SendHAStatuses(statuses []HAStatus) error {
	return c.doDirectSend("ha-status", "HA statuses", statuses)
}

func (c *Client) SendSecurityStats(stats []SecurityStats) error {
	return c.doDirectSend("security-stats", "security stats", stats)
}

func (c *Client) SendSDWANHealth(health []SDWANHealth) error {
	return c.doDirectSend("sdwan-health", "SD-WAN health", health)
}

func (c *Client) SendLicenseInfo(licenses []LicenseInfo) error {
	return c.doDirectSend("license-info", "license info", licenses)
}

func (c *Client) SendInterfaceAddresses(addrs []InterfaceAddress) error {
	return c.doDirectSend("interface-addresses", "interface addresses", addrs)
}

// --- FetchDevices ---

func (c *Client) FetchDevices() ([]DeviceInfo, error) {
	devices, _, err := c.FetchDevicesAndConfig()
	return devices, err
}

// FetchDevicesAndConfig returns the device list along with per-probe
// runtime config the server pushes alongside it (e.g. tftp_server_ip).
func (c *Client) FetchDevicesAndConfig() ([]DeviceInfo, string, error) {
	if !c.approved.Load() {
		if !c.tryReregister() {
			return nil, "", fmt.Errorf("probe not approved")
		}
	}

	url := fmt.Sprintf("%s/api/probes/%d/devices", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch devices: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("fetch devices returned status %d", resp.StatusCode)
	}

	var result DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("failed to decode devices response: %w", err)
	}

	return result.Data, result.TFTPServerIP, nil
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
		log.Println("[Relay] Probe not approved, attempting re-registration before sync...")
		if !c.tryReregister() {
			c.mu.Lock()
			c.trapQueue = append(traps, c.trapQueue...)
			c.pingQueue = append(pings, c.pingQueue...)
			c.syslogQueue = append(syslogs, c.syslogQueue...)
			c.flowQueue = append(flows, c.flowQueue...)
			c.mu.Unlock()
			return
		}
	}

	probeID := c.GetProbeID()
	baseURL := fmt.Sprintf("%s/api/probes/%d", c.Config.ServerURL, probeID)

	if len(traps) > 0 {
		c.sendBatchesSequential(baseURL+"/traps", "traps", traps)
		time.Sleep(500 * time.Millisecond)
	}
	if len(pings) > 0 {
		c.sendBatchesSequential(baseURL+"/pings", "pings", pings)
		time.Sleep(500 * time.Millisecond)
	}
	if len(syslogs) > 0 {
		c.sendBatchesSequential(baseURL+"/syslog", "syslog", syslogs)
		time.Sleep(500 * time.Millisecond)
	}
	if len(flows) > 0 {
		c.sendBatchesSequential(baseURL+"/flows", "flows", flows)
	}
}

func splitIntoChunks(items interface{}, chunkSize int) []interface{} {
	if chunkSize <= 0 {
		chunkSize = 1
	}
	value := reflect.ValueOf(items)
	length := value.Len()

	chunks := make([]interface{}, 0, (length+chunkSize-1)/chunkSize)
	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize
		if end > length {
			end = length
		}
		chunk := value.Slice(i, end).Interface()
		chunks = append(chunks, chunk)
	}
	return chunks
}

func (c *Client) sendBatchesSequential(url, name string, items interface{}) {
	actualBatchSize := c.Config.MaxBatchSize
	if actualBatchSize <= 0 {
		actualBatchSize = maxBatchSize
	}

	chunks := splitIntoChunks(items, actualBatchSize)
	totalChunks := len(chunks)

	for i, chunk := range chunks {
		if i > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		if !c.sendBatch(url, name, chunk) {
			switch name {
			case "traps":
				if items2, ok := chunk.([]*TrapEvent); ok {
					c.requeueTraps(items2)
				}
			case "pings":
				if items2, ok := chunk.([]*PingResult); ok {
					c.requeuePings(items2)
				}
			case "syslog":
				if items2, ok := chunk.([]*SyslogMessage); ok {
					c.requeueSyslogs(items2)
				}
			case "flows":
				if items2, ok := chunk.([]*FlowSample); ok {
					c.requeueFlows(items2)
				}
			default:
				log.Printf("[Relay] ERROR: Unknown batch name %q - attempting generic requeue", name)
				c.requeueGeneric(name, chunk)
			}
			log.Printf("[Relay] Failed to send %s batch chunk %d/%d", name, i+1, totalChunks)
			return
		}
		log.Printf("[Relay] Sent %s batch chunk %d/%d (%d items)", name, i+1, totalChunks, reflect.ValueOf(chunk).Len())
	}
}

func (c *Client) requeueGeneric(name string, chunk interface{}) {
	v := reflect.ValueOf(chunk)
	length := v.Len()
	c.mu.Lock()
	defer c.mu.Unlock()
	switch name {
	case "traps":
		space := maxQueueSize - len(c.trapQueue)
		if space > 0 {
			if space >= length {
				c.trapQueue = append(c.trapQueue, chunk.([]*TrapEvent)...)
			} else {
				c.trapQueue = append(c.trapQueue, v.Slice(0, space).Interface().([]*TrapEvent)...)
			}
		}
	case "pings":
		space := maxQueueSize - len(c.pingQueue)
		if space > 0 {
			if space >= length {
				c.pingQueue = append(c.pingQueue, chunk.([]*PingResult)...)
			} else {
				c.pingQueue = append(c.pingQueue, v.Slice(0, space).Interface().([]*PingResult)...)
			}
		}
	case "syslog":
		space := maxQueueSize - len(c.syslogQueue)
		if space > 0 {
			if space >= length {
				c.syslogQueue = append(c.syslogQueue, chunk.([]*SyslogMessage)...)
			} else {
				c.syslogQueue = append(c.syslogQueue, v.Slice(0, space).Interface().([]*SyslogMessage)...)
			}
		}
	case "flows":
		space := maxQueueSize - len(c.flowQueue)
		if space > 0 {
			if space >= length {
				c.flowQueue = append(c.flowQueue, chunk.([]*FlowSample)...)
			} else {
				c.flowQueue = append(c.flowQueue, v.Slice(0, space).Interface().([]*FlowSample)...)
			}
		}
	}
}

func (c *Client) requeueTraps(items []*TrapEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	space := maxQueueSize - len(c.trapQueue)
	if space > len(items) {
		space = len(items)
	}
	if space > 0 {
		c.trapQueue = append(items[:space], c.trapQueue...)
		log.Printf("[Relay] Re-queued %d trap events", space)
	} else {
		log.Printf("[Relay] WARNING: Could not requeue %d traps - queue full", len(items))
	}
}

func (c *Client) requeuePings(items []*PingResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	space := maxQueueSize - len(c.pingQueue)
	if space > len(items) {
		space = len(items)
	}
	if space > 0 {
		c.pingQueue = append(items[:space], c.pingQueue...)
		log.Printf("[Relay] Re-queued %d ping results", space)
	} else {
		log.Printf("[Relay] WARNING: Could not requeue %d pings - queue full", len(items))
	}
}

func (c *Client) requeueSyslogs(items []*SyslogMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	space := maxQueueSize - len(c.syslogQueue)
	if space > len(items) {
		space = len(items)
	}
	if space > 0 {
		c.syslogQueue = append(items[:space], c.syslogQueue...)
		log.Printf("[Relay] Re-queued %d syslog messages", space)
	} else {
		log.Printf("[Relay] WARNING: Could not requeue %d syslog messages - queue full", len(items))
	}
}

func (c *Client) requeueFlows(items []*FlowSample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	space := maxQueueSize - len(c.flowQueue)
	if space > len(items) {
		space = len(items)
	}
	if space > 0 {
		c.flowQueue = append(items[:space], c.flowQueue...)
		log.Printf("[Relay] Re-queued %d flow samples", space)
	} else {
		log.Printf("[Relay] WARNING: Could not requeue %d flow samples - queue full", len(items))
	}
}

func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case 400, 401, 403, 404, 405, 409, 410, 422, 429:
		return false
	default:
		return true
	}
}

func (c *Client) sendBatch(url, name string, data interface{}) bool {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("[Relay] Failed to marshal %s batch: %v", name, err)
		return false
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
		if err != nil {
			log.Printf("[Relay] Failed to send %s batch (attempt %d/3): %v", name, attempt+1, err)
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[Relay] Warning: failed to read %s response body: %v", name, err)
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[Relay] Sent %s batch to server", name)
			return true
		}

		if resp.StatusCode == 404 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			log.Printf("[Relay] Probe not found/auth failed (%d on %s), attempting re-registration...", resp.StatusCode, name)
			c.approved.Store(false)
			if c.tryReregister() {
				continue
			}
			return false
		}

		if resp.StatusCode == 400 {
			log.Printf("[Relay] Bad request (400) for %s batch: %s - not retrying", name, string(bodyBytes))
			return false
		}

		if !isRetryableStatus(resp.StatusCode) {
			log.Printf("[Relay] Non-retryable status %d for %s batch: %s", resp.StatusCode, name, string(bodyBytes))
			return false
		}

		log.Printf("[Relay] Failed to send %s batch: status %d (attempt %d/3): %s", name, resp.StatusCode, attempt+1, string(bodyBytes))
		time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
	}
	return false
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

type ConfigRevision struct {
	ID            uint      `json:"id"`
	DeviceID      uint      `json:"device_id"`
	Timestamp     time.Time `json:"timestamp"`
	Checksum      string    `json:"checksum"`
	ConfigText    string    `json:"config_text"`
	Length        int       `json:"length"`
	TriggerSource string    `json:"trigger_source,omitempty"` // syslog | poll | manual
	BackupQuality string    `json:"backup_quality,omitempty"` // full | masked | unknown
}

type ProcessSnapshot struct {
	ID        uint          `json:"id"`
	DeviceID  uint          `json:"device_id"`
	Timestamp time.Time     `json:"timestamp"`
	Processes []ProcessInfo `json:"processes"`
}

type ProcessInfo struct {
	Name    string  `json:"name"`
	PID     int     `json:"pid"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"mem"`
	Command string  `json:"command"`
}

type InterfaceErrorSnapshot struct {
	ID          uint      `json:"id"`
	DeviceID    uint      `json:"device_id"`
	Timestamp   time.Time `json:"timestamp"`
	Interface   string    `json:"interface"`
	InErrors    uint64    `json:"in_errors"`
	InDiscards  uint64    `json:"in_discards"`
	OutErrors   uint64    `json:"out_errors"`
	OutDiscards uint64    `json:"out_discards"`
}

type SensorDetail struct {
	ID        uint      `json:"id"`
	DeviceID  uint      `json:"device_id"`
	Timestamp time.Time `json:"timestamp"`
	Name      string    `json:"name"`
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	Status    string    `json:"status"`
}

type LicenseDetail struct {
	ID          uint      `json:"id"`
	DeviceID    uint      `json:"device_id"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
	ExpiryDate  string    `json:"expiry_date"`
	Status      string    `json:"status"`
	Details     string    `json:"details"`
}

func (c *Client) SendConfigRevision(rev *ConfigRevision) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}
	jsonData, err := json.Marshal(rev)
	if err != nil {
		return fmt.Errorf("failed to marshal config revision: %w", err)
	}
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.probeID) + "/config-revision"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send config revision: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for logging
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[RELAY] SendConfigRevision success for device %d: %s", rev.DeviceID, string(bodyBytes))
		return nil
	}
	log.Printf("[RELAY] SendConfigRevision failed for device %d - status %d: %s", rev.DeviceID, resp.StatusCode, string(bodyBytes))
	return fmt.Errorf("send config revision returned status %d: %s", resp.StatusCode, string(bodyBytes))
}

func (c *Client) SendProcessSnapshot(snap *ProcessSnapshot) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}
	jsonData, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("failed to marshal process snapshot: %w", err)
	}
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.probeID) + "/process-snapshot"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send process snapshot: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send process snapshot returned status %d", resp.StatusCode)
}

func (c *Client) SendInterfaceErrorSnapshot(snap *InterfaceErrorSnapshot) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}
	jsonData, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("failed to marshal interface error snapshot: %w", err)
	}
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.probeID) + "/interface-errors"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send interface error snapshot: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send interface error snapshot returned status %d", resp.StatusCode)
}

func (c *Client) SendInterfaceErrorSnapshots(snaps []InterfaceErrorSnapshot) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}
	if len(snaps) == 0 {
		return nil
	}
	jsonData, err := json.Marshal(snaps)
	if err != nil {
		return fmt.Errorf("failed to marshal interface error snapshots: %w", err)
	}
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.probeID) + "/interface-errors"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send interface error snapshots: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send interface error snapshots returned status %d", resp.StatusCode)
}

func (c *Client) SendSensorDetails(sensors []SensorDetail) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}
	if len(sensors) == 0 {
		return nil
	}
	jsonData, err := json.Marshal(sensors)
	if err != nil {
		return fmt.Errorf("failed to marshal sensor details: %w", err)
	}
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.probeID) + "/sensor-details"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send sensor details: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send sensor details returned status %d", resp.StatusCode)
}

func (c *Client) SendLicenseDetails(licenses []LicenseDetail) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}
	if len(licenses) == 0 {
		return nil
	}
	jsonData, err := json.Marshal(licenses)
	if err != nil {
		return fmt.Errorf("failed to marshal license details: %w", err)
	}
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.probeID) + "/license-details"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send license details: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send license details returned status %d", resp.StatusCode)
}
