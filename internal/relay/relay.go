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
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/relay/queue"
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
	// QueueDiskPath is the directory where the 4 BoltDB spool files
	// (traps.bolt, pings.bolt, syslog.bolt, flows.bolt) are stored.
	// If empty, the queues operate in memory-only mode (no durability).
	// AUDIT-058: disk spillover makes the queues survive process
	// restarts and central-server outages.
	QueueDiskPath string
	// QueueMaxBytes is the per-queue on-disk byte cap. 0 disables.
	// Default is 1 GiB.
	QueueMaxBytes int64
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
	queuesOnce            sync.Once
	probeID               uint
	probeName             string
	reregisterAttempts    int
	lastReregisterAttempt time.Time

	// Data queues (AUDIT-058: SpilloverQueue wraps []byte + bbolt).
	// Items pushed to these queues are JSON-marshaled; on overflow the
	// oldest in-memory item is moved to the on-disk BoltDB file, where
	// it is evicted oldest-first when the byte cap is hit.
	//
	// Queues are lazily opened on first Send* (see ensureQueues) so
	// tests that only exercise non-queue code paths (mTLS, send
	// retries, etc.) do not have to pre-configure a disk path.
	trapQueue   *queue.SpilloverQueue
	pingQueue   *queue.SpilloverQueue
	syslogQueue *queue.SpilloverQueue
	flowQueue   *queue.SpilloverQueue

	// AUDIT-054 (v2): config-revision retry queue. Same SpilloverQueue
	// primitive as the 4 event queues above. Marshaled *ConfigRevision
	// JSON is pushed on transport error or non-2xx response, then
	// drained in `syncData` via `sendRevisionBatch` which retries each
	// revision 3× with 1s/2s backoff. Disk persistence (same BoltDB
	// mechanism) gives restart-survival for free — without this, a
	// collector crash mid-retry would drop the pending revision and the
	// central server would lose the only copy of the config backup.
	revisionQueue *queue.SpilloverQueue
}

func NewClient(cfg Config) *Client {
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 60 * time.Second
	}

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	return &Client{
		Config: cfg,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:       tlsConfig,
				MaxIdleConns:          200,
				MaxIdleConnsPerHost:   50,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
		stopChan: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// ensureQueues lazily opens the four SpilloverQueue instances on the
// first call. Subsequent calls are no-ops. AUDIT-058.
//
// If QueueDiskPath is empty, queues are not opened and Send* methods
// will log a warning. This matches the "memory-only" fallback
// described in the issue spec.
func (c *Client) ensureQueues() {
	c.queuesOnce.Do(func() {
		diskPath := c.Config.QueueDiskPath
		if diskPath == "" {
			log.Println("[Relay] QueueDiskPath is empty; queues disabled (Send* will log warnings)")
			return
		}

		maxBytes := c.Config.QueueMaxBytes
		if maxBytes == 0 {
			maxBytes = 1 << 30 // 1 GiB default (issue spec)
		}

		open := func(name string) *queue.SpilloverQueue {
			q, err := queue.Open(queue.Config{
				Path:     filepath.Join(diskPath, name+".bolt"),
				Bucket:   name,
				MaxMem:   maxQueueSize,
				MaxBytes: maxBytes,
			})
			if err != nil {
				log.Fatalf("[Relay] Failed to open %s queue at %s: %v", name, filepath.Join(diskPath, name+".bolt"), err)
			}
			return q
		}

		c.trapQueue = open("traps")
		c.pingQueue = open("pings")
		c.syslogQueue = open("syslog")
		c.flowQueue = open("flows")
		c.revisionQueue = open("revisions")
	})
}

// buildTLSConfig assembles the *tls.Config used by the relay's HTTP client
// (AUDIT-048). It is split out of NewClient so the error paths are unit
// testable without spawning a subprocess; NewClient turns every error into
// log.Fatalf because they all represent startup misconfigurations that must
// abort the process before the first request goes out.
//
// mTLS (PROBE_TLS_CERT + PROBE_TLS_KEY) is loaded here. Previously the cert
// and key paths were parsed from env vars and stored on Config, but NewClient
// silently dropped them — so the documented mTLS mode was fiction.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file %s: %w", cfg.CACertFile, err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", cfg.CACertFile)
		}
		tlsConfig.RootCAs = caPool
	}

	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, fmt.Errorf(
				"mTLS misconfiguration: both PROBE_TLS_CERT and PROBE_TLS_KEY must be set (got cert=%q key=%q)",
				cfg.TLSCertFile, cfg.TLSKeyFile)
		}
		// Refuse world- or group-readable private keys. Skipped on Windows
		// where the kernel doesn't enforce Unix permission bits.
		if runtime.GOOS != "windows" {
			info, err := os.Stat(cfg.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("stat TLS key file %s: %w", cfg.TLSKeyFile, err)
			}
			if mode := info.Mode().Perm(); mode&0o077 != 0 {
				return nil, fmt.Errorf(
					"TLS key file %s has permissive mode %#o — world/group readable private keys are rejected; chmod 600 (or stricter) and restart",
					cfg.TLSKeyFile, mode)
			}
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf(
				"load mTLS client cert/key pair (cert=%s key=%s): %w",
				cfg.TLSCertFile, cfg.TLSKeyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.InsecureSkipVerify {
		log.Println("WARNING: TLS certificate verification is disabled — do not use in production")
		tlsConfig.InsecureSkipVerify = true
	}

	return tlsConfig, nil
}

func (c *Client) doAuthenticatedRequest(method, url string, body []byte) (*http.Response, error) {
	return c.doAuthenticatedRequestH(method, url, body, nil)
}

// doAuthenticatedRequestH is doAuthenticatedRequest with extra request headers
// (e.g. the AUDIT-042 X-Probe-Batch-ID idempotency key).
func (c *Client) doAuthenticatedRequestH(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Config.RegistrationKey)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.httpClient.Do(req)
}

// newBatchID returns a random idempotency key for one probe data batch
// (AUDIT-042). It is generated once per batch and reused across that batch's
// retry attempts, so the server can dedupe a batch whose response timed out
// after it was actually saved instead of inserting duplicate rows.
func newBatchID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
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
//
// AUDIT-058: these methods now marshal to JSON and push to a
// SpilloverQueue. The SpilloverQueue handles the in-memory cap (drops
// oldest from RAM) and disk-spillover (overflow moves oldest to
// BoltDB, evicted oldest-first on byte-cap). The previous behavior of
// "drop oldest from RAM" is preserved; the new behavior is the disk
// spillover, which is durable across process restarts.

func (c *Client) SendTrap(trap *TrapEvent) {
	c.ensureQueues()
	if c.trapQueue == nil {
		return
	}
	data, err := json.Marshal(trap)
	if err != nil {
		log.Printf("[Relay] Failed to marshal trap: %v", err)
		return
	}
	if err := c.trapQueue.Push(data); err != nil {
		log.Printf("[Relay] Failed to enqueue trap: %v", err)
	}
}

func (c *Client) SendPingResult(result *PingResult) {
	c.ensureQueues()
	if c.pingQueue == nil {
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		log.Printf("[Relay] Failed to marshal ping result: %v", err)
		return
	}
	if err := c.pingQueue.Push(data); err != nil {
		log.Printf("[Relay] Failed to enqueue ping result: %v", err)
	}
}

func (c *Client) SendSyslogMessage(msg *SyslogMessage) {
	c.ensureQueues()
	if c.syslogQueue == nil {
		return
	}
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[Relay] Failed to marshal syslog message: %v", err)
		return
	}
	if err := c.syslogQueue.Push(data); err != nil {
		log.Printf("[Relay] Failed to enqueue syslog message: %v", err)
	}
}

func (c *Client) SendFlowSample(sample *FlowSample) {
	c.ensureQueues()
	if c.flowQueue == nil {
		return
	}
	data, err := json.Marshal(sample)
	if err != nil {
		log.Printf("[Relay] Failed to marshal flow sample: %v", err)
		return
	}
	if err := c.flowQueue.Push(data); err != nil {
		log.Printf("[Relay] Failed to enqueue flow sample: %v", err)
	}
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
	c.ensureQueues()
	if c.trapQueue == nil {
		return
	}

	if !c.approved.Load() {
		log.Println("[Relay] Probe not approved, attempting re-registration before sync...")
		if !c.tryReregister() {
			return
		}
	}

	probeID := c.GetProbeID()
	baseURL := fmt.Sprintf("%s/api/probes/%d", c.Config.ServerURL, probeID)

	// AUDIT-058: drain in bounded chunks so a multi-day backlog doesn't
	// materialize as one giant [][]byte in RAM. Each chunk is
	// 10× MaxBatchSize (so a 1000-batch config drains 10K items at a
	// time).
	drainChunk := c.Config.MaxBatchSize * 10
	if drainChunk <= 0 {
		drainChunk = 10000
	}

	// traps
	for {
		raw, err := c.trapQueue.Drain(drainChunk)
		if err != nil {
			log.Printf("[Relay] drain traps: %v", err)
			break
		}
		if len(raw) == 0 {
			break
		}
		traps := unmarshalTraps(raw)
		c.sendBatchesSequential(baseURL+"/traps", "traps", traps)
		if len(raw) < drainChunk {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// pings
	for {
		raw, err := c.pingQueue.Drain(drainChunk)
		if err != nil {
			log.Printf("[Relay] drain pings: %v", err)
			break
		}
		if len(raw) == 0 {
			break
		}
		pings := unmarshalPings(raw)
		c.sendBatchesSequential(baseURL+"/pings", "pings", pings)
		if len(raw) < drainChunk {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// syslogs
	for {
		raw, err := c.syslogQueue.Drain(drainChunk)
		if err != nil {
			log.Printf("[Relay] drain syslogs: %v", err)
			break
		}
		if len(raw) == 0 {
			break
		}
		syslogs := unmarshalSyslogs(raw)
		c.sendBatchesSequential(baseURL+"/syslog", "syslog", syslogs)
		if len(raw) < drainChunk {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// flows
	for {
		raw, err := c.flowQueue.Drain(drainChunk)
		if err != nil {
			log.Printf("[Relay] drain flows: %v", err)
			break
		}
		if len(raw) == 0 {
			break
		}
		flows := unmarshalFlows(raw)
		c.sendBatchesSequential(baseURL+"/flows", "flows", flows)
		if len(raw) < drainChunk {
			break
		}
	}

	// AUDIT-054: drain the config-revision retry queue. Same bounded
	// chunking as the 4 event queues above. Each batch is then handed
	// to sendRevisionBatch which retries each revision individually
	// (3× with 1s/2s backoff) and re-queues the survivors.
	//
	// Done AFTER the event queues so a flooded event-queue backlog
	// can't starve the much smaller (and more important — these are
	// the only copies of config backups) revision queue.
	for {
		raw, err := c.revisionQueue.Drain(drainChunk)
		if err != nil {
			log.Printf("[Relay] drain revisions: %v", err)
			break
		}
		if len(raw) == 0 {
			break
		}
		c.sendRevisionBatch(baseURL+"/config-revision", raw)
		if len(raw) < drainChunk {
			break
		}
	}
}

// unmarshalTraps converts a slice of JSON bytes (as produced by the
// SpilloverQueue on Drain) into a typed slice for batch sending.
// Malformed items are logged and skipped (one bad event should not
// stall the whole sync).
func unmarshalTraps(raw [][]byte) []*TrapEvent {
	out := make([]*TrapEvent, 0, len(raw))
	for _, b := range raw {
		var t TrapEvent
		if err := json.Unmarshal(b, &t); err != nil {
			log.Printf("[Relay] Failed to unmarshal trap: %v", err)
			continue
		}
		out = append(out, &t)
	}
	return out
}

func unmarshalPings(raw [][]byte) []*PingResult {
	out := make([]*PingResult, 0, len(raw))
	for _, b := range raw {
		var p PingResult
		if err := json.Unmarshal(b, &p); err != nil {
			log.Printf("[Relay] Failed to unmarshal ping: %v", err)
			continue
		}
		out = append(out, &p)
	}
	return out
}

func unmarshalSyslogs(raw [][]byte) []*SyslogMessage {
	out := make([]*SyslogMessage, 0, len(raw))
	for _, b := range raw {
		var s SyslogMessage
		if err := json.Unmarshal(b, &s); err != nil {
			log.Printf("[Relay] Failed to unmarshal syslog: %v", err)
			continue
		}
		out = append(out, &s)
	}
	return out
}

func unmarshalFlows(raw [][]byte) []*FlowSample {
	out := make([]*FlowSample, 0, len(raw))
	for _, b := range raw {
		var f FlowSample
		if err := json.Unmarshal(b, &f); err != nil {
			log.Printf("[Relay] Failed to unmarshal flow: %v", err)
			continue
		}
		out = append(out, &f)
	}
	return out
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
	items, ok := chunk.([]*TrapEvent)
	if !ok {
		log.Printf("[Relay] ERROR: Generic requeue for %q got unexpected type %T", name, chunk)
		return
	}
	c.requeueTraps(items)
}

func (c *Client) requeueTraps(items []*TrapEvent) {
	if c.trapQueue == nil {
		log.Printf("[Relay] WARNING: Could not requeue %d traps - queue disabled", len(items))
		return
	}
	requeued := 0
	for _, t := range items {
		data, err := json.Marshal(t)
		if err != nil {
			log.Printf("[Relay] Failed to marshal trap for requeue: %v", err)
			continue
		}
		if err := c.trapQueue.Push(data); err != nil {
			log.Printf("[Relay] Re-queue trap: %v", err)
			continue
		}
		requeued++
	}
	if requeued > 0 {
		log.Printf("[Relay] Re-queued %d trap events", requeued)
	} else {
		log.Printf("[Relay] WARNING: Could not requeue %d traps - queue full", len(items))
	}
}

func (c *Client) requeuePings(items []*PingResult) {
	if c.pingQueue == nil {
		log.Printf("[Relay] WARNING: Could not requeue %d pings - queue disabled", len(items))
		return
	}
	requeued := 0
	for _, p := range items {
		data, err := json.Marshal(p)
		if err != nil {
			log.Printf("[Relay] Failed to marshal ping for requeue: %v", err)
			continue
		}
		if err := c.pingQueue.Push(data); err != nil {
			log.Printf("[Relay] Re-queue ping: %v", err)
			continue
		}
		requeued++
	}
	if requeued > 0 {
		log.Printf("[Relay] Re-queued %d ping results", requeued)
	} else {
		log.Printf("[Relay] WARNING: Could not requeue %d pings - queue full", len(items))
	}
}

func (c *Client) requeueSyslogs(items []*SyslogMessage) {
	if c.syslogQueue == nil {
		log.Printf("[Relay] WARNING: Could not requeue %d syslog messages - queue disabled", len(items))
		return
	}
	requeued := 0
	for _, s := range items {
		data, err := json.Marshal(s)
		if err != nil {
			log.Printf("[Relay] Failed to marshal syslog for requeue: %v", err)
			continue
		}
		if err := c.syslogQueue.Push(data); err != nil {
			log.Printf("[Relay] Re-queue syslog: %v", err)
			continue
		}
		requeued++
	}
	if requeued > 0 {
		log.Printf("[Relay] Re-queued %d syslog messages", requeued)
	} else {
		log.Printf("[Relay] WARNING: Could not requeue %d syslog messages - queue full", len(items))
	}
}

func (c *Client) requeueFlows(items []*FlowSample) {
	if c.flowQueue == nil {
		log.Printf("[Relay] WARNING: Could not requeue %d flow samples - queue disabled", len(items))
		return
	}
	requeued := 0
	for _, f := range items {
		data, err := json.Marshal(f)
		if err != nil {
			log.Printf("[Relay] Failed to marshal flow for requeue: %v", err)
			continue
		}
		if err := c.flowQueue.Push(data); err != nil {
			log.Printf("[Relay] Re-queue flow: %v", err)
			continue
		}
		requeued++
	}
	if requeued > 0 {
		log.Printf("[Relay] Re-queued %d flow samples", requeued)
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

	// AUDIT-042: one idempotency key per batch, reused across all retry
	// attempts so the server dedupes a timed-out-but-saved batch.
	batchID := newBatchID()
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.doAuthenticatedRequestH("POST", url, jsonData, map[string]string{"X-Probe-Batch-ID": batchID})
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

		// AUDIT-058: close the disk-spillover queues. Each Close flushes
		// the in-memory tier to BoltDB so a subsequent process can
		// replay the full queue. Done after the final flush so we
		// capture any data the loop just sent.
		for name, q := range map[string]*queue.SpilloverQueue{
			"traps":     c.trapQueue,
			"pings":     c.pingQueue,
			"syslog":    c.syslogQueue,
			"flows":     c.flowQueue,
			"revisions": c.revisionQueue,
		} {
			if q == nil {
				continue
			}
			if err := q.Close(); err != nil {
				log.Printf("[Relay] Error closing %s queue: %v", name, err)
			}
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
		// AUDIT-054: enqueue on transport errors (TLS handshake, DNS,
		// conn reset) so a transient outage doesn't drop the only copy
		// of the config backup. The queue is disk-persistent, so even a
		// collector crash mid-retry is recoverable: the next process
		// reopens the BoltDB file and the drain resumes.
		c.enqueueRevisionBytes(jsonData)
		return fmt.Errorf("failed to send config revision (enqueued for retry): %w", err)
	}
	defer resp.Body.Close()

	// Read response body for logging
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[RELAY] SendConfigRevision success for device %d: %s", rev.DeviceID, string(bodyBytes))
		return nil
	}
	// AUDIT-054: non-2xx means the server didn't durably store the
	// revision. Enqueue for the next syncData drain — sendRevisionBatch
	// will retry 3× with backoff and surface 4xx-vs-5xx differently.
	c.enqueueRevisionBytes(jsonData)
	log.Printf("[RELAY] SendConfigRevision failed for device %d - status %d (enqueued for retry): %s", rev.DeviceID, resp.StatusCode, string(bodyBytes))
	return fmt.Errorf("send config revision returned status %d (enqueued for retry): %s", resp.StatusCode, string(bodyBytes))
}

// enqueueRevisionBytes pushes a pre-marshaled *ConfigRevision JSON
// payload into the disk-persistent revision queue. Lazily opens the
// queue (mirrors Send* for the 4 event queues) so callers that bypass
// the Send* path (e.g. tests) still get a working queue.
//
// Returns silently on enqueue error: the SpilloverQueue.Push failure
// modes are all "I/O is wedged or the cap is exceeded"; the caller has
// already returned an error to its caller and there is nothing useful
// to do with a second error. The disk-persistent queue is the
// best-effort durability layer, not a hard guarantee.
//
// AUDIT-054 (v2): the first attempt at this fix used a plain
// `[]*ConfigRevision` slice under `c.mu`, matching the trap/ping/flow
// pattern. That was the wrong primitive: it lost all pending revisions
// on process restart. Reusing the SpilloverQueue from AUDIT-058 gives
// retry-on-failure AND restart-survival with zero new dependencies.
func (c *Client) enqueueRevisionBytes(data []byte) {
	c.ensureQueues()
	if c.revisionQueue == nil {
		return
	}
	if err := c.revisionQueue.Push(data); err != nil {
		log.Printf("[RELAY] Failed to enqueue config revision: %v", err)
	}
}

// sendRevisionBatch drains the revisionQueue via Drain, unmarshals each
// payload, and calls sendOneRevisionWithRetry for each. Failed items
// are re-pushed (they become the tail of the queue; the FIFO ordering
// means they'll be retried after whatever the previous drain left
// behind).
//
// AUDIT-054 (v2) design note: the v1 attempt (closed PR #45) used
// requeueRevisions with prepend-to-front semantics so re-failed items
// would be retried first. With a SpilloverQueue (strict FIFO), the
// only requeue primitive is Push, which appends to the tail. For the
// revision use case the ordering is acceptable: revisions are
// infrequent (one per config-change event), so "failed again at the
// back of the line" still means a retry within one syncData cycle
// (default 30s). If strict priority matters, a future change can
// extend SpilloverQueue with a PushFront primitive.
func (c *Client) sendRevisionBatch(url string, raw [][]byte) {
	var failed [][]byte
	for _, data := range raw {
		rev, err := unmarshalConfigRevision(data)
		if err != nil {
			log.Printf("[Relay] Failed to unmarshal config revision (dropping): %v", err)
			continue
		}
		if !c.sendOneRevisionWithRetry(url, rev) {
			failed = append(failed, data)
		}
	}
	if len(failed) > 0 {
		for _, data := range failed {
			if err := c.revisionQueue.Push(data); err != nil {
				log.Printf("[Relay] Failed to re-queue config revision: %v", err)
			}
		}
		log.Printf("[Relay] Re-queued %d config revisions for next syncData cycle", len(failed))
	}
}

// unmarshalConfigRevision parses the JSON payload that was marshaled
// in SendConfigRevision. Malformed payloads are surfaced as errors so
// the caller can drop them (one bad item should not stall the whole
// drain).
func unmarshalConfigRevision(data []byte) (*ConfigRevision, error) {
	var rev ConfigRevision
	if err := json.Unmarshal(data, &rev); err != nil {
		return nil, err
	}
	return &rev, nil
}

// sendOneRevisionWithRetry attempts to deliver a single config
// revision with up to 3 attempts (1s, 2s backoff between attempts).
// On 401/403/404 it attempts re-registration; if re-registration
// succeeds, the loop continues with a fresh attempt; otherwise it
// returns false (the caller will re-queue).
//
// AUDIT-054 (v2): the 4xx/5xx branching matches the relay package's
// other Send* methods (e.g. sendBatchesSequential). 400 is treated as
// a permanent client error (don't retry, don't re-queue — the
// revision is malformed and will fail the same way next time). 5xx
// and transport errors are transient and worth retrying.
func (c *Client) sendOneRevisionWithRetry(url string, rev *ConfigRevision) bool {
	jsonData, err := json.Marshal(rev)
	if err != nil {
		log.Printf("[Relay] Failed to marshal config revision: %v", err)
		return false
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
		if err != nil {
			log.Printf("[Relay] SendConfigRevision transport error for device %d (attempt %d/3): %v", rev.DeviceID, attempt+1, err)
			if attempt < 2 {
				time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			}
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[Relay] SendConfigRevision success for device %d: %s", rev.DeviceID, string(bodyBytes))
			return true
		}

		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
			log.Printf("[Relay] SendConfigRevision auth/reject for device %d (status %d), attempting re-registration", rev.DeviceID, resp.StatusCode)
			c.approved.Store(false)
			if c.tryReregister() {
				continue
			}
			return false
		}

		if resp.StatusCode == 400 {
			log.Printf("[Relay] SendConfigRevision 400 (bad request) for device %d, not retrying: %s", rev.DeviceID, string(bodyBytes))
			return false
		}

		// 5xx or other transient server error.
		log.Printf("[Relay] SendConfigRevision status %d for device %d (attempt %d/3): %s", resp.StatusCode, rev.DeviceID, attempt+1, string(bodyBytes))
		if attempt < 2 {
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
		}
	}
	return false
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
