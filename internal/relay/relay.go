package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/relay/queue"
	"firewall-collector/internal/safego"
)

const maxReregisterAttempts = 5

// heartbeatQuiesceCooldown is how long the heartbeat loop stays quiet after
// the server refuses a heartbeat with 410 Gone (probe rejected /
// decommissioned / disabled). Mirrors tryReregister's 10-minute cooldown: long
// enough to stop hammering a deliberate refusal, short enough that an admin
// re-commission is picked up without restarting the collector.
const heartbeatQuiesceCooldown = 10 * time.Minute

var (
	maxQueueSize = 10000
	maxBatchSize = 1000
)

// flowCountersOffWindow is how long a 404 on /flow-counters suppresses that
// one endpoint (AUDIT-288 — see Client.flowCountersOffUntil). A var, not a
// const, so tests can shrink it to exercise self-expiry.
var flowCountersOffWindow = 30 * time.Minute

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
	// Source identifies which writer produced this row so the server's alert
	// engine can trust a 0 session_count as "idle" only from an authoritative
	// full SNMP poll (AUDIT AL-M2). SystemStatusSourceSNMP for the SNMP poll,
	// SystemStatusSourceSSHPerf for the FortiGate SSH performance freshness row.
	Source string `json:"source"`
}

// system_status writer sources (AUDIT AL-M2), mirrored on the server.
const (
	SystemStatusSourceSNMP    = "snmp"
	SystemStatusSourceSSHPerf = "ssh-perf"
)

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
	// SourceIP is the UDP source address the datagram actually arrived from,
	// used ONLY by the collector's source-attribution binding (AUDIT-186) and
	// never serialized to the server. For sFlow it commonly differs from
	// SamplerAddress (the in-band agent_address); for NetFlow/IPFIX they are the
	// same. json:"-" so the wire contract with the server is unchanged.
	SourceIP       string `json:"-"`
	SequenceNumber uint32 `json:"sequence_number"`
	SamplingRate   uint32 `json:"sampling_rate"`
	SrcAddr        string `json:"src_addr"`
	DstAddr        string `json:"dst_addr"`
	SrcPort        uint16 `json:"src_port"`
	DstPort        uint16 `json:"dst_port"`
	Protocol       uint8  `json:"protocol"`
	Bytes          uint64 `json:"bytes"`
	Packets        uint64 `json:"packets"`
	InputIfIndex   uint32 `json:"input_if_index"`
	OutputIfIndex  uint32 `json:"output_if_index"`
	TCPFlags       uint8  `json:"tcp_flags"`
	// Drops is the sFlow v5 sample-pool drops counter (RFC 3176 §3.1.1,
	// sflow_version_5.txt): the CUMULATIVE number of times the agent
	// dropped a sample since it (re)started — NOT a per-sample delta.
	// The server's flow_agent_drops pipeline correctly baselines the
	// first sighting and records increases as deltas; this comment was
	// previously wrong about the semantics (fixed per the 2026-07-03
	// flow-protocol research) even though the code was right. Non-zero
	// growth indicates agent-side congestion. omitempty: a pre-adopting
	// server sees no wire field at all. NetFlow/IPFIX rows always carry
	// 0 here — export loss for those protocols is a collector metric
	// (sequence gaps), never this field.
	Drops uint64 `json:"drops,omitempty"`
	// BGP/AS enrichment from the sFlow extended_gateway record (RFC 3176
	// data format 1003), present only when the sampling router is BGP-speaking
	// and exports it (many firewalls don't). SrcAS/DstAS are the source AS and
	// the destination's origin AS (last hop of the dst AS path); ASPath is the
	// space-separated dst AS path; NextHop is the BGP next-hop address. All are
	// omitempty so a pre-adopting server sees no wire fields and is unchanged —
	// the same backward-compatible pattern as Drops above. The server prefers
	// these AS numbers over its GeoLite2 lookup when present.
	SrcAS   uint32 `json:"src_as,omitempty"`
	DstAS   uint32 `json:"dst_as,omitempty"`
	ASPath  string `json:"as_path,omitempty"`
	NextHop string `json:"next_hop,omitempty"`
	// ---- Tranche 3 (NetFlow v5/v9 + IPFIX) wire fields. All omitempty, same
	// backward-compatible pattern as Drops above: the sFlow parser never sets
	// them (zero values marshal absent), a pre-adopting server drops the
	// unknown JSON keys, and a pre-adopting collector sends nothing. JSON names
	// MUST match the server's models.FlowSample exactly. Full field rationale:
	// Firewall-Mon docs/flow-protocol-research-2026-07-03.md §2.1.

	// FlowSource labels the exporting protocol (FlowSource* constants below):
	// 0/absent = sFlow, 1 = NetFlow v5, 2 = NetFlow v9, 3 = IPFIX. The server
	// clamps unknown values to 0 at ingest.
	FlowSource uint8 `json:"flow_source,omitempty"`
	// FlowStart/FlowEnd bound the interval a NetFlow/IPFIX record aggregates
	// (active timeouts run to 30 min — a flow record is NOT an instant, unlike
	// an sFlow point sample). Pointers so nil marshals absent — a non-pointer
	// time.Time zero value would serialize as "0001-01-01T00:00:00Z" and leak
	// onto the wire for every sFlow row; the server uses *time.Time too. The
	// legacy Timestamp field stays = flow end for server chart compatibility.
	FlowStart *time.Time `json:"flow_start,omitempty"`
	FlowEnd   *time.Time `json:"flow_end,omitempty"`
	// FirewallEvent is IPFIX IE 233 (NSEL/FortiGate): 0 none, 1 created,
	// 2 deleted, 3 denied, 4 alert, 5 update. Denied-flow visibility is the
	// headline NetFlow-over-sFlow win; denied/create records legally carry
	// zero byte counters.
	FirewallEvent uint8 `json:"firewall_event,omitempty"`
	// FlowEndReason is IE 136; 2 = active timeout (the flow CONTINUES in a
	// later record) — the key input for future flow stitching.
	FlowEndReason uint8 `json:"flow_end_reason,omitempty"`
	// Post-NAT tuple (IEs 225-228, 281/282 for v6, ASA legacy 40001-40004):
	// what the flow looked like AFTER translation. Empty/0 when the exporter
	// is not NATing or doesn't report it.
	PostNATSrcAddr string `json:"post_nat_src_addr,omitempty"`
	PostNATDstAddr string `json:"post_nat_dst_addr,omitempty"`
	PostNATSrcPort uint16 `json:"post_nat_src_port,omitempty"`
	PostNATDstPort uint16 `json:"post_nat_dst_port,omitempty"`
	// ICMPTypeCode is IE 32/139 (type*256+code) for protocol 1/58 rows; by
	// convention the port fields are zeroed for ICMP (NetFlow v5 encodes the
	// type/code in dst_port — the parser moves it here and clears the ports).
	ICMPTypeCode uint16 `json:"icmp_type_code,omitempty"`
	// TOS is IE 5 (or the NetFlow v5 tos byte).
	TOS uint8 `json:"tos,omitempty"`
	// SrcVLAN/DstVLAN are IEs 58/59 (sFlow extended_switch to follow later).
	SrcVLAN uint16 `json:"src_vlan,omitempty"`
	DstVLAN uint16 `json:"dst_vlan,omitempty"`
	// AppName is the EXPORTER's application identification (PAN App-ID 56701,
	// FortiGate app options) — vendor truth that outranks the server's port
	// heuristic when present.
	AppName string `json:"app_name,omitempty"`
}

// Flow source labels (FlowSample.FlowSource). Must stay in lockstep with the
// server's models.FlowSource* constants.
const (
	FlowSourceSFlow     = 0
	FlowSourceNetFlowV5 = 1
	FlowSourceNetFlowV9 = 2
	FlowSourceIPFIX     = 3
)

// InterfaceCounterSample is one sFlow counters_sample (RFC 3176 data format 2/4)
// carrying the generic interface counters (if_counters record, format 1): the
// agent-pushed equivalent of SNMP ifSpeed / ifInOctets / ifOutOctets etc. The
// server uses these as an interface-bandwidth source (and ifSpeed for the
// capacity detector) when SNMP is unavailable or host-restricted. Gated behind
// schema_version >= 2: the collector only emits these to a server that
// negotiated v2, so a pre-v2 server never sees the new /flow-counters endpoint.
type InterfaceCounterSample struct {
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	ProbeID        uint      `json:"probe_id"`
	SamplerAddress string    `json:"sampler_address"`
	// SourceIP is the UDP source the counter datagram arrived from — collector
	// -internal source-binding only (AUDIT-186), never sent to the server.
	SourceIP    string `json:"-"`
	IfIndex     uint32 `json:"if_index"`
	IfType      uint32 `json:"if_type,omitempty"`
	IfSpeed     uint64 `json:"if_speed,omitempty"` // bits/sec (sFlow reports 64-bit ifSpeed)
	IfDirection uint32 `json:"if_direction,omitempty"`
	IfStatus    uint32 `json:"if_status,omitempty"`
	InOctets    uint64 `json:"in_octets,omitempty"`
	InErrors    uint64 `json:"in_errors,omitempty"`
	InDiscards  uint64 `json:"in_discards,omitempty"`
	OutOctets   uint64 `json:"out_octets,omitempty"`
	OutErrors   uint64 `json:"out_errors,omitempty"`
	OutDiscards uint64 `json:"out_discards,omitempty"`
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

// DiskUsage is one per-filesystem usage row (SNMP hrStorageTable). Field JSON
// tags MUST match the server's models.DiskUsage. Schema v3.
type DiskUsage struct {
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id"`
	Mount       string    `json:"mount"`
	TotalBytes  uint64    `json:"total_bytes"`
	UsedBytes   uint64    `json:"used_bytes"`
	UsedPercent float64   `json:"used_percent"`
}

// LoadAverage is the 1/5/15-minute system load (UCD laLoad). Schema v3.
type LoadAverage struct {
	Timestamp time.Time `json:"timestamp"`
	DeviceID  uint      `json:"device_id"`
	Load1     float64   `json:"load1"`
	Load5     float64   `json:"load5"`
	Load15    float64   `json:"load15"`
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

// TopologyEntry is one row of L2 topology evidence (schema v5): an ARP-cache
// binding (entry_type "arp": IP+MAC seen via local interface if_index) or an
// FDB/MAC-table binding (entry_type "fdb": MAC learned on if_index, VLAN
// vlan_id). MAC addresses are canonical lowercase colon form — the server
// joins them against interface MACs to infer port-to-port links. Each send is
// the device's COMPLETE snapshot for the entry types it contains; the server
// replaces, not appends.
type TopologyEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	DeviceID   uint      `json:"device_id"`
	EntryType  string    `json:"entry_type"` // "fdb" | "arp"
	IfIndex    int       `json:"if_index"`
	IfName     string    `json:"if_name,omitempty"`    // SSH-sourced ARP only
	MACAddress string    `json:"mac_address"`          // canonical "aa:bb:cc:dd:ee:ff"
	IPAddress  string    `json:"ip_address,omitempty"` // arp only
	VlanID     int       `json:"vlan_id,omitempty"`    // fdb only
	Source     string    `json:"source"`               // "snmp" | "ssh"
}

// TopologyNeighbor is one LLDP/CDP neighbor-table row (schema v5): the local
// port plus whatever identity the neighbor advertised. Like TopologyEntry,
// each send is the device's complete snapshot per protocol.
type TopologyNeighbor struct {
	Timestamp       time.Time `json:"timestamp"`
	DeviceID        uint      `json:"device_id"`
	Protocol        string    `json:"protocol"` // "lldp" | "cdp"
	LocalIfIndex    int       `json:"local_if_index"`
	LocalPortName   string    `json:"local_port_name,omitempty"`
	RemoteChassisID string    `json:"remote_chassis_id"`
	RemotePortID    string    `json:"remote_port_id"`
	RemotePortDesc  string    `json:"remote_port_desc,omitempty"`
	RemoteSysName   string    `json:"remote_sys_name,omitempty"`
	RemoteSysDesc   string    `json:"remote_sys_desc,omitempty"`
	RemoteCaps      string    `json:"remote_caps,omitempty"`
	RemoteMgmtAddr  string    `json:"remote_mgmt_addr,omitempty"` // neighbor's advertised mgmt IP (CDP cacheAddress)
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

// SchemaVersionMin / SchemaVersionMax pin the probe↔server relay wire-format
// range this collector speaks. They MUST stay in lockstep with the server's
// relay.SchemaVersionMin / relay.SchemaVersionMax (xphox2/Firewall-Monitoring
// internal/relay/relay.go) and the MIGRATING.md / SUPPORT-MATRIX.md docs. The
// collector advertises SchemaVersionMax on register; a server that supports
// only an older range replies HTTP 426 (Upgrade Required) with the supported
// range in the X-Probe-Schema-Version-Supported header.
// v2 (R5) adds the sFlow interface counter-samples telemetry type
// (/flow-counters endpoint). It is gated: the collector only emits counter
// samples to a server that negotiated v2, so a v1 server never sees the new
// endpoint. v1 remains fully supported (Min stays 1) for mixed-version deploys.
// v4 adds the server→collector COMMAND CHANNEL: the heartbeat response
// carries `pending_commands` (PendingCommand) and the collector reports each
// outcome to POST /api/probes/:id/command-result (CommandResult). Both
// directions are gated on a negotiated schema ≥ 4 (mirroring the disk/load
// v3 gate), so a v3 server is never POSTed an endpoint it doesn't have and a
// v3 collector never parses commands.
// v5 adds L2 TOPOLOGY snapshots (TopologyEntry ARP/FDB rows to
// /topology-entries, TopologyNeighbor LLDP/CDP rows to /topology-neighbors),
// gated on negotiated schema ≥ 5. These are state snapshots with server-side
// replace semantics, sent via doSnapshotSend (never spooled — a replayed old
// snapshot would revert newer state).
const (
	SchemaVersionMin = 1
	SchemaVersionMax = 5
)

// AgentVersion is the collector's own software version, reported on register
// and every heartbeat.
//
// It exists because the server previously had NO way to know which collector
// build it was talking to — only the negotiated schema_version, which tracks the
// wire format and not the binary. That gap forced anything version-dependent to
// infer the build indirectly: the IPSec telemetry gate had to match on the text
// of a failure the collector returned, and diagnosing a stale collector meant
// looking for side effects in unrelated telemetry.
//
// Set once at startup by the binary that owns the version constant.
var AgentVersion string

// SetAgentVersion records the collector's version for reporting. Safe to call
// before any client exists.
func SetAgentVersion(v string) { AgentVersion = v }

type RegisterRequest struct {
	RegistrationKey string `json:"registration_key"`
	// AgentVersion is informational: an older server ignores the unknown field,
	// so sending it is always backward-compatible.
	AgentVersion string `json:"agent_version,omitempty"`
	// SchemaVersion advertises the relay wire-format version this collector
	// speaks. Pre-handshake servers (< v0.10.382) ignore the unknown field, so
	// sending it is always backward-compatible; a handshake-aware server
	// validates it and replies 426 if it's outside the server's range.
	SchemaVersion int `json:"schema_version,omitempty"`
}

type RegisterResponse struct {
	Success   bool   `json:"success"`
	ProbeID   uint   `json:"probe_id"`
	ProbeName string `json:"probe_name"`
	Message   string `json:"message"`
	Approved  bool   `json:"approved"`
	// SchemaVersion is the version the server selected for this probe. A
	// pre-handshake server omits it (zero value) → the collector assumes v1.
	SchemaVersion int `json:"schema_version,omitempty"`
}

// PendingCommand is one server→collector command delivered on the heartbeat
// response (schema v4). The server attaches pending_commands only for probes
// that registered with schema ≥ 4, and re-delivers a command whose result it
// hasn't received (at-least-once) — the executor must dedupe by CommandID.
// SECURITY: Payload is the command's type-specific JSON document; future
// command types will carry credentials in it, so it must NEVER be logged
// (log CommandID + Type only).
type PendingCommand struct {
	CommandID string    `json:"command_id"`
	DeviceID  uint      `json:"device_id"`
	Type      string    `json:"type"`
	Payload   string    `json:"payload"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CommandResult is the body of POST /api/probes/:id/command-result (schema
// v4): the outcome report for one executed PendingCommand. Status must be
// "succeeded" or "failed"; the server is idempotent by CommandID (first
// terminal result wins), so retries and redelivery races are safe.
type CommandResult struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	Result    string `json:"result"`
}

// heartbeatResponse is the schema-v4 heartbeat reply shape. Pre-v4 servers
// return just {"success":true}; decoding tolerates the absent field.
type heartbeatResponse struct {
	Success         bool             `json:"success"`
	PendingCommands []PendingCommand `json:"pending_commands"`
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

	// heartbeatQuiescedUntil (LC-02): while now < this, sendHeartbeatWithStatus
	// short-circuits without POSTing. Set when the server answers 410 Gone —
	// the probe was rejected/decommissioned/disabled ON PURPOSE (server M7:
	// "heartbeat refused", deliberately non-retryable) — so hammering at full
	// cadence or churning re-registration is wrong. Rechecked after the
	// cooldown so an admin re-commission recovers without a collector restart;
	// also cleared by a successful registration. Guarded by mu.
	heartbeatQuiescedUntil time.Time

	// Data queues (AUDIT-058: SpilloverQueue wraps []byte + bbolt).
	// Items pushed to these queues are JSON-marshaled; on overflow the
	// oldest in-memory item is moved to the on-disk BoltDB file, where
	// it is evicted oldest-first when the byte cap is hit.
	//
	// Queues are lazily opened on first Send* (see ensureQueues) so
	// tests that only exercise non-queue code paths (mTLS, send
	// retries, etc.) do not have to pre-configure a disk path.
	trapQueue        *queue.SpilloverQueue
	pingQueue        *queue.SpilloverQueue
	syslogQueue      *queue.SpilloverQueue
	flowQueue        *queue.SpilloverQueue
	flowCounterQueue *queue.SpilloverQueue // sFlow interface counters (schema v2)

	// negotiatedSchema holds the schema_version the server selected at register
	// time (0 until first successful registration → treated as v1). Read on the
	// send path to gate v2-only telemetry (counter samples); written in Register.
	negotiatedSchema atomic.Int32

	// flowCountersOffUntil (AUDIT-288) suppresses ONLY the /flow-counters
	// endpoint until the stored UnixNano deadline, set when that endpoint
	// answers 404. A 404 on ONE route is endpoint-level evidence, not
	// protocol-version evidence: the old response — negotiatedSchema.Store(1)
	// — also killed the unrelated v3 disk/load sends, the v4 command channel
	// (including IPSec deploys), and the v5 topology gates until a collector
	// restart. Self-expiring, so a transient 404 (proxy blip, rolling deploy)
	// recovers without a restart at the cost of one 404 per window; cleared
	// immediately by a successful re-registration (fresh evidence), mirroring
	// the heartbeatQuiescedUntil reset.
	flowCountersOffUntil atomic.Int64

	// AUDIT-054 (v2): config-revision retry queue. Same SpilloverQueue
	// primitive as the 4 event queues above. Marshaled *ConfigRevision
	// JSON is pushed on transport error or non-2xx response, then
	// drained in `syncData` via `sendRevisionBatch` which retries each
	// revision 3× with 1s/2s backoff. Disk persistence (same BoltDB
	// mechanism) gives restart-survival for free — without this, a
	// collector crash mid-retry would drop the pending revision and the
	// central server would lose the only copy of the config backup.
	revisionQueue *queue.SpilloverQueue

	// metricQueue (2026-06-23 audit H9) buffers the primary SNMP-metric
	// sends (the 10 doDirectSend endpoints: system status, interface stats,
	// VPN, hardware sensors, processor stats, HA, security stats, SD-WAN,
	// license, interface addresses) when the server is unreachable. Before this
	// they had NO queue — doDirectSend's callers only logged on failure, so a
	// server outage discarded every health sample for its full duration while
	// the lower-value event streams (traps/syslog/pings/flows) WERE preserved,
	// inverting data-value priority. Each item is a metricEnvelope (endpoint +
	// already-marshaled payload) so one queue serves all 10 differently-routed
	// metric types; drained in syncData via drainMetricQueue.
	metricQueue *queue.SpilloverQueue

	// observedHostKeysFn, if set, returns a snapshot of the SSH host-key
	// fingerprints the collector has observed (device ID -> "SHA256:..."). The
	// heartbeat includes it so the server can detect host-key changes.
	observedHostKeysFn func() map[uint]string

	// commandHandlerFn, if set, receives the pending_commands the server
	// attached to a heartbeat response (schema v4). Invoked on a separate
	// goroutine so a slow command executor can never stall the heartbeat
	// cadence (a stalled heartbeat marks the probe offline server-side).
	// SECURITY: command payloads may carry credentials for future command
	// types — the handler must never log them.
	commandHandlerFn func([]PendingCommand)

	// onMetricSendFailed, if set, is called (with the metric kind) whenever a
	// primary metric send fails and is buffered to the spillover queue. Wired to
	// the observability counter firewall_collector_metric_send_failed_total (M12).
	onMetricSendFailed func(kind string)

	// onQueueDrop / onDataBatchSent (AUDIT-210) surface previously-dead queue
	// metrics. onQueueDrop is installed onto every SpilloverQueue's OnDrop and
	// wired to firewall_collector_queue_dropped_total; onDataBatchSent is called
	// at each metric-send outcome and wired to
	// firewall_collector_data_batch_sent_total. Both are plain callbacks so the
	// queue/relay layers never import observability (import-cycle avoidance).
	onQueueDrop     func(queue string)
	onDataBatchSent func(queue, outcome string)

	// queuesReady is set true (with the queue-pointer writes happening-before it,
	// in the same goroutine) once ensureQueues has successfully opened all seven
	// queues. QueueDepth checks it before reading a queue pointer so a concurrent
	// /metrics scrape never races the lazy open — the atomic Load/Store pair
	// provides the memory barrier. Left false on the disabled / partial-open
	// paths, where QueueDepth correctly reports 0.
	queuesReady atomic.Bool
}

// SetObservedHostKeysProvider registers a source of observed SSH host-key
// fingerprints (device ID -> fingerprint) to include on each heartbeat.
func (c *Client) SetObservedHostKeysProvider(fn func() map[uint]string) {
	c.observedHostKeysFn = fn
}

// SetCommandHandler registers the executor for heartbeat-delivered server
// commands (schema v4). The handler is invoked asynchronously with each
// batch of pending commands; it must dedupe by CommandID itself (the server
// re-delivers a command whose result it hasn't received — at-least-once).
func (c *Client) SetCommandHandler(fn func([]PendingCommand)) {
	c.commandHandlerFn = fn
}

// SetMetricSendFailedHook registers a callback invoked (with the metric kind)
// each time a primary metric send fails and is buffered — typically
// metrics.IncMetricSendFailed.
func (c *Client) SetMetricSendFailedHook(fn func(kind string)) {
	c.onMetricSendFailed = fn
}

// SetQueueDropHook registers a callback invoked (with the queue name) each time
// a SpilloverQueue evicts an item because its byte cap is full — typically
// metrics.IncQueueDropped (AUDIT-210). The callback is read at drop time, so it
// may be installed before or after the queues are lazily opened.
func (c *Client) SetQueueDropHook(fn func(queue string)) {
	c.onQueueDrop = fn
}

// SetDataBatchSentHook registers a callback invoked (with queue name and
// "success"|"failure") at each metric-send outcome — typically
// metrics.OnDataBatchSent (AUDIT-210).
func (c *Client) SetDataBatchSentHook(fn func(queue, outcome string)) {
	c.onDataBatchSent = fn
}

// fireDataBatchSent reports one metric-send outcome, nil-hook-safe.
func (c *Client) fireDataBatchSent(queue, outcome string) {
	if c.onDataBatchSent != nil {
		c.onDataBatchSent(queue, outcome)
	}
}

// QueueDepth returns the in-memory depth of the named spillover queue, or 0 for
// an unknown queue or one not yet opened (AUDIT-210). Names match ensureQueues:
// traps, pings, syslog, flows, flow-counters, revisions, metrics.
//
// NOTE: SpilloverQueue.Depth() counts only the front + in-memory tiers; items
// spilled to the on-disk BoltDB tier are NOT included, so during a prolonged
// outage this under-reports the true backlog. Making Depth() include the disk
// tier is a separate concern and deliberately not changed here.
func (c *Client) QueueDepth(name string) int {
	// The queue pointers are written once inside ensureQueues' sync.Once and
	// published via queuesReady; skip the read entirely until it's set so a
	// scrape can never race the lazy open.
	if !c.queuesReady.Load() {
		return 0
	}
	var q *queue.SpilloverQueue
	switch name {
	case "traps":
		q = c.trapQueue
	case "pings":
		q = c.pingQueue
	case "syslog":
		q = c.syslogQueue
	case "flows":
		q = c.flowQueue
	case "flow-counters":
		q = c.flowCounterQueue
	case "revisions":
		q = c.revisionQueue
	case "metrics":
		q = c.metricQueue
	default:
		return 0
	}
	if q == nil {
		return 0
	}
	return q.Depth()
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
			log.Println("[Relay] PROBE_QUEUE_DISK_PATH not set; spillover queues DISABLED — telemetry is dropped (not buffered) while the central server is unreachable. Set it to a writable, persistent directory to survive server outages and restarts.")
			return
		}

		// Create the directory if it doesn't exist (e.g. a fresh volume mount)
		// so a valid-but-not-yet-created path doesn't fail the queue open.
		// AUDIT-224 (gosec G301): 0o750, not 0o755 — this holds queued
		// telemetry; nothing outside the collector's user/group reads it.
		if err := os.MkdirAll(diskPath, 0o750); err != nil {
			log.Printf("[Relay] WARNING: cannot create queue directory %s: %v — spillover queues DISABLED (telemetry dropped during outages). Fix the path/permissions and restart.", diskPath, err)
			return
		}

		maxBytes := c.Config.QueueMaxBytes
		if maxBytes == 0 {
			maxBytes = 1 << 30 // 1 GiB default (issue spec)
		}

		// Fail SOFT: if any spool can't be opened (e.g. an unwritable mounted
		// volume on a rootless container), warn and run queue-disabled rather
		// than log.Fatalf'ing into a crash-loop. Send* methods null-check each
		// queue, so a disabled queue degrades to live-relay-only safely.
		var openErr error
		open := func(name string) *queue.SpilloverQueue {
			if openErr != nil {
				return nil
			}
			path := filepath.Join(diskPath, name+".bolt")
			q, err := queue.Open(queue.Config{
				Path:     path,
				Bucket:   name,
				MaxMem:   maxQueueSize,
				MaxBytes: maxBytes,
				// AUDIT-210: surface byte-cap drops on
				// firewall_collector_queue_dropped_total. The closure reads the
				// hook at drop time, so wiring order with SetQueueDropHook doesn't
				// matter; the queue package stays observability-free.
				OnDrop: func() {
					if c.onQueueDrop != nil {
						c.onQueueDrop(name)
					}
				},
			})
			if err != nil {
				openErr = err
				log.Printf("[Relay] WARNING: cannot open %s queue at %s: %v — spillover queues DISABLED.", name, path, err)
				return nil
			}
			return q
		}

		c.trapQueue = open("traps")
		c.pingQueue = open("pings")
		c.syslogQueue = open("syslog")
		c.flowQueue = open("flows")
		c.flowCounterQueue = open("flow-counters")
		c.revisionQueue = open("revisions")
		c.metricQueue = open("metrics")

		if openErr != nil {
			// Partial open: close whatever succeeded and run fully disabled,
			// rather than with an inconsistent subset of queues.
			for _, q := range []*queue.SpilloverQueue{c.trapQueue, c.pingQueue, c.syslogQueue, c.flowQueue, c.flowCounterQueue, c.revisionQueue, c.metricQueue} {
				if q != nil {
					_ = q.Close()
				}
			}
			c.trapQueue, c.pingQueue, c.syslogQueue, c.flowQueue, c.flowCounterQueue, c.revisionQueue, c.metricQueue = nil, nil, nil, nil, nil, nil, nil
			return
		}

		// Publish the queue pointers for QueueDepth (AUDIT-210). The writes
		// above happen-before this Store in program order, and QueueDepth reads
		// them only after observing queuesReady==true, so a concurrent scrape is
		// race-free.
		c.queuesReady.Store(true)

		log.Printf("[Relay] Spillover queues enabled at %s (cap %d MiB per queue) — telemetry survives server outages and restarts.", diskPath, maxBytes>>20)
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
	// Pin TLS 1.2 as the floor to match the server (L10). The Go 1.25 client
	// default is already 1.2, so this is defensive against a GODEBUG/toolchain
	// change that could lower it.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

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
	// W3C trace context + request ID so the server can correlate this probe→
	// server request into one trace instead of always starting a fresh root span
	// (2026-06-23 audit, M10). Set before the caller's headers so an explicit
	// override still wins.
	if tp, rid := newTraceContext(); tp != "" {
		req.Header.Set("traceparent", tp)
		req.Header.Set("X-Request-ID", rid)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.httpClient.Do(req)
}

// newTraceContext generates a spec-valid W3C `traceparent` header value and a
// matching request ID. The collector has no OpenTelemetry SDK, so this emits
// version 00 with random 16-byte trace / 8-byte span IDs and the sampled flag
// (01); the server's W3C-aware middleware adopts it as the parent span. The
// trace ID doubles as the X-Request-ID for plain log correlation. Returns
// ("", "") on the rare crypto/rand failure, in which case the caller omits the
// headers (the request still succeeds, just untraced).
func newTraceContext() (traceparent, requestID string) {
	traceID := make([]byte, 16)
	spanID := make([]byte, 8)
	if _, err := rand.Read(traceID); err != nil {
		return "", ""
	}
	if _, err := rand.Read(spanID); err != nil {
		return "", ""
	}
	tid := hex.EncodeToString(traceID)
	return fmt.Sprintf("00-%s-%s-01", tid, hex.EncodeToString(spanID)), tid
}

// contentBatchID returns the idempotency key for one probe data batch
// (AUDIT-042): the SHA-256 of the marshaled payload.
//
// M19 of the 2026-07-01 audit: the key used to be RANDOM, minted per send
// call — so it only deduped the in-call retries. A batch that timed out
// client-side AFTER the server committed it was requeued and re-sent on the
// next sync cycle under a FRESH key the server could not match, inserting
// every row twice (duplicated cumulative interface counters then skewed the
// delta-based bandwidth math). Deriving the key from the CONTENT makes it
// stable across send attempts, requeues, sync cycles, and process restarts:
// an identical body always carries the identical key, so the server's
// (probe_id, batch_id) dedup catches the replay no matter when it happens.
// Every payload embeds collector-stamped time.Now() timestamps, so distinct
// collections never collide.
func contentBatchID(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:16])
}

// httpErrorDetail extracts a human-readable error message from a non-2xx
// response: the JSON `error`/`message` field the server's probeErr/response
// helpers emit if present, otherwise the trimmed raw body (capped at 4 KiB),
// otherwise "". Consumes the response body.
func httpErrorDetail(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var er struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &er)
	if er.Error != "" {
		return er.Error
	}
	if er.Message != "" {
		return er.Message
	}
	return strings.TrimSpace(string(body))
}

// --- Registration ---

// parseSchemaRange parses the server's "min-max" (or bare "N") schema-version
// support header. ok=false when it can't be parsed (M20).
func parseSchemaRange(s string) (min, max int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, e1 := strconv.Atoi(strings.TrimSpace(s[:i]))
		hi, e2 := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if e1 != nil || e2 != nil || lo > hi {
			return 0, 0, false
		}
		return lo, hi, true
	}
	v, e := strconv.Atoi(s)
	if e != nil {
		return 0, 0, false
	}
	return v, v, true
}

func (c *Client) Register() error {
	// M20 of the 2026-07-01 audit: advertise SchemaVersionMax but FALL BACK to
	// the highest mutually-supported version on a 426, instead of failing. The
	// pre-fix code hard-errored (and cmd/collector then log.Fatalf'd into a
	// crash loop that stopped ALL site telemetry) whenever this collector was
	// upgraded ahead of the server — but the collector speaks every version
	// down to SchemaVersionMin (higher-version features like counter samples
	// are already gated on the negotiated version), so registering as v1
	// against a v1 server is correct, not an error.
	advertise := SchemaVersionMax
	for attempt := 0; attempt < 2; attempt++ {
		data := RegisterRequest{
			RegistrationKey: c.Config.RegistrationKey,
			SchemaVersion:   advertise,
			AgentVersion:    AgentVersion,
		}
		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal registration data: %w", err)
		}
		resp, err := c.doAuthenticatedRequest("POST", c.Config.ServerURL+"/api/probes/register", jsonData)
		if err != nil {
			return fmt.Errorf("registration request failed: %w", err)
		}

		if resp.StatusCode == http.StatusUpgradeRequired {
			supported := resp.Header.Get("X-Probe-Schema-Version-Supported")
			drainAndClose(resp)
			serverMin, serverMax, ok := parseSchemaRange(supported)
			if ok {
				target := SchemaVersionMax
				if serverMax < target {
					target = serverMax
				}
				// Retry only if a compatible, strictly-lower version exists.
				if target >= SchemaVersionMin && target >= serverMin && target < advertise {
					log.Printf("[Relay] Server supports schema %s; re-registering as v%d (was v%d)", supported, target, advertise)
					advertise = target
					continue
				}
			}
			shown := supported
			if shown == "" {
				shown = "unknown"
			}
			return fmt.Errorf("registration rejected: this collector speaks schema_version %d-%d but the server supports %s — no compatible version (see MIGRATING.md)",
				SchemaVersionMin, SchemaVersionMax, shown)
		}

		return c.finishRegister(resp)
	}
	return fmt.Errorf("registration failed: no mutually-supported schema version after fallback")
}

// finishRegister processes a non-426 registration response (M20 refactor:
// pulled out of Register so the 426 fallback loop can retry cleanly).
func (c *Client) finishRegister(resp *http.Response) error {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Surface the server's error body so the failure is self-explanatory
		// (e.g. "Probe not found — it may have been deleted", "Invalid
		// registration key") instead of a bare status code the operator has to
		// go spelunking for.
		detail := httpErrorDetail(resp)
		if detail == "" {
			return fmt.Errorf("registration failed with HTTP status %d", resp.StatusCode)
		}
		return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, detail)
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
	// A successful (re-)registration proves the probe exists and is wanted
	// again — lift any 410-Gone heartbeat quiesce immediately (LC-02).
	c.heartbeatQuiescedUntil = time.Time{}
	c.mu.Unlock()

	c.approved.Store(result.Approved)

	// The server echoes the schema_version it selected for this probe. A
	// pre-handshake server (< v0.10.382) omits it → assume v1.
	negotiated := result.SchemaVersion
	if negotiated == 0 {
		negotiated = 1
	}
	c.negotiatedSchema.Store(int32(negotiated))
	// AUDIT-288: a successful (re-)registration is fresh endpoint evidence —
	// lift any /flow-counters 404 suppression immediately (mirrors the
	// heartbeatQuiescedUntil reset above).
	c.flowCountersOffUntil.Store(0)

	if !result.Approved {
		log.Printf("Probe registered (schema_version %d) but waiting for approval in admin panel...", negotiated)
	} else {
		log.Printf("Probe registered and approved! (schema_version %d)", negotiated)
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

	backoff := reregisterBackoff(attempts)
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

// sendHeartbeatWithStatus POSTs one heartbeat and maps the server's response
// onto the LC-02 status taxonomy. Pre-fix, every non-401/403 status —
// including the server's deliberate 410 Gone for a decommissioned probe, 429
// backpressure, 400, and 5xx — fell through to `return nil`, so
// runHeartbeatLoop refreshed the /readyz timestamp and counted a Prometheus
// success while the server refused to update last_seen and marked the probe
// offline. Taxonomy now:
//
//	2xx      -> success (nil): the ONLY outcome that refreshes /readyz.
//	401/403  -> auth lost: re-register with backoff (pre-existing behavior).
//	410 Gone -> non-retryable refusal (server M7: probe rejected /
//	            decommissioned / disabled): quiesce heartbeats for
//	            heartbeatQuiesceCooldown instead of re-register churn or
//	            full-cadence retries; error so the failure is counted.
//	429      -> server backpressure: retryable (isRetryableStatus), no
//	            re-registration; the next scheduled heartbeat IS the backoff,
//	            so just report failure and let the cadence pace the retry.
//	other    -> failed heartbeat (error): counted by /readyz + metrics,
//	            retried on the normal cadence.
func (c *Client) sendHeartbeatWithStatus(status string) error {
	c.mu.Lock()
	probeID := c.probeID
	quiescedUntil := c.heartbeatQuiescedUntil
	c.mu.Unlock()

	if remaining := time.Until(quiescedUntil); remaining > 0 {
		return fmt.Errorf("heartbeat quiesced for another %v — server answered 410 Gone (probe rejected/decommissioned/disabled); re-commission it in the admin UI", remaining.Round(time.Second))
	}

	data := map[string]interface{}{
		"probe_id":  probeID,
		"status":    status,
		"timestamp": time.Now().Unix(),
	}
	// Reported on every heartbeat, not just register, so an upgrade is visible
	// within one cadence rather than only after a re-registration that may never
	// happen.
	if AgentVersion != "" {
		data["agent_version"] = AgentVersion
	}
	if c.observedHostKeysFn != nil {
		if keys := c.observedHostKeysFn(); len(keys) > 0 {
			data["observed_host_keys"] = keys
		}
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

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		c.handlePendingCommands(resp)
		return nil

	case resp.StatusCode == 401 || resp.StatusCode == 403:
		c.mu.Lock()
		attempts := c.reregisterAttempts
		c.reregisterAttempts++
		c.mu.Unlock()

		if attempts >= maxReregisterAttempts {
			return fmt.Errorf("max re-registration attempts (%d) reached, giving up", maxReregisterAttempts)
		}

		backoff := reregisterBackoff(attempts)
		log.Printf("Probe unauthorized (attempt %d/%d), retrying registration in %v...",
			attempts+1, maxReregisterAttempts, backoff)
		time.Sleep(backoff)
		return c.Register()

	case resp.StatusCode == http.StatusGone:
		c.mu.Lock()
		c.heartbeatQuiescedUntil = time.Now().Add(heartbeatQuiesceCooldown)
		c.mu.Unlock()
		detail := httpErrorDetail(resp)
		log.Printf("[Relay] Heartbeat refused (HTTP 410): %s — probe rejected/decommissioned/disabled on the server; quiescing heartbeats for %v (re-commission it in the admin UI to recover)",
			detail, heartbeatQuiesceCooldown)
		return fmt.Errorf("heartbeat refused (HTTP 410): %s", detail)

	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("heartbeat rate-limited (HTTP 429): %s — retrying on the normal heartbeat cadence", httpErrorDetail(resp))

	default:
		return fmt.Errorf("heartbeat failed (HTTP %d): %s", resp.StatusCode, httpErrorDetail(resp))
	}
}

// handlePendingCommands parses the schema-v4 pending_commands field off a
// successful heartbeat response and hands the batch to the registered
// command handler on its own goroutine (a slow executor must never stall the
// heartbeat cadence — a stalled heartbeat marks the probe offline
// server-side). Gated on a negotiated schema ≥ 4: below that the server
// never sends the field and this collector doesn't parse for it, mirroring
// the disk/load v3 send gate. Never logs command payloads.
func (c *Client) handlePendingCommands(resp *http.Response) {
	if c.negotiatedSchema.Load() < 4 || c.commandHandlerFn == nil {
		return
	}
	var hb heartbeatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&hb); err != nil {
		log.Printf("[Relay] Heartbeat response parse (pending_commands): %v", err)
		return
	}
	if len(hb.PendingCommands) == 0 {
		return
	}
	log.Printf("[Relay] Heartbeat delivered %d pending command(s)", len(hb.PendingCommands))
	// AUDIT-212: safego, not a bare go — a panicking command executor must not
	// kill the collector (the server redelivers the command at-least-once, so a
	// bare go turned one poison command into a process crash loop).
	safego.Go("relay:commandHandler", func() { c.commandHandlerFn(hb.PendingCommands) })
}

// SendCommandResult reports the outcome of one executed server command to
// POST /api/probes/:id/command-result (schema v4). Mirrors the disk/load v3
// gate: a no-op against a server that negotiated < 4 (it has no such route,
// and 404s would churn re-registration). The server is idempotent by
// CommandID, so redelivery races and retried POSTs are safe.
func (c *Client) SendCommandResult(res CommandResult) error {
	if c.negotiatedSchema.Load() < 4 {
		return nil
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("failed to marshal command result: %w", err)
	}
	url := fmt.Sprintf("%s/api/probes/%d/command-result", c.Config.ServerURL, c.GetProbeID())
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send command result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("command result for %s returned HTTP %d: %s",
			res.CommandID, resp.StatusCode, httpErrorDetail(resp))
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

// SendInterfaceCounterSample enqueues an sFlow interface counter sample. It is
// gated on schema v2 plus the AUDIT-288 404-suppression window: if the server
// negotiated v1 (or registration hasn't completed yet), or /flow-counters
// recently answered 404, the sample is dropped silently rather than queued, so
// we never POST the /flow-counters endpoint to a server that doesn't have it
// (which would 404 and trip the re-registration path). Once the server is
// upgraded and the probe re-registers at v2 — or the suppression window lapses
// — counters start flowing; no probe restart needed.
func (c *Client) SendInterfaceCounterSample(cs *InterfaceCounterSample) {
	if !c.flowCountersEnabled() {
		return
	}
	c.ensureQueues()
	if c.flowCounterQueue == nil {
		return
	}
	data, err := json.Marshal(cs)
	if err != nil {
		log.Printf("[Relay] Failed to marshal interface counter sample: %v", err)
		return
	}
	if err := c.flowCounterQueue.Push(data); err != nil {
		log.Printf("[Relay] Failed to enqueue interface counter sample: %v", err)
	}
}

// --- Direct send (SNMP poll results sent immediately) ---

// doDirectSend is a helper for direct Send methods with retry and approval-revocation handling.
// expBackoff is the per-attempt exponential retry delay shared by the data-send
// paths (sendBatch, sendOneRevisionWithRetry): 1s, 2s, 4s for attempts 0, 1, 2.
func expBackoff(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt)) * time.Second
}

// reregisterBackoff is the registration retry delay: an exponential 2^attempt ×
// 10s base plus up to 5s of random jitter, so a fleet of probes recovering from
// a shared server outage doesn't reconnect in lock-step (thundering herd).
func reregisterBackoff(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt))*10*time.Second + time.Duration(mrand.Intn(5000))*time.Millisecond // #nosec G404 -- reconnect jitter, not a security value
}

// metricEnvelope is one buffered primary-metric send: the endpoint to POST to
// and the already-marshaled JSON body. One metricQueue holds envelopes for all
// 10 metric endpoints so a single queue serves every differently-routed type.
type metricEnvelope struct {
	Endpoint string          `json:"e"`
	Name     string          `json:"n"`
	Payload  json.RawMessage `json:"p"`
}

// doDirectSend sends a primary SNMP-metric batch immediately. On a transient
// failure (server unreachable, 5xx, or 429 backpressure) it buffers the payload
// to the metric spillover queue (H9) instead of dropping it, so a server outage
// no longer discards health telemetry — syncData drains the queue on recovery.
// One live attempt is made (plus one retry after a successful re-registration);
// the durable queue, not inline backoff, is what survives a prolonged outage, so
// we no longer burn ~7s of per-metric per-device backoff here (audit: "drop
// doDirectSend retries to 1").
func (c *Client) doDirectSend(endpoint string, name string, payload interface{}) (err error) {
	// AUDIT-210: report the batch outcome on
	// firewall_collector_data_batch_sent_total. Every success path returns nil;
	// every buffered/dropped path returns a non-nil error — so err==nil is
	// exactly "reached the server (2xx)". The queue label is "metrics" (the
	// spillover queue these sends buffer to).
	defer func() {
		outcome := "failure"
		if err == nil {
			outcome = "success"
		}
		c.fireDataBatchSent("metrics", outcome)
	}()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", name, err)
	}

	if !c.approved.Load() {
		if !c.tryReregister() {
			c.enqueueMetric(endpoint, name, jsonData)
			return fmt.Errorf("probe not approved (buffered %s)", name)
		}
	}

	url := fmt.Sprintf("%s/api/probes/%d/%s", c.Config.ServerURL, c.GetProbeID(), endpoint)

	// M19: direct metric sends previously carried NO idempotency key, so a
	// response lost after a server-side commit meant the buffered replay
	// inserted every row twice. The content-derived key travels with the
	// identical marshaled body through the spillover queue, so the drain's
	// re-POST dedupes server-side (v0.10.539 adds the check to these routes).
	hdr := map[string]string{"X-Probe-Batch-ID": contentBatchID(jsonData)}

	resp, err := c.doAuthenticatedRequestH("POST", url, jsonData, hdr)
	if err != nil {
		// Transport failure (server down): buffer for the recovery drain.
		c.enqueueMetric(endpoint, name, jsonData)
		return fmt.Errorf("failed to send %s (buffered): %w", name, err)
	}
	drainAndClose(resp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Auth/not-found: re-register once, then retry the send once.
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		log.Printf("[Relay] Probe rejected (%d on %s), attempting re-registration...", resp.StatusCode, name)
		c.approved.Store(false)
		if c.tryReregister() {
			resp2, err2 := c.doAuthenticatedRequestH("POST", url, jsonData, hdr)
			if err2 == nil {
				drainAndClose(resp2)
				if resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
					return nil
				}
			}
		}
		c.enqueueMetric(endpoint, name, jsonData)
		return fmt.Errorf("probe re-register/send failed (%d on %s, buffered)", resp.StatusCode, name)
	}

	// Other non-2xx: buffer if transient (5xx/429), drop if a permanent
	// rejection (a malformed batch would otherwise loop in the queue forever).
	if isRetryableStatus(resp.StatusCode) {
		c.enqueueMetric(endpoint, name, jsonData)
		return fmt.Errorf("send %s returned status %d (buffered)", name, resp.StatusCode)
	}
	return fmt.Errorf("send %s returned permanent status %d (dropped)%s", name, resp.StatusCode, permanentDropHint(resp.StatusCode))
}

// doSnapshotSend sends a state-snapshot batch (L2 topology) immediately and
// NEVER buffers it to the spillover queue: the server applies these with
// DELETE+INSERT replace semantics, so a spooled old snapshot re-POSTed after
// a newer one has been accepted would revert the device's state until the
// next cycle. On any failure the batch is dropped (counted via
// onMetricSendFailed) — the next topology cycle resends the full state, which
// is cheap and self-healing. Auth loss still gets one re-register + one retry,
// mirroring doDirectSend.
func (c *Client) doSnapshotSend(endpoint string, name string, payload interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", name, err)
	}

	dropped := func(format string, args ...interface{}) error {
		if c.onMetricSendFailed != nil {
			c.onMetricSendFailed(name)
		}
		return fmt.Errorf(format, args...)
	}

	if !c.approved.Load() {
		if !c.tryReregister() {
			return dropped("probe not approved (%s dropped)", name)
		}
	}

	url := fmt.Sprintf("%s/api/probes/%d/%s", c.Config.ServerURL, c.GetProbeID(), endpoint)
	// The content-derived idempotency key still travels so a response lost
	// after a server-side commit dedupes the immediate auth-retry below.
	hdr := map[string]string{"X-Probe-Batch-ID": contentBatchID(jsonData)}

	resp, err := c.doAuthenticatedRequestH("POST", url, jsonData, hdr)
	if err != nil {
		return dropped("failed to send %s (dropped): %w", name, err)
	}
	drainAndClose(resp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		log.Printf("[Relay] Probe rejected (%d on %s), attempting re-registration...", resp.StatusCode, name)
		c.approved.Store(false)
		if c.tryReregister() {
			resp2, err2 := c.doAuthenticatedRequestH("POST", url, jsonData, hdr)
			if err2 == nil {
				drainAndClose(resp2)
				if resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
					return nil
				}
			}
		}
		return dropped("probe re-register/send failed (%d on %s, dropped)", resp.StatusCode, name)
	}

	return dropped("send %s returned status %d (dropped)", name, resp.StatusCode)
}

// drainAndClose drains and closes an HTTP response body so the underlying
// keep-alive connection can be reused (closing without draining forces the
// transport to drop the connection — the per-cycle pool-defeat the audit flagged
// in doDirectSend).
func drainAndClose(resp *http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// enqueueMetric buffers a failed metric send for the recovery drain. A nil queue
// (spillover disabled — PROBE_QUEUE_DISK_PATH unset) means the data is dropped,
// already warned about once at ensureQueues.
func (c *Client) enqueueMetric(endpoint, name string, payload []byte) {
	// Count the send failure regardless of whether spillover is enabled (M12).
	if c.onMetricSendFailed != nil {
		c.onMetricSendFailed(name)
	}
	c.ensureQueues()
	if c.metricQueue == nil {
		return
	}
	env := metricEnvelope{Endpoint: endpoint, Name: name, Payload: append(json.RawMessage(nil), payload...)}
	b, err := json.Marshal(env)
	if err != nil {
		log.Printf("[Relay] Failed to envelope %s metric for queue: %v", name, err)
		return
	}
	if err := c.metricQueue.Push(b); err != nil {
		log.Printf("[Relay] Failed to enqueue %s metric: %v", name, err)
	}
}

// postMetricRaw POSTs an already-marshaled metric body once and reports
// (ok, permanent). It does not enqueue or re-register — the drain loop decides
// whether to requeue. permanent is true for non-retryable 4xx so a poison
// payload is dropped rather than requeued forever.
func (c *Client) postMetricRaw(endpoint, name string, body []byte) (ok bool, permanent bool) {
	url := fmt.Sprintf("%s/api/probes/%d/%s", c.Config.ServerURL, c.GetProbeID(), endpoint)
	// M19: the replayed body is byte-identical to the original send, so the
	// content-derived key matches and the server dedupes a
	// timed-out-but-committed original.
	resp, err := c.doAuthenticatedRequestH("POST", url, body, map[string]string{"X-Probe-Batch-ID": contentBatchID(body)})
	if err != nil {
		return false, false
	}
	drainAndClose(resp)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, false
	}
	return false, !isRetryableStatus(resp.StatusCode)
}

// drainMetricQueue forwards buffered metric sends on recovery. On the first
// transient failure it requeues the unsent remainder and stops (the server is
// still down — retry next sync). Permanently-rejected and malformed items are
// dropped so they cannot wedge the queue.
func (c *Client) drainMetricQueue(drainChunk int) {
	if c.metricQueue == nil {
		return
	}
	for {
		raw, err := c.metricQueue.Drain(drainChunk)
		if err != nil {
			log.Printf("[Relay] drain metrics: %v", err)
			return
		}
		if len(raw) == 0 {
			return
		}
		for idx, item := range raw {
			var env metricEnvelope
			if err := json.Unmarshal(item, &env); err != nil {
				log.Printf("[Relay] drain metrics: dropping malformed envelope: %v", err)
				continue
			}
			ok, permanent := c.postMetricRaw(env.Endpoint, env.Name, env.Payload)
			// AUDIT-210: a drained resend is a data-batch outcome too.
			if ok {
				c.fireDataBatchSent("metrics", "success")
			} else {
				c.fireDataBatchSent("metrics", "failure")
			}
			if ok || permanent {
				if permanent {
					log.Printf("[Relay] drain metrics: %s permanently rejected — dropping", env.Name)
				}
				continue
			}
			// Transient failure: server still unreachable. Requeue this item and
			// every unsent item after it, then stop until the next sync.
			for _, rem := range raw[idx:] {
				if err := c.metricQueue.Push(rem); err != nil {
					log.Printf("[Relay] drain metrics: requeue failed: %v", err)
				}
			}
			return
		}
		if len(raw) < drainChunk {
			return
		}
	}
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

// SendDiskUsage / SendLoadAverage are schema-v3 endpoints. They no-op against a
// server that negotiated a lower schema (i.e. one without these routes), so a
// lagging prod server is never 404-thrashed into a re-register loop.
func (c *Client) SendDiskUsage(rows []DiskUsage) error {
	if c.negotiatedSchema.Load() < 3 {
		return nil
	}
	return c.doDirectSend("disk-usage", "disk usage", rows)
}

func (c *Client) SendLoadAverage(rows []LoadAverage) error {
	if c.negotiatedSchema.Load() < 3 {
		return nil
	}
	return c.doDirectSend("load-average", "load average", rows)
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

// SendTopologyEntries / SendTopologyNeighbors are schema-v5 endpoints carrying
// L2 topology STATE SNAPSHOTS (server replaces the device's rows on every
// batch). They no-op against a lower-schema server, and they deliberately use
// doSnapshotSend instead of doDirectSend: spooling a failed snapshot and
// replaying it later could land AFTER a newer live snapshot and revert the
// device's topology server-side. Dropping is safe — the next topology cycle
// resends the complete state.
func (c *Client) SendTopologyEntries(entries []TopologyEntry) error {
	if c.negotiatedSchema.Load() < 5 {
		return nil
	}
	return c.doSnapshotSend("topology-entries", "topology entries", entries)
}

func (c *Client) SendTopologyNeighbors(neighbors []TopologyNeighbor) error {
	if c.negotiatedSchema.Load() < 5 {
		return nil
	}
	return c.doSnapshotSend("topology-neighbors", "topology neighbors", neighbors)
}

// TopologySupported reports whether the negotiated relay schema carries the
// v5 L2-topology endpoints. The poll loop consults this BEFORE walking — the
// FDB/ARP/LLDP walks are the most expensive SNMP operations the collector
// does (full-table walks, thousands of rows), so against a pre-v5 server they
// are skipped entirely rather than collected and silently discarded by the
// send gates above.
func (c *Client) TopologySupported() bool {
	return c.negotiatedSchema.Load() >= 5
}

// flowCountersEnabled reports whether interface counter samples may be queued
// and drained: the negotiated schema must carry the v2 /flow-counters endpoint
// AND the endpoint must not be under an AUDIT-288 404-suppression window.
func (c *Client) flowCountersEnabled() bool {
	return c.negotiatedSchema.Load() >= 2 && time.Now().UnixNano() >= c.flowCountersOffUntil.Load()
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

	// Drain each event queue and forward it. Every queue runs the same
	// drain → unmarshal → send → requeue-on-failure pipeline (drainAndSend);
	// only the payload type, endpoint, and log labels differ. The flow queue
	// historically runs without the inter-chunk pause the others use, preserved
	// here via interChunkDelay: 0.
	drainAndSend(c, baseURL, drainChunk, queueDrainSpec[TrapEvent]{
		queue: c.trapQueue, endpoint: "/traps", sendName: "traps",
		drainLabel: "traps", unmarshalLabel: "trap",
		noun: "traps", nounLong: "trap events", interChunkDelay: 500 * time.Millisecond,
	})
	drainAndSend(c, baseURL, drainChunk, queueDrainSpec[PingResult]{
		queue: c.pingQueue, endpoint: "/pings", sendName: "pings",
		drainLabel: "pings", unmarshalLabel: "ping",
		noun: "pings", nounLong: "ping results", interChunkDelay: 500 * time.Millisecond,
	})
	drainAndSend(c, baseURL, drainChunk, queueDrainSpec[SyslogMessage]{
		queue: c.syslogQueue, endpoint: "/syslog", sendName: "syslog",
		drainLabel: "syslogs", unmarshalLabel: "syslog",
		noun: "syslog messages", nounLong: "syslog messages", interChunkDelay: 500 * time.Millisecond,
	})
	drainAndSend(c, baseURL, drainChunk, queueDrainSpec[FlowSample]{
		queue: c.flowQueue, endpoint: "/flows", sendName: "flows",
		drainLabel: "flows", unmarshalLabel: "flow",
		noun: "flow samples", nounLong: "flow samples", interChunkDelay: 0,
	})
	// sFlow interface counters are a schema-v2-only endpoint. Only drain them
	// when the server CURRENTLY negotiates v2 AND the endpoint is not under an
	// AUDIT-288 404-suppression window. SendInterfaceCounterSample gates new
	// pushes the same way, but a backlog queued while the endpoint was live
	// survives a server ROLLBACK to v1 — and POSTing it to the now-absent
	// /flow-counters endpoint 404s, which sendBatch would misread as "probe
	// deleted", flapping the probe's approval and forcing a re-register every
	// sync (audit L13). Discard the undeliverable backlog instead, so it
	// neither 404s nor grows.
	if c.flowCountersEnabled() {
		drainAndSend(c, baseURL, drainChunk, queueDrainSpec[InterfaceCounterSample]{
			queue: c.flowCounterQueue, endpoint: "/flow-counters", sendName: "flow-counters",
			drainLabel: "flow-counters", unmarshalLabel: "interface counter",
			noun: "interface counters", nounLong: "interface counter samples", interChunkDelay: 0,
		})
	} else {
		discardQueue(c.flowCounterQueue, drainChunk, "flow-counters")
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

	// H9: drain buffered primary metrics last — like revisions, these are
	// envelope-tagged with their own endpoint, so they use a dedicated drain
	// rather than the typed event-queue pipeline.
	c.drainMetricQueue(drainChunk)
}

// unmarshalQueued converts a slice of JSON bytes (as produced by the
// SpilloverQueue on Drain) into a typed pointer slice for batch sending.
// Malformed items are logged and skipped — one bad event must not stall the
// whole sync.
func unmarshalQueued[T any](raw [][]byte, label string) []*T {
	out := make([]*T, 0, len(raw))
	for _, b := range raw {
		var t T
		if err := json.Unmarshal(b, &t); err != nil {
			log.Printf("[Relay] Failed to unmarshal %s: %v", label, err)
			continue
		}
		out = append(out, &t)
	}
	return out
}

// chunkSlice splits items into sub-slices of at most size elements. A size <= 0
// clamps to 1.
func chunkSlice[T any](items []T, size int) [][]T {
	if size <= 0 {
		size = 1
	}
	chunks := make([][]T, 0, (len(items)+size-1)/size)
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
}

// sendBatchesSequential sends items in MaxBatchSize chunks, pausing briefly
// between chunks. On the first TRANSIENT failure it hands that chunk AND every
// not-yet-attempted item after it to requeue and reports stopped=true so the
// caller halts the drain — the server is unreachable, so continuing would just
// fail chunk after chunk while the pre-fix code dropped this drain's unsent
// tail on the floor (AUDIT-175: one syncData cycle during an outage collapsed
// an arbitrarily large disk spool to the single requeued chunk). A PERMANENT
// rejection still drops only that poison chunk and keeps going (M3). Generic
// over the payload type so every event queue shares one path.
func sendBatchesSequential[T any](c *Client, url, name string, items []*T, requeue func([]*T)) (stopped bool) {
	actualBatchSize := c.Config.MaxBatchSize
	if actualBatchSize <= 0 {
		actualBatchSize = maxBatchSize
	}

	chunks := chunkSlice(items, actualBatchSize)
	totalChunks := len(chunks)

	for i, chunk := range chunks {
		if i > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		delivered, permanent := c.sendBatch(url, name, chunk)
		if delivered {
			// AUDIT-210: report the batch outcome. name is the queue label
			// (traps|pings|syslog|flows|flow-counters), matching allQueueNames.
			c.fireDataBatchSent(name, "success")
			log.Printf("[Relay] Sent %s batch chunk %d/%d (%d items)", name, i+1, totalChunks, len(chunk))
			continue
		}
		if permanent {
			// Drop the poison chunk (a requeue would retry it forever and evict
			// good data at the byte cap) and keep going — later chunks may deliver.
			c.fireDataBatchSent(name, "failure")
			log.Printf("[Relay] Dropping %s batch chunk %d/%d (%d items): permanent server rejection", name, i+1, totalChunks, len(chunk))
			continue
		}
		// Transient failure: requeue this chunk plus the whole unattempted tail
		// (chunkSlice is contiguous from index 0, so items[i*actualBatchSize:]
		// is exactly chunk i onward) and stop the drain until the next sync.
		c.fireDataBatchSent(name, "failure")
		requeue(items[i*actualBatchSize:])
		log.Printf("[Relay] Failed to send %s batch chunk %d/%d (transient); requeued it plus the %d-chunk remainder and stopped this drain", name, i+1, totalChunks, totalChunks-i-1)
		return true
	}
	return false
}

// requeueItems pushes a failed ordered run back onto the HEAD of its queue in
// one PushFront call, so the next drain retries it FIRST and re-chunks from
// index 0 — a full-size failed chunk then replays byte-identically, keeping
// the M19 content-derived idempotency key stable across sync cycles so the
// server's (probe_id, batch_id) dedup catches the replay (AUDIT-213/214: the
// old item-at-a-time tail Push regrouped the items into a differently-keyed
// batch the server could not dedup, re-inserting a committed-but-timed-out
// batch as duplicates). The window is narrowed, not closed: a partial final
// chunk that gains newly-arrived neighbors, a PushFront overflow split, or a
// restart can still regroup one batch under a fresh key. noun labels the
// count in the disabled/full warnings; nounLong labels the success line
// (e.g. "traps" vs "trap events").
func requeueItems[T any](q *queue.SpilloverQueue, items []*T, noun, nounLong string) {
	if q == nil {
		log.Printf("[Relay] WARNING: Could not requeue %d %s - queue disabled", len(items), noun)
		return
	}
	run := make([][]byte, 0, len(items))
	for _, it := range items {
		data, err := json.Marshal(it)
		if err != nil {
			log.Printf("[Relay] Failed to marshal %s for requeue: %v", noun, err)
			continue
		}
		run = append(run, data)
	}
	if len(run) == 0 {
		log.Printf("[Relay] WARNING: Could not requeue %d %s - nothing marshalable", len(items), noun)
		return
	}
	if err := q.PushFront(run); err != nil {
		log.Printf("[Relay] Re-queue %s: %v", noun, err)
		return
	}
	log.Printf("[Relay] Re-queued %d %s at the queue head", len(run), nounLong)
}

// queueDrainSpec describes how one event queue is drained and forwarded.
type queueDrainSpec[T any] struct {
	queue           *queue.SpilloverQueue
	endpoint        string // appended to baseURL, e.g. "/traps"
	sendName        string // batch name in send logs: "traps","pings","syslog","flows"
	drainLabel      string // label in "drain %s" errors
	unmarshalLabel  string // label in unmarshal errors
	noun            string // requeue disabled/full count label
	nounLong        string // requeue success count label
	interChunkDelay time.Duration
}

// drainAndSend repeatedly drains a queue in bounded chunks (AUDIT-058) and
// forwards each chunk, requeuing on failure. A transient send failure stops
// the whole drain (AUDIT-175): the failed run is already head-requeued and the
// server is unreachable, so draining further would only churn. Shared by every
// event queue so the per-queue loops no longer copy-paste the pipeline.
func drainAndSend[T any](c *Client, baseURL string, drainChunk int, spec queueDrainSpec[T]) {
	if spec.queue == nil {
		return // queue not opened (spillover disabled, or a v2-gated queue on a v1 server)
	}
	for {
		raw, err := spec.queue.Drain(drainChunk)
		if err != nil {
			log.Printf("[Relay] drain %s: %v", spec.drainLabel, err)
			break
		}
		if len(raw) == 0 {
			break
		}
		items := unmarshalQueued[T](raw, spec.unmarshalLabel)
		if sendBatchesSequential(c, baseURL+spec.endpoint, spec.sendName, items, func(chunk []*T) {
			requeueItems(spec.queue, chunk, spec.noun, spec.nounLong)
		}) {
			break // transient stop: retry from the queue head next sync
		}
		if len(raw) < drainChunk {
			break
		}
		if spec.interChunkDelay > 0 {
			time.Sleep(spec.interChunkDelay)
		}
	}
}

// discardQueue empties a queue without sending it, used when the queue's
// endpoint is known to be unsupported by the currently-negotiated server (audit
// L13 — a schema-v2 counter backlog against a server rolled back to v1). Drains
// in bounded chunks so a large backlog doesn't materialize in RAM at once.
func discardQueue(q *queue.SpilloverQueue, chunk int, label string) {
	if q == nil {
		return
	}
	total := 0
	for {
		raw, err := q.Drain(chunk)
		if err != nil {
			log.Printf("[Relay] discard %s: %v", label, err)
			return
		}
		if len(raw) == 0 {
			break
		}
		total += len(raw)
		if len(raw) < chunk {
			break
		}
	}
	if total > 0 {
		log.Printf("[Relay] discarded %d buffered %s (endpoint unavailable: server schema too low, or suppressed after a 404)", total, label)
	}
}

func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	// 429 (Too Many Requests) is TRANSIENT — the server rate-limits probe
	// ingestion endpoints with it, so treating it as non-retryable (the
	// pre-v1.2.132 behavior) silently DROPPED whole SNMP-metric batches the
	// moment the server pushed back. It is retryable; the surrounding retry
	// loops already pace with expBackoff (1s/2s/4s), which is the correct
	// response to backpressure. The 4xx codes below are genuine permanent
	// rejections (bad request, auth, not-found, conflict, gone, unprocessable).
	//
	// AUDIT-287: 413 (Payload Too Large) and 414 (URI Too Long) are PERMANENT
	// too — every retry replays the byte-identical body (the M19 idempotency
	// contract depends on that), so a body too large once is too large on
	// every retry; treating them as transient requeued the oversized batch
	// forever. The collector already clamps batches to the server's own
	// 1000-item ingestion cap (serverMaxBatchItems in internal/config), so a
	// 413 in practice means a proxy in FRONT of the server caps request
	// bodies below the server's limit — an operator-side fix, named in the
	// drop log (lower PROBE_MAX_BATCH_SIZE or raise the proxy's
	// client_max_body_size).
	case 400, 401, 403, 404, 405, 409, 410, 413, 414, 422:
		return false
	default:
		return true
	}
}

// permanentDropHint returns the operator remedy for permanent rejections that
// have one (AUDIT-287: 413/414 imply a proxy request-size cap below the
// server's own 1000-item batch limit), or "" for statuses that don't.
func permanentDropHint(statusCode int) string {
	if statusCode == 413 || statusCode == 414 {
		return " — a proxy in front of the server rejects request bodies below the server's own batch cap; lower PROBE_MAX_BATCH_SIZE or raise the proxy's client_max_body_size"
	}
	return ""
}

// sendBatch delivers one batch and reports (delivered, permanent):
//   - delivered=true            -> consumed by the server (or safely dropped);
//     the caller must NOT requeue.
//   - delivered=false, permanent=true  -> a permanent rejection (400/422/other
//     non-retryable 4xx, or unmarshalable payload); the caller must DROP it, not
//     requeue — otherwise the poison batch is retried every sync cycle forever
//     and eventually evicts good telemetry at the byte cap (audit M3).
//   - delivered=false, permanent=false -> a transient failure (network error,
//     5xx, 429, or a re-registration in progress); the caller should requeue.
func (c *Client) sendBatch(url, name string, data interface{}) (delivered bool, permanent bool) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		// Re-marshaling identical data will fail again — dropping is correct.
		log.Printf("[Relay] Failed to marshal %s batch (dropping, permanent): %v", name, err)
		return false, true
	}

	// AUDIT-042 + M19: content-derived idempotency key — identical across
	// retry attempts AND across sync-cycle requeues of the same chunk, so the
	// server dedupes a timed-out-but-saved batch whenever it comes back.
	batchID := contentBatchID(jsonData)
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.doAuthenticatedRequestH("POST", url, jsonData, map[string]string{"X-Probe-Batch-ID": batchID})
		if err != nil {
			log.Printf("[Relay] Failed to send %s batch (attempt %d/3): %v", name, attempt+1, err)
			time.Sleep(expBackoff(attempt))
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[Relay] Warning: failed to read %s response body: %v", name, err)
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[Relay] Sent %s batch to server", name)
			return true, false
		}

		// A 404 on the schema-v2-only /flow-counters endpoint means THAT ENDPOINT
		// is unavailable (a pre-v2 or rolled-back server, or a proxy blip), NOT
		// that the probe was deleted — so drop this batch instead of deapproving
		// + re-registering, and suppress just that endpoint so syncData stops
		// draining v2 counters (audit L13). AUDIT-288: the suppression is
		// endpoint-scoped and self-expiring (flowCountersOffUntil), never a
		// negotiatedSchema collapse — the old Store(1) also disabled the
		// unrelated v3/v4/v5 features until restart. A genuinely deleted probe
		// still surfaces as a 404 on the core endpoints (/flows, /pings, …),
		// which keep the re-register path.
		if resp.StatusCode == 404 && name == "flow-counters" {
			log.Printf("[Relay] /flow-counters unsupported by server (404); dropping batch and suppressing counter sync for %v (self-expiring; also cleared by re-registration)", flowCountersOffWindow)
			c.flowCountersOffUntil.Store(time.Now().Add(flowCountersOffWindow).UnixNano())
			return true, false // treat as consumed so the batch is not requeued
		}

		if resp.StatusCode == 404 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			log.Printf("[Relay] Probe not found/auth failed (%d on %s), attempting re-registration...", resp.StatusCode, name)
			c.approved.Store(false)
			if c.tryReregister() {
				continue
			}
			// Re-registration is in progress / pending approval — transient, so
			// requeue and retry next cycle rather than dropping the data.
			return false, false
		}

		if resp.StatusCode == 400 {
			log.Printf("[Relay] Bad request (400) for %s batch (dropping, permanent): %s", name, string(bodyBytes))
			return false, true
		}

		if !isRetryableStatus(resp.StatusCode) {
			log.Printf("[Relay] Non-retryable status %d for %s batch (dropping, permanent)%s: %s", resp.StatusCode, name, permanentDropHint(resp.StatusCode), string(bodyBytes))
			return false, true
		}

		log.Printf("[Relay] Failed to send %s batch: status %d (attempt %d/3): %s", name, resp.StatusCode, attempt+1, string(bodyBytes))
		time.Sleep(expBackoff(attempt))
	}
	// Exhausted retries on a transient condition — requeue for the next cycle.
	return false, false
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
			"traps":         c.trapQueue,
			"pings":         c.pingQueue,
			"syslog":        c.syslogQueue,
			"flows":         c.flowQueue,
			"flow-counters": c.flowCounterQueue,
			"revisions":     c.revisionQueue,
			"metrics":       c.metricQueue,
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
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.GetProbeID()) + "/config-revision"
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
// would be retried first. At the time the SpilloverQueue's only requeue
// primitive was the tail Push used here; SpilloverQueue.PushFront now
// exists (added for the AUDIT-175 event-queue head-requeue), but the
// revision path deliberately keeps the tail Push: revisions are
// infrequent (one per config-change event) and each is retried
// individually, so "failed again at the back of the line" still means
// a retry within one syncData cycle (default 30s) and there is no
// multi-item batch whose idempotency key a regroup could change.
func (c *Client) sendRevisionBatch(url string, raw [][]byte) {
	var failed [][]byte
	for _, data := range raw {
		rev, err := unmarshalConfigRevision(data)
		if err != nil {
			log.Printf("[Relay] Failed to unmarshal config revision (dropping): %v", err)
			continue
		}
		delivered, permanent := c.sendOneRevisionWithRetry(url, rev)
		// AUDIT-210: report the batch outcome under the "revisions" queue label.
		if delivered {
			c.fireDataBatchSent("revisions", "success")
		} else {
			c.fireDataBatchSent("revisions", "failure")
		}
		if !delivered && !permanent {
			// Only requeue transient failures. A permanent rejection (400/422/…)
			// is dropped — requeuing it would retry the same poison payload every
			// sync cycle forever and evict good revisions at the byte cap (M3).
			failed = append(failed, data)
		} else if !delivered {
			log.Printf("[Relay] Dropping config revision for device %d: permanent server rejection", rev.DeviceID)
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
func (c *Client) sendOneRevisionWithRetry(url string, rev *ConfigRevision) (delivered bool, permanent bool) {
	jsonData, err := json.Marshal(rev)
	if err != nil {
		log.Printf("[Relay] Failed to marshal config revision (dropping, permanent): %v", err)
		return false, true
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
		if err != nil {
			log.Printf("[Relay] SendConfigRevision transport error for device %d (attempt %d/3): %v", rev.DeviceID, attempt+1, err)
			if attempt < 2 {
				time.Sleep(expBackoff(attempt))
			}
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[Relay] SendConfigRevision success for device %d: %s", rev.DeviceID, string(bodyBytes))
			return true, false
		}

		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
			log.Printf("[Relay] SendConfigRevision auth/reject for device %d (status %d), attempting re-registration", rev.DeviceID, resp.StatusCode)
			c.approved.Store(false)
			if c.tryReregister() {
				continue
			}
			// Re-registration pending — transient, requeue.
			return false, false
		}

		if resp.StatusCode == 400 {
			log.Printf("[Relay] SendConfigRevision 400 (bad request) for device %d (dropping, permanent): %s", rev.DeviceID, string(bodyBytes))
			return false, true
		}

		if !isRetryableStatus(resp.StatusCode) {
			log.Printf("[Relay] SendConfigRevision non-retryable status %d for device %d (dropping, permanent)%s: %s", resp.StatusCode, rev.DeviceID, permanentDropHint(resp.StatusCode), string(bodyBytes))
			return false, true
		}

		// 5xx or other transient server error.
		log.Printf("[Relay] SendConfigRevision status %d for device %d (attempt %d/3): %s", resp.StatusCode, rev.DeviceID, attempt+1, string(bodyBytes))
		if attempt < 2 {
			time.Sleep(expBackoff(attempt))
		}
	}
	// Exhausted retries on a transient condition — requeue.
	return false, false
}

func (c *Client) SendProcessSnapshot(snap *ProcessSnapshot) error {
	if !c.approved.Load() {
		return fmt.Errorf("probe not approved")
	}
	jsonData, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("failed to marshal process snapshot: %w", err)
	}
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.GetProbeID()) + "/process-snapshot"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send process snapshot: %w", err)
	}
	drainAndClose(resp) // drain so the keep-alive connection can be reused (L6/L7)
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
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.GetProbeID()) + "/interface-errors"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send interface error snapshot: %w", err)
	}
	drainAndClose(resp) // drain so the keep-alive connection can be reused (L7)
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
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.GetProbeID()) + "/interface-errors"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send interface error snapshots: %w", err)
	}
	drainAndClose(resp) // drain so the keep-alive connection can be reused (L7)
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
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.GetProbeID()) + "/sensor-details"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send sensor details: %w", err)
	}
	drainAndClose(resp) // drain so the keep-alive connection can be reused (L7)
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
	url := c.Config.ServerURL + "/api/probes/" + fmt.Sprint(c.GetProbeID()) + "/license-details"
	resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
	if err != nil {
		return fmt.Errorf("failed to send license details: %w", err)
	}
	drainAndClose(resp) // drain so the keep-alive connection can be reused (L7)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send license details returned status %d", resp.StatusCode)
}
