# Changelog

## 1.2.5 - 2026-03-02

### Added
- **Processor stats polling**: Collector now polls per-core CPU usage via FortiGate `fgProcessorUsage` OID and sends to server (was missing — only the server poller had this)
- **Sensor unit inference**: Hardware sensors now include Type and Unit fields inferred from name patterns (temperature → °C, fan → RPM, voltage → mV)
- `GetProcessorStats()` to SNMP client and `ProcessorBaseOID()`/`ParseProcessorStats()` to vendor profile interface

### Fixed
- Ping now uses correct `*net.UDPAddr` for UDP ICMP mode instead of `*net.IPAddr`
- Ping errors now include wrapped context (which host failed, at what stage) for easier debugging

## 1.2.4 - 2026-03-02

### Added
- Per-device SNMP success logging showing device_id, CPU, memory, and session values after each poll
- Poll cycle summary log showing enabled/total device count
- Device refresh log now lists device names and IDs for easier debugging

## 1.2.3 - 2026-03-02

### Fixed
- **Ping error messages**: When all pings fail, the error message now includes the actual underlying error (e.g., "socket: permission denied") instead of a generic "Request timeout", helping diagnose Docker permission issues

## 1.2.2 - 2026-03-02

### Added
- **Multi-vendor SNMP architecture**: New `VendorProfile` interface and registry (`internal/snmp/vendor.go`) with FortiGate profile (`vendor_fortigate.go`); all vendor-specific OIDs moved out of `snmp.go`
- **Vendor field on DeviceInfo**: `relay.DeviceInfo` now includes `Vendor` string from server; polling methods pass vendor to SNMP calls

### Changed
- **SNMP refactoring**: `GetSystemStatus()`, `GetVPNStatus()`, `GetHardwareSensors()` now accept optional vendor parameter and delegate to vendor profiles
- **Trap receiver**: Uses vendor profile registry for OID lookups instead of hardcoded FortiGate OIDs

## 1.2.1 - 2026-03-02

### Fixed
- **Interface names missing**: SNMP ifXTable walk now reads `ifName` (`.1.3.6.1.2.1.31.1.1.1.1`) and uses it to override the generic `ifDescr` value; on FortiGate devices, `ifDescr` returns generic descriptions while `ifName` returns the actual interface names (`port1`, `wan1`, etc.)

## 1.2.0 - 2026-03-01

### Added
- **Hardware sensor polling**: Collector now polls FortiGate hardware sensors (fgHwSensorEntry MIB) via SNMP and sends them to the server's new `/api/probes/:id/hardware-sensors` endpoint, enabling the Hardware tab on device detail pages

## 1.1.9 - 2026-03-01

### Fixed
- **System status shows 0/-**: SNMP GET returns PDUs with `.0` instance suffix for scalar MIB objects but OID constants were missing the suffix, so the switch statement never matched any values; appended `.0` to all 9 system OID constants (CPU, memory, memory cap, disk, disk cap, sessions, uptime, version, hostname)

## 1.1.8 - 2026-03-01

### Fixed
- **Docker image version tagging**: CI now extracts version from source and pushes semver tags (`1.1.8`, `1.1`) alongside `latest`, so container managers (Portainer, Watchtower) can detect available updates
- **Dockerfile version label**: Version label is now set dynamically via build arg instead of being hardcoded (was stuck at 1.1.5)
- **docker-compose.yml**: References Docker Hub image `xphox/firewall-collector:latest` instead of local-only `firewall-collector:latest`

## 1.1.7 - 2026-03-01

### Fixed
- **SNMP traps not received**: Trap parser now correctly extracts the trap OID from the `snmpTrapOID.0` varbind value (SNMPv2c/v3 format) instead of searching varbind names, which never matched; also handles SNMPv1 enterprise+specific-trap OID construction
- **Trap device mapping**: Trap source IP is now resolved to a device ID by matching against the known device list, so traps are associated with the correct device
- **Generic trap support**: Traps with non-FortiGate OIDs are now accepted as "GENERIC" info-level events instead of being silently dropped
- **Trap message includes all varbinds**: Message now concatenates all payload varbinds instead of only the first matching one
- **Trap debug logging**: Incoming traps are logged with source IP, varbind count, version, and community for troubleshooting

## 1.1.6 - 2026-03-01

### Fixed
- **sFlow data empty**: Rewrote sFlow v5 parser to fully decode datagram headers, flow samples, and raw packet header records; extracts source/destination IP, ports, protocol, bytes, packets, TCP flags, and interface indices instead of only reading sequence number and agent IP
- **sFlow device mapping**: Agent IP from sFlow datagrams is now resolved to a device ID by matching against the known device list, so flow data is correctly associated with devices

## 1.1.5 - 2026-03-01

### Added
- **SNMPv3 support**: Per-device SNMPv3 credentials (username, auth type/pass, priv type/pass) received from server and used when connecting to v3 devices
- **VPN tunnel polling**: Collects IPSec VPN tunnel status from FortiGate devices via SNMP (tunnel name, remote gateway, status, bytes in/out) and relays to server
- **Enhanced interface collection**: ifXTable walk for alias, HC 64-bit counters, high speed; ifMtu and ifPhysAddress (MAC) from ifTable; Q-BRIDGE-MIB for native VLAN ID; human-readable interface type names

### Changed
- `NewSNMPClient()` now accepts optional `SNMPv3Config` parameter for per-device v3 credentials
- `DeviceInfo` struct includes 5 new SNMPv3 fields matching server relay contract
- `InterfaceStats` struct includes 6 new fields (Alias, MTU, MACAddress, TypeName, HighSpeed, VLANID)
- Added `VPNStatus` DTO and `SendVPNStatuses()` relay method

## 1.1.4 - 2026-03-01

### Added
- **docker-compose.yml**: Reference compose file with `restart: unless-stopped`, `stop_grace_period: 30s`, all port mappings, env vars, and commented-out TLS cert volume mounts

### Fixed
- **Shutdown flush race**: `relay.Stop()` now waits up to 15s for `DataSendLoop` to complete its final `syncData()` flush before sending the offline heartbeat (previously could exit before flush finished)
- **Docker STOPSIGNAL**: Added explicit `STOPSIGNAL SIGTERM` to Dockerfile to document the expected shutdown signal

## 1.1.3 - 2026-03-01

### Fixed
- **SNMP poll goroutine leak**: Added semaphore (max 10 concurrent) and `sync.WaitGroup` tracking to prevent unbounded goroutine spawning when polls take longer than the interval
- **Shutdown race condition**: `stop()` now waits for in-flight SNMP polls to complete via `WaitGroup` instead of `time.Sleep(1s)` hack

## 1.1.2 - 2026-03-01

### Fixed
- **Syslog TCP read deadline**: Moved `SetReadDeadline` inside read loop so it resets per-read instead of expiring 60s after connection start
- **Syslog Stop() double-close panic**: Both TCP and UDP receivers now use `sync.Once` to prevent panic on double-close of stopCh
- **sFlow Stop() double-close panic**: Same `sync.Once` fix for sFlow receiver

## 1.1.1 - 2026-03-01

### Fixed
- **FlowSample DTO mismatch**: Rewrote FlowSample struct to match server model exactly (added 11 missing fields: `sampling_rate`, `src_addr`, `dst_addr`, `src_port`, `dst_port`, `protocol`, `bytes`, `packets`, `input_if_index`, `output_if_index`, `tcp_flags`; removed non-existent `sample_count`)
- **Relay Stop() panic**: Wrapped `close(stopChan)` in `sync.Once` to prevent panic on double-close
- **Trap Start() silent failure**: Now waits up to 2s for listener to confirm startup or return error instead of always returning nil
- **Syslog IPv6 source IP**: Use `net.SplitHostPort()` for TCP connections instead of `strings.LastIndex(":")` which breaks on IPv6 addresses
- **Unbounded queue growth**: Capped all 4 data queues (trap, ping, syslog, flow) at 10,000 entries; drops oldest when full to prevent OOM
- **sFlow handler**: Removed reference to deleted `SampleCount` field, aligned with corrected FlowSample DTO

## 1.1.0 - 2026-03-01

### Added
- SNMP polling: polls system status (CPU, memory, disk, sessions, uptime) and interface stats from assigned devices
- SNMP trap receiver: listens for FortiGate SNMP traps with OID-based type/severity classification
- Syslog receiver: TCP and UDP listeners with RFC 5424 parsing and device ID extraction
- sFlow receiver: UDP listener with sFlow v5 datagram validation
- Ping collector: ICMP ping with configurable interval, timeout, and count per device
- Queue-based data relay: all collected data is batched and sent to server with 3-retry logic
- Device list fetching: periodically fetches assigned devices from server for SNMP polling and ping targets
- Feature toggles: each collector can be individually enabled/disabled via environment variables
- Configurable listener ports, poll intervals, and ping parameters via environment variables
- Full orchestration with graceful shutdown (stop all receivers, flush queues, send offline heartbeat)

### Changed
- Rewritten `cmd/collector/main.go` with `Collector` struct for full lifecycle management
- Relay client now includes DTOs, data queues, batch sync loop, and `FetchDevices()`/`SendSystemStatuses()`/`SendInterfaceStats()` methods
- Config expanded with 15 new fields for listener ports, intervals, and feature toggles
- Dockerfile updated with all new environment variable defaults

## 1.0.4 - 2026-02-28

### Improved
- Send offline heartbeat to server on graceful shutdown so the server knows immediately instead of waiting for a timeout
- Heartbeat and sync intervals are now configurable via `PROBE_HEARTBEAT_INTERVAL` and `PROBE_SYNC_INTERVAL` env vars (in seconds, defaults: 60 and 30)
- Remove unnecessary gcc/musl-dev from Dockerfile builder stage (not needed with `CGO_ENABLED=0`)
- Add `go mod download` layer to Dockerfile for faster rebuilds when only source code changes

## 1.0.3 - 2026-02-28

### Fixed
- Send initial heartbeat immediately on startup instead of waiting 60 seconds for the first ticker interval

## 1.0.2 - 2026-02-28

### Improved
- Add `PROBE_REGISTRATION_KEY` and `PROBE_SERVER_URL` as pre-defined environment variables in Dockerfile so users can see and fill them in directly in Docker UIs instead of typing variable names manually

## 1.0.1 - 2026-02-28

### Security
- Remove default `InsecureSkipVerify: true` — TLS now verifies certificates using the system CA store by default
- Add `PROBE_INSECURE_SKIP_VERIFY` env var for explicit opt-in (with logged warning)
- CA cert file read errors are now fatal instead of silently falling back to insecure mode
- Add Bearer token authentication (`Authorization` header) on all HTTP requests, not just registration

### Fixed
- Handle `json.Marshal` errors in `Register()` and `SendHeartbeat()` instead of ignoring them
- Check HTTP status code before attempting JSON decode in `Register()` — prevents confusing parse errors on 500 responses
- Add exponential backoff (10s-160s) and max retry limit (5) for re-registration on 401/403 to prevent infinite loops
- Add 30-second HTTP client timeout to prevent goroutines from hanging on unresponsive servers
- Protect `probeID` and `probeName` with mutex to fix data race between heartbeat goroutine and main thread
- Fix duplicate "keen" in random name adjectives list (replaced with "sharp")
- Handle `crypto/rand.Read` and `crypto/rand.Int` errors instead of ignoring them
- Remove unused `running` field from Client struct

## 1.0.0

- Initial release with probe registration, heartbeat loop, and TLS/mTLS support
