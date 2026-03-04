# Changelog

## 1.2.22 - 2026-03-04

### Added
- **Dialup VPN Phase 2 selectors & uptime**: Parse missing FortiGate dialup VPN table OIDs — `.3` (lifetime/uptime), `.5-.8` (source/dest IP range selectors) — so hub-side dialup tunnels now report `local_subnet`, `remote_subnet`, and `tunnel_uptime` to the server
- **rangeToCIDR helper**: Converts IP range selectors (begin/end) to CIDR notation for dialup VPN Phase 2 subnets

## 1.2.21 - 2026-03-03

### Fixed
- **buildCIDR wildcard subnets**: Preserve `0.0.0.0/0` for Phase 2 wildcard selectors instead of discarding them as empty — fixes VXLAN carrier tunnels and "any" selectors reporting empty subnets to server

## 1.2.20 - 2026-03-03

### Fixed
- **TCP syslog connection WaitGroup**: Added `connWg sync.WaitGroup` to `SyslogReceiver` to properly track active TCP connections; `Stop()` now waits for all in-flight connection handlers to finish before returning, preventing goroutine leaks on shutdown

## 1.2.19 - 2026-03-03

### Fixed
- **Relay batch re-queue on failure**: `sendBatch` now returns a success flag; when all 3 retry attempts fail, queued data (traps, pings, syslog, flows) is re-queued for the next sync cycle instead of being silently dropped, bounded by `maxQueueSize` to prevent memory growth.

## 1.2.18 - 2026-03-02

### Added
- **IPSec Phase 2 selector collection**: VPNStatus relay DTO now includes `phase1_name`, `local_subnet`, `remote_subnet`, and `tunnel_uptime` fields
- **FortiGate Phase 2 SNMP OIDs**: Collector now parses OIDs .2 (Phase 1 name), .5/.6 (remote subnet addr/mask), .7/.8 (local subnet addr/mask), .21 (tunnel uptime) from the VPN tunnel table
- **CIDR notation conversion**: Subnet address + mask pairs are converted to CIDR format (e.g., "10.0.0.0/24") via new `buildCIDR()` helper before relay to server

## 1.2.17 - 2026-03-02

### Fixed
- **sFlow device resolution via interface IPs**: `resolveDeviceByIP()` now checks both management IPs and a cached interface IP→device map, resolving sFlow agents sending from non-management addresses
- **Interface IP cache**: After each SNMP walk, collected interface addresses are cached locally for instant sFlow device mapping (excludes 0.0.0.0 and 127.0.0.1)

## 1.2.16 - 2026-03-02

### Added
- **Interface IP address collection**: New `GetInterfaceAddresses()` SNMP method walks standard IP-MIB `ipAddrTable` to collect all IP addresses assigned to device interfaces (vendor-neutral, works on FortiGate, Palo Alto, Cisco, etc.)
- **`InterfaceAddress` relay DTO**: New data type with timestamp, device_id, if_index, ip_address, net_mask
- **`SendInterfaceAddresses()` relay method**: Sends collected interface addresses to server via `POST /api/probes/:id/interface-addresses`
- Interface address collection integrated into `pollDevice()` — runs after interface stats, before VPN status

## 1.2.15 - 2026-03-02

### Added
- **Comprehensive FortiGate SNMP monitoring expansion** — 6 new data collection areas:
  - **Extended SystemStatus**: Session setup rates (1/10/30/60 min), IPv6 session count, low memory usage/capacity, AV/IPS signature versions, SSL-VPN user/tunnel counts — all sent as new fields in existing `SystemStatus` DTO
  - **SSL-VPN tunnel discovery**: Walks `fgVpnSslTunnelTable` to report individual SSL-VPN client sessions as VPN tunnels with `tunnel_type: "sslvpn"`
  - **HA cluster monitoring**: New `HAProvider` optional interface; FortiGate implementation reads HA mode/group scalars + walks `fgHaStatsTable` for per-member CPU/mem/net/sessions/packets/bytes/sync status
  - **Security stats (AV/IPS/WebFilter)**: New `SecurityStatsProvider` interface; reads per-VDOM counters for antivirus detected/blocked, IPS by severity, WebFilter blocked
  - **SD-WAN health checks**: New `SDWANProvider` interface; walks `fgVWLHealthCheckLinkTable` for link name, state, latency, packet send/recv, interface; computes packet loss percentage
  - **License/contract info**: New `LicenseProvider` interface; walks `fgLicContracts` table for contract description and expiry dates
- `TunnelType` field on `VPNStatus` DTO — existing IPSec tunnels tagged `"ipsec"`, dialup tunnels `"ipsec-dialup"`, SSL-VPN `"sslvpn"`
- 5 new optional vendor interfaces: `SSLVPNProvider`, `HAProvider`, `SecurityStatsProvider`, `SDWANProvider`, `LicenseProvider`
- 4 new relay `Send*` methods: `SendHAStatuses`, `SendSecurityStats`, `SendSDWANHealth`, `SendLicenseInfo`
- 4 new SNMP client methods: `GetHAStatus`, `GetSecurityStats`, `GetSDWANHealth`, `GetLicenseInfo`
- All new data types collected in `pollDevice()` with silent skip when unsupported

## 1.2.14 - 2026-03-02

### Added
- **Dial-up VPN tunnel detection**: Hub-side FortiGates running dial-in IPSec (spoke/hub topology) now show connected VPN peers. Previously only the spoke side reported tunnels because the code only walked `fgVpnTunTable` (site-to-site). Now also walks `fgVpnDialupTable` which contains active dial-up peers, and merges both into the VPN status output.
- `DialupVPNProvider` optional interface for vendor profiles that expose dial-up VPN peers in a separate SNMP table

## 1.2.13 - 2026-03-02

### Fixed
- **Ping always reports timeout on Linux**: Removed `echo.ID != id` check from ICMP reply matching — with `udp4` sockets the kernel rewrites the echo ID with an internal value, so the ID check always failed. The kernel already filters replies to the correct socket, making the ID check unnecessary; only sequence number matching is needed
- **Hardware sensors showing 0**: Added `isValidPDU()` guard to `ParseHardwareSensors()`, `ParseVPNStatus()`, and `ParseProcessorStats()` — `NoSuchObject`/`NoSuchInstance` PDUs were being processed as zero values instead of being skipped

### Added
- Ping success/failure logging with latency and packet loss for visibility (`[Ping] device (ip): latency=X.Xms loss=X%`)

## 1.2.12 - 2026-03-02

### Added
- **Deep SNMP diagnostic on startup**: Credential validation (warns if community is empty, port is 0, v3 username missing), vendor-neutral sysObjectID test (works on ANY SNMP device) to distinguish "device unreachable" from "wrong vendor OIDs", plus detailed connection parameter logging
- **Per-device credential guard**: Skips polling with clear warning if SNMP community is empty or port is 0, instead of sending doomed requests that timeout after 20s
- **Verbose poll failure logging**: SNMP failures now log port, version, community length, and vendor alongside the error for immediate root-cause visibility

## 1.2.11 - 2026-03-02

### Fixed
- **SNMP timeout fix**: Switched docker-compose.yml from bridge networking to `network_mode: host` — Docker's NAT bridge was dropping outbound SNMP (UDP 161) and ICMP packets, causing "request timeout" on all devices. Host networking lets the container use the host's network stack directly, eliminating the NAT layer that was blocking outbound polls.

### Removed
- Removed `ports:` section (not needed with host networking — all ports are directly accessible)

## 1.2.10 - 2026-03-02

### Added
- **SNMP startup diagnostic**: On startup, tests SNMP connectivity to the first enabled device and reports detailed results (success with stats, or failure with troubleshooting hints)
- **Device list dump on startup**: Logs all assigned devices with IP, SNMP port, version, community (redacted), vendor, and enabled status for immediate config verification
- **Immediate first poll**: SNMP polling now runs immediately on startup instead of waiting for the first ticker interval (60s delay eliminated)

### Changed
- Refactored SNMP polling loop into `runPollCycle()` for cleaner startup + ticker reuse
- Added `network_mode: host` option (commented) to docker-compose.yml with documentation explaining when to use it for SNMP/ICMP outbound connectivity

## 1.2.9 - 2026-03-02

### Changed
- **Ping full rewrite**: Replaced entire ping implementation with clean, robust design:
  - Uses `udp4` ICMP sockets exclusively — kernel filters replies to each socket, no cross-talk between concurrent goroutines, no raw socket edge cases
  - One socket per device (reused across all count pings) instead of opening/closing per individual ping
  - `sendEcho()` helper handles one echo request/reply cycle with proper ID+Seq validation
  - Removed all raw socket (`ip4:icmp`) attempts and `ipv4.PacketConn` wrapping that caused panics
  - Resolve and socket errors report proper results instead of silently dropping

## 1.2.8 - 2026-03-02

### Fixed
- **Ping panic on ipv4.PacketConn**: Removed `ipv4.NewPacketConn` wrapper that panicked when wrapping `icmp.PacketConn` from `icmp.ListenPacket("ip4:icmp")` — now uses plain `conn.ReadFrom()` for both raw and UDP sockets, returning TTL=0 (unavailable) instead of crashing

## 1.2.7 - 2026-03-02

### Fixed
- **Disk usage percentage calculation**: FortiGate `fgSysDiskUsage`/`fgSysDiskCapacity` OIDs return values in MB, not percentage — now correctly computes `usage/capacity * 100` instead of storing raw MB as percentage
- **SNMP PDU type guard**: Added `isValidPDU()` check to skip `NoSuchObject`/`NoSuchInstance`/`EndOfMibView` responses instead of silently treating unsupported OIDs as zero
- **Ping rewrite**: Fixed hardcoded `Seq: 1` causing response collisions — now uses global atomic sequence counter with unique values per request
- **Ping response validation**: Echo replies are now validated by matching ID and Seq fields, preventing acceptance of stale or wrong replies
- **Ping TTL**: Attempts raw ICMP socket (`ip4:icmp`) for real TTL from IP header; falls back to unprivileged UDP ICMP with TTL=0 (unknown) instead of hardcoded 64
- **Ping concurrency**: Devices are now pinged concurrently (max 10 parallel) instead of sequentially, preventing timeout cascading across many devices
- **Ping ICMP error handling**: `DestinationUnreachable` and `TimeExceeded` now return specific error messages instead of being silently ignored
- **Disk debug logging**: SNMP poll log now includes `Disk=X%/YMB` for each device

## 1.2.6 - 2026-03-02

### Fixed
- **Docker ICMP ping**: Added `cap_add: NET_RAW` and `sysctls: net.ipv4.ping_group_range` to docker-compose.yml so ICMP ping works inside the container without "socket: permission denied" errors

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
