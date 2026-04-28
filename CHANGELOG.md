# Changelog

## 1.2.72 - 2026-04-28

### Added
- **Syslog-triggered config backups (FortiGate)**: collector now parses incoming syslog and recognises FortiOS event-log IDs `0100044546` (attribute changed) and `0100044547` (object-attribute changed) as config-change signals. When one arrives for a known device, a backup is queued with a 60-second debounce keyed on `(deviceID, cfgtid)` so multi-line commits collapse into a single backup attempt. Logged as `[Syslog→Backup] queued backup for <name> in 1m0s (logid=… cfgtid=… cfgpath=… action=… user=…)`.
- **`internal/syslog/fortigate.go`**: `FortiEvent` type + `ParseFortiEvent(*relay.SyslogMessage) *FortiEvent` extracting `logid`, `type`, `subtype`, `level`, `vd`, `user`, `ui`, `action`, `cfgtid`, `cfgpath`, `cfgobj`, `cfgattr`, `devid`, `devname`, `msg`. Hand-rolled key=value parser tolerates quoted strings, empty values, missing trailing space. Full unit tests.
- **TFTP filename now encodes provenance**: `fgt_<id>_<trigger>_config` (e.g. `fgt_2_syslog_config`). The TFTP write handler parses both deviceID and trigger from the filename so revisions arrive at the server already labeled `syslog`/`poll`/`manual`. Legacy `fgt_<id>_config` filenames still parse and default to `poll` for compatibility with in-flight uploads from older collectors.
- **Backup quality detection**: write handler scans uploaded bytes for FortiOS 7.2.1+ password-masking markers (`config_masked_password`, `ENC <removed>`) and tags the revision `BackupQuality="masked"`. The server surfaces this as a UI badge so operators see "this backup is not restorable — secrets must be re-entered."
- **`relay.ConfigRevision` DTO**: new optional `trigger_source` and `backup_quality` fields. Server-side handler populates `NormalizedChecksum` and dedup behavior independently; these fields are pure provenance/quality metadata.

### Changed
- **`fetchConfigViaTFTP` signature**: now takes `(dev, checksum, triggerSource string)`. Existing SSH-poll call site passes `"poll"`; new syslog trigger passes `"syslog"`. Empty triggerSource defaults to `"poll"`.
- **Default `SSHPollInterval`** confirmed at **15 minutes** when not set per-device. This is the floor cadence in the new hybrid trigger model: syslog gives near-instant detection where forwarding is configured, the periodic poll backstops everything else.

### Why
FortiOS regenerates the encryption IV on every `set <field> ENC <blob>` line on every config emission, so periodic polling alone produced false-positive `CONFIG_CHANGE` alerts on every backup of every FortiGate. The server-side fix (v0.10.187) hashes a vendor-normalized copy and only alerts on real changes; this collector update reduces *load* on the firewall by polling less aggressively (15 min instead of 1 min) and detecting *real* changes faster (within seconds of the commit) via syslog. Both halves are required.

## 1.2.71 - 2026-04-28

### Diagnosed
- **Root cause of "TFTP backup never arrives" silent failure**: the SSH user being used to run `execute backup config tftp` does **not** have permission to back up config. FortiOS responds with `The current admin user does not have the permission to backup config. Command fail. Return code -37` — but on accounts with even more restricted profiles, the response is stripped entirely, which is why production logs showed an empty FortiGate response and no WRQ ever landed on the listener. Resolution is on the FortiGate: assign the SSH user an admin profile that includes Configuration & Settings read+write (or `super_admin`).

### Added
- **diag-backup verdict for permission denied**: `cmd/diag-backup` now recognises FortiOS `Return code -37` / "permission to backup config" output and prints a labelled verdict pointing at the admin profile, instead of the previous generic "no upload arrived" message. Includes the exact CLI to fix it.

## 1.2.70 - 2026-04-28

### Added
- **`cmd/diag-backup`: end-to-end TFTP backup diagnostic**. Single-shot tool that exercises the full path against a real firewall and prints a definitive verdict on where it succeeds or fails — no more iterating on production logs.
  - Binds a TFTP listener (default port 6969 so it doesn't need root or conflict with a running collector)
  - SSH connects to the device
  - Sends `execute backup config tftp <file> <target>` (PTY by default; `-use-pty=false` for comparison)
  - Logs raw FortiGate output with byte count
  - Watches the listener for the WRQ + transfer
  - Prints a labelled verdict: full success / SSH closed silently / firewall couldn't reach TFTP server / firewall says OK but no WRQ / etc., with concrete next steps for each failure mode
  - Build with: `go build -o diag-backup ./cmd/diag-backup/`
  - Example: `./diag-backup -device-host=192.168.5.1 -device-user=admin -device-password='...' -listen-port=6969 -tftp-target=192.168.5.25`

## 1.2.69 - 2026-04-28

### Fixed
- **TFTP backup SSH session was probably exiting before the upload ran**: Logs showed `[TFTP] FortiGate response from <fw>:` followed by no content, with the whole SSH round-trip completing in ~1 second — far too fast for FortiOS to actually have run the upload. Some FortiOS builds drop non-PTY SSH channels before completing side-effecting `execute` commands. `BackupConfigTFTP` now allocates a PTY (`xterm`, 80x200) before sending the command, with a 90-second timeout (long enough for the firewall to either finish or print a definitive failure, short enough that diagnostics aren't buried for 10 minutes).

### Added
- **Raw FortiGate output is now always logged for TFTP backup** (`[TFTP] FortiGate raw response from <fw> (N bytes):`) — including byte count. Previously only the post-`cleanOutput` text was logged, and only when non-empty, which hid the case where FortiGate's actual response got stripped or the channel closed silently.
- New SSH client methods: `ExecuteRaw(cmd, timeout)` and `ExecuteWithPty(cmd, timeout)` for callers that need unfiltered output and/or PTY allocation. The existing `Execute` is unchanged behaviorally (no PTY, cleanOutput applied).

## 1.2.68 - 2026-04-28

### Changed
- **Clearer TFTP log wording**: Replaced `Sending 'execute backup config tftp <file> <ip>' to <firewall>` with `SSH to <firewall>: instructing firewall to upload config '<file>' to collector at <ip>`. The old wording read as if the config was being sent *to* the firewall, when in fact we're sending an SSH command to the firewall that tells it to upload its config *to the collector*. Followup line now says `SSH command accepted by <firewall> — waiting for firewall to TFTP-upload config to collector`.

## 1.2.67 - 2026-04-28

### Added
- **Honors admin-set TFTP Server IP from server**: `GET /api/probes/:id/devices` now carries the per-probe `tftp_server_ip` value the admin entered on the server's Probe edit form (server v0.10.186+). The collector caches it on every device-list refresh and uses it as the destination IP in `execute backup config tftp <file> <ip>`. This is the right answer when the collector runs in Docker with `PROBE_LISTEN_ADDR=0.0.0.0` and cannot reliably auto-detect what IP each firewall reaches it at.
- **Relay client**: new `FetchDevicesAndConfig()` returning `([]DeviceInfo, tftpServerIP, error)`. The existing `FetchDevices()` is kept as a thin wrapper for compatibility.

### Changed
- **TFTP target selection priority**: admin-configured `tftp_server_ip` wins; if blank, falls back to the v1.2.66 per-device auto-detection (dial the firewall's IP, take the kernel's local source). Each backup attempt now logs which path was taken.

## 1.2.66 - 2026-04-27

### Fixed
- **TFTP config backup silently failing for firewalls behind tunnels/NAT**: The collector was determining a single global outbound IP at startup by dialing `8.8.8.8` — i.e., the local source address used to reach the public internet. When firewalls live on a private LAN, behind a site-to-site VPN, or behind NAT, that public-facing IP is *not* the IP the firewall sees the collector at, so `execute backup config tftp <file> <wrong-ip>` had no route from the firewall and no WRQ ever arrived. The collector now determines the outbound IP **per device** by dialing each device's own IP, so the kernel returns the correct local source for that device's network path.
- **Source `version` constant** bumped (was stuck at 1.2.64 even though 1.2.65 had shipped).

### Changed
- **`BackupConfigTFTP` returns command output**: FortiGate prints diagnostic messages such as `Send config file to tftp server failed.` or `config backup successful` after `execute backup config tftp`. Previously the collector discarded that output, hiding what the firewall actually saw. The collector now logs the FortiGate response for every TFTP backup attempt — making future failures self-diagnosing.

## 1.2.65 - 2026-04-27

### Added
- **SSH parser tests** (`internal/ssh/parser_test.go`): 26 unit tests covering all 7 parser functions — `ParseSensorInfo` (single-line dot-separator + multi-line block formats, alarm status, unit variants), `ParsePerformanceStatus` (CPU fields, memory ×1024 conversion, network kbps, uptime days→seconds), `ParseVPNPhase1/2` (single/multiple tunnels, last-entry flush), `ParseProcessTop` (both trigger paths, header filtering), `ParseInterfaceList`, `ParseLicenseStatus`.
- **SSH regression tests** (`internal/ssh/regression_test.go`): 7 tests mapping directly to past changelog bugs — sensor dot-separator regex, `%` unit parsing, `$` in config values, last-entry flush for VPN/interfaces, memory ×1024.
- **Relay tests** (`internal/relay/relay_test.go`): 14 tests covering queue overflow drop-oldest for all 4 queue types, concurrent write safety, `splitIntoChunks` edge cases, `tryReregister` 60-second rate-limit and 10-minute cooldown guards, `requeueTraps` prepend-to-front and capacity enforcement.
- **TFTP concurrent transfer regression test** (`internal/tftp/regression_test.go`): runs 3 simultaneous WRQ uploads to verify the rewritten server (fresh ephemeral TID per transfer) has no socket race condition.
- **Collector helper tests** (`cmd/collector/collector_helpers_test.go`): 5 tests for `devIDFromFilename` (valid/invalid) and `checksumFromData` (format, determinism, MD5 correctness).

### Fixed
- **`sensorLineRegex` unit group** changed from `\w+` to `\S+` so sensor readings reported with `%` units (storage usage) are now correctly parsed. Previously the digit before `%` leaked into the value and the `%` was silently lost.

## 1.2.64 - 2026-04-27

### Fixed
- **tftp-test debug client**: The standalone `tftp-test` utility had the same `DialUDP` bug as the unit tests — once the TFTP server moved to a fresh ephemeral TID port, the connected client socket dropped its replies. Switched to `ListenUDP` and explicit `WriteToUDP(serverTID)` so it can verify the production server.

## 1.2.63 - 2026-04-27

### Fixed
- **TFTP config backup actually works now**: Fixed two bugs that prevented FortiGate config backup over TFTP from ever succeeding.
  - `execute backup config tftp` was being given an `IP:PORT` string (e.g. `192.168.1.10:69`); FortiGate's CLI requires a bare IPv4 address and was silently failing to resolve the malformed argument. The collector now passes only the IP.
  - The TFTP server used a single UDP socket on port 69 for both new RRQ/WRQ requests and per-transfer DATA/ACK packets. The main `serve()` loop and the per-WRQ goroutine raced for incoming DATA, so half the time the listen loop would receive a DATA packet, treat it as an unknown opcode, and reply ERROR ("Not implemented") — killing the transfer. Per RFC 1350 the server must allocate a fresh ephemeral UDP port (the server TID) for each transfer; the rewrite does this and isolates each transfer to its own socket.

### Added
- **WRQ multi-packet test**: New `TestTFTPServerWRQ` exercises a 1500-byte upload across three blocks and asserts the server's TID port differs from the listen port. Would have caught the race condition above.

## 1.2.48 - 2026-04-27

### Fixed
- **TFTP config backup not working**: Fixed bug where `tftpOutboundIP` was never set because `determineOutboundIP()` was called AFTER `ListenAndServe()`, which blocks forever. Now determines the outbound IP BEFORE starting the TFTP server. This ensures firewalls receive the correct target IP when issuing `execute backup config tftp` command.

## 1.2.47 - 2026-04-27

### Fixed
- **ssh-test cleanOutput**: Sync ssh-test tool with main ssh.go cleanOutput fix (same prompt filtering logic)

### Added
- **TFTP tests**: Add unit tests for extractFilename, ACK, shutdown, and write handler

## 1.2.46 - 2026-04-27

### Fixed
- **cleanOutput config truncation bug**: Fixed prompt detection that incorrectly filtered config lines containing `$` character. Lines like `set alias "FortiGate-100E$"` were being removed. Now only filters actual CLI prompts (lines ending with `FW-XXX #` or `FW-XXX $`).

### Added
- **TFTP config fetch support**: Added TFTP server for receiving config backups directly from FortiGate. Enable with `PROBE_TFTP_CONFIG_ENABLED=true` and configure port with `PROBE_TFTP_PORT`. FortiGate uses `execute backup config tftp <filename> <server>` to push configs.

## 1.2.45 - 2026-04-27

### Fixed
- **ParseSensorInfo regex**: Reverted `\.+` pattern was incorrectly changed to `[^\w]+` which broke sensor parsing on FortiGate. Restored original `\.+` pattern.

## 1.2.44 - 2026-04-27

### Fixed
- **GetVPNStatus and GetSystemSessionList**: Removed `| no-more` from all commands - does not work on FortiGate, cleanOutput handles pagination.

## 1.2.43 - 2026-04-27

### Fixed
- **GetInterfaceList command**: Removed `| no-more` - does not work on FortiGate-60F and cleanOutput function already handles `--More--` pagination. Command now works without pipe modifier.

## 1.2.42 - 2026-04-27

### Fixed
- **GetConfig command**: `show full-configuration | no-more` fails on FortiGate with "unrecognized pipe command". Removed `| no-more` from GetConfig.

## 1.2.41 - 2026-04-27

### Fixed
- **ParseSensorInfo temperature regex**: Fixed regex to properly parse temperature sensor values from FortiGate `execute sensor list` output.

## 1.2.40 - 2026-04-27

### Fixed
- **SSH pagination over tunnels**: Note: `| no-more` does NOT work with `show full-configuration` command.

## 1.2.39 - 2026-04-27

### Fixed
- **GetConfig uses full-configuration**: Changed `show` to `show full-configuration` to get the COMPLETE config including all default values. Previously `show` only returned modified settings, not the full configuration.
- **SSH command timeout**: Added 10-minute timeout to `Execute()` to prevent hanging on slow IPSec management tunnels when retrieving large configs. Increased from 5 minutes to 10 minutes for large FortiGate configs.
- **Goroutine leak on timeout**: Fixed goroutine leak when SSH command timed out - now properly closes the session to terminate orphaned goroutines

## 1.2.37 - 2026-04-23

### Fixed
- **ParseSensorInfo for single-line format**: Added `sensorLineRegex` to handle FortiGate output like "1 CPU ON-DIE Temperature ........ 63.8 C" which has all info on one line
- **ParseProcessTop for FortiGate new format**: FortiGate newer firmware doesn't output "Run Time:" header - process list now detected by presence of "U," and "T," in the same line

### Added
- **Enhanced ssh-test tool**: Now tests all SSH commands with proper parsing validation (sensor, process, interface, license, performance, vpn, ha, checksum, config)

## 1.2.36 - 2026-04-23

## 1.2.35 - 2026-04-22

### Added
- **Debug logging for sensor parsing**: Added logging to ParseSensorInfo to debug why sensors aren't being collected

## 1.2.34 - 2026-04-22

### Fixed
- **Security: SSH host key verification**: Changed from custom callback that accepts any host to `ssh.InsecureIgnoreHostKey()` for clearer intent
- **SSH concurrency limit**: Added semaphore (5 concurrent) to prevent unlimited goroutine spawns during SSH polling
- **VPN Phase1 duplicate handling**: Added warning log when duplicate Phase1 tunnel names are detected, keeps first occurrence
- **VPN phase1name regex**: Fixed to capture quoted phase1 names (e.g., `"phase1name"`) instead of only non-whitespace
- **VPN status regex**: Fixed greedy `.+` to `\S+` to avoid capturing trailing whitespace
- **Dead code removal**: Removed unused `splitByWhitespace()` function
- **Queue overflow optimization**: Changed from O(n) slice slicing to `append()` pattern for queue overflow handling

## 1.2.33 - 2026-04-22

### Fixed
- **VPN Status fallback**: Default Status to "unknown" when Phase1 lookup fails (no matching phase1 interface found)
- **VPN RemoteGateway fallback**: Use p2.RemoteGateway as fallback when p1.RemoteGateway is empty

## 1.2.32 - 2026-04-22

### Added
- SSH: Add `GetPerformanceStatus()` to collect CPU per core, memory, network usage, sessions via `get system performance status`
- SSH: Add `ParsePerformanceStatus()` parser for performance data
- SSH: Add `GetVPNStatus()` to collect IPSEC phase1/phase2 tunnel configs via `show vpn ipsec phase1-interface` and `show vpn ipsec phase2-interface`
- SSH: Add `ParseVPNPhase1()` and `ParseVPNPhase2()` parsers for IPSEC tunnel configuration
- SSH: Add `GetHAStatus()` and `GetSystemSessionList()` methods to FortiGateClient
- SSH polling: Send performance status as SystemStatus (CPU usage, memory, sessions, uptime)
- SSH polling: Send VPN tunnel statuses from phase1/phase2 configs
- SSH polling: Send CPU breakdown (user/system/nice/idle/iowait/irq/softirq) and network throughput (in/out kbps) via `get system performance status`
- SSH polling: Send phase1 interface name and mode for VPN tunnel display
- Relay: Add NetworkInKbps, NetworkOutKbps, CPU breakdown fields, MemoryFree, MemoryFreeable to SystemStatus
- Relay: Add InterfaceName, Mode to VPNStatus

## 1.2.31 - 2026-04-18

### Fixed
- Fix syslog queue full causing network spikes and 400 errors: add batch size limiting and sequential sending with 500ms stagger between queues
- Add `splitIntoChunks()` to split large queues into configurable batch sizes (default 1000) to prevent server 400 errors
- Add `sendBatchesSequential()` to replace parallel batch sends with sequential chunks, reducing traffic spikes
- Add proper 400 error handling — stop retrying immediately and log response body for debugging
- Add `isRetryableStatus()` to avoid retrying non-retryable errors (400, 401, 403, 404, 405, 409, 410, 422, 429, 502, 503, 504)
- Add warning logs when requeue cannot fit all items (was silently dropping data)
- Fix division by zero in `splitIntoChunks()` if chunkSize <= 0
- Fix `io.ReadAll` error being silently discarded — now logs warning
- Add `requeueGeneric()` fallback for unknown batch names to prevent silent data loss
- Add default case in sendBatchesSequential switch with error logging

### Changed
- `SyncInterval` now uses exponential backoff (2^attempt) instead of linear for batch send retries
- HTTP client timeout increased from 30s to 60s for large batch uploads
- HTTP transport tuned: MaxIdleConns=25, MaxIdleConnsPerHost=10, IdleConnTimeout=90s

### Added
- New env vars: `PROBE_MAX_QUEUE_SIZE` (default 10000) and `PROBE_MAX_BATCH_SIZE` (default 1000)
- Added `MaxBatchSize` to relay.Config struct for configurable batch sizes
- Added `ConfigureLimits()` function to set global queue and batch limits
- Added `requeueGeneric()` for type-agnostic requeue fallback

## 1.2.30 - 2026-04-04

### Fixed
- Add automatic re-registration recovery when probe loses approval — previously a single 404/401/403 response (e.g., from a transient server restart) permanently killed data collection with no recovery mechanism
- `syncData()` now re-queues data instead of silently dropping it when probe is unapproved
- `doDirectSend()` and `sendBatch()` now attempt re-registration before giving up on auth/not-found errors
- `FetchDevices()` and pre-send approval checks now attempt re-registration instead of immediately failing
- Re-registration is rate-limited (60s between attempts) with exponential backoff; after 5 consecutive failures, enters 10-minute cooldown then resets — probe keeps retrying indefinitely until server returns

## 1.2.29 - 2026-03-18

### Fixed
- Remove `.claude/settings.local.json` from tracking — local Claude Code permissions should not be in a public repo
- Expand `.gitignore` with standard Go, IDE, OS, and secrets patterns
- Add `.claude` and `*.exe` to `.dockerignore`

## 1.2.28 - 2026-03-15

### Fixed
- Add retry logic (3 attempts, 2s delay) to all direct Send methods — previously only batched sends retried
- Add approval-revocation handling on direct Sends — 401/403/404 now sets probe as unapproved (matching sendBatch behavior)
- Refactor 10 duplicate Send methods into shared `doDirectSend` helper
- Add circuit breaker for failed device polls — after 3 consecutive failures, device enters backoff mode (polled every 5th cycle)
- Fix ping count not used — was hardcoded to `-c 1`, now uses configured count
- Track deviceRefreshLoop goroutine in WaitGroup for proper graceful shutdown
- Add jitter to heartbeat retry backoff to prevent thundering herd when multiple probes reconnect simultaneously

## 1.2.27 - 2026-03-09

### Added
- Palo Alto Networks vendor profile with PAN-COMMON-MIB support (system status, sessions, GlobalProtect stats, AV/threat versions)
- Palo Alto VPN tunnel detection via IF-MIB tunnel.* interface patterns
- Palo Alto hardware sensors via ENTITY-SENSOR-MIB (temperature, fan, voltage, power)
- Palo Alto per-CPU stats via HOST-RESOURCES-MIB (management plane, data plane)
- Palo Alto HA cluster status via PAN-COMMON-MIB scalar OIDs
- Palo Alto SNMP trap definitions (VPN, HA, hardware, GlobalProtect, threat events)
- SonicWall vendor profile with SNWL-COMMON-MIB and SONICWALL-FIREWALL-IP-STATISTICS-MIB
- SonicWall system status (CPU, RAM, session count from enterprise OIDs)
- SonicWall IPSec VPN tunnel monitoring via sonicSAStatTable (peer gateway, subnets, byte counters)
- SonicWall hardware sensor monitoring via sonicwallSensorsTable
- SonicWall SNMP trap definitions (IPSec, HA, IPS, security services, WAN failover)

## 1.2.26 - 2026-03-09

### Added
- Firewalla VPN tunnel detection via IF-MIB interface name patterns (WireGuard wg*, OpenVPN tun*/tap*, IPSec vti*)
- Linux-specific VPN helper (`vendor_linux_vpn.go`) with ifType-based disambiguation for ambiguous tun* interfaces

## 1.2.25 - 2026-03-09

### Added
- **VPN tunnel detection for pfSense & OPNsense**: Detect VPN tunnels from IF-MIB interface name patterns — no firewall-side configuration required
  - OpenVPN server (`ovpns*`) and client (`ovpnc*`) instances with up/down status and traffic counters
  - WireGuard interfaces (`wg*`, `tun_wg*`) with status and aggregate traffic
  - Route-based IPSec VTI interfaces (`ipsec*`) with per-tunnel status and traffic
  - Shared BSD VPN detection helper (`vendor_bsd_vpn.go`) used by both pfSense and OPNsense profiles

## 1.2.24 - 2026-03-09

### Added
- **pfSense vendor profile**: SNMP vendor profile for pfSense firewalls (FreeBSD-based). Uses UCD-SNMP-MIB for CPU/memory, BEGEMOT-PF-MIB for active PF state count (mapped to session count), HOST-RESOURCES-MIB for per-CPU load, and SNMPv2-MIB for system info
- **OPNsense vendor profile**: SNMP vendor profile for OPNsense firewalls. Same FreeBSD/BEGEMOT-PF-MIB stack as pfSense with OPNsense-specific version parsing
- Both profiles include PF firewall state count as session metric (unique to pf-based firewalls)
- VPN, HA, security stats, and hardware sensors gracefully return empty (not available via SNMP on these platforms)

## 1.2.23 - 2026-03-09

### Added
- **Firewalla vendor profile**: New SNMP vendor profile for Firewalla devices (Ubuntu Linux-based). Uses standard Linux MIBs since Firewalla has no enterprise-specific OIDs
  - CPU usage via UCD-SNMP-MIB (ssCpuUser + ssCpuSystem + ssCpuIdle)
  - Memory usage via UCD-SNMP-MIB (memTotalReal, memAvailReal, memBuffer, memCached) with proper Linux memory accounting
  - System info via SNMPv2-MIB (sysName, sysDescr, sysUpTime)
  - Per-CPU load via HOST-RESOURCES-MIB (hrProcessorLoad)
  - Hardware temperature/fan sensors via lm-sensors NET-SNMP extension MIB
  - Interface statistics work out of the box via standard IF-MIB
  - VPN, HA, security stats, SD-WAN, and license info gracefully return empty (not available via SNMP on Firewalla)

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
