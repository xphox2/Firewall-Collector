# Changelog

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
