# Architecture (collector side)

> Canonical combined architecture: [xphox2/Firewall-Monitoring/docs/architecture.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/architecture.md).
> That doc has the full data-flow and sequence diagrams (probe registration, poll cycle, alert firing).
> This file covers the collector's internal structure only.

## Process model

The collector (`cmd/collector/main.go`) is a single Go binary that runs
as a long-lived process. On startup it:

1. Parses env vars (`internal/config/config.go`).
2. Registers with the central server (`POST /api/probes/register`).
3. Fetches the device list (`GET /api/probes/:id/devices`).
4. Starts the parallel goroutines below.
5. Sends heartbeats and drains the on-disk queue in the background.

```
                       ┌──────────────────────────────────────────┐
                       │              cmd/collector               │
                       │           (single Go process)            │
                       │                                          │
   SNMP trap ───162───▶│  internal/snmp/trap.go  ──┐              │
   syslog    ───514───▶│  internal/syslog         ─┤              │
   sFlow     ──6343───▶│  internal/sflow          ─┤              │
   ICMP      ───────▶  │  internal/ping           ─┤              │
   SSH poll  ────────▶  │  internal/ssh            ─┼─▶ Spillover  │
   TFTP recv ───69────▶  │  internal/tftp           ─┘  Queue      │
                       │                              (BoltDB)    │
                       │  internal/relay  ──────HTTP/HTTPS──────▶ │──▶ Firewall-Monitoring
                       │  (schema_version  handshake, mTLS)        │
                       │                                          │
                       │  internal/observability ◀── /healthz     │
                       │                          ◀── /readyz      │
                       │                          ◀── /metrics    │
                       └──────────────────────────────────────────┘
```

## Package map

| Package | Purpose |
|---|---|
| `cmd/collector` | Main process. Wires receivers, pollers, the relay, and graceful shutdown. Dispatches the `ssh-test` subcommand before anything else (so a typo doesn't accidentally launch the collector). |
| `cmd/diag-backup` | Single-shot diagnostic binary: SSH + TFTP round-trip with a `VERDICT:` line. Not on by default — operator-invoked. |
| `cmd/tftp-test` | Standalone TFTP client test. Operator-invoked. |
| `internal/config` | Loads and validates env vars. Refuses to start without `PROBE_REGISTRATION_KEY`. |
| `internal/relay` | The HTTP client to the server: `Register`, `Heartbeat`, `FetchDevicesAndConfig`, `SendSystemStatus`, `SendInterfaceStats`, `SendTrapEvents`, `SendFlowSamples`, `SendSyslogMessages`, `SendPingResults`, `SendConfigRevision`, `SendHardwareSensors`, `SendLicenseInfo`, `SendVPNStatus`, `SendHAStatus`, `SendSDWANHealth`, `SendSecurityStats`, `SendProcessSnapshot`, `SendInterfaceErrorSnapshots`, `SendSensorDetails`, `SendLicenseDetails`. Owns the mTLS client config. Implements the `schema_version` handshake (1.2.108+). |
| `internal/relay/queue` | `SpilloverQueue` — in-memory slice + BoltDB on disk. FIFO eviction. Restart-survivable. Used by all six streams/queues (the five event streams plus the metric queue added in 1.2.133). |
| `internal/snmp` | `SNMPClient` (v1/v2c/v3), `TrapReceiver`, the `VendorProfile` registry with 8 in-tree profiles. |
| `internal/syslog` | RFC 5424 parser + FortiGate hostname/SD device-ID extraction. |
| `internal/sflow` | sFlow v5 datagram parser. |
| `internal/ssh` | `FortiGateClient` (password or public key, optional PTY for TFTP-backup channels). |
| `internal/sshtool` | The `ssh-test` subcommand. Wraps `internal/ssh` (no duplicated code). |
| `internal/tftp` | RFC 1350 TFTP server. AUDIT-050: 2 MB cap, per-source-IP allowlist + rate limit, panic-recovery. |
| `internal/ping` | `PingCollector` — fork-execs `/bin/ping`. Requires `NET_RAW`. |
| `internal/observability` | `/healthz`, `/readyz`, `/metrics` HTTP server. The readyz gate is approval + heartbeat-fresh + listeners-bound. |
| `internal/safego` | `safego.Go(name, fn)` and `safego.AfterFunc(d, name, fn)` — wrap long-lived goroutines so a panic logs and continues. |

## Lifecycle (one poll cycle)

1. `relay.FetchDevicesAndConfig` returns the device list + per-probe
   `tftp_server_ip` (server-pushed; see `relay.RegisterResponse`).
2. `runPollCycle` fans out per-device work (semaphore-bounded).
3. Per device, in parallel:
   - `snmp.SNMPClient.GetSystemStatus`, `GetInterfaceStats`, `GetInterfaceAddresses`, `GetHardwareSensors`, `GetProcessorStats`, plus vendor-specific data (HA, SD-WAN, security stats, license info, VPN phase-1/phase-2).
   - `ssh.FortiGateClient.GetConfigChecksum`, `GetConfig`, plus any
     enabled telemetry commands (process top, interface list, sensor
     list, performance status, HA status, VPN status).
   - `ping.PingCollector.UpdateDevices` adds the device to the next
     ping tick (4 pings at 1-second intervals, 5-second timeout).
4. All `Send*` methods enqueue their marshaled JSON onto the
   `SpilloverQueue` for that stream.
5. `relay.DataSendLoop` drains the queues in bounded chunks and POSTs
   them. The 6 streams/queues are independent (own mutex, own queue), so a
   flood in one doesn't stall the others. Each relay request carries a
   W3C `traceparent` + `X-Request-ID` header (1.2.137) for cross-repo
   trace correlation on the server.
6. On a 401/403/404 the relay triggers a re-registration. The 4xx
   codes (400/401/403/404) drop or re-register, the 5xx codes retry
   with 1s/2s backoff (3 attempts). `X-Probe-Batch-ID` makes the POSTs
   idempotent on the server.

## Schema-version handshake

On register the relay sends `schema_version: SchemaVersionMax` (currently
`1`). The server validates and replies with one of:

- **200 + echo**: happy path. The probe logs the version the server
  selected.
- **426 (Upgrade Required)**: the server's `X-Probe-Schema-Version-Supported`
  header names the range it accepts. The probe surfaces an actionable
  error pointing at `MIGRATING.md` and **does not lose on-disk queue data**.
- **Absent field (old server)**: defaults to v1, fully backward-compatible.

The full contract, including the server's response shape, is documented in
[xphox2/Firewall-Monitoring/MIGRATING.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/MIGRATING.md).

## Shutdown

On SIGINT/SIGTERM:

1. Stop accepting new connections (drain poll WGs, then stop listeners).
2. Flush the SpilloverQueues to the server in bounded chunks.
3. Send a final "offline" heartbeat.
4. Close the BoltDB files.
5. Stop the observability server last (so `/readyz` flips to 503 during
   the drain and a load balancer can de-list the probe).

The container's `STOPSIGNAL` is SIGTERM and the compose `stop_grace_period`
is 30s, matching `shutdownDrainTimeout`.
