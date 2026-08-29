# Environment Variables (authoritative reference)

> Server-side env vars: [xphox2/Firewall-Monitoring/config.env.example](https://github.com/xphox2/Firewall-Monitoring/blob/master/config.env.example).
> This file covers the **probe** only. The probe reads env vars exclusively
> (no config file, no CLI flags on the main binary).

The collector's source of truth is `internal/config/config.go`. Every
variable on this page is wired there. If you find a mismatch, the
**source wins** — open a PR against this file.

## Server connection

| Variable | Required | Default | Description |
|---|---|---|---|
| `PROBE_REGISTRATION_KEY` | **Yes** | — | Bearer token from the server's admin UI. Process refuses to start without it. |
| `PROBE_SERVER_URL` | No | `https://stats.technicallabs.org` | Central server base URL. |
| `PROBE_TLS_CERT` | No | — | Path to PEM client cert for mTLS. |
| `PROBE_TLS_KEY` | No | — | Path to PEM client key. Refuses world-readable perms (`0o077` blocked on Unix). |
| `PROBE_CA_CERT` | No | — | Path to PEM CA pool used to verify the server. |
| `PROBE_INSECURE_SKIP_VERIFY` | No | `false` | `true`/`false`/`1`/`yes` to skip TLS verification. **Not for production.** |

## Intervals (seconds)

All intervals are parsed as integers. Zero or non-numeric → default.

| Variable | Default | Description |
|---|---|---|
| `PROBE_HEARTBEAT_INTERVAL` | `60` | Heartbeat to server. |
| `PROBE_SYNC_INTERVAL` | `30` | Data-batch send cadence. |
| `PROBE_POLL_INTERVAL` | `60` | SNMP poll cycle per device. |
| `PROBE_DEVICE_REFRESH_INTERVAL` | `300` | Device-list refresh. |
| `PROBE_PING_INTERVAL` | `60` | ICMP ping cycle. |
| `PROBE_PING_TIMEOUT` | `5` | Per-ping timeout. |
| `PROBE_PING_COUNT` | `4` | Pings per device per cycle. |

## Listeners

The collector binds to `PROBE_LISTEN_ADDR` (default `0.0.0.0`).

| Variable | Default | Description |
|---|---|---|
| `PROBE_SNMP_TRAP_PORT` | `162` | SNMP trap UDP. |
| `PROBE_SYSLOG_PORT` | `514` | Syslog TCP + UDP. |
| `PROBE_SFLOW_PORT` | `6343` | sFlow UDP. |
| `PROBE_NETFLOW_PORT` | `2055` | NetFlow UDP. `0` disables this socket. Version dispatch is content-based, so v5/v9/IPFIX all decode on either flow port. |
| `PROBE_IPFIX_PORT` | `4739` | IPFIX UDP. `0` disables this socket (both ports `0` = receiver skipped with a startup warning). |
| `PROBE_TFTP_PORT` | `69` | TFTP UDP (WRQ-receive for FortiGate config backups). |
| `PROBE_SNMP_TRAP_COMMUNITY` | _(empty)_ | Optional community allowlist filter. When set, only traps carrying this community are accepted; when **empty the collector accepts traps from ANY community** (a startup warning is logged, but it is NOT rejected). Set it to your devices' trap community to restrict the exposed 162/udp listener. |

## Feature toggles

All `true` by default. Set to `false` / `0` / `no` to disable.

| Variable | Default | Enables |
|---|---|---|
| `PROBE_SNMP_TRAP_ENABLED` | `true` | SNMP trap receiver. |
| `PROBE_SYSLOG_ENABLED` | `true` | Syslog receiver. |
| `PROBE_SFLOW_ENABLED` | `true` | sFlow receiver. |
| `PROBE_NETFLOW_ENABLED` | `true` | NetFlow v5/v9 + IPFIX receiver (both flow ports). |
| `PROBE_PING_ENABLED` | `true` | ICMP ping collector. |
| `PROBE_TFTP_CONFIG_ENABLED` | `true` | TFTP WRQ-receive (FortiGate config push). |

## Source-attribution binding

| Variable | Default | Description |
|---|---|---|
| `PROBE_STRICT_SOURCE_BINDING` | `true` | Binds an ingested sample/upload's CLAIMED device identity to the real UDP sender for the two paths that attribute by a body/filename field instead of the packet source: sFlow (attributes by the in-band `agent_address`) and TFTP config backup (attributes by the WRQ filename). When the UDP source resolves to a **known** monitored device that **disagrees** with the claimed device — the detectable intra-fleet forgery, e.g. an allowlisted device X submitting telemetry or a config revision in device Y's name — the sample/upload is **rejected** (`true`, STRICT) or logged-and-attributed-by-claim (`false`, warn-only). When the UDP source is **unresolvable** — a multi-homed FortiGate whose sFlow egress IP isn't cached, or a NAT'd/jump-host TFTP upload — the binding can't be enforced, so **both** modes warn and fall back to the claimed identity rather than drop a legitimate device. A source that agrees with the claim is accepted silently. Accepts the case-insensitive `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off` forms. Rejects are counted on `firewall_collector_source_binding_rejects_total` (labeled by path `sflow`/`tftp`). This layers on top of, and does not replace, the fleet source-IP allowlist. |

## UDP rate limiting

Per-source-IP token-bucket limiting on the sFlow/syslog/trap receivers, so a
flooding or spoofed source can't starve the parse loop or the spillover queue.
Each firewall is a distinct source IP with its own bucket; limits are per
listener (syslog is high — FortiGate traffic logging is chatty). On by default
with generous headroom; drops increment `firewall_collector_rate_limited_drops_total{listener}`.

| Variable | Default | Description |
|---|---|---|
| `PROBE_RATE_LIMIT_ENABLED` | `true` | Master switch for UDP rate limiting. |
| `PROBE_RATE_LIMIT_MAX_SOURCES` | `8192` | Max distinct source IPs tracked per listener (memory bound). |
| `PROBE_SFLOW_RATE_LIMIT_PPS` | `1000` | sFlow datagrams/sec per source. |
| `PROBE_SFLOW_RATE_LIMIT_GLOBAL_PPS` | `30000` | sFlow aggregate ceiling across all sources. |
| `PROBE_NETFLOW_RATE_LIMIT_PPS` | `1000` | NetFlow/IPFIX datagrams/sec per source (each datagram carries up to ~30 records). Shared by both flow ports. |
| `PROBE_NETFLOW_RATE_LIMIT_GLOBAL_PPS` | `30000` | NetFlow/IPFIX aggregate ceiling across all sources. |
| `PROBE_SYSLOG_RATE_LIMIT_PPS` | `5000` | Syslog msgs/sec per source (high — traffic logs). |
| `PROBE_SYSLOG_RATE_LIMIT_GLOBAL_PPS` | `100000` | Syslog aggregate ceiling. |
| `PROBE_TRAP_RATE_LIMIT_PPS` | `500` | SNMP traps/sec per source. |
| `PROBE_TRAP_RATE_LIMIT_GLOBAL_PPS` | `10000` | SNMP trap aggregate ceiling. |

## UDP receive scaling

| Variable | Default | Description |
|---|---|---|
| `PROBE_UDP_WORKERS` | `1` | Parallel SO_REUSEPORT receive sockets/goroutines per high-volume UDP listener (sFlow, syslog). Set >1 to spread receive across cores when CPU-bound on receive (Linux only; clamped to 1 elsewhere). |

## Dual-export flow dedup

When a device exports **both** sFlow and NetFlow/IPFIX for the same
interfaces (FortiGate/VyOS can), every byte would be double-counted in
server-side aggregates. The collector applies a per-exporter source
preference with automatic failover (5-minute activity window); sFlow
**counter** samples always pass — they are interface counters, not flow
records. Suppressed samples increment
`firewall_collector_flowdedup_suppressed_total{family}`.

| Variable | Default | Description |
|---|---|---|
| `PROBE_FLOW_DEDUP` | `prefer-netflow` | `prefer-netflow` (drop sFlow flow samples while NetFlow is live from that exporter) / `prefer-sflow` (the mirror image) / `off` (relay both — the server flags mixed-source devices). Unknown values behave as `off`. |

## NetFlow sampling overrides

NetFlow/IPFIX carries a sampling rate the exporter self-reports; the collector
scales each flow's byte/packet counts back up by it. Some exporters report the
wrong rate — the server's SUPPORT-MATRIX documents MikroTik ROS 6.49.x
byte-swapping the sampling interval — which silently mis-scales every flow from
that device. This variable is the operator escape hatch: a per-exporter-IP
pin that overrides whatever the exporter reports. It is step 1 (highest
priority) of the sampler precedence chain in `cmd/collector/main.go`, applied
before the NetFlow receiver starts, so the very first record resolves against
the pinned rate. Overrides are configuration, not learned state — they are
never persisted to the template cache and are re-applied on every start.

| Variable | Default | Description |
|---|---|---|
| `PROBE_NETFLOW_SAMPLING_OVERRIDES` | _(empty)_ | Comma-separated `exporterIP=rate` pairs (e.g. `192.0.2.1=1000,2001:db8::1=512`). IPs are normalized through `net.ParseIP().String()` to match the receiver's exporter keys (IPv4 and IPv6 both allowed); each rate must be an integer `1..4294967295`. Malformed entries are logged and skipped — one typo neither crashes the collector nor discards the valid entries. Empty (the default) = no overrides; every exporter's self-reported rate is trusted. |

## Queue + batch sizing

| Variable | Default | Description |
|---|---|---|
| `PROBE_MAX_QUEUE_SIZE` | `10000` | In-memory cap per stream. Beyond this, FIFO eviction to BoltDB. |
| `PROBE_MAX_BATCH_SIZE` | `1000` | Items per HTTP POST. |
| `PROBE_QUEUE_DISK_PATH` | `` (empty); **`/queue` in the shipped Docker image/compose** | Directory for the disk-spillover queues. Empty = in-memory only (telemetry is dropped, not buffered, while the server is unreachable). The Docker image sets `/queue` by default, so container deploys DO spill to disk unless overridden. Set to a writable persistent dir to survive outages/restarts. |

The disk-spillover queue's path is wired in `cmd/collector/main.go:187`
(`relay.Config.QueueDiskPath` ← `PROBE_QUEUE_DISK_PATH`). The *code*
default is empty (in-memory only), but the **shipped Docker image and
compose set `PROBE_QUEUE_DISK_PATH=/queue`**, so container deployments
spill to disk out of the box; only a non-container run with the var
unset is in-memory-only. See `internal/relay/queue/queue.go` for the
queue's `Path` / `Bucket` / `MaxMem` / `MaxBytes` fields.

The NetFlow receiver also persists its v9/IPFIX template + sampler caches
to `<PROBE_QUEUE_DISK_PATH>/netflow-templates.json` (saved on shutdown and
every 5 minutes). With no disk path there is no persistence — a restart
re-learns templates from the wire, a blind window of up to one exporter
template-refresh cycle (~30 min).

## Observability

| Variable | Default | Description |
|---|---|---|
| `PROBE_METRICS_ADDR` | `127.0.0.1:9090` | Bind for `/healthz`, `/readyz`, `/metrics`. |

## Logging

| Variable | Default | Description |
|---|---|---|
| `PROBE_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `warning` / `error`. Unknown → `info` + one-shot warning. |
| `PROBE_LOG_FORMAT` | `text` | `text` / `json`. Unknown → `text`. |

## Operator subcommands

| Variable | Default | Description |
|---|---|---|
| `PROBE_TEST_PASSWORD` | — | SSH password for the `collector ssh-test` subcommand. Read by `internal/sshtool/sshtool.go`. |

## Sibling-repo env vars

The collector does **not** read the server's env vars, and the server no
longer has a bundled probe. The obsolete `cmd/probe/` was removed from
`xphox2/Firewall-Monitoring` (server commit `493ef87`); the probe is now
**only** this repo. The server's own binaries live under `cmd/api`,
`cmd/configcheck`, `cmd/poller`, and `cmd/trap-receiver`, and their env
vars are documented in the server repo's
[`config.env.example`](https://github.com/xphox2/Firewall-Monitoring/blob/master/config.env.example).
Every `PROBE_*` variable is read by this collector; the canonical source
of truth is `internal/config/config.go` in this repo.
