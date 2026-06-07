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
| `PROBE_TFTP_PORT` | `69` | TFTP UDP (WRQ-receive for FortiGate config backups). |
| `PROBE_SNMP_TRAP_COMMUNITY` | _(empty)_ | **Required** when traps are enabled — empty is rejected at startup. |

## Feature toggles

All `true` by default. Set to `false` / `0` / `no` to disable.

| Variable | Default | Enables |
|---|---|---|
| `PROBE_SNMP_TRAP_ENABLED` | `true` | SNMP trap receiver. |
| `PROBE_SYSLOG_ENABLED` | `true` | Syslog receiver. |
| `PROBE_SFLOW_ENABLED` | `true` | sFlow receiver. |
| `PROBE_PING_ENABLED` | `true` | ICMP ping collector. |
| `PROBE_TFTP_CONFIG_ENABLED` | `true` | TFTP WRQ-receive (FortiGate config push). |

## Queue + batch sizing

| Variable | Default | Description |
|---|---|---|
| `PROBE_MAX_QUEUE_SIZE` | `10000` | In-memory cap per stream. Beyond this, FIFO eviction to BoltDB. |
| `PROBE_MAX_BATCH_SIZE` | `1000` | Items per HTTP POST. |

The disk-spillover queue's path is wired in `cmd/collector/main.go:138-148`
(`relay.Config.QueueDiskPath`); the current production default leaves it
empty (in-memory only) and the disk persistence activates when the env
var is set. **This is documented in the env-var file but the wiring is
intentionally opt-in** — see `internal/relay/queue/queue.go` for the
queue's `Path` / `Bucket` / `MaxMem` / `MaxBytes` fields.

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

The collector does **not** read the server's env vars. A subset of
server-side `PROBE_*` env vars (different prefix semantics) configure
the in-server probe mode (`cmd/probe/main.go` inside
`xphox2/Firewall-Monitoring`). The two probe implementations share a
`PROBE_*` prefix; the canonical list of variables is whichever repo
hosts the binary you are running.
