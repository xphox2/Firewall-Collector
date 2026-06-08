# Firewall Collector

> **Lightweight probe for collecting firewall data at remote sites and
> relaying to the central [Firewall-Monitoring](https://github.com/xphox2/Firewall-Monitoring)
> server.**
>
> This repo builds a single Go binary (`firewall-collector`) plus two
> operator-invoked diagnostic tools. It is the **probe** half of the
> project; the **server** half is its own repo, with its own README,
> admin UI, and runbook.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/xphox2/Firewall-Collector/actions)
[![Version](https://img.shields.io/badge/version-1.2.108-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.25.0+-00ADD8)](go.mod)

## Sibling project

This is **one of two** repositories. The other is
[Firewall-Monitoring](https://github.com/xphox2/Firewall-Monitoring) — the
central server that stores the data, renders the dashboards, runs the
alert engine, and exposes the admin UI. You need both: this repo
**deploys at the remote site**, the other repo **runs at HQ**.

| | Probe (this repo) | Server (sibling) |
|---|---|---|
| Role | Listen at the edge, relay to HQ | Store, alert, visualize, configure |
| Binaries | `firewall-collector`, `firewall-collector-diag-backup`, `firewall-collector-tftp-test` | `fwmon-api`, `fwmon-poller`, `fwmon-trap`, `fwmon-probe` |
| Listens on | 162/udp, 514/tcp+udp, 6343/udp, 69/udp | 8080/tcp, 162/udp, 514/udp+tcp, 6343/udp, 8089/tcp |
| Talks to | The server (HTTPS, mTLS) | The probe (HTTPS), the device (SNMP/SSH/TFTP) |
| Docs | this README + [docs/](docs/STRUCTURE.md) | [README](https://github.com/xphox2/Firewall-Monitoring/blob/master/README.md) + [docs/](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/STRUCTURE.md) |

## Features

Every feature below is shipped in the current `1.2.x` release. **Role
tag** — `[Probe]` runs on the collector (this repo), `[Server]` runs on
the central server, `[Both]` requires both sides. **Status** — Stable
shipping, Beta shipping but with a known follow-up, Planned a public
AUDIT-NNN row exists.

### Data ingest

- **[Probe] SNMP polling** (v1/v2c/v3, MD5/SHA/SHA2, DES/AES/AES192/256)
  on `PROBE_POLL_INTERVAL` (default 60s). Per-device `VendorProfile`
  registry with FortiGate, Palo Alto, SonicWall, pfSense, OPNsense,
  Firewalla, generic Linux/BSD VPN.
- **[Probe] SNMP trap receiver** (UDP/162). V1 enterprise + V2c
  specific-trap OID classification with severity. Community string
  enforcement, goroutine-per-trap, panic-recovery.
- **[Probe] Syslog receiver** (TCP + UDP, 514). RFC 5424 parser with 6
  timestamp formats, FortiGate hostname + structured-data device-ID
  extraction.
- **[Probe] sFlow v5 receiver** (UDP/6343). Ethernet + 802.1Q VLAN,
  IPv4/IPv6 + TCP/UDP. `FuzzParseSFlowDatagram` target.
- **[Probe] ICMP ping collector** (latency + loss, 10-concurrent
  semaphore, requires `NET_RAW`).
- **[Probe] SSH config + telemetry polling** (FortiGate). Password or
  public-key auth. Pulls `diagnose sys csum`, `show full-configuration`,
  `diagnose sys top`, `diagnose netlink interface list`, `execute
  sensor list`, `get system performance status`, `show vpn ipsec
  phase1/2-interface`, `get system ha status`.
- **[Probe] TFTP config backup receive** (UDP/69). 2 MB hard cap,
  per-source-IP allowlist + rate limit, panic-recovery. Detects masked
  passwords (FortiOS 7.2.1+).
- **[Probe] Syslog-triggered debounced config backup** (60s debounce on
  `logid=0100044546`/`447`).
- **[Planned] NetFlow v5/v9/IPFIX ingest** — tracked but not yet
  scheduled.

### Relay (probe → server)

- **[Both] Registration + approval handshake** — `POST /api/probes/register`.
- **[Both] `schema_version` handshake** — added 1.2.108 / 0.10.382. The
  probe advertises its wire-format version; the server replies 426 on
  out-of-range. No data loss on a 426 — on-disk queue is preserved.
  See [MIGRATING.md on the server](https://github.com/xphox2/Firewall-Monitoring/blob/master/MIGRATING.md).
- **[Probe] Heartbeat** every `PROBE_HEARTBEAT_INTERVAL` (default 60s);
  "offline" status on graceful shutdown.
- **[Probe] Per-stream `SpilloverQueue`** — in-memory + BoltDB disk
  persistence. Survives process restart and server outage.
- **[Both] `X-Probe-Batch-ID` idempotency key** — server-side dedup.
- **[Probe] Retry with 1s/2s backoff** (3 attempts), re-registration on
  401/403/404, drop-on-400.
- **[Probe] mTLS to central server** — refuses world-readable private
  keys.

### Observability

- **[Probe] `GET /healthz`** — always 200 if the process is up.
- **[Probe] `GET /readyz`** — 200 iff approved + heartbeat-fresh +
  every listener bound, else 503 with `X-Ready-Reason`.
- **[Probe] Prometheus `/metrics`** — 13 collectors with the
  `firewall_collector_` prefix.
- **[Probe] Structured logging** (slog) — `text` or `json`.

### Resiliency

- **[Probe] Graceful shutdown on SIGINT/SIGTERM** — drain poll WGs →
  stop listeners → flush queues → final heartbeat → close BoltDB →
  stop observability last.
- **[Probe] Per-device circuit breaker** — 3 consecutive fails → back
  off to every 5th poll cycle.
- **[Probe] Per-queue independent locking** — no cross-stream
  contention.
- **[Probe] `safego.Go` panic-recovery** on every long-lived goroutine.

### Operator tooling

- **[Probe] `firewall-collector ssh-test`** subcommand — 10 checks
  (`all` / `checksum` / `config` / `process` / `interface` / `sensor` /
  `license` / `performance` / `vpn` / `ha`), JSON or text.
- **[Probe] `firewall-collector-diag-backup`** — end-to-end SSH+TFTP
  with a `VERDICT:` line.
- **[Probe] `firewall-collector-tftp-test`** — standalone TFTP client
  test.

### Deployment

- **[Probe] Multi-stage rootless Docker image** (`alpine:3.19`,
  `nobody:65534`, `cap_drop: ALL`, `cap_add: NET_RAW`).
- **[Probe] Auto-pushed image tags** (`:1.2.x` exact, `:1.2` moving,
  `:stable`, `:latest`).

The full **website-ready** feature inventory (with status, role, and
"since" version for every row) lives in [docs/FEATURES.md](docs/FEATURES.md).

## Architecture

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
                       │  (schema_version handshake, mTLS)        │
                       │                                          │
                       │  internal/observability ◀── /healthz     │
                       │                          ◀── /readyz      │
                       │                          ◀── /metrics    │
                       └──────────────────────────────────────────┘
```

The **full** architecture (with sequence diagrams for probe
registration, poll cycle, alert firing, and the combined probe+server
data flow) is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (collector view) and
[server's architecture.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/architecture.md) (combined view).

## Quick Start

### Prerequisites

- A **central server** running [Firewall-Monitoring](https://github.com/xphox2/Firewall-Monitoring)
  — v0.10.382 or later (the `schema_version` handshake was added there).
  Pre-0.10.382 servers still work; they ignore the handshake field.
- A **registration key** generated in the server's admin UI
  (Admin → Probes → Generate key).
- The collector listens on UDP `162`, UDP/TCP `514`, UDP `6343`, UDP
  `69`. If you use the default `network_mode: host`, those ports are
  bound on the host. If you switch to bridged mode, you publish them.
- The collector needs **outbound HTTPS** to the server. No inbound
  ports are required at the site.

### 1. Generate a registration key (in the server admin UI)

Admin → Probes → Generate key. Copy it.

### 2. Deploy the collector

**Docker (recommended):**

```bash
docker run -d \
  --name firewall-collector \
  --restart unless-stopped \
  --network host \
  -e PROBE_REGISTRATION_KEY=your-registration-key \
  -e PROBE_SERVER_URL=https://your-server.example.com \
  -e PROBE_SNMP_TRAP_COMMUNITY=your-community-string \
  xphox/firewall-collector:1.2
```

The pinned `:1.2` tag tracks the latest 1.2.x patch automatically. For
reproducible builds, pin to `:1.2.108`.

**Docker Compose (copy to `docker-compose.yml`):**

```yaml
services:
  firewall-collector:
    image: xphox/firewall-collector:1.2
    container_name: firewall-collector
    restart: unless-stopped
    network_mode: host
    environment:
      PROBE_REGISTRATION_KEY: "your-registration-key"
      PROBE_SERVER_URL: "https://your-server.example.com"
      PROBE_SNMP_TRAP_COMMUNITY: "your-community-string"
      # Optional:
      # PROBE_TLS_CERT: /etc/collector/tls.crt
      # PROBE_TLS_KEY:  /etc/collector/tls.key
      # PROBE_CA_CERT:  /etc/collector/ca.crt
      # PROBE_LOG_LEVEL: info
      # PROBE_LOG_FORMAT: json
    # volumes:
    #   - ./tls:/etc/collector:ro
```

**Binary (Linux amd64):**

```bash
PROBE_REGISTRATION_KEY=your-registration-key \
PROBE_SNMP_TRAP_COMMUNITY=your-community-string \
  ./firewall-collector
```

### 3. Approve the probe (in the server admin UI)

The probe will appear under **Pending Approvals** within ~10s. Approve
it, then edit it to assign it to a site. The server will push the
device list to the probe; the probe starts polling immediately.

### 4. Verify

On the probe host:

```bash
curl -sf http://127.0.0.1:9090/readyz   # expect: 200 (or 503 with X-Ready-Reason)
curl -sf http://127.0.0.1:9090/metrics | head  # Prometheus exposition
```

On the server: the probe's row should show `last_seen` updating and
`last_data_received` ticking.

## Configuration

The probe is configured exclusively by **environment variables** — no
config file, no CLI flags on the main binary. The full authoritative
reference is [docs/ENV-VARS.md](docs/ENV-VARS.md). Server-side env vars
are in the server's
[config.env.example](https://github.com/xphox2/Firewall-Monitoring/blob/master/config.env.example).

The most-frequently-set variables:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PROBE_REGISTRATION_KEY` | **Yes** | — | Bearer token from the server's admin UI |
| `PROBE_SERVER_URL` | No | `https://stats.technicallabs.org` | Central server base URL |
| `PROBE_SNMP_TRAP_COMMUNITY` | Yes (if traps enabled) | — | SNMP trap community filter; empty rejected at startup |
| `PROBE_TLS_CERT` / `PROBE_TLS_KEY` / `PROBE_CA_CERT` | No | — | mTLS to the server |
| `PROBE_HEARTBEAT_INTERVAL` | No | `60` | Heartbeat period (s) |
| `PROBE_SYNC_INTERVAL` | No | `30` | Data-batch send period (s) |
| `PROBE_POLL_INTERVAL` | No | `60` | SNMP poll cycle (s) |
| `PROBE_LISTEN_ADDR` | No | `0.0.0.0` | Bind for all listeners |
| `PROBE_METRICS_ADDR` | No | `127.0.0.1:9090` | Bind for `/healthz` `/readyz` `/metrics` |
| `PROBE_LOG_LEVEL` / `PROBE_LOG_FORMAT` | No | `info` / `text` | `slog` config |
| `PROBE_SNMP_TRAP_ENABLED` / `PROBE_SYSLOG_ENABLED` / `PROBE_SFLOW_ENABLED` / `PROBE_PING_ENABLED` / `PROBE_TFTP_CONFIG_ENABLED` | No | `true` | Feature toggles |

## Upgrading

The collector's `docker-compose.yml` and Quick Start example pin to the
moving `1.2` major.minor tag rather than `:latest`, so you always know
what you have running and can roll back predictably.

| Tag | Stability | Use it for |
|---|---|---|
| `:1.2.108` | exact version | production — pinned, reproducible builds |
| `:1.2` | moving major.minor | gets every 1.2.x patch automatically (default in `docker-compose.yml`) |
| `:stable` | tracks the default branch | the most recent merge to `master` that passed CI |
| `:latest` | tracks the default branch | alias for `:stable`; exists for tooling compatibility |

```bash
docker compose pull && docker compose up -d
```

Roll back:

```bash
docker compose pull xphox/firewall-collector:1.2.107
docker compose up -d
```

The container's `STOPSIGNAL` is SIGTERM and the compose
`stop_grace_period` is 30s, matching the collector's drain timeout —
no in-flight data is dropped on upgrade.

## Compatibility

The collector and the server are deployed and upgraded independently.
The `schema_version` handshake (1.2.108 / 0.10.382) makes the upgrade
**order-independent** — both directions are backward-compatible. The
canonical compatibility table is the server's
[SUPPORT-MATRIX.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/SUPPORT-MATRIX.md);
the 1-pager version is [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

| Collector | Talks to server | Notes |
|---|---|---|
| **1.2.108+** (current) | 0.10.382+ (recommended), 0.10.380+ (works, field ignored) | Advertises `schema_version` on register |
| 1.2.78 – 1.2.107 | any 0.10.x | Pre-handshake; field omitted → server assumes v1 |
| < 1.2.78 | unsupported | Missing disk-spillover and several hardening fixes |

## Operations

The collector is intended to be a **set-and-forget** process. Day-2
operations are limited to:

- **Rolling restart** (image upgrade) — covered above.
- **Re-issuing the registration key** — generate a new one in the
  server admin UI, then `docker compose up -d` with the new env var.
  The probe re-registers on the next 60-second heartbeat.
- **Replacing the TLS cert** — drop the new PEM files into the
  bind-mounted `./tls` directory and `docker compose restart`. The probe
  reloads the cert on restart (no SIGHUP hot-reload in this release).

The server's
[docs/OPERATIONS.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/OPERATIONS.md)
covers the **central** side (admin password reset, JWT rotation,
backup/restore, scale, DR); the probe side is intentionally simpler.

## Security

- The collector binds to `PROBE_LISTEN_ADDR` (default `0.0.0.0`) on
  well-known ports. In production, **firewall those ports at the host**
  (or place the collector on a dedicated management VLAN).
- mTLS to the central server is supported (`PROBE_TLS_CERT` /
  `PROBE_TLS_KEY` / `PROBE_CA_CERT`). The collector refuses
  world/group-readable private keys.
- `PROBE_INSECURE_SKIP_VERIFY=true` is for testing only and triggers
  a loud startup warning.
- TFTP WRQ has a 2 MB hard cap and a per-source-IP allowlist +
  rate-limit (opt-in via env vars in the server's device record).
- The container runs as `nobody:65534` with `cap_drop: ALL` and only
  `cap_add: NET_RAW` (required for the `ping` fork-exec).
- See [SECURITY.md](SECURITY.md) for the supported-versions table,
  threat model, and the 90-day coordinated-disclosure policy.

## API / Wire format

The collector does **not** expose an HTTP API. The wire format is
**inbound UDP** (syslog, SNMP trap, sFlow, TFTP) and **outbound HTTPS
to the server** (the relay). The server's admin API is documented in
the [server's README](https://github.com/xphox2/Firewall-Monitoring/blob/master/README.md#api-endpoints).

The relay batch shape (`internal/relay/relay.go`) is a JSON envelope
with per-stream arrays (e.g. `{"system_statuses": [...], "interface_stats": [...]}`).
The server-side decoder is the source of truth for the field names.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the dev environment, the QA
gate (`go vet` + `go test -race` + `staticcheck` + `govulncheck`), and
the four contribution buckets (new vendor profile, new data source,
bug fix, docs/CI). All doc filenames are **UPPERCASE** (standardized
in 1.2.107).

## License

MIT — see [LICENSE](LICENSE).
