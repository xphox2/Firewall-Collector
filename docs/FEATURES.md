# Features

> Server-side features: [xphox2/Firewall-Monitoring/docs/FEATURES.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/FEATURES.md).
> This file is the **probe-side** feature inventory. Every row is verified
> against `internal/` source — if a row says "Stable" the corresponding
> code is in `main`, not in a draft branch.

**Status legend**

- **Stable** — shipping in the current `1.2.x` release, exercised in CI,
  covered by tests.
- **Beta** — shipping but the audit row says "not done" or there's a known
  follow-up. Safe to use, but read the linked caveat.
- **Planned** — a public `AUDIT-NNN` row exists or the CHANGELOG mentions
  it as deferred. Do not depend on it in production.

**Role legend**

- **[Probe]** — the collector does it (this repo).
- **[Server]** — the central server does it ([xphox2/Firewall-Monitoring](https://github.com/xphox2/Firewall-Monitoring)).
- **[Both]** — both sides participate.

## Data ingest

| Feature | Status | Role | First stable |
|---|---|---|---|
| SNMP polling (v1 / v2c / v3, MD5/SHA/SHA2, DES/AES/AES192/256) | Stable | [Probe] | 1.0.0 |
| Per-device vendor OID profile (FortiGate, Palo Alto, SonicWall, pfSense, OPNsense, Firewalla, generic Linux/BSD VPN) | Stable | [Probe] | 1.0.0 |
| SNMP trap receiver (UDP/162, V1 enterprise + V2c specific-trap, community filter) | Stable | [Probe] | 1.0.0 |
| Syslog receiver — TCP + UDP, RFC 5424 + FortiGate hostname/SD device-ID extraction | Stable | [Probe] | 1.0.0 |
| sFlow v5 receiver (UDP/6343, formats 1 and 3, Ethernet + 802.1Q VLAN, IPv4/IPv6 + TCP/UDP) | Stable | [Probe] | 1.0.0 |
| ICMP ping collector (latency + loss, 10-concurrent semaphore) | Stable | [Probe] | 1.0.0 |
| SSH config + telemetry polling (FortiGate: checksum, full config, process top, interface list, sensor list, performance, VPN phase-1/phase-2, HA) | Stable | [Probe] | 1.0.0 |
| TFTP config backup receive (UDP/69, 2 MB cap, panic-recovery) | Stable | [Probe] | 1.0.0 |
| Syslog-triggered debounced config backup (60 s debounce on `logid=0100044546`/`447`) | Stable | [Probe] | 1.2.93 |
| NetFlow v5 / v9 / IPFIX ingest | Planned | [Both] | — |

## Syslog/sFlow/sFlow-NetFlow security hardening

| Feature | Status | Role | Since |
|---|---|---|---|
| Per-source-IP allow-list (TFTP WRQ) | Stable | [Probe] | effective since v1.2.132 (AUDIT-050; controls existed since 1.2.106 but were not wired until v1.2.132) |
| Per-source-IP rate limit (TFTP WRQ, opt-in) | Stable | [Probe] | effective since v1.2.132 (AUDIT-050; controls existed since 1.2.106 but were not wired until v1.2.132) |
| 2 MB hard cap on TFTP transfer | Stable | [Probe] | 1.2.103 |
| TFTP server panic-recovery (handler goroutine) | Stable | [Probe] | 1.2.103 |
| `safego.Go` panic-recovery on all long-lived goroutines | Stable | [Probe] | 1.2.88 (AUDIT-052) |

## Relay (probe → server)

| Feature | Status | Role | Since |
|---|---|---|---|
| Registration + approval handshake | Stable | [Probe] + [Server] | 1.0.0 |
| `schema_version` handshake (HTTP 426 on mismatch) | Stable | [Probe] + [Server] | 1.2.108 / 0.10.382 |
| Re-registration on 401/403/404 (rate-limited, 10-min cooldown after 5 fails) | Stable | [Probe] | 1.0.0 |
| Heartbeat (default 60 s, "offline" on graceful shutdown) | Stable | [Probe] | 1.0.0 |
| Per-stream `SpilloverQueue` — in-memory + BoltDB disk persistence | Stable | [Probe] | 1.2.101 / 1.2.104 (AUDIT-058) |
| Metric spillover queue (primary metrics now disk-durable; survives server outage instead of silent loss) | Stable | [Probe] | 1.2.133 (H9) |
| W3C `traceparent` + `X-Request-ID` injection on relay requests | Stable | [Probe] | 1.2.137 (M10) |
| Bounded batches (`PROBE_MAX_BATCH_SIZE=1000`) | Stable | [Probe] | 1.0.0 |
| Retry with 1 s / 2 s backoff (3 attempts) | Stable | [Probe] | 1.0.0 |
| `X-Probe-Batch-ID` idempotency key | Stable | [Probe] + [Server] | 1.2.97 (AUDIT-042) |
| `SendConfigRevision` retry-with-backoff (config backups are durable) | Stable | [Probe] | 1.2.106 (AUDIT-054 v2) |
| mTLS to central server (PEM cert+key, refuses world-readable keys) | Stable | [Probe] | 1.2.79 (AUDIT-048) |
| HTTP transport tuning (HTTP/2, 200 idle conns, 10 s response-header timeout) | Stable | [Probe] | 1.2.98 (AUDIT-072) |

## Observability

| Feature | Status | Role | Since |
|---|---|---|---|
| `GET /healthz` (always 200 if process is up) | Stable | [Probe] | 1.2.98 (AUDIT-057) |
| `GET /readyz` (200 iff approved + heartbeat-fresh + every listener bound, else 503 with `X-Ready-Reason`) | Stable | [Probe] | 1.2.98 (AUDIT-057) |
| Prometheus `/metrics` (14 collectors with `firewall_collector_` prefix) | Stable | [Probe] | 1.2.98 (AUDIT-057) |
| `firewall_collector_metric_send_failed_total` counter (per-stream relay-send failures) | Stable | [Probe] | 1.2.133 (M12) |
| Structured logging (slog, `text` or `json`) | Stable | [Probe] | 1.2.101 (AUDIT-056) |

## Resiliency

| Feature | Status | Role | Since |
|---|---|---|---|
| Graceful shutdown on SIGINT/SIGTERM (drain poll WGs → listeners → relay → metrics last) | Stable | [Probe] | 1.0.0 |
| On-disk queue survives process restart + server outage | Stable | [Probe] | 1.2.101 / 1.2.104 (AUDIT-058) |
| Per-device circuit breaker (3 consecutive poll fails → back off to every 5th cycle) | Stable | [Probe] | 1.0.0 |
| Per-queue independent locking (no cross-stream contention) | Stable | [Probe] | 1.2.97 (AUDIT-064) |
| Startup diagnostic on first device (`runStartupDiagnostic`) | Stable | [Probe] | 1.0.0 |

## Operator tooling

| Feature | Status | Role | Since |
|---|---|---|---|
| `collector ssh-test` subcommand (`all` / `checksum` / `config` / `process` / `interface` / `sensor` / `license` / `performance` / `vpn` / `ha`, JSON or text) | Stable | [Probe] | 1.2.100 (AUDIT-060) |
| `firewall-collector-diag-backup` binary (end-to-end SSH+TFTP, `VERDICT:` line) | Stable | [Probe] | 1.0.0 |
| `firewall-collector-tftp-test` binary (operator-side TFTP client test) | Stable | [Probe] | 1.0.0 |

## Deployment

| Feature | Status | Role | Since |
|---|---|---|---|
| Multi-stage rootless Docker image (`alpine:3.21`, `nobody:65534`, `cap_drop: ALL`, `cap_add: NET_RAW`) | Stable | [Probe] | 1.2.93 (AUDIT-047) |
| `host` network mode for the listener ports (with extensive inline security comment) | Stable | [Probe] | 1.0.0 |
| Multi-arch container image (`linux/amd64`; arm64 is on the roadmap) | Beta | [Probe] | 1.2.93 |
| Reproducible builds (`-trimpath -buildvcs=false`) | Stable | [Probe] | 1.2.93 |
| Auto-pushed image tags (`:1.2.x` exact, `:1.2` moving, `:stable`, `:latest`) | Stable | [Probe] | 1.2.93 |

## Vendor profiles

The collector ships with a `VendorProfile` registry; the default is
FortiGate. The list is verified in `internal/snmp/vendor_test.go` (the
compile-time `VendorProfile` satisfaction test).

| Vendor | Profile | HA | SD-WAN | Security stats | License | VPN |
|---|---|---|---|---|---|---|
| **fortigate** (default) | full | ✅ | ✅ | ✅ | ✅ | site-to-site + dialup + SSL |
| **paloalto** | full | ✅ | ✅ | ✅ | ✅ | site-to-site + SSL |
| **sonicwall** | full | ✅ | — | — | ✅ | site-to-site |
| **pfsense** | full | ✅ (CARP) | — | — | — | IPsec |
| **opnsense** | full | ✅ (CARP) | — | — | — | IPsec |
| **firewalla** | basic | — | — | — | — | — |
| **linux_vpn** | basic | — | — | — | — | IPsec / WireGuard (generic) |
| **bsd_vpn** | basic | — | — | — | — | IPsec (generic) |

To add a vendor: see [CUSTOM-VENDOR.md](CUSTOM-VENDOR.md).

## Roadmap (deferred from current `1.2.x` series)

These are tracked in `docs/audit-2026-06-23-consolidated.md` (the
current audit) and surfaced here so customers don't plan around vaporware.

| Feature | Tracking | Status |
|---|---|---|
| NetFlow v5/v9/IPFIX ingest | AUDIT-NNN not yet assigned | Planned |
| Multi-arch container image (linux/arm64) | — | Planned |
| Hot-reload of `internal/config` (no restart on env change) | AUDIT-NNN not yet assigned | Planned |
| Server-side mTLS client-cert verification of probes | not in collector; server-side only | [Server] Planned ([CERT-ROTATION.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/CERT-ROTATION.md)) |
| Per-probe mTLS key issuance via `/api/admin/rotate-mtls` | — | [Server] Planned |

## Coverage stats

| Metric | Value | Source |
|---|---|---|
| Go source lines (collector, non-test) | ~7,500 | `find . -name '*.go' ! -name '*_test.go' -exec wc -l {} +` |
| Go source lines (collector, with tests) | ~15,000 | same with `*_test.go` |
| Internal packages | 12 | `internal/{config,relay,relay/queue,observability,syslog,sflow,snmp,ssh,sshtool,tftp,safego,ping}` |
| Binaries built | 3 | `cmd/{collector,diag-backup,tftp-test}` |
| Vendors with full VendorProfile | 3 | fortigate, paloalto, sonicwall |
| Fuzz targets | 3 | `FuzzParseRFC5424`, `FuzzParseSFlowDatagram`, plus the relay round-trips |
