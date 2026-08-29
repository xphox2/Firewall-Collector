# Compatibility (collector ↔ server)

> Canonical table: [xphox2/Firewall-Monitoring/docs/SUPPORT-MATRIX.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/SUPPORT-MATRIX.md).
> This file is a 1-pager so anyone reading the collector's docs in
> isolation can see the version matrix. **The canonical version is the
> server's** — if this file and the server's disagree, the server wins.

## Quick rules

1. The server is **backward-compatible** with any supported collector
   (1.2.78 through the current 1.3.x series).
2. A collector ≥ the server's `schema_version` floor just works.
3. A collector with a `schema_version` outside the server's accepted
   range gets **HTTP 426** on `/api/probes/register` and the probe
   surfaces an actionable error. The probe's on-disk queue is
   preserved — no data loss.
4. Wire format: `internal/relay/relay.go::SchemaVersionMin` / `SchemaVersionMax`
   on both repos. They **MUST** stay in lockstep. The current value
   is `1-4` on both sides.

## Compatibility table

| Server version | Accepts collectors | Notes |
|---|---|---|
| **0.11.x** (current master) | all 1.2.x and 1.3.x | Server-side `schema_version` validation introduced in 0.10.382; unchanged since. |
| 0.10.382 | 1.2.108+ | `schema_version` field is required starting here; absent field → 1 (back-compat). |
| 0.10.380 and earlier | all 1.2.x | Pre-handshake. The probe's `schema_version` field is ignored. |

| Collector version | Talks to server | Notes |
|---|---|---|
| **1.3.15+** (current, **schema v5**) | 0.11.94+ for L2 topology; any 0.11.x otherwise | Negotiates **schema v5** — L2 topology snapshots for the port-to-port connection map: `POST /probes/:id/topology-entries` (ARP + MAC-table rows) and `POST /probes/:id/topology-neighbors` (LLDP/CDP), collected every 5th SNMP cycle. Both sends are gated on the negotiated schema ≥ 5, so against a ≤ 0.11.93 server nothing changes. Snapshots are never spooled: a failed send is dropped and the next cycle resends the complete state (the server REPLACES a device's rows per batch — replaying an old snapshot would revert newer state). |
| 1.3.14 (**schema v4**) | 0.11.75+ for the command channel; any 0.11.x otherwise | Negotiates **schema v4** — the first server→collector COMMAND CHANNEL: the heartbeat response may carry `pending_commands`, which the collector executes (only the `noop` type so far) and acknowledges via `POST /api/probes/:id/command-result`, idempotent by `command_id`. Both directions are gated on the negotiated schema ≥ 4, so against a ≤ 0.11.74 server nothing changes (no parsing, no result POSTs, no 404 churn). Command payloads may later carry credentials — run the relay over **HTTPS**; payloads are never logged. Deploy the server first; the collector follows at any time. |
| 1.3.10 – 1.3.13 | 0.11.73+ for disk/load; any 0.11.x otherwise | Negotiates **schema v3**. Sends `disk_usage` + `load_average` only when the server negotiates ≥ 3; against an older (v2) server those two sends no-op, everything else works. |
| 1.2.137 – 1.3.9 | 0.10.382+ (recommended), 0.10.380+ (works, field ignored) | Advertises `schema_version` on register (v2). |
| 1.2.78 – 1.2.107 | any 0.10.x | Pre-handshake. Field omitted → server assumes v1. |
| < 1.2.78 | unsupported | Missing disk-spillover (1.2.101) and several other hardening fixes. |

## Upgrading

The server-first order is recommended (server can keep accepting old
probes; new probes can register against a server that's already aware of
the new `schema_version`), but the order is **not** required — the
handshake is symmetric and both directions are backward-compatible.

**Step 1.** Update the server (see [xphox2/Firewall-Monitoring/docs/UPGRADE-2026-06.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/UPGRADE-2026-06.md) for a runbook).

**Step 2.** Update each collector (the container's `stop_grace_period`
matches the drain timeout, so `docker compose pull && up -d` is safe).

**Step 3.** Verify in the admin UI: Probes page should show
`schema_version: 4` for every re-registered probe (server 0.11.75+
persists the negotiated version on the probe row). A lower value is a
mismatch — check the probe's logs and the server's
[MIGRATING.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/MIGRATING.md).
