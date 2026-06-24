# Compatibility (collector ↔ server)

> Canonical table: [xphox2/Firewall-Monitoring/docs/SUPPORT-MATRIX.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/SUPPORT-MATRIX.md).
> This file is a 1-pager so anyone reading the collector's docs in
> isolation can see the version matrix. **The canonical version is the
> server's** — if this file and the server's disagree, the server wins.

## Quick rules

1. The server is **backward-compatible** with any 1.2.x collector.
2. A collector ≥ the server's `schema_version` floor just works.
3. A collector with a `schema_version` outside the server's accepted
   range gets **HTTP 426** on `/api/probes/register` and the probe
   surfaces an actionable error. The probe's on-disk queue is
   preserved — no data loss.
4. Wire format: `internal/relay/relay.go::SchemaVersionMin` / `SchemaVersionMax`
   on both repos. They **MUST** stay in lockstep. The current value
   is `1-1` on both sides.

## Compatibility table

| Server version | Accepts collectors | Notes |
|---|---|---|
| **0.10.487+** (current master) | all 1.2.x | Server-side `schema_version` validation introduced in 0.10.382. |
| 0.10.382 | 1.2.108+ | `schema_version` field is required starting here; absent field → 1 (back-compat). |
| 0.10.380 and earlier | all 1.2.x | Pre-handshake. The probe's `schema_version` field is ignored. |

| Collector version | Talks to server | Notes |
|---|---|---|
| **1.2.137+** (current) | 0.10.382+ (recommended), 0.10.380+ (works, field ignored) | Advertises `schema_version` on register. |
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
`schema_version: 1` for every registered probe. Anything else is a
mismatch — check the probe's logs and the server's
[MIGRATING.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/MIGRATING.md).
