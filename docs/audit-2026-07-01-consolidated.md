# Internal Audit — 2026-07-01 (Consolidated, Dual-Repo)

**Scope:** Both repositories of the firewall-monitoring product, focused on the code shipped since the 2026-06-23 audit (that audit is fully resolved — see `audit-2026-06-23-consolidated.md`).
- **Server** — `Firewall-Mon` (Go module `firewall-mon`, audited at v0.10.527): sFlow analytics R1–R6 (classification, GeoIP/ASN, detection engine, threat-intel feeds, BGP enrichment, interface counter samples schema v2, SSE real-time NOC), Console design language + 3-mode charts, probe register-by-key + stale sweep, ingestion batch rewrites.
- **Collector** — `Firewall-Collector` (Go module `firewall-collector`, audited at v1.2.152): per-source + per-listener UDP rate limiting, SO_REUSEPORT workers, BGP `extended_gateway` parsing, counter samples, BoltDB NoSync spillover queue, registration retry.

Multi-agent consensus report: 15 finder dimensions + 8 critic-directed follow-up dimensions across both repos; every finding survived adversarial refutation-based verification (HIGH findings required two independent verifier lenses — code correctness and impact/reachability). 64 raw-deduped candidates were refuted or merged down to the set below. A collector-scoped copy lives at `Firewall-Collector/docs/audit-2026-07-01-consolidated.md`.

---

## Executive Summary

**64 confirmed findings** (server 52, collector 12). The new sFlow analytics plane works, but the risk concentrates in four clusters:

1. **Rollup/aggregation data integrity** — every paginated GROUP BY aggregation (flow rollups, rollup promotion, syslog summaries) pages with LIMIT/OFFSET and no ORDER BY, then blanket-deletes its source rows: above one page of groups, data is silently double-counted or destroyed, unrecoverably. The syslog 1h→1d promote step re-introduces the exact bug (M2 of 2026-06-23) that was fixed one function above it.
2. **Silent self-disablement of the monitoring plane** — the poller's advisory work-lock leaks across pooled connections and makes a *single* poller skip its own ticks; a swallowed panic leaves a zombie poller behind green health checks; NOC snapshot errors broadcast all-zero dashboards marked "live"; trap rate-limit drops have no log or metric.
3. **Untrusted-input hardening gaps on the collector** — the per-source limiter's idle eviction can never fire (spoof flood permanently poisons it), TCP syslog bypasses the UDP rate-limit defense entirely, and sFlow sub-record parsers read past their record boundary.
4. **Lifecycle/contract drift** — rejected/decommissioned probes can resurrect themselves through register/heartbeat; the v2 schema handshake crash-loops against v1 servers; batch rewrites turned per-row resilience into all-or-nothing 500s that poison the collector's retry queue.

### Counts by severity

| Severity | Server | Collector | Total |
|---|---|---|---|
| High | 8 | 2 | **10** |
| Medium | 24 | 6 | **30** |
| Low | 20 | 4 | **24** |
| **Total** | **52** | **12** | **64** |

---

## HIGH

### H1. Paginated GROUP BY aggregations use LIMIT/OFFSET with no ORDER BY — groups duplicated or lost above one page
> **✅ RESOLVED (v0.10.532)** — all four aggregation loops now share one correctness shape: MAX(id) watermark (immutable source set), deterministic ORDER BY over the full group key, and one transaction wrapping every page insert plus a single watermark-scoped delete. Regression tests in `rollup_integrity_h1h2h3_test.go`.
- **server** · `internal/database/flows.go:677-684` (aggregateFlowsToRollup), `flows.go:746-753` (aggregateRollupsUp), `internal/database/syslog_agg.go:86-92` (aggregateSyslogToSummary), `syslog_agg.go:179-185` (promoteSyslogSummaries)
- All four aggregation loops page a multi-column GROUP BY with `.Limit(N).Offset(offset)` and **no ORDER BY**. Each page re-executes the full aggregate; PostgreSQL gives no ordering guarantee for un-ORDERed (hash, parallel) aggregation, so page N and N+1 can overlap or skip groups. `aggregateRollupsUp` even mutates the table it is paging over between pages. With >50k flow groups per cycle (guaranteed at the 100k samples/sec design target, and in any backlog-recovery cycle after downtime — the group key includes src/dst/port, so cardinality explodes), some groups insert twice (double-counted bytes) and others never (lost bytes). `FlowRollup` has no unique constraint, so duplicates are silent.
- **Fix:** deterministic ORDER BY over the full group key on every paginated aggregate — or better, single-pass `INSERT INTO … SELECT … GROUP BY` / keyset pagination.

### H2. Rollup aggregate-then-delete is non-atomic and non-idempotent — partial failure double-counts; late-arriving backlog rows are deleted un-aggregated
> **✅ RESOLVED (v0.10.532)** — see H1: single-transaction all-or-nothing pass (mid-pass failure rolls back completely, next cycle retries identical work), and the delete is scoped to the pre-captured watermark so backlog rows arriving mid-pass survive to the next cycle.
- **server** · `internal/database/flows.go:694-718` (and same shape at `762-784`)
- (a) Each page commits in its own transaction and `batchInsertRollups` is a plain `Create` (no upsert/unique key); if a later page errors, raw rows are NOT deleted, so the next cycle re-aggregates them and re-inserts the already-committed groups — bytes permanently doubled. (b) The consumed-row DELETE is a blanket `timestamp < cutoff` after all pages: rows ingested during the multi-minute aggregation window — exactly what the collector's BoltDB backlog replay produces (old timestamps) — are deleted without ever being rolled up.
- **Fix:** capture a MAX(id) watermark before scanning and both aggregate and delete `WHERE id <= watermark AND timestamp < cutoff`; make rollup inserts idempotent (unique index + `ON CONFLICT DO UPDATE`).

### H3. promoteSyslogSummaries deletes ALL un-promoted hourly summaries inside the page-1 transaction — every group beyond the first 5000 destroyed
> **✅ RESOLVED (v0.10.532)** — the per-page unscoped delete is gone; promote now uses the shared watermark/ORDER BY/single-transaction shape with one scoped delete after all pages. Regression test `TestPromoteSyslogSummaries_MultiPage_NoGroupLoss_H3`.
- **server** · `internal/database/syslog_agg.go:198`
- The 1h→1d promote loop pages in 5000-group pages, but the DELETE inside each per-page transaction is **not page-scoped**: it deletes every `1h` row `< cutoff`. After page 1 commits, page 2 finds nothing and the loop exits silently — groups beyond the first 5000 are destroyed un-promoted, and the raw syslog behind them was already deleted when the hourly summaries were created. This is exactly the 2026-06-23 M2 bug, whose fix is documented in `aggregateSyslogToSummary` (`syslog_agg.go:101-107`, delete moved AFTER the loop) — the promote step did not get the same fix.
- **Fix:** mirror the sibling: single `WHERE interval_type='1h' AND timestamp < ?` delete after the pagination loop completes without error.

### H4. flow_rollups '1d', flow_detections, and flow_agent_drops have no retention path — unbounded growth on the DB that syslog once filled
> **✅ RESOLVED (v0.10.533)** — CleanupOldData now ages flow_rollups on `timestamp` (all interval types; RETENTION_FLOW_ROLLUP_DAYS, default 365), flow_detections on `detected_at` (RETENTION_FLOW_DETECTION_DAYS, default 90), and flow_agent_drops on `window_start` (RETENTION_AGENT_DROPS_DAYS, default 30), all via the batched-delete path. Regression test `TestCleanupOldData_FlowAnalyticsTables_H4`.
- **server** · `internal/database/cleanup.go:219-226`
- `CleanupOldData` covers `flow_samples` and `flow_if_counters` but none of the other sFlow-analytics tables. Terminal `1d` rollups are keyed by the full conversation tuple — one row per distinct conversation per day, 10^5–10^6 rows/day on a busy network, forever. `flow_detections` appends every 5-min cycle and only ever gets an `acknowledged` flip. `flow_agent_drops` shares the gap (latent: `SaveAgentDrops` has no production caller yet — see M2). None is partitioned, so the eventual cleanup will be the painful full-table-DELETE shape already lived through with `syslog_messages`. Violates invariant 9.
- **Fix:** cleanup entries for `flow_rollups` (`interval_type='1d'` older than `RETENTION_FLOW_ROLLUP_DAYS`), `flow_detections` (on `detected_at`), `flow_agent_drops` (on `window_start`), with `RETENTION_*` knobs.

### H5. IRC sendAutoStatus holds Manager.mu.RLock across blocking Privmsg sends — an IRC outage wedges admin handlers, alert delivery, and graceful shutdown
> **✅ RESOLVED (v0.10.535)** — sendAutoStatus now snapshots the due (conn, channel) pairs under `m.mu.RLock`, releases the lock, and runs the N+1-query statusFn plus all Privmsg sends lock-free, gated on `conn.Connected()` (polling the connection's own liveness instead of the never-fired DISCONNECTED callback). A parked send can still stall auto-status itself, but can no longer wedge admin handlers, alert delivery, or shutdown.
- **server** · `internal/irc/bot.go:282`
- `sendAutoStatus` (every 30s) holds `m.mu.RLock` while running the N+1-query statusFn AND `conn.Privmsg` per status line. In the pinned go-ircevent version, `pwrite` (buffered 10) loses its consumer during reconnects and is *replaced* on reconnect — a sender parked on the old channel blocks forever, and the `DISCONNECTED` callback that would nil `b.Conn` never fires in this library version. Once >10 lines accumulate during an outage, statusLoop parks holding the RLock; the next `m.mu.Lock` caller (ReloadCommands/RestartBot from admin HTTP handlers) blocks, and RWMutex writer-queueing then hangs every subsequent RLock (SendToChannel alert delivery, Manager.Stop) — hung admin requests pile up and shutdown hangs until SIGKILL.
- **Fix:** snapshot bots/channels under RLock, release, then send; add per-send timeouts; poll `conn.Connected()` instead of relying on the never-fired DISCONNECTED callback.

### H6. Collector per-source rate-limiter idle eviction can never fire — a spoofed-source flood permanently poisons the limiter
> **✅ RESOLVED (collector v1.2.154)** — eviction now computes the effective token count (stored + refill the idle time would earn) instead of the unsatisfiable stored-tokens check; `TestIdleEviction` strengthened to assert the new source gets a real per-source bucket (it previously couldn't distinguish eviction from the global-fallback path), plus `TestIdleEviction_EffectiveRefillPredicate_H6`.
- **collector** · `internal/ratelimit/ratelimit.go:164`
- Token refill happens only lazily inside `take()`, so an idle bucket's stored tokens are frozen at its last post-take value — always `< burst`. The eviction predicate `b.tokens >= l.burst` is therefore unsatisfiable: `evictOneIdleLocked` is dead code and `IdleTTL` a dead knob (the package doc's reclaim claim is false; `TestIdleEviction` passes for the wrong reason). After a >8192-spoofed-IP flood the map fills forever: every datagram from any NEW source (including a legitimately renumbered firewall) runs a futile O(256) scan under the shared per-packet mutex — serializing all SO_REUSEPORT workers exactly when the defense matters — and is admitted under the global bucket only, which a sustained flood exhausts, starving legitimate new senders until restart.
- **Fix:** evict on computed effective refill (`tokens + elapsed*rate >= burst`) or on `idle > TTL` alone; strengthen the test to assert the new source got a per-source bucket.

### H7. Collector queue replay loads the entire on-disk spool (up to 1 GiB/queue) into RAM at startup — OOM crash-loop after the outage the queue exists to survive
> **✅ RESOLVED (collector v1.2.154)** — `replay()` now walks the cursor backward (newest → oldest), copies only the newest `MaxMem` values into RAM, and counts everything older by key/value length only; peak replay heap is bounded by `MaxMem` items regardless of spool size. FIFO/tier semantics unchanged, pinned by the existing replay tests.
- **collector** · `internal/relay/queue/queue.go:141`
- `replay()` copies every key+value in the BoltDB bucket into a slice before deciding which `MaxMem` items stay in memory. Disk cap defaults to 1 GiB, ×7 queues. Server down for days → spool fills (by design) → collector restarts → `Open→replay` allocates ~1 GiB+ heap for one queue. On memory-constrained probe hosts (the documented Synology NAS deployment) this OOM-kills the process, which restarts and OOMs again — and the crash loop prevents the drain that would shrink the spool.
- **Fix:** iterate the cursor backward collecting only the newest `MaxMem` values; compute diskSize with a length-only pass.

### H8. Fresh Docker deploy crash-loops: entrypoint never chowns the /data bind mount and fwmon-api log.Fatalf's persisting the auto-generated admin password
> **✅ RESOLVED (v0.10.530)** — fixed by community PR [#50](https://github.com/xphox2/Firewall-Monitoring/pull/50) (@rovicomm), who independently diagnosed the same root cause the day before this audit and implemented exactly the recommended remedy: a runtime non-recursive `chown fwmon:fwmon /data` (leaving `/data/pgdata` postgres-owned). Merged 2026-07-01.
- **server** · `entrypoint.sh:168` (+ `docker-compose.yml:26`, `cmd/api/main.go:270`)
- With no `ADMIN_PASSWORD` set (the README first-run path), main takes the auto-generated-password branch and must write `/data/.admin-password`. But `/data` is a bind mount Docker auto-creates root:root 0755; the image's build-time chown is shadowed, and the entrypoint's runtime chown targets only `/data/firewall-mon.db*` (matches nothing on the PG image) and `/config` — never `/data` itself. The su-exec'd `fwmon` user gets EACCES → `log.Fatalf` → `restart: unless-stopped` produces a permanent first-boot crash loop for a brand-new operator.
- **Fix:** in entrypoint (runs as root) `chown fwmon:fwmon /data` non-recursively (leaving pgdata postgres-owned), or point SECRETS_DIR at the already-chowned `/config`, or seed ADMIN_PASSWORD into the generated config.env like JWT_SECRET_KEY.

### H9. Poller advisory work-lock is released on a different pooled connection — silent no-op release makes a SINGLE poller skip its own poll/rollup/detect/cleanup ticks
> **✅ RESOLVED (v0.10.534)** — `TryAcquirePollerWorkLock` now pins a dedicated `*sql.Conn` (the `AcquireAPISingletonLock` pattern) and returns a release func that unlocks on that SAME backend then closes it; the unlock's boolean return is also checked and logged.
- **server** · `internal/database/database.go:429-456`
- `pg_try_advisory_lock`/`pg_advisory_unlock` are session-scoped, but `TryAcquirePollerWorkLock`/`ReleasePollerWorkLock` issue them through GORM's pool, so the unlock routinely lands on a different backend than the lock. `pg_advisory_unlock` on a non-owning session returns `false` with a WARNING — not a SQL error — so the `err != nil` check never fires. The lock stays held by an idle pooled conn until recycled (≤5 min); the next tick's probe returns false and `runUnderLeaderLock` logs "another poller holds the work lock" and skips the ENTIRE tick — polling, offline detection, rollup, flow-detect, threat feeds, cleanup — in a single-poller deployment, chronically and silently, with a log that misattributes it to a second poller. The sibling `AcquireAPISingletonLock` (`database.go:469-495`) documents this exact hazard and pins a `sql.Conn` — the poller lock is the one advisory lock that skips the pattern.
- **Fix:** pin one `*sql.Conn` for acquire, stash it, release on the SAME conn, then Close; also check `pg_advisory_unlock`'s boolean.

### H10. Direct-link connection traffic ships CUMULATIVE interface counters in the per-bucket-delta chart contract — orders-of-magnitude inflated transfer/Mbps
> **✅ RESOLVED (v0.10.537)** — `interfaceTrafficWindow` now converts to per-bucket deltas PER INTERFACE before summing (consecutive-bucket difference, clamped at 0 on counter resets, first/baseline bucket dropped) — matching the tunnel path's LAG() semantics, so both UI consumers render correct transfer/Mbps for every family. The regression test that pinned the cumulative pass-through was rewritten to assert exact delta totals including a mid-series counter reset.
- **server** · `internal/database/connection_detail.go:662`
- `GetConnectionTraffic`'s direct-family path (ethernet/lag/l2vlan/bridge/wan) sums `GetInterfaceChartWindow` buckets, which are AVG of `interface_stats.in_bytes/out_bytes` — documented **raw cumulative counters** (invariant: bandwidth math must use consecutive deltas). The tunnel path of the same endpoint returns LAG() per-bucket deltas. Both UI consumers (connection-detail page, diagram side panel) run the payload through `FwmonBwChart.normalizeDeltas`, treating cumulative octets as per-bucket transfer: a member interface with 2 TB cumulative InBytes renders every hour bucket as ~2 TB transferred / ~4.4 Gbps flat — monotonically growing garbage. The regression test (`connection_traffic_direct_test.go:48`) pins the wrong (pass-through) behavior; the JS comment "arrives as per-bucket deltas" is false for the direct family.
- **Fix:** delta consecutive buckets per interface server-side (clamp <0 to 0 for resets) BEFORE summing across interfaces; update the regression test.

---

## MEDIUM

### M1. Ingestion silently truncates flow/counter/ping batches to 1000 items — 200 OK, batch marked processed, tail permanently lost
> **✅ RESOLVED (v0.10.538 + collector v1.2.155)** — every truncation site (flows, counters, pings, interface addresses/stats, system statuses, plus the already-alerting syslog/traps) now goes through one `truncateProbeBatch` helper that logs the drop and records the probe truncation alert on >20% overshoot; the collector clamps `PROBE_MAX_BATCH_SIZE` to the server's 1000-item cap so updated deployments never truncate at all. (413-reject was deliberately avoided: pre-v1.2.155 collectors treat non-2xx as retryable and would poison-loop.)
- **server** · `internal/api/handlers/handlers_data.go:195` (+ collector `internal/config/config.go:108`)
- `samples = samples[:1000]` with no log/alert, then 200 + `markBatchIfOK`, so the collector's dedup/retry can never resend the tail. The collector's `PROBE_MAX_BATCH_SIZE` is unclamped — any operator tuning it above 1000 (natural for a high-rate site draining a backlog) loses every batch's tail invisibly. The traps path records a truncation alert; flows/counters/pings record nothing.
- **Fix:** 413 on oversize (collector re-chunks), or process all rows; clamp the collector knob; log + RecordProbeDataTruncation.

### M2. samplingBackoffDetector reads flow_agent_drops, which nothing in production writes — sFlow drop monitoring silently inert (invariant 2)
> **✅ RESOLVED (v0.10.542)** — the flow-ingest handler now folds each batch's CUMULATIVE per-agent drops counters into `flow_agent_drops` via per-agent deltas (`recordAgentDrops`: baseline on first sighting, positive delta on growth, re-baseline on counter reset, bounded tracking map). End-to-end test `TestFlowIngest_AggregatesAgentDrops_M2` ingests two batches and asserts the `sampling_backoff` detection fires.
- **server** · `internal/detect/detectors.go:130` (+ `internal/database/agent_drops.go` TODO)
- `SaveAgentDrops` has only test callers; the promised 1-minute rollup of `FlowSample.Drops` into `flow_agent_drops` was never built (the doc comment admits it's a TODO). Per-sample `Drops` IS persisted into `flow_samples` but nothing reads that column. An overloaded agent drops samples in prod → detector sees 0 rows → no SFLOW_SAMPLING_BACKOFF alert ever fires while operators believe drop monitoring is active. Traffic under-reporting goes unnoticed — the condition the drops work was meant to catch.
- **Fix:** aggregate `Drops` by (agent, sampling_rate, minute) at ingest or in the 5-min rollup and upsert via `SaveAgentDrops`; regression-test the pipeline end to end.

### M3. Flow-detection re-alerts a one-shot finding 2–3× and a persistent one every ~5 min; a CooldownMinutes=0 policy row means per-cycle alert storms
> **✅ RESOLVED (v0.10.544)** — the policy- and rule-level cooldown copies now use the same `> 0` floor the site/device overrides already had (a 0 policy/rule inherits the default instead of disabling the cooldown → no per-cycle storm), and SFLOW_* alert types default to a 15-minute cooldown (≥ the detection window), so overlapping re-detections collapse and a persistent condition paces to once per window. Tests in `cooldown_floor_m3_test.go`.
- **server** · `cmd/poller/main.go:355` (+ `internal/alerts/policy.go:151`)
- A 15-min detection window on a 5-min cadence re-detects one event in 3 consecutive cycles, and the default cooldown (5 min) equals the cycle period, so each re-detection notifies. `policy.go:151` copies `policy.CooldownMinutes` without the `>0` floor that site/device overrides get, so a policy row with 0 gives a guaranteed per-cycle storm for every SFLOW_* type. No DB restart backstop in `ProcessFlowDetection` — a poller restart re-fires every still-detected finding at once.
- **Fix:** default SFLOW_* cooldown ≥ the window length; apply the `>0` guard; dedupe persisted detections on (dedup_key, overlapping window).

### M4. Threat-intel Matcher.Match is an O(n) scan called twice per flow sample on the ingest hot path
> **✅ RESOLVED (v0.10.542)** — prefixes are bucketed by bit length into maps keyed on the masked prefix; a lookup is one map probe per distinct prefix length (a handful), independent of feed size, still lock-free and allocation-free. Bonus: overlapping prefixes now return the MOST SPECIFIC match, and 4-in-6 mapped addresses match the IPv4 buckets. Test + benchmark in `threatintel_m4_test.go`.
- **server** · `internal/threatintel/threatintel.go:80`
- Flat `[]entry` scanned to the end on every miss (the common case), twice per sample, synchronously in `ReceiveFlowSamples`. With THREAT_FEEDS_ENABLED the default bundle is ~40–70k prefixes (feeds allow 500k each): ~0.3–0.7 ms per non-matching sample ≈ a full core at ~2k samples/sec — two orders of magnitude off the 100k/sec target; ingest slows, collector pushes time out, BoltDB backlog grows.
- **Fix:** longest-prefix-match structure — per-prefix-length maps keyed on masked addr (~O(24) lookups) or a binary radix trie; build once in New, lock-free lookup.

### M5. UpsertThreatIntelBatch has no in-batch (cidr,source) dedup — PG error 21000 aborts the whole feed; indicators then TTL-expire out silently
> **✅ RESOLVED (v0.10.542)** — the batch is deduped by (cidr, source) before the ON CONFLICT upsert, keeping the first occurrence. Also closes its duplicate finding (M-severity #40 in the raw set). Test `TestUpsertThreatIntelBatch_InBatchDedup_M5`.
- **server** · `internal/database/threat_intel.go:53` (+ `internal/threatfeed/threatfeed.go:143`)
- `normalize()` masks prefixes, so distinct feed lines collapse to identical (cidr,source) pairs; repeated lines are common in aggregate lists. PostgreSQL rejects a statement where two rows hit the same ON CONFLICT target ("cannot affect row a second time"), and `CreateInBatches` wraps all chunks in one transaction, so the WHOLE feed rolls back; `runThreatFeedSync` just logs. Every sync fails → after the 14-day TTL that feed's coverage silently drops to zero. SQLite tolerates it, so dev/tests pass while prod PG fails (invariant 4).
- **Fix:** dedup by (CIDR, Source) before insert.

### M6. Direction() classifies multicast/broadcast/unspecified as external — false C2-beacon and data-exfil detections from LAN chatter
> **✅ RESOLVED (v0.10.544)** — `isInternal` now treats `IsMulticast()`, `IsUnspecified()`, and the limited broadcast 255.255.255.255 as local scope, so SSDP/mDNS/IPTV multicast and DHCP DISCOVER no longer land in Outbound/External. Test `TestDirection_MulticastBroadcastUnspecified_M6` with real-outbound/inbound controls.
- **server** · `internal/classify/classify.go:219`
- `privateNets` covers RFC1918/loopback/link-local/CGNAT/ULA only. SSDP/mDNS to 239.255.255.250 (small, perfectly periodic) is stamped Outbound and matches the c2_beacon candidate query — recurring false "C2 beacon" detections for every chatty IoT/UPnP host; internal IPTV multicast bytes count toward data_exfil; DHCP DISCOVER (0.0.0.0→255.255.255.255) lands in "external transit".
- **Fix:** treat `IsMulticast()`, `IsUnspecified()`, and 255.255.255.255 as local scope; regression-test 239.255.255.250, ff02::1, 255.255.255.255, 0.0.0.0.

### M7. Probe lifecycle not enforced: rejected probes re-approve themselves via register; heartbeat resurrects decommissioned probes; validateProbe ignores enabled/decommissioned_at
> **✅ RESOLVED (v0.10.540)** — all three planes gated: RegisterProbe returns 403 for rejected / 410 for decommissioned-or-disabled probes (reactivation only via the admin UI's approve/RecommissionProbe); ProbeHeartbeat returns 410 instead of writing online+last_seen; validateProbe refuses ingestion when `DecommissionedAt != nil || !Enabled`. RecommissionProbe already restores `enabled=true`, so the re-commission flow is unaffected. Tests in `handlers_probes_lifecycle_m7_test.go` (register/heartbeat/ingest gates + DB-state-unchanged + active-probe control).
- **server** · `internal/api/handlers/handlers_probes.go:548` (RegisterProbe), `:673` (ProbeHeartbeat), `:780` (validateProbe)
- RegisterProbe (unauthenticated, key-based) short-circuits only when already approved+online; otherwise it unconditionally writes `approval_status='approved', status='online'` — a probe the admin explicitly REJECTED (RejectProbe leaves the key valid) restores itself by re-POSTing register. ProbeHeartbeat authenticates by bearer key only and unconditionally writes online+last_seen, so a still-running collector permanently resurrects a decommissioned probe — immune to the v0.10.521 stale sweep because last_seen stays fresh. validateProbe checks only `approval_status=='approved'`, so disabled/decommissioned probes keep full data ingestion, and each POST refreshes last_seen/last_data_received.
- **Fix:** register returns 403 for rejected / 409 for decommissioned; heartbeat and validateProbe refuse when `!Enabled || DecommissionedAt != nil || ApprovalStatus=='rejected'`.

### M8. IRC event callbacks read b.Conn without the mutex on unrecovered library goroutines — Stop/Restart racing a PRIVMSG nil-derefs and crashes fwmon-api
> **✅ RESOLVED (v0.10.535)** — every AddCallback closure now recovers first (`defer logging.Recover("irc-callback-*")`, closing the REL-01 gap on go-ircevent's bare goroutines), and onConnected/onPrivmsg/handleCommand/isAdmin/onJoin snapshot `b.Conn` under `b.mu.RLock` with a nil-check before any dereference (the pattern SendMessage already used).
- **server** · `internal/irc/bot.go:460` (onPrivmsg), `:521` (handleCommand), `:417-429`, `:608-611`
- `b.Conn` is nil'd under `b.mu` by Stop/onQuit, but callbacks read it lock-free, and go-ircevent runs each callback in a bare `go func` with NO recover — the REL-01 SafeGo containment doesn't cover them. Admin hits RestartBot while a `!status` callback is mid-flight (multi-query statusFn widens the window) → nil-deref panic in a library goroutine → whole process down.
- **Fix:** `defer logging.Recover(...)` first in every callback; copy `b.Conn` under RLock and nil-check (the pattern `SendMessage` already follows).

### M9. Threat-feed sync runs inline in the poller's single select loop — a blackholed feed host stalls polling, alerting, and offline detection for minutes
> **✅ RESOLVED (v0.10.544)** — the sync now runs in its own `logging.SafeGo` goroutine, guarded by a `feedSyncRunning` atomic (intervals can't stack) with the cross-process leader lock acquired inside the goroutine. The select loop stays free of network I/O, so a slow/blackholed feed no longer stalls polling/alerting/offline-detection or hangs shutdown. Tests `TestStartThreatFeedSyncAsync_*_M9`.
- **server** · `cmd/poller/main.go:406`
- `runThreatFeedSync` executes synchronously in a select arm: sequential fetches (90s ctx each, 5 default feeds) + up-to-500k-row upserts. Worst case ~7.5 min of fetch alone during which no SNMP polls run (ticks dropped), no alert evaluation, no stale sweeps, and stopChan isn't serviced (shutdown stalls).
- **Fix:** run in its own SafeGo goroutine with an already-running guard; keep the select loop free of network I/O.

### M10. GetNOCSnapshotFiltered ignores every query error and returns nil — DB failures broadcast an all-zero "live" NOC dashboard
> **✅ RESOLVED (v0.10.541)** — the core flow aggregate, device status counts, and site breakdown now propagate errors (top-N/country sub-queries stay tolerated per the original design), so the hub's keep-last-good branch and the one-shot handler's 500 branch are live code again; the hub also logs compute failures rate-limited to once/min. Test `TestGetNOCSnapshot_PropagatesCoreErrors_M10`.
- **server** · `internal/database/noc.go:204` (errors ignored from `:129` on)
- Every `.Error` is discarded; the function unconditionally returns `(snap, nil)`, so the hub's keep-last-good branch and the handler's 500 branch are dead code. A statement_timeout on the COUNT(DISTINCT) (known prod incident class) → wall-board shows 0 bps / "No sites or devices yet" with a green "● live" badge during exactly the incident window.
- **Fix:** propagate errors (or a hadErrors flag) so computeAndBroadcast keeps `h.latest`; rate-limited log.

### M11. NOC hub runs ~7–15 aggregate scans (incl. two COUNT(DISTINCT)) every 5s unconditionally — never gated on subscribers, duplicated on every ALLOW_MULTI_API follower
> **✅ RESOLVED (v0.10.541)** — ticks compute only while ≥1 SSE subscriber is connected; the 0→1 transition computes a fresh snapshot inline for the first paint. This also zeroes the follower duplication (an unwatched follower computes nothing) without breaking follower SSE the way primary-gating the hub would. Covers the L-severity duplicate of this finding too. Test `TestNOCHub_ComputesOnFirstSubscribe_M11`.
- **server** · `internal/api/handlers/noc.go:22`, `:63`
- `Run()` never consults `len(h.subs)`; `main.go:333` starts the hub on followers too (only IRC bots are gated). ~84+ flow-table aggregate scans/minute 24/7 against the same PG doing ingest, whether anyone watches or not; at the design target the 5-min window is ~30M rows and the tick just degrades.
- **Fix:** skip compute when no subscribers (compute on first subscribe); gate the hub to the singleton primary.

### M12. Tunnel/overlay connection traffic never populates bucket_ms — 3-mode charts fall back to a 60s interval, 60× inflated Mbps on 7d/30d
> **✅ RESOLVED (v0.10.537, with H10 — same endpoint)** — the tunnel path now backfills `BucketMs` from the bucket string via `parseBucketToMillis`, exactly like `GetInterfaceChartWindow`, so `normalizeDeltas` computes rates from the real bucket width on every range.
- **server** · `internal/database/connection_detail.go:800`
- The tunnel LAG() SELECT has no bucket_ms column, so every row serializes 0; `normalizeDeltas`' `medianIntervalSec()` falls back to 60 while 7d/30d buckets are HOURLY → exactly 60× inflated throughput (5-min cadence on minute buckets gives 5×). The direct path populates BucketMs, so direct vs tunnel show inconsistent rates side by side.
- **Fix:** backfill `rows[i].BucketMs = parseBucketToMillis(...)` like `GetInterfaceChartWindow`; JS fallback to parsing `d.bucket` when bucket_ms is 0.

### M13. Chart empty-state destroys the canvas permanently — later range switches throw and show a false error toast (two files)
> **✅ RESOLVED (v0.10.546)** — both traffic charts now use a STABLE host container (`#traffic-chart-host` / `#panel-traffic-chart-host`): the empty-state writes the message into the host (not `canvas.parentElement`), and the data path re-creates the canvas if a prior empty-state removed it — the admin-flows.js pattern. No more throw-on-next-range (connection-detail) or silent-dead-tab (panel).
- **server** · `cmd/api/static/js/admin-connection-detail.js:329`; `diagram-panels.js:333-335`
- The no-data branch replaces `canvas.parentElement.innerHTML`, removing the canvas; the next load finds null and either throws inside `FwmonBwChart.mount` (error toast on every 30s re-poll until reload) or silently never renders again (panel variant). `admin-flows.js:756-761` shows the intended re-create pattern — this is a missed sibling of an applied fix.
- **Fix:** re-create the canvas if missing on the data path, or render the empty message into a sibling element.

### M14. Webhook failure errors embed the full Slack/Discord webhook URL (secret token) and are logged (invariant 7)
> **✅ RESOLVED (v0.10.545)** — `postJSON` now redacts to scheme+host on both error paths: the non-2xx error and the transport error (Go's `*url.Error` stringifies the whole request URL). Test `TestPostJSON_RedactsWebhookSecret_M14` covers both.
- **server** · `internal/notifier/notifier.go:262`
- `postJSON` formats the destination URL into the error on non-2xx; Slack/Discord tokens live in the URL path. A revoked/rate-limited webhook writes the secret to container logs on every alert — hundreds of lines during a storm.
- **Fix:** log scheme+host (or channel label) + status only.

### M15. ReportScheduler and AlertManager guard the same *config.Config fields with two different mutexes — data race
> **✅ RESOLVED (v0.10.546)** — `ReportScheduler` now owns a PRIVATE copy of `AlertsConfig`, seeded at construction and refreshed from the DB (report + email/SMTP/webhook + spike, same source AlertManager reads), so it never touches the shared cfg. No shared mutable memory ⇒ no race. Test `TestReportScheduler_PrivateConfigIsolation_M15`.
- **server** · `internal/report/report.go:199` (+ `cmd/poller/main.go:1993-1998`)
- Same cfg pointer; `AlertManager.RefreshThresholds` writes `cfg.Alerts.Report*`/SMTP* under `am.mu` while `ReportScheduler` reads/writes the same strings under `rs.mu`. Two mutexes = no mutual exclusion; torn string headers can panic or send to garbage recipients.
- **Fix:** single owner — scheduler keeps a private snapshot, or one shared mutex for cfg.Alerts.

### M16. Collector TCP syslog has no rate limiting, no connection cap, no accept backoff — full bypass of the UDP defense on the same port
> **✅ RESOLVED (collector v1.2.157)** — the TCP path now enforces the same per-source rate limiter (per-line, before parse), caps concurrent connections at 256, backs off on persistent Accept errors, and stops logging one line per malformed message. Tests `TestSyslogTCP_RateLimited_M16` / `TestSyslogTCP_ConnectionCap_M16`.
- **collector** · `internal/syslog/syslog.go:82`
- One goroutine + 64KB buffer per connection, unlimited; no `Limiter.Allow` anywhere on the TCP path; unparseable lines log unthrottled; persistent Accept errors (e.g. EMFILE caused by the flood itself) hot-loop. A hostile host on the monitored LAN exhausts FDs/memory or floods the queue at TCP line rate, sidestepping the per-source PPS budget entirely.
- **Fix:** same SetRateLimiter hook per line/read; connection semaphore; backoff on non-temporary Accept errors.

### M17. bbolt NoSync can corrupt (not just truncate) the spool on power loss, and one corrupt file makes ensureQueues permanently disable ALL seven queues
> **✅ RESOLVED (collector v1.2.157)** — `Open` now quarantines an unreadable/corrupt spool file (renames to `<name>.bolt.corrupt-<ts>`) and recreates a fresh one, so a single corrupt file self-heals go-forward instead of failing Open and taking all seven queues down with it. Test `TestOpen_QuarantinesCorruptFile_M17`.
- **collector** · `internal/relay/queue/queue.go:92` (+ `relay.go:571-580`)
- With NoSync, meta/data pages hit disk in arbitrary order — bbolt's own docs warn the DB can corrupt on crash; the file's bounded-loss comment overpromises. On next start `Open/replay` fails and ensureQueues closes and nils EVERY queue on any single failure: the collector runs durability-disabled indefinitely (one WARNING), dropping all telemetry in every future outage until an operator hand-deletes the .bolt file.
- **Fix:** quarantine-and-recreate the corrupt file (`<name>.bolt.corrupt-<ts>`); disable only the failed queue; correct the comment.

### M18. Throttled fsync and per-item bolt transactions execute while holding the queue mutex shared by all UDP ingest workers
> **✅ RESOLVED (collector v1.2.157)** — the throttled `db.Sync()` moved off the hot path to a dedicated background ticker goroutine (writes set a dirty flag; an idle queue never fsyncs); the full-file fsync no longer blocks every UDP worker on `q.mu`. `Close` keeps its final unconditional fsync. Test `TestQueue_BackgroundSyncDurable_M18`.
- **collector** · `internal/relay/queue/queue.go:271`
- Above ~333 samples/s sustained (MaxMem 10000 / 30s drain) the memory tier is in permanent overflow, so every Push pays a bolt COW transaction under `q.mu`, and up to once per 2s one Push runs `db.Sync()` — a full-file fsync of a potentially ~1 GiB spool — while holding the lock. Every worker blocks, kernel socket buffers overflow, datagrams drop silently: the M7 stall reduced in frequency but moved onto a global lock, firing exactly under flood/outage conditions.
- **Fix:** background ticker for Sync (or release q.mu around it); batch overflow evictions.

### M19. Idempotency batch IDs are re-minted on requeue, and the direct-send metric path has no batch ID at all — timeout-after-commit duplicates rows
> **✅ RESOLVED (collector v1.2.156)** — batch IDs are now derived from the payload content (SHA-256), so an identical body carries the identical key across retries, sync-cycle requeues, and process restarts (every payload embeds collector-stamped timestamps, so distinct collections never collide); and the direct-send metric path (`doDirectSend`/`postMetricRaw`) now sends `X-Probe-Batch-ID` on every attempt including spillover-queue replays. Test `TestContentBatchID_DeterministicAndDistinct_M19`.
- **collector** · `internal/relay/relay.go:1543` (+ server-side M26/L17)
- `newBatchID()` is per-`sendBatch`-call: if all 3 in-call retries fail transport-level after a server commit, the requeued items are re-chunked and re-sent under a FRESH ID the server can't match. The metric path (`doDirectSend`/`drainMetricQueue`) sends no `X-Probe-Batch-ID` — replayed system-status/interface-stats/VPN payloads insert duplicate rows; duplicated cumulative counters at near-identical timestamps skew delta-based bandwidth math.
- **Fix:** assign the key at first enqueue (store in the envelope) and reuse across cycles; add the header to direct sends (server: L17).

### M20. Collector always advertises schema v2 with no fallback on HTTP 426 — registering against a v1 server (v0.10.382–v0.10.512) crash-loops and stops all site telemetry
> **✅ RESOLVED (collector v1.2.158)** — `Register()` now parses the 426's `X-Probe-Schema-Version-Supported` header and re-registers once at the highest mutually-supported version (the collector speaks every version down to `SchemaVersionMin`; higher-version features are gated on the negotiated version). A v2 collector against a v1 server now negotiates v1 instead of crash-looping. Tests `TestParseSchemaRange_M20` / `TestRegister_FallsBackToV1OnUpgradeRequired_M20`.
- **collector** · `internal/relay/relay.go:714` (+ `cmd/collector/main.go` register retry → `log.Fatalf`)
- A handshake-aware v1 server rejects v2 with 426 before auth; the collector retries the identical request 6× then Fatalf's → container restart policy = permanent crash loop, even though the collector speaks v1 perfectly (counter samples are already gated on negotiated ≥2). Live prod lags HEAD, so collector-first upgrades are realistic; the v0.10.513 changelog's "v2 collector ↔ v1 server keep working unchanged" claim is false for registration.
- **Fix:** on 426, re-register at the highest mutually supported version; and/or server clamps to `min(requested, max)` instead of rejecting.

### M21. RETENTION_SYSLOG_CRITICAL_DAYS still defaults to 0 (keep forever) — the syslog-bloat incident fix lives only in docker-compose.yml
> **✅ RESOLVED (v0.10.547)** — `config.env.example` now ships a documented core-retention block (`RETENTION_SYSLOG_CRITICAL_DAYS=30` with the incident rationale + the other core knobs), so `deploy.sh`-seeded native installs get the safe value. The code default stays 0 deliberately — flipping it would silently delete existing installs' critical syslog on upgrade (the "don't assume user data is expendable" rule).
- **server** · `internal/config/config.go:330` (+ `config.env.example`)
- The documented root cause of the 2026-05 syslog incident (severity≤5 kept forever; FortiGate traffic logs are severity 5) is still the code default. `deploy.sh` seeds `config.env.example` verbatim on native installs, and that file has no RETENTION_* syslog lines at all — every non-compose deployment path replays the incident.
- **Fix:** default 30 in code (matching compose), or at minimum add the var with rationale to config.env.example.

### M22. Docker image build never builds (or freshness-checks) Tailwind — `git pull && docker compose build` silently ships a stale committed tailwind.css
> **✅ RESOLVED (v0.10.547)** — a `Tailwind CSS freshness` CI job (`.github/workflows/ci.yml`) runs `npm ci && npm run tailwind` and fails on `git diff` of `tailwind.css`, so a stale committed artifact can never merge and the file the Dockerfile copies is always in sync with `styles.css`.
- **server** · `Dockerfile:24` (+ `.github/workflows/ci.yml`)
- v0.10.527 wired npm into make/deploy.sh only; the Dockerfile COPYs the committed artifact, and CI has zero npm/tailwind references, so a styles.css edit without regeneration passes green and the documented compose upgrade path embeds the stale css — the exact v0.10.500→526 regression shape, with no error anywhere.
- **Fix:** node stage in the Dockerfile, or a CI job that regenerates and fails on `git diff --exit-code` of tailwind.css.

### M23. docs/ENV-VARS.md contradicts the code on three vars (trap community "required", INSECURE_SKIP_VERIFY accepted values, queue disk-path default)
> **✅ RESOLVED (collector v1.2.158)** — `PROBE_INSECURE_SKIP_VERIFY` now routes through `parseBool` so the documented `1`/`yes` actually work (code matches doc); the ENV-VARS.md rows for the trap community (optional allowlist; empty = accept-all with a warning, NOT rejected) and the queue disk path (container default `/queue`) are corrected to match the code/Dockerfile.
- **collector** · `docs/ENV-VARS.md:46`, `:20`, `:91`
- (1) PROBE_SNMP_TRAP_COMMUNITY is documented "Required — empty rejected at startup" but the code treats empty as accept-ANY-community (warning only) and the Dockerfile defaults it to "" — the shipped container accepts every community on 162/udp. (2) PROBE_INSECURE_SKIP_VERIFY documents `1`/`yes` but the code matches only literal `"true"` — doc-following operators get silent TLS failures. (3) The "production default leaves disk path empty" prose is wrong: the Dockerfile sets `/queue`.
- **Fix:** correct the doc (source wins); route the bool through parseBool; consider fail-fast on empty trap community to match the server posture.

### M24. LINK_UP trap from any device auto-resolves and auto-acknowledges LINK_DOWN alerts of EVERY device — direct trap path never resolves DeviceID
> **✅ RESOLVED (v0.10.545)** — `ProcessTrap` resolves DeviceID from the trap's source IP (`ResolveDeviceByIP`, so per-device policies apply and device_id scopes recovery) and scopes every trap alert's `MetricName` to `snmp_trap_<sourceIP>` as defense-in-depth when the IP maps to no device. A LINK_UP now resolves only the same source's LINK_DOWN. Test `TestProcessTrap_LinkUpScopedBySource_M24`.
- **server** · `internal/alerts/alerts.go:590` (+ `internal/snmp/trap.go:190-311`, `cmd/trap-receiver/main.go:132-139`)
- Direct traps carry DeviceID=0, and sendRecovery's UPDATE matches `device_id=0 AND alert_type='LINK_DOWN' AND metric_name='snmp_trap'` — which is ALL direct-trap LINK_DOWNs. Firewall B's LINK_UP closes firewall A's still-open LINK_DOWN with "Auto-resolved". Same root cause: per-device alert policies never apply to direct traps.
- **Fix:** resolve DeviceID from trap.SourceIP (as the poller pipeline does); if unresolvable, scope the resolve by source IP.

### M25. trap-receiver never prunes AlertManager.lastAlert — unbounded growth keyed by spoofable source IPs
> **✅ RESOLVED (v0.10.545)** — two layers: the trap-receiver now runs a 1-minute `PruneExpiredCooldowns` ticker (mirroring the poller), and `AlertManager` hard-caps `lastAlert` at 50k entries via `recordCooldownLocked` (all cooldown writes route through it; inline expired-prune then oldest-eviction), so any embedding process is bounded by construction. Test `TestRecordCooldownLocked_Bounded_M25`.
- **server** · `cmd/trap-receiver/main.go:129` (+ `internal/alerts/alerts.go:194,203,434`)
- `PruneExpiredCooldowns` is called only from the poller; the trap-receiver's own AlertManager never evicts. The per-IP token map is bounded, but its idle sweep re-admits ~10k new IPs per 5-min window; each spoofed IP carrying a known warning/critical OID with the correct community adds a permanent lastAlert entry (~2.8M/day max, hundreds of MB), each also producing an alert row + notification (cooldown is per-key, so unique IPs bypass it).
- **Fix:** prune ticker in the trap-receiver; cap lastAlert with LRU eviction inside AlertManager so every embedder is safe by construction.

### M26. SaveSystemStatuses turned resilient per-row saves into an all-or-nothing multi-row INSERT — one bad row 500s the batch and poisons the collector's retry queue
> **✅ RESOLVED (v0.10.538)** — all 14 plural batch savers (system status, interface stats/errors, VPN/HA/security/SD-WAN, traps, pings, processor stats, sensors, syslog, flow counters, and the flow-samples SQLite path) now share `batchInsertWithFallback`: the multi-row INSERT stays the fast path; on failure it retries per-row, logs and drops only the unsalvageable rows, and errors only when every row fails. A clock-skewed or partition-orphaned row degrades one row instead of halting that metric type's ingestion. Test `TestBatchInsertWithFallback_M26`.
- **server** · `internal/database/telemetry.go:21` (+ `handlers_data.go:600-604`)
- v0.10.484 (M5) batched the insert; on partitioned prod PG one row outside the partition range (clock-skewed collector, or a spillover replay after its month's partition was dropped — there is no DEFAULT partition) fails the entire INSERT → 500. The collector buffers 500s as retryable and `drainMetricQueue` requeues the poison item and stops the drain cycle on each hit: system-status ingestion halts entirely (old behavior: log-and-continue, 200), and drains of the other metric types are repeatedly cut short. Same sibling class as M5.
- **Fix:** on batch failure fall back to per-row (log-and-skip) with 200 + saved count, or 400 for never-succeeds rows so the collector drops them; longer-term a DEFAULT partition or server-side timestamp clamp.

### M27. Device-detail chart prefers sFlow whenever ≥2 buckets exist anywhere in the window — stale/partial sFlow hides live SNMP bandwidth
> **✅ RESOLVED (v0.10.546)** — `loadInterfaceChart` now fetches both sources and prefers sFlow only when it is at least as FRESH as SNMP (its last `bucket_ms` is not older); otherwise SNMP wins. A stopped/partial sFlow export (collector down, a brief past trial, a sparse zoom sub-window) no longer hides the live SNMP-measured traffic.
- **server** · `cmd/api/static/js/admin-device-detail.js:874`
- No recency/coverage check: sFlow that died 3h into an incident still wins the 24h view (chart silently ends 3h ago); a 30-min sFlow trial last week claims the whole 7d/30d view; zooming past sFlow coverage silently flips source (different counter baseline). No UI override to force SNMP.
- **Fix:** accept sFlow only if its last bucket is within ~2 intervals of the window end; otherwise pick the series with the newer last bucket.

### M28. CheckProbeDataFlow includes decommissioned probes — PROBE_DATA_LAG alerts fire forever after a probe is retired
> **✅ RESOLVED (v0.10.540)** — the check now skips probes with `DecommissionedAt != nil || !Enabled` (GetApprovedProbes itself unchanged — its other consumers legitimately include retired probes for attribution). Test `TestCheckProbeDataFlow_SkipsDecommissioned_M28` with an active-lagging-probe positive control.
- **server** · `internal/alerts/alerts.go:928`
- `GetApprovedProbes` selects on approval_status only, and decommission deliberately doesn't change it. After the collector is shut down, lag grows past the default 60-min threshold and the alert re-fires every cooldown, indefinitely — the documented soft-decommission path produces a permanent alert stream until the operator hard-deletes the probe, which decommission exists to avoid.
- **Fix:** skip `DecommissionedAt != nil` (and arguably `!Enabled`) in CheckProbeDataFlow.

### M29. Trap rate-limiter drops (token exhaustion and map-cap lockout) are completely silent — despite three code/CHANGELOG claims of drop visibility
> **✅ RESOLVED (v0.10.541)** — `fwmon_trap_ratelimit_drops_total{reason="rate"|"cap"}` counts every drop on the trap-receiver's /metrics, and a summary log line fires at most once per minute (so a flood can't turn the defense into a log-volume DoS). The code comments now match reality. Test `TestTrapRateLimiter_DropsAreVisible_M29`.
- **server** · `internal/snmp/trap.go:161` (claims at `trap.go:89-91`, `cmd/trap-receiver/main.go:117`)
- `allow()==false` → bare return: no log, no metric, though comments assert "the operator sees a clear rate-limited pattern in the logs" and "/metrics carries the trap rate-limiter". A legit link-flap storm past 10/sec loses traps tracelessly; worse, a spoof flood filling the 10k-bucket cap silently rejects every NEW legitimate device IP for up to 5 min — real LINK_DOWN/HA-failover traps vanish during exactly the event traps exist to report.
- **Fix:** `fwmon_trap_ratelimit_drops_total{reason}` counter + throttled summary log line.

### M30. A panic in the poller's Start() loop is swallowed by SafeGo with no restart — zombie poller behind green /healthz and /readyz
> **✅ RESOLVED (v0.10.534)** — both halves shipped: the Start() goroutine is now supervised (recover per attempt, restart with capped exponential backoff, clean exit only on Stop()), and /readyz additionally requires a loop heartbeat within max(3× poll interval, 10 min) — stamped at loop start, before each select wait, and when leader-locked work is picked up — so a halted or wedged loop flips the daemon to not-ready. Test `TestPollerLoopHeartbeat_M30`.
- **server** · `cmd/poller/main.go:1980`
- The entire ticker select loop (poll, rollup, flow-detect, feeds, cleanup, sweeps) runs in one SafeGo goroutine; Recover logs and swallows, nothing restarts the loop. readyz only pings the DB and healthz is unconditional 200, so any panic in one tick's work (exactly the new-code class shipped in R1–R6) permanently halts the daemon's entire purpose while orchestrators and Prometheus see green. Crashing would be safer — the supervisor would restart it.
- **Fix:** restart-with-backoff for the loop goroutine, or a lastCycleCompleted timestamp that fails readyz when stale (>3× interval).

---

## LOW

### L1. GetFlowStats estimated_bytes double-scales by AvgSamplingRate (bytes are already sampling-scaled at ingest)
> **✅ RESOLVED (v0.10.548)** — `EstimatedBytes = TotalBytes` (bytes is already sampling-scaled at ingest); stale scaling comment removed.
- **server** · `internal/database/flows.go:260-261` — no UI consumer yet, but the field over-reports by ~the sampling rate, and the stale comment at `:215` invites re-introducing double-scaling. Fix: `EstimatedBytes = TotalBytes` (or drop it); fix the comments.

### L2. PruneExpiredCooldowns evicts on a fixed 10-min threshold — truncates operator-set cooldowns >10 min for event-type alerts once per day
> **✅ RESOLVED (v0.10.549)** — the cooldown map now stores each key's effective cooldown alongside its timestamp (`cooldownFor`), and prune evicts a key only once it is past its OWN window (was a fixed `alertCooldown*2` ≈ 10 min that truncated longer operator-set cooldowns). The poller also prunes hourly. Test `TestPruneExpired_RespectsPerKeyCooldown_L2`.
- **server** · `internal/alerts/alerts.go:439` — track effective cooldown per key and evict past it; run hourly.

### L3. threatfeed.Parse ignores bufio.Scanner errors — silently truncated feeds logged as successful syncs
> **✅ RESOLVED (v0.10.549)** — `Parse` returns `sc.Err()` and `Fetch` propagates it, so an over-long line (`bufio.ErrTooLong`, e.g. a one-line HTML error page) or a mid-body read error is a feed-fetch failure, not a silently-truncated "successful" sync. Test `TestParse_SurfacesScannerError_L3`.
- **server** · `internal/threatfeed/threatfeed.go:137` — a >1 MiB line (HTML error page with 200) stops the scan silently; indicators past it TTL-expire. Fix: return `sc.Err()`; treat scan errors as fetch failures.

### L4. Partial GeoLite2 open logs "enrichment disabled" while half of it runs; mmap'd .mmdb has no reload path (in-place overwrite risks SIGBUS)
> **✅ RESOLVED (v0.10.550)** — a partial open (one of Country/ASN loads) now logs "partial load … enrichment enabled … with reduced coverage" instead of "disabled". `GeoResolver` holds each reader behind an `atomic.Pointer`; a new `Reload()` re-stats the `.mmdb` files on a 6h ticker and hot-swaps any that changed, retiring the old reader and closing it only on the *next* cycle so an in-flight lookup never dereferences an unmapped reader. Operators must rename-into-place (MaxMind's updater does); documented. Test `TestGeoResolver_ReloadNilSafe`.
- **server** · `internal/classify/geo.go:38` (+ `handlers.go:52-53`) — periodic mtime check + atomic swap; fix the log; document rename-not-overwrite.

### L5. SSE stream clears the write deadline — a zero-window client pins its handler goroutine in a blocked Write indefinitely
> **✅ RESOLVED (v0.10.550)** — the NOC SSE handler no longer clears the write deadline outright; it arms a rolling 15s per-write deadline (`SetWriteDeadline`) before every snapshot/keepalive flush. A healthy reader keeps resetting it (so a live stream is never truncated), while a client that stops reading unblocks the goroutine so it returns and unsubscribes.
- **server** · `internal/api/handlers/noc.go:156` — set a rolling per-write deadline instead.

### L6. Malformed ?focus= percent-encoding throws uncaught URIError — NOC page fails to init; Connections page wipes the just-rendered map
> **✅ RESOLVED (v0.10.551)** — both `parseFocus` (NOC) and `getConnFocusParam` (Connections) wrap `decodeURIComponent` in try/catch and return null on a `URIError`, so a hand-edited or truncated `?focus=` no longer aborts NOC init or wipes the just-rendered connection map.
- **server** · `cmd/api/static/js/admin-noc.js:410`, `admin-main.js:2711` — wrap decodeURIComponent in try/catch.

### L7. Critical-alert HTML part declares quoted-printable but writes the body raw — RFC-illegal; compliant QP decoders mangle `=XX` sequences in alert text
> **✅ RESOLVED (v0.10.549)** — the HTML part is now written through `mime/quotedprintable.NewWriter`, so the body actually matches its declared `quoted-printable` encoding (no more `=XX` mangling / raw-8-bit rejection by compliant decoders).
- **server** · `internal/notifier/notifier.go:376` — use `mime/quotedprintable.NewWriter`, or declare 8bit like the no-attachment branch.

### L8. SVG chart renderers divide by len(series)-1 with only a len==0 guard — 1-point series emits NaN path coordinates, chart drops
> **✅ RESOLVED (v0.10.549)** — both SVG renderers require ≥2 points before plotting (the placeholder shows otherwise), so a 1-point series no longer emits `NaN` path coordinates that break the report preview / PDF. Test `TestSVGCharts_NoNaNOnSinglePoint_L8`.
- **server** · `internal/report/svg_charts.go:198` — fall back to the placeholder when nPoints < 2.

### L9. sFlow sub-record parsers bound reads against the datagram, not recEnd — a lying record length bleeds adjacent-record bytes into BGP/counter telemetry
> **✅ RESOLVED (collector v1.2.159)** — both flow-record and counter-record dispatch loops now hand each sub-parser a slice bounded to the record's own declared length (`data[off:recEnd]`) with a record-local offset, so a lying `recLen` can no longer let `parseRawPacketHeader`/`parseExtendedGateway`/`parseIfCounters` read past `recEnd` and fold the following record's bytes into `SrcAS`/next-hop/64-bit octet counters (the fake multi-exabyte spike). Regression test `TestParseSFlowDatagram_LyingRecLenNoBleed_L9`.
- **collector** · `internal/sflow/sflow.go:462` — garbage SrcAS/ASPath persisted; fake multi-exabyte counter spikes from one malformed packet (no crash). Fix: slice the record first (`rec := data[off:recEnd]`) and parse with local offsets.

### L10. Lax syslog priority parsing turns garbage into severity 0 (emergency) or negative severity — server classifies as critical and retains 30 days
> **✅ RESOLVED (collector v1.2.159)** — `parsePriority` now enforces the RFC 5424 PRIVAL grammar: a leading `<`, a closing `>`, and 1–3 all-digit bytes (0–191). `<abc>`, `<>`, a missing `>`, trailing non-digits, and overflowing digit runs are rejected instead of silently decoding to severity 0 (Emergency) or a negative severity that slipped past the `>191` check. Tests updated (`TestParsePriority_OutOfRange`, `TestParseRFC5424_MalformedPriority`).
- **collector** · `internal/syslog/syslog.go:369` — `<abc>` → severity 0; overflowing digit runs go negative and pass the `>191` check. Fix: require closing `>`, 1–3 digits, reject otherwise.

### L11. sFlow readLoop worker exits on first non-timeout error but leaves its SO_REUSEPORT socket bound — kernel keeps hashing datagrams to a dead socket
> **✅ RESOLVED (collector v1.2.159)** — both UDP receivers (sFlow and syslog) now supervise each worker socket: on a persistent non-timeout read error they close the dead fd (so the kernel drops it from the SO_REUSEPORT hash and rebalances to the live workers) and reopen a fresh listener after a growing backoff (200ms→30s), instead of the sFlow receiver returning and blackholing its share of agents or the syslog receiver spinning a tight hot-loop re-reading the errored socket. `Stop()` snapshots the conn slice under a new `connsMu` so it closes whichever fd a worker currently holds.
- **collector** · `internal/sflow/sflow.go:142` — 1/N of agents silently blackholed until restart (all of them if single-worker); syslog's UDP loop picked the opposite (hot-loop) behavior. Fix: close the conn on exit (kernel rebalances) and/or respawn with backoff; align both receivers.

### L12. Schema-v2 shipped asymmetrically: collector transmits if_direction, server model lacks the field — silently dropped at ingest (invariant 3)
> **✅ RESOLVED (v0.10.551)** — `FlowInterfaceCounter` gained an `IfDirection uint32` field (`json:"if_direction"`) and migration v18 adds the `if_direction bigint` column, so the collector's schema-v2 value now binds at ingest and persists instead of being dropped. Regression test `TestFlowInterfaceCounter_IfDirectionPersists_L12`.
- **server** · `internal/models/models.go:847` — add `IfDirection` + migration, or remove from the collector struct.

### L13. Flow-counters queue drains without re-checking the negotiated schema version — after a server rollback, endless 404s are misread as probe-not-found (approval flap + re-register every sync)
> **✅ RESOLVED (collector v1.2.160)** — `syncData` only drains the flow-counter queue when the server currently negotiates schema v2; when it doesn't (a rollback to v1), the undeliverable v2 backlog is discarded (`discardQueue`) instead of POSTed to the now-absent `/flow-counters` endpoint. As defense-in-depth, `sendBatch` treats a 404 specifically on `/flow-counters` as "endpoint unsupported → drop the batch" and records the downgrade (`negotiatedSchema=1`) instead of deapproving + re-registering; a genuinely deleted probe still surfaces via 404 on the core endpoints. Tests `TestSendBatch_FlowCounters404DropsNotDeapprove_L13`, `TestSendBatch_CoreEndpoint404StillReregisters_L13`.
- **collector** · `internal/relay/relay.go:1353` — skip/discard the drain when negotiated <2; treat endpoint-404 as "unsupported, drop batch" not "probe deleted".

### L14. config.env.example ships SNMP_TRAP_COMMUNITY=public and deploy.sh seeds it verbatim — native installs accept the world's best-known community on exposed 162/udp
> **✅ RESOLVED (v0.10.551)** — `config.env.example` now ships `SNMP_TRAP_COMMUNITY=` (empty). deploy.sh seeds config.env from the example verbatim on first install, so an empty value means the trap receiver opens NO listener on 162/udp and idles (AUDIT-012) until the operator sets their real community — rather than a fresh deploy accepting spoofed traps under `public`.
- **server** · `config.env.example:119` — ship it empty/commented so the AUDIT-012 startup rejection actually fires.

### L15. /readyz uses unbounded sql.DB.Ping() and the observability server has no write timeout — a wedged PG hangs probes and leaks a goroutine per scrape
> **✅ RESOLVED (v0.10.534)** — both daemons' readyz closures use `PingContext` with a 2s deadline, and `StartObservabilityServer` sets a 30s `WriteTimeout` (shipped with the M30 readyz rework — same lines).
- **server** · `cmd/poller/main.go:1982` (+ `internal/metrics/metrics.go:117`) — PingContext with a 2s deadline; WriteTimeout/TimeoutHandler on the mux.

### L16. updatePingStatsBatch is an unlocked read-modify-write — concurrent folds for the same (device,target) lose or double-count a whole batch in the lifetime series
> **✅ RESOLVED (v0.10.550)** — the per-target fold is now a single atomic `FoldPingStats` (`INSERT … ON CONFLICT (device_id, target_ip) DO UPDATE`) that recomputes min/max and the running average `(avg·samples + Σ)/(samples+K)` in-SQL against the row's pre-update values, so interleaved folds can no longer clobber each other's batch. Dialect-aware `min`/`max` vs `LEAST`/`GREATEST`. Tests `TestFoldPingStats_AtomicAccumulation_L16`, `TestFoldPingStats_ManyFoldsSumSamples_L16`.
- **server** · `internal/api/handlers/handlers_data.go:427` — atomic UPDATE (`samples = samples + ?` …) or SELECT FOR UPDATE; pre-existing pattern, but the batch rewrite widened the loss unit from one sample to the batch.

### L17. ReceiveSystemStatuses (and the other 8 direct-send metric endpoints) have no batch idempotency on either side — timeout-after-commit replays insert duplicate rows
> **✅ RESOLVED (v0.10.539 + collector v1.2.156)** — the eight time-series direct-send endpoints (system status, interface stats, VPN/HA statuses, processor stats, hardware sensors, security stats, SD-WAN health) now run the AUDIT-042 `batchDedupCheck`/`markBatchIfOK` pair, and the collector sends content-derived `X-Probe-Batch-ID` on those routes (M19). The current-state upsert endpoints (interface addresses, license info) were deliberately excluded — replays there are idempotent by design. No-op for pre-v1.2.156 collectors (no header ⇒ no dedup), so version skew is safe.
- **server** · `internal/api/handlers/handlers_data.go:568` — add batchDedupCheck/markBatchIfOK server-side and X-Probe-Batch-ID to collector direct sends (pairs with M19); duplicates skew per-device history charts, and M26's new 500 path makes replays far more frequent at HEAD.

### L18. Device-detail sFlow bandwidth chart is unreachable for devices that never had an SNMP interface snapshot — precisely the devices the feature was built for
> **✅ RESOLVED (v0.10.551)** — the device-detail handler unions the interface_stats list with the latest sFlow counter per distinct `if_index` (`GetLatestInterfaceCountersByDevice`), synthesizing an interface card for each flow-only if_index. An SNMP-host-restricted device pushing sFlow if_counters now renders interface cards, and clicking one reaches the sflow-chart endpoint. Test `TestGetLatestInterfaceCountersByDevice_L18`.
- **server** · `internal/api/handlers/handlers_devices.go:346` — the interfaces array comes only from interface_stats, so SNMP-host-restricted devices pushing sFlow if_counters render zero interface cards and the sflow-chart endpoint is never called. Fix: union the interface list with DISTINCT if_index from flow_if_counters.

### L19. loadInterfaceChart/loadTunnelChart lack an in-flight staleness guard — overlapping responses leak Chart.js instances and overwrite live state with stale buckets
> **✅ RESOLVED (v0.10.551)** — both loaders stamp each request with a per-key monotonically increasing token (`ifaceChartSeq`/`tunnelChartSeq`) and drop any response whose token is no longer current, so a slower earlier response can't overwrite the live chart with stale buckets or leak the newer Chart.js instance.
- **server** · `cmd/api/static/js/admin-device-detail.js:839` — the fd3315d fix class, missed on these two loaders (60s poll + range clicks make overlap routine). Fix: per-target request token + destroy any instance already in the slot.

### L20. "Awaiting data from probe…" banner appended on every 60s poll with no dedup — unbounded stacking on devices awaiting their probe
> **✅ RESOLVED (v0.10.551)** — `renderSystemStatus` removes any prior `.awaiting-probe-data` banner before (re)rendering, so exactly one banner shows while awaiting data and none lingers once real status arrives — no more stacking on each poll.
- **server** · `cmd/api/static/js/admin-device-detail.js:150` — guard the append / assign instead of insertAdjacentHTML; remove when data arrives.

### L21. Flows showChartEmpty() wipes the canvas without destroying charts.bandwidth or clearing lastBwData — theme toggle resurrects the previous filter's chart over "No data"
> **✅ RESOLVED (v0.10.551)** — `showChartEmpty` (and the no-points branch of `renderBandwidth`) now destroy `charts.bandwidth` and null `lastBwData` before replacing the host innerHTML, so the orphaned-canvas Chart instance can't leak and a theme/mode toggle can't redraw the previous filter's chart over the empty state.
- **server** · `cmd/api/static/js/admin-flows.js:798` — mirror renderBandwidth's own empty path (destroy + null + clear lastBwData).

### L22. AddThreatIntel stores the CIDR un-normalized while the matcher masks it — equivalent prefixes duplicate, and deleting the visible row leaves the hidden one enforcing
> **✅ RESOLVED (v0.10.548)** — `AddThreatIntel` canonicalizes the CIDR (`canonicalThreatCIDR`, masked) before storage, so the DB key, displayed value, and enforced prefix are identical. Test `TestCanonicalThreatCIDR_L22`.
- **server** · `internal/api/handlers/handlers_analytics.go:499` — canonicalize with `.Masked().String()` before storage; displayed scope ≠ enforced scope otherwise.

### L23. detect_beacon_max_cv / detect_capacity_threshold accept 'NaN' — persisted and displayed as active but silently ignored by the poller
> **✅ RESOLVED (v0.10.548)** — the range checks are inverted to `!(v > 0 && v <= max)`, which NaN/±Inf fail, so a non-finite value is rejected at write instead of persisting as displayed-but-ignored.
- **server** · `internal/api/handlers/handlers_settings.go:177` — NaN fails every range comparison, passing write-side guards and failing the poller's `v > 0`. Fix: reject non-finite, or invert checks to `!(v > 0 && v <= max)`.

### L24. GetFlowSamples binds the raw protocol query string against a numeric column — non-numeric value 500s on PG (SQLite silently matches nothing)
> **✅ RESOLVED (v0.10.548)** — protocol, probe_id, device_id, and site_id are now parsed with `strconv` and applied only on success (matching the sibling numeric filters), so a non-numeric value drops the filter instead of 500-ing on PostgreSQL.
- **server** · `internal/api/handlers/handlers_analytics.go:287` — the one unparsed numeric filter in the v0.10.508+ surface; parse with strconv like the sibling filters.

---

## Cross-cutting patterns

1. **The "fix one sibling, miss the others" pattern dominates this audit.** H3 re-introduces the exact bug fixed one function above it; M13/L19/L20/L21 are all missed siblings of applied chart-lifecycle fixes; M26 repeats M5's all-or-nothing batch shape; H9 skips the connection-pinning pattern its own sibling documents. When a fix ships, grep for the pattern, not the symptom (the "improve everything at once" rule).
2. **Batch/aggregate rewrites traded resilience for atomicity without idempotency.** H1/H2/H3/M5/M26/L16/L17 are all one root idea: multi-row operations that either partially commit without dedup keys or fail wholesale on one bad row. Any batch write needs (a) a deterministic scope, (b) an idempotency key or upsert, (c) a poison-row escape hatch.
3. **Claims in comments/docs/changelogs that the code doesn't back** — M29 (drop visibility), M23 (ENV-VARS), M20 (changelog compat claim), H6 (package doc), M2 (drops TODO). Verifiers found these by diffing prose against code; CI-testable assertions beat prose.
4. **Idle/unsubscribed work and unbounded state** — M11/L5 (NOC), M25 (lastAlert), H4 (retention), H6 (limiter map). Every cache/map/ticker needs an owner answering "who evicts, who stops".

## Suggested fix order

1. **Data integrity now:** H1+H2+H3 (one PR — same functions), H10+M12 (one PR — same endpoint), H4+M21 (retention pass).
2. **Monitoring-plane reliability:** H9, M30, M10, M29, M24, M25 (poller/trap/NOC trust cluster).
3. **Collector hardening:** H6, H7, M16, M17, M18, L9, L10, L11 (one hardening pass).
4. **Lifecycle/contract:** M7+M28+L18-adjacent probe lifecycle PR; M19+L17 idempotency pair; M20+L13 schema-skew pair; M26+M1 ingestion-resilience pair.
5. **Everything else** in severity order; the LOW frontend items (L19–L21, M13, L6) are one sibling-sweep PR.
