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
- **server** · `internal/database/flows.go:677-684` (aggregateFlowsToRollup), `flows.go:746-753` (aggregateRollupsUp), `internal/database/syslog_agg.go:86-92` (aggregateSyslogToSummary), `syslog_agg.go:179-185` (promoteSyslogSummaries)
- All four aggregation loops page a multi-column GROUP BY with `.Limit(N).Offset(offset)` and **no ORDER BY**. Each page re-executes the full aggregate; PostgreSQL gives no ordering guarantee for un-ORDERed (hash, parallel) aggregation, so page N and N+1 can overlap or skip groups. `aggregateRollupsUp` even mutates the table it is paging over between pages. With >50k flow groups per cycle (guaranteed at the 100k samples/sec design target, and in any backlog-recovery cycle after downtime — the group key includes src/dst/port, so cardinality explodes), some groups insert twice (double-counted bytes) and others never (lost bytes). `FlowRollup` has no unique constraint, so duplicates are silent.
- **Fix:** deterministic ORDER BY over the full group key on every paginated aggregate — or better, single-pass `INSERT INTO … SELECT … GROUP BY` / keyset pagination.

### H2. Rollup aggregate-then-delete is non-atomic and non-idempotent — partial failure double-counts; late-arriving backlog rows are deleted un-aggregated
- **server** · `internal/database/flows.go:694-718` (and same shape at `762-784`)
- (a) Each page commits in its own transaction and `batchInsertRollups` is a plain `Create` (no upsert/unique key); if a later page errors, raw rows are NOT deleted, so the next cycle re-aggregates them and re-inserts the already-committed groups — bytes permanently doubled. (b) The consumed-row DELETE is a blanket `timestamp < cutoff` after all pages: rows ingested during the multi-minute aggregation window — exactly what the collector's BoltDB backlog replay produces (old timestamps) — are deleted without ever being rolled up.
- **Fix:** capture a MAX(id) watermark before scanning and both aggregate and delete `WHERE id <= watermark AND timestamp < cutoff`; make rollup inserts idempotent (unique index + `ON CONFLICT DO UPDATE`).

### H3. promoteSyslogSummaries deletes ALL un-promoted hourly summaries inside the page-1 transaction — every group beyond the first 5000 destroyed
- **server** · `internal/database/syslog_agg.go:198`
- The 1h→1d promote loop pages in 5000-group pages, but the DELETE inside each per-page transaction is **not page-scoped**: it deletes every `1h` row `< cutoff`. After page 1 commits, page 2 finds nothing and the loop exits silently — groups beyond the first 5000 are destroyed un-promoted, and the raw syslog behind them was already deleted when the hourly summaries were created. This is exactly the 2026-06-23 M2 bug, whose fix is documented in `aggregateSyslogToSummary` (`syslog_agg.go:101-107`, delete moved AFTER the loop) — the promote step did not get the same fix.
- **Fix:** mirror the sibling: single `WHERE interval_type='1h' AND timestamp < ?` delete after the pagination loop completes without error.

### H4. flow_rollups '1d', flow_detections, and flow_agent_drops have no retention path — unbounded growth on the DB that syslog once filled
- **server** · `internal/database/cleanup.go:219-226`
- `CleanupOldData` covers `flow_samples` and `flow_if_counters` but none of the other sFlow-analytics tables. Terminal `1d` rollups are keyed by the full conversation tuple — one row per distinct conversation per day, 10^5–10^6 rows/day on a busy network, forever. `flow_detections` appends every 5-min cycle and only ever gets an `acknowledged` flip. `flow_agent_drops` shares the gap (latent: `SaveAgentDrops` has no production caller yet — see M2). None is partitioned, so the eventual cleanup will be the painful full-table-DELETE shape already lived through with `syslog_messages`. Violates invariant 9.
- **Fix:** cleanup entries for `flow_rollups` (`interval_type='1d'` older than `RETENTION_FLOW_ROLLUP_DAYS`), `flow_detections` (on `detected_at`), `flow_agent_drops` (on `window_start`), with `RETENTION_*` knobs.

### H5. IRC sendAutoStatus holds Manager.mu.RLock across blocking Privmsg sends — an IRC outage wedges admin handlers, alert delivery, and graceful shutdown
- **server** · `internal/irc/bot.go:282`
- `sendAutoStatus` (every 30s) holds `m.mu.RLock` while running the N+1-query statusFn AND `conn.Privmsg` per status line. In the pinned go-ircevent version, `pwrite` (buffered 10) loses its consumer during reconnects and is *replaced* on reconnect — a sender parked on the old channel blocks forever, and the `DISCONNECTED` callback that would nil `b.Conn` never fires in this library version. Once >10 lines accumulate during an outage, statusLoop parks holding the RLock; the next `m.mu.Lock` caller (ReloadCommands/RestartBot from admin HTTP handlers) blocks, and RWMutex writer-queueing then hangs every subsequent RLock (SendToChannel alert delivery, Manager.Stop) — hung admin requests pile up and shutdown hangs until SIGKILL.
- **Fix:** snapshot bots/channels under RLock, release, then send; add per-send timeouts; poll `conn.Connected()` instead of relying on the never-fired DISCONNECTED callback.

### H6. Collector per-source rate-limiter idle eviction can never fire — a spoofed-source flood permanently poisons the limiter
- **collector** · `internal/ratelimit/ratelimit.go:164`
- Token refill happens only lazily inside `take()`, so an idle bucket's stored tokens are frozen at its last post-take value — always `< burst`. The eviction predicate `b.tokens >= l.burst` is therefore unsatisfiable: `evictOneIdleLocked` is dead code and `IdleTTL` a dead knob (the package doc's reclaim claim is false; `TestIdleEviction` passes for the wrong reason). After a >8192-spoofed-IP flood the map fills forever: every datagram from any NEW source (including a legitimately renumbered firewall) runs a futile O(256) scan under the shared per-packet mutex — serializing all SO_REUSEPORT workers exactly when the defense matters — and is admitted under the global bucket only, which a sustained flood exhausts, starving legitimate new senders until restart.
- **Fix:** evict on computed effective refill (`tokens + elapsed*rate >= burst`) or on `idle > TTL` alone; strengthen the test to assert the new source got a per-source bucket.

### H7. Collector queue replay loads the entire on-disk spool (up to 1 GiB/queue) into RAM at startup — OOM crash-loop after the outage the queue exists to survive
- **collector** · `internal/relay/queue/queue.go:141`
- `replay()` copies every key+value in the BoltDB bucket into a slice before deciding which `MaxMem` items stay in memory. Disk cap defaults to 1 GiB, ×7 queues. Server down for days → spool fills (by design) → collector restarts → `Open→replay` allocates ~1 GiB+ heap for one queue. On memory-constrained probe hosts (the documented Synology NAS deployment) this OOM-kills the process, which restarts and OOMs again — and the crash loop prevents the drain that would shrink the spool.
- **Fix:** iterate the cursor backward collecting only the newest `MaxMem` values; compute diskSize with a length-only pass.

### H8. Fresh Docker deploy crash-loops: entrypoint never chowns the /data bind mount and fwmon-api log.Fatalf's persisting the auto-generated admin password
- **server** · `entrypoint.sh:168` (+ `docker-compose.yml:26`, `cmd/api/main.go:270`)
- With no `ADMIN_PASSWORD` set (the README first-run path), main takes the auto-generated-password branch and must write `/data/.admin-password`. But `/data` is a bind mount Docker auto-creates root:root 0755; the image's build-time chown is shadowed, and the entrypoint's runtime chown targets only `/data/firewall-mon.db*` (matches nothing on the PG image) and `/config` — never `/data` itself. The su-exec'd `fwmon` user gets EACCES → `log.Fatalf` → `restart: unless-stopped` produces a permanent first-boot crash loop for a brand-new operator.
- **Fix:** in entrypoint (runs as root) `chown fwmon:fwmon /data` non-recursively (leaving pgdata postgres-owned), or point SECRETS_DIR at the already-chowned `/config`, or seed ADMIN_PASSWORD into the generated config.env like JWT_SECRET_KEY.

### H9. Poller advisory work-lock is released on a different pooled connection — silent no-op release makes a SINGLE poller skip its own poll/rollup/detect/cleanup ticks
- **server** · `internal/database/database.go:429-456`
- `pg_try_advisory_lock`/`pg_advisory_unlock` are session-scoped, but `TryAcquirePollerWorkLock`/`ReleasePollerWorkLock` issue them through GORM's pool, so the unlock routinely lands on a different backend than the lock. `pg_advisory_unlock` on a non-owning session returns `false` with a WARNING — not a SQL error — so the `err != nil` check never fires. The lock stays held by an idle pooled conn until recycled (≤5 min); the next tick's probe returns false and `runUnderLeaderLock` logs "another poller holds the work lock" and skips the ENTIRE tick — polling, offline detection, rollup, flow-detect, threat feeds, cleanup — in a single-poller deployment, chronically and silently, with a log that misattributes it to a second poller. The sibling `AcquireAPISingletonLock` (`database.go:469-495`) documents this exact hazard and pins a `sql.Conn` — the poller lock is the one advisory lock that skips the pattern.
- **Fix:** pin one `*sql.Conn` for acquire, stash it, release on the SAME conn, then Close; also check `pg_advisory_unlock`'s boolean.

### H10. Direct-link connection traffic ships CUMULATIVE interface counters in the per-bucket-delta chart contract — orders-of-magnitude inflated transfer/Mbps
- **server** · `internal/database/connection_detail.go:662`
- `GetConnectionTraffic`'s direct-family path (ethernet/lag/l2vlan/bridge/wan) sums `GetInterfaceChartWindow` buckets, which are AVG of `interface_stats.in_bytes/out_bytes` — documented **raw cumulative counters** (invariant: bandwidth math must use consecutive deltas). The tunnel path of the same endpoint returns LAG() per-bucket deltas. Both UI consumers (connection-detail page, diagram side panel) run the payload through `FwmonBwChart.normalizeDeltas`, treating cumulative octets as per-bucket transfer: a member interface with 2 TB cumulative InBytes renders every hour bucket as ~2 TB transferred / ~4.4 Gbps flat — monotonically growing garbage. The regression test (`connection_traffic_direct_test.go:48`) pins the wrong (pass-through) behavior; the JS comment "arrives as per-bucket deltas" is false for the direct family.
- **Fix:** delta consecutive buckets per interface server-side (clamp <0 to 0 for resets) BEFORE summing across interfaces; update the regression test.

---

## MEDIUM

### M1. Ingestion silently truncates flow/counter/ping batches to 1000 items — 200 OK, batch marked processed, tail permanently lost
- **server** · `internal/api/handlers/handlers_data.go:195` (+ collector `internal/config/config.go:108`)
- `samples = samples[:1000]` with no log/alert, then 200 + `markBatchIfOK`, so the collector's dedup/retry can never resend the tail. The collector's `PROBE_MAX_BATCH_SIZE` is unclamped — any operator tuning it above 1000 (natural for a high-rate site draining a backlog) loses every batch's tail invisibly. The traps path records a truncation alert; flows/counters/pings record nothing.
- **Fix:** 413 on oversize (collector re-chunks), or process all rows; clamp the collector knob; log + RecordProbeDataTruncation.

### M2. samplingBackoffDetector reads flow_agent_drops, which nothing in production writes — sFlow drop monitoring silently inert (invariant 2)
- **server** · `internal/detect/detectors.go:130` (+ `internal/database/agent_drops.go` TODO)
- `SaveAgentDrops` has only test callers; the promised 1-minute rollup of `FlowSample.Drops` into `flow_agent_drops` was never built (the doc comment admits it's a TODO). Per-sample `Drops` IS persisted into `flow_samples` but nothing reads that column. An overloaded agent drops samples in prod → detector sees 0 rows → no SFLOW_SAMPLING_BACKOFF alert ever fires while operators believe drop monitoring is active. Traffic under-reporting goes unnoticed — the condition the drops work was meant to catch.
- **Fix:** aggregate `Drops` by (agent, sampling_rate, minute) at ingest or in the 5-min rollup and upsert via `SaveAgentDrops`; regression-test the pipeline end to end.

### M3. Flow-detection re-alerts a one-shot finding 2–3× and a persistent one every ~5 min; a CooldownMinutes=0 policy row means per-cycle alert storms
- **server** · `cmd/poller/main.go:355` (+ `internal/alerts/policy.go:151`)
- A 15-min detection window on a 5-min cadence re-detects one event in 3 consecutive cycles, and the default cooldown (5 min) equals the cycle period, so each re-detection notifies. `policy.go:151` copies `policy.CooldownMinutes` without the `>0` floor that site/device overrides get, so a policy row with 0 gives a guaranteed per-cycle storm for every SFLOW_* type. No DB restart backstop in `ProcessFlowDetection` — a poller restart re-fires every still-detected finding at once.
- **Fix:** default SFLOW_* cooldown ≥ the window length; apply the `>0` guard; dedupe persisted detections on (dedup_key, overlapping window).

### M4. Threat-intel Matcher.Match is an O(n) scan called twice per flow sample on the ingest hot path
- **server** · `internal/threatintel/threatintel.go:80`
- Flat `[]entry` scanned to the end on every miss (the common case), twice per sample, synchronously in `ReceiveFlowSamples`. With THREAT_FEEDS_ENABLED the default bundle is ~40–70k prefixes (feeds allow 500k each): ~0.3–0.7 ms per non-matching sample ≈ a full core at ~2k samples/sec — two orders of magnitude off the 100k/sec target; ingest slows, collector pushes time out, BoltDB backlog grows.
- **Fix:** longest-prefix-match structure — per-prefix-length maps keyed on masked addr (~O(24) lookups) or a binary radix trie; build once in New, lock-free lookup.

### M5. UpsertThreatIntelBatch has no in-batch (cidr,source) dedup — PG error 21000 aborts the whole feed; indicators then TTL-expire out silently
- **server** · `internal/database/threat_intel.go:53` (+ `internal/threatfeed/threatfeed.go:143`)
- `normalize()` masks prefixes, so distinct feed lines collapse to identical (cidr,source) pairs; repeated lines are common in aggregate lists. PostgreSQL rejects a statement where two rows hit the same ON CONFLICT target ("cannot affect row a second time"), and `CreateInBatches` wraps all chunks in one transaction, so the WHOLE feed rolls back; `runThreatFeedSync` just logs. Every sync fails → after the 14-day TTL that feed's coverage silently drops to zero. SQLite tolerates it, so dev/tests pass while prod PG fails (invariant 4).
- **Fix:** dedup by (CIDR, Source) before insert.

### M6. Direction() classifies multicast/broadcast/unspecified as external — false C2-beacon and data-exfil detections from LAN chatter
- **server** · `internal/classify/classify.go:219`
- `privateNets` covers RFC1918/loopback/link-local/CGNAT/ULA only. SSDP/mDNS to 239.255.255.250 (small, perfectly periodic) is stamped Outbound and matches the c2_beacon candidate query — recurring false "C2 beacon" detections for every chatty IoT/UPnP host; internal IPTV multicast bytes count toward data_exfil; DHCP DISCOVER (0.0.0.0→255.255.255.255) lands in "external transit".
- **Fix:** treat `IsMulticast()`, `IsUnspecified()`, and 255.255.255.255 as local scope; regression-test 239.255.255.250, ff02::1, 255.255.255.255, 0.0.0.0.

### M7. Probe lifecycle not enforced: rejected probes re-approve themselves via register; heartbeat resurrects decommissioned probes; validateProbe ignores enabled/decommissioned_at
- **server** · `internal/api/handlers/handlers_probes.go:548` (RegisterProbe), `:673` (ProbeHeartbeat), `:780` (validateProbe)
- RegisterProbe (unauthenticated, key-based) short-circuits only when already approved+online; otherwise it unconditionally writes `approval_status='approved', status='online'` — a probe the admin explicitly REJECTED (RejectProbe leaves the key valid) restores itself by re-POSTing register. ProbeHeartbeat authenticates by bearer key only and unconditionally writes online+last_seen, so a still-running collector permanently resurrects a decommissioned probe — immune to the v0.10.521 stale sweep because last_seen stays fresh. validateProbe checks only `approval_status=='approved'`, so disabled/decommissioned probes keep full data ingestion, and each POST refreshes last_seen/last_data_received.
- **Fix:** register returns 403 for rejected / 409 for decommissioned; heartbeat and validateProbe refuse when `!Enabled || DecommissionedAt != nil || ApprovalStatus=='rejected'`.

### M8. IRC event callbacks read b.Conn without the mutex on unrecovered library goroutines — Stop/Restart racing a PRIVMSG nil-derefs and crashes fwmon-api
- **server** · `internal/irc/bot.go:460` (onPrivmsg), `:521` (handleCommand), `:417-429`, `:608-611`
- `b.Conn` is nil'd under `b.mu` by Stop/onQuit, but callbacks read it lock-free, and go-ircevent runs each callback in a bare `go func` with NO recover — the REL-01 SafeGo containment doesn't cover them. Admin hits RestartBot while a `!status` callback is mid-flight (multi-query statusFn widens the window) → nil-deref panic in a library goroutine → whole process down.
- **Fix:** `defer logging.Recover(...)` first in every callback; copy `b.Conn` under RLock and nil-check (the pattern `SendMessage` already follows).

### M9. Threat-feed sync runs inline in the poller's single select loop — a blackholed feed host stalls polling, alerting, and offline detection for minutes
- **server** · `cmd/poller/main.go:406`
- `runThreatFeedSync` executes synchronously in a select arm: sequential fetches (90s ctx each, 5 default feeds) + up-to-500k-row upserts. Worst case ~7.5 min of fetch alone during which no SNMP polls run (ticks dropped), no alert evaluation, no stale sweeps, and stopChan isn't serviced (shutdown stalls).
- **Fix:** run in its own SafeGo goroutine with an already-running guard; keep the select loop free of network I/O.

### M10. GetNOCSnapshotFiltered ignores every query error and returns nil — DB failures broadcast an all-zero "live" NOC dashboard
- **server** · `internal/database/noc.go:204` (errors ignored from `:129` on)
- Every `.Error` is discarded; the function unconditionally returns `(snap, nil)`, so the hub's keep-last-good branch and the handler's 500 branch are dead code. A statement_timeout on the COUNT(DISTINCT) (known prod incident class) → wall-board shows 0 bps / "No sites or devices yet" with a green "● live" badge during exactly the incident window.
- **Fix:** propagate errors (or a hadErrors flag) so computeAndBroadcast keeps `h.latest`; rate-limited log.

### M11. NOC hub runs ~7–15 aggregate scans (incl. two COUNT(DISTINCT)) every 5s unconditionally — never gated on subscribers, duplicated on every ALLOW_MULTI_API follower
- **server** · `internal/api/handlers/noc.go:22`, `:63`
- `Run()` never consults `len(h.subs)`; `main.go:333` starts the hub on followers too (only IRC bots are gated). ~84+ flow-table aggregate scans/minute 24/7 against the same PG doing ingest, whether anyone watches or not; at the design target the 5-min window is ~30M rows and the tick just degrades.
- **Fix:** skip compute when no subscribers (compute on first subscribe); gate the hub to the singleton primary.

### M12. Tunnel/overlay connection traffic never populates bucket_ms — 3-mode charts fall back to a 60s interval, 60× inflated Mbps on 7d/30d
- **server** · `internal/database/connection_detail.go:800`
- The tunnel LAG() SELECT has no bucket_ms column, so every row serializes 0; `normalizeDeltas`' `medianIntervalSec()` falls back to 60 while 7d/30d buckets are HOURLY → exactly 60× inflated throughput (5-min cadence on minute buckets gives 5×). The direct path populates BucketMs, so direct vs tunnel show inconsistent rates side by side.
- **Fix:** backfill `rows[i].BucketMs = parseBucketToMillis(...)` like `GetInterfaceChartWindow`; JS fallback to parsing `d.bucket` when bucket_ms is 0.

### M13. Chart empty-state destroys the canvas permanently — later range switches throw and show a false error toast (two files)
- **server** · `cmd/api/static/js/admin-connection-detail.js:329`; `diagram-panels.js:333-335`
- The no-data branch replaces `canvas.parentElement.innerHTML`, removing the canvas; the next load finds null and either throws inside `FwmonBwChart.mount` (error toast on every 30s re-poll until reload) or silently never renders again (panel variant). `admin-flows.js:756-761` shows the intended re-create pattern — this is a missed sibling of an applied fix.
- **Fix:** re-create the canvas if missing on the data path, or render the empty message into a sibling element.

### M14. Webhook failure errors embed the full Slack/Discord webhook URL (secret token) and are logged (invariant 7)
- **server** · `internal/notifier/notifier.go:262`
- `postJSON` formats the destination URL into the error on non-2xx; Slack/Discord tokens live in the URL path. A revoked/rate-limited webhook writes the secret to container logs on every alert — hundreds of lines during a storm.
- **Fix:** log scheme+host (or channel label) + status only.

### M15. ReportScheduler and AlertManager guard the same *config.Config fields with two different mutexes — data race
- **server** · `internal/report/report.go:199` (+ `cmd/poller/main.go:1993-1998`)
- Same cfg pointer; `AlertManager.RefreshThresholds` writes `cfg.Alerts.Report*`/SMTP* under `am.mu` while `ReportScheduler` reads/writes the same strings under `rs.mu`. Two mutexes = no mutual exclusion; torn string headers can panic or send to garbage recipients.
- **Fix:** single owner — scheduler keeps a private snapshot, or one shared mutex for cfg.Alerts.

### M16. Collector TCP syslog has no rate limiting, no connection cap, no accept backoff — full bypass of the UDP defense on the same port
- **collector** · `internal/syslog/syslog.go:82`
- One goroutine + 64KB buffer per connection, unlimited; no `Limiter.Allow` anywhere on the TCP path; unparseable lines log unthrottled; persistent Accept errors (e.g. EMFILE caused by the flood itself) hot-loop. A hostile host on the monitored LAN exhausts FDs/memory or floods the queue at TCP line rate, sidestepping the per-source PPS budget entirely.
- **Fix:** same SetRateLimiter hook per line/read; connection semaphore; backoff on non-temporary Accept errors.

### M17. bbolt NoSync can corrupt (not just truncate) the spool on power loss, and one corrupt file makes ensureQueues permanently disable ALL seven queues
- **collector** · `internal/relay/queue/queue.go:92` (+ `relay.go:571-580`)
- With NoSync, meta/data pages hit disk in arbitrary order — bbolt's own docs warn the DB can corrupt on crash; the file's bounded-loss comment overpromises. On next start `Open/replay` fails and ensureQueues closes and nils EVERY queue on any single failure: the collector runs durability-disabled indefinitely (one WARNING), dropping all telemetry in every future outage until an operator hand-deletes the .bolt file.
- **Fix:** quarantine-and-recreate the corrupt file (`<name>.bolt.corrupt-<ts>`); disable only the failed queue; correct the comment.

### M18. Throttled fsync and per-item bolt transactions execute while holding the queue mutex shared by all UDP ingest workers
- **collector** · `internal/relay/queue/queue.go:271`
- Above ~333 samples/s sustained (MaxMem 10000 / 30s drain) the memory tier is in permanent overflow, so every Push pays a bolt COW transaction under `q.mu`, and up to once per 2s one Push runs `db.Sync()` — a full-file fsync of a potentially ~1 GiB spool — while holding the lock. Every worker blocks, kernel socket buffers overflow, datagrams drop silently: the M7 stall reduced in frequency but moved onto a global lock, firing exactly under flood/outage conditions.
- **Fix:** background ticker for Sync (or release q.mu around it); batch overflow evictions.

### M19. Idempotency batch IDs are re-minted on requeue, and the direct-send metric path has no batch ID at all — timeout-after-commit duplicates rows
- **collector** · `internal/relay/relay.go:1543` (+ server-side M26/L17)
- `newBatchID()` is per-`sendBatch`-call: if all 3 in-call retries fail transport-level after a server commit, the requeued items are re-chunked and re-sent under a FRESH ID the server can't match. The metric path (`doDirectSend`/`drainMetricQueue`) sends no `X-Probe-Batch-ID` — replayed system-status/interface-stats/VPN payloads insert duplicate rows; duplicated cumulative counters at near-identical timestamps skew delta-based bandwidth math.
- **Fix:** assign the key at first enqueue (store in the envelope) and reuse across cycles; add the header to direct sends (server: L17).

### M20. Collector always advertises schema v2 with no fallback on HTTP 426 — registering against a v1 server (v0.10.382–v0.10.512) crash-loops and stops all site telemetry
- **collector** · `internal/relay/relay.go:714` (+ `cmd/collector/main.go` register retry → `log.Fatalf`)
- A handshake-aware v1 server rejects v2 with 426 before auth; the collector retries the identical request 6× then Fatalf's → container restart policy = permanent crash loop, even though the collector speaks v1 perfectly (counter samples are already gated on negotiated ≥2). Live prod lags HEAD, so collector-first upgrades are realistic; the v0.10.513 changelog's "v2 collector ↔ v1 server keep working unchanged" claim is false for registration.
- **Fix:** on 426, re-register at the highest mutually supported version; and/or server clamps to `min(requested, max)` instead of rejecting.

### M21. RETENTION_SYSLOG_CRITICAL_DAYS still defaults to 0 (keep forever) — the syslog-bloat incident fix lives only in docker-compose.yml
- **server** · `internal/config/config.go:330` (+ `config.env.example`)
- The documented root cause of the 2026-05 syslog incident (severity≤5 kept forever; FortiGate traffic logs are severity 5) is still the code default. `deploy.sh` seeds `config.env.example` verbatim on native installs, and that file has no RETENTION_* syslog lines at all — every non-compose deployment path replays the incident.
- **Fix:** default 30 in code (matching compose), or at minimum add the var with rationale to config.env.example.

### M22. Docker image build never builds (or freshness-checks) Tailwind — `git pull && docker compose build` silently ships a stale committed tailwind.css
- **server** · `Dockerfile:24` (+ `.github/workflows/ci.yml`)
- v0.10.527 wired npm into make/deploy.sh only; the Dockerfile COPYs the committed artifact, and CI has zero npm/tailwind references, so a styles.css edit without regeneration passes green and the documented compose upgrade path embeds the stale css — the exact v0.10.500→526 regression shape, with no error anywhere.
- **Fix:** node stage in the Dockerfile, or a CI job that regenerates and fails on `git diff --exit-code` of tailwind.css.

### M23. docs/ENV-VARS.md contradicts the code on three vars (trap community "required", INSECURE_SKIP_VERIFY accepted values, queue disk-path default)
- **collector** · `docs/ENV-VARS.md:46`, `:20`, `:91`
- (1) PROBE_SNMP_TRAP_COMMUNITY is documented "Required — empty rejected at startup" but the code treats empty as accept-ANY-community (warning only) and the Dockerfile defaults it to "" — the shipped container accepts every community on 162/udp. (2) PROBE_INSECURE_SKIP_VERIFY documents `1`/`yes` but the code matches only literal `"true"` — doc-following operators get silent TLS failures. (3) The "production default leaves disk path empty" prose is wrong: the Dockerfile sets `/queue`.
- **Fix:** correct the doc (source wins); route the bool through parseBool; consider fail-fast on empty trap community to match the server posture.

### M24. LINK_UP trap from any device auto-resolves and auto-acknowledges LINK_DOWN alerts of EVERY device — direct trap path never resolves DeviceID
- **server** · `internal/alerts/alerts.go:590` (+ `internal/snmp/trap.go:190-311`, `cmd/trap-receiver/main.go:132-139`)
- Direct traps carry DeviceID=0, and sendRecovery's UPDATE matches `device_id=0 AND alert_type='LINK_DOWN' AND metric_name='snmp_trap'` — which is ALL direct-trap LINK_DOWNs. Firewall B's LINK_UP closes firewall A's still-open LINK_DOWN with "Auto-resolved". Same root cause: per-device alert policies never apply to direct traps.
- **Fix:** resolve DeviceID from trap.SourceIP (as the poller pipeline does); if unresolvable, scope the resolve by source IP.

### M25. trap-receiver never prunes AlertManager.lastAlert — unbounded growth keyed by spoofable source IPs
- **server** · `cmd/trap-receiver/main.go:129` (+ `internal/alerts/alerts.go:194,203,434`)
- `PruneExpiredCooldowns` is called only from the poller; the trap-receiver's own AlertManager never evicts. The per-IP token map is bounded, but its idle sweep re-admits ~10k new IPs per 5-min window; each spoofed IP carrying a known warning/critical OID with the correct community adds a permanent lastAlert entry (~2.8M/day max, hundreds of MB), each also producing an alert row + notification (cooldown is per-key, so unique IPs bypass it).
- **Fix:** prune ticker in the trap-receiver; cap lastAlert with LRU eviction inside AlertManager so every embedder is safe by construction.

### M26. SaveSystemStatuses turned resilient per-row saves into an all-or-nothing multi-row INSERT — one bad row 500s the batch and poisons the collector's retry queue
- **server** · `internal/database/telemetry.go:21` (+ `handlers_data.go:600-604`)
- v0.10.484 (M5) batched the insert; on partitioned prod PG one row outside the partition range (clock-skewed collector, or a spillover replay after its month's partition was dropped — there is no DEFAULT partition) fails the entire INSERT → 500. The collector buffers 500s as retryable and `drainMetricQueue` requeues the poison item and stops the drain cycle on each hit: system-status ingestion halts entirely (old behavior: log-and-continue, 200), and drains of the other metric types are repeatedly cut short. Same sibling class as M5.
- **Fix:** on batch failure fall back to per-row (log-and-skip) with 200 + saved count, or 400 for never-succeeds rows so the collector drops them; longer-term a DEFAULT partition or server-side timestamp clamp.

### M27. Device-detail chart prefers sFlow whenever ≥2 buckets exist anywhere in the window — stale/partial sFlow hides live SNMP bandwidth
- **server** · `cmd/api/static/js/admin-device-detail.js:874`
- No recency/coverage check: sFlow that died 3h into an incident still wins the 24h view (chart silently ends 3h ago); a 30-min sFlow trial last week claims the whole 7d/30d view; zooming past sFlow coverage silently flips source (different counter baseline). No UI override to force SNMP.
- **Fix:** accept sFlow only if its last bucket is within ~2 intervals of the window end; otherwise pick the series with the newer last bucket.

### M28. CheckProbeDataFlow includes decommissioned probes — PROBE_DATA_LAG alerts fire forever after a probe is retired
- **server** · `internal/alerts/alerts.go:928`
- `GetApprovedProbes` selects on approval_status only, and decommission deliberately doesn't change it. After the collector is shut down, lag grows past the default 60-min threshold and the alert re-fires every cooldown, indefinitely — the documented soft-decommission path produces a permanent alert stream until the operator hard-deletes the probe, which decommission exists to avoid.
- **Fix:** skip `DecommissionedAt != nil` (and arguably `!Enabled`) in CheckProbeDataFlow.

### M29. Trap rate-limiter drops (token exhaustion and map-cap lockout) are completely silent — despite three code/CHANGELOG claims of drop visibility
- **server** · `internal/snmp/trap.go:161` (claims at `trap.go:89-91`, `cmd/trap-receiver/main.go:117`)
- `allow()==false` → bare return: no log, no metric, though comments assert "the operator sees a clear rate-limited pattern in the logs" and "/metrics carries the trap rate-limiter". A legit link-flap storm past 10/sec loses traps tracelessly; worse, a spoof flood filling the 10k-bucket cap silently rejects every NEW legitimate device IP for up to 5 min — real LINK_DOWN/HA-failover traps vanish during exactly the event traps exist to report.
- **Fix:** `fwmon_trap_ratelimit_drops_total{reason}` counter + throttled summary log line.

### M30. A panic in the poller's Start() loop is swallowed by SafeGo with no restart — zombie poller behind green /healthz and /readyz
- **server** · `cmd/poller/main.go:1980`
- The entire ticker select loop (poll, rollup, flow-detect, feeds, cleanup, sweeps) runs in one SafeGo goroutine; Recover logs and swallows, nothing restarts the loop. readyz only pings the DB and healthz is unconditional 200, so any panic in one tick's work (exactly the new-code class shipped in R1–R6) permanently halts the daemon's entire purpose while orchestrators and Prometheus see green. Crashing would be safer — the supervisor would restart it.
- **Fix:** restart-with-backoff for the loop goroutine, or a lastCycleCompleted timestamp that fails readyz when stale (>3× interval).

---

## LOW

### L1. GetFlowStats estimated_bytes double-scales by AvgSamplingRate (bytes are already sampling-scaled at ingest)
- **server** · `internal/database/flows.go:260-261` — no UI consumer yet, but the field over-reports by ~the sampling rate, and the stale comment at `:215` invites re-introducing double-scaling. Fix: `EstimatedBytes = TotalBytes` (or drop it); fix the comments.

### L2. PruneExpiredCooldowns evicts on a fixed 10-min threshold — truncates operator-set cooldowns >10 min for event-type alerts once per day
- **server** · `internal/alerts/alerts.go:439` — track effective cooldown per key and evict past it; run hourly.

### L3. threatfeed.Parse ignores bufio.Scanner errors — silently truncated feeds logged as successful syncs
- **server** · `internal/threatfeed/threatfeed.go:137` — a >1 MiB line (HTML error page with 200) stops the scan silently; indicators past it TTL-expire. Fix: return `sc.Err()`; treat scan errors as fetch failures.

### L4. Partial GeoLite2 open logs "enrichment disabled" while half of it runs; mmap'd .mmdb has no reload path (in-place overwrite risks SIGBUS)
- **server** · `internal/classify/geo.go:38` (+ `handlers.go:52-53`) — periodic mtime check + atomic swap; fix the log; document rename-not-overwrite.

### L5. SSE stream clears the write deadline — a zero-window client pins its handler goroutine in a blocked Write indefinitely
- **server** · `internal/api/handlers/noc.go:156` — set a rolling per-write deadline instead.

### L6. Malformed ?focus= percent-encoding throws uncaught URIError — NOC page fails to init; Connections page wipes the just-rendered map
- **server** · `cmd/api/static/js/admin-noc.js:410`, `admin-main.js:2711` — wrap decodeURIComponent in try/catch.

### L7. Critical-alert HTML part declares quoted-printable but writes the body raw — RFC-illegal; compliant QP decoders mangle `=XX` sequences in alert text
- **server** · `internal/notifier/notifier.go:376` — use `mime/quotedprintable.NewWriter`, or declare 8bit like the no-attachment branch.

### L8. SVG chart renderers divide by len(series)-1 with only a len==0 guard — 1-point series emits NaN path coordinates, chart drops
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
- **server** · `internal/models/models.go:847` — add `IfDirection` + migration, or remove from the collector struct.

### L13. Flow-counters queue drains without re-checking the negotiated schema version — after a server rollback, endless 404s are misread as probe-not-found (approval flap + re-register every sync)
- **collector** · `internal/relay/relay.go:1353` — skip/discard the drain when negotiated <2; treat endpoint-404 as "unsupported, drop batch" not "probe deleted".

### L14. config.env.example ships SNMP_TRAP_COMMUNITY=public and deploy.sh seeds it verbatim — native installs accept the world's best-known community on exposed 162/udp
- **server** · `config.env.example:119` — ship it empty/commented so the AUDIT-012 startup rejection actually fires.

### L15. /readyz uses unbounded sql.DB.Ping() and the observability server has no write timeout — a wedged PG hangs probes and leaks a goroutine per scrape
- **server** · `cmd/poller/main.go:1982` (+ `internal/metrics/metrics.go:117`) — PingContext with a 2s deadline; WriteTimeout/TimeoutHandler on the mux.

### L16. updatePingStatsBatch is an unlocked read-modify-write — concurrent folds for the same (device,target) lose or double-count a whole batch in the lifetime series
- **server** · `internal/api/handlers/handlers_data.go:427` — atomic UPDATE (`samples = samples + ?` …) or SELECT FOR UPDATE; pre-existing pattern, but the batch rewrite widened the loss unit from one sample to the batch.

### L17. ReceiveSystemStatuses (and the other 8 direct-send metric endpoints) have no batch idempotency on either side — timeout-after-commit replays insert duplicate rows
- **server** · `internal/api/handlers/handlers_data.go:568` — add batchDedupCheck/markBatchIfOK server-side and X-Probe-Batch-ID to collector direct sends (pairs with M19); duplicates skew per-device history charts, and M26's new 500 path makes replays far more frequent at HEAD.

### L18. Device-detail sFlow bandwidth chart is unreachable for devices that never had an SNMP interface snapshot — precisely the devices the feature was built for
- **server** · `internal/api/handlers/handlers_devices.go:346` — the interfaces array comes only from interface_stats, so SNMP-host-restricted devices pushing sFlow if_counters render zero interface cards and the sflow-chart endpoint is never called. Fix: union the interface list with DISTINCT if_index from flow_if_counters.

### L19. loadInterfaceChart/loadTunnelChart lack an in-flight staleness guard — overlapping responses leak Chart.js instances and overwrite live state with stale buckets
- **server** · `cmd/api/static/js/admin-device-detail.js:839` — the fd3315d fix class, missed on these two loaders (60s poll + range clicks make overlap routine). Fix: per-target request token + destroy any instance already in the slot.

### L20. "Awaiting data from probe…" banner appended on every 60s poll with no dedup — unbounded stacking on devices awaiting their probe
- **server** · `cmd/api/static/js/admin-device-detail.js:150` — guard the append / assign instead of insertAdjacentHTML; remove when data arrives.

### L21. Flows showChartEmpty() wipes the canvas without destroying charts.bandwidth or clearing lastBwData — theme toggle resurrects the previous filter's chart over "No data"
- **server** · `cmd/api/static/js/admin-flows.js:798` — mirror renderBandwidth's own empty path (destroy + null + clear lastBwData).

### L22. AddThreatIntel stores the CIDR un-normalized while the matcher masks it — equivalent prefixes duplicate, and deleting the visible row leaves the hidden one enforcing
- **server** · `internal/api/handlers/handlers_analytics.go:499` — canonicalize with `.Masked().String()` before storage; displayed scope ≠ enforced scope otherwise.

### L23. detect_beacon_max_cv / detect_capacity_threshold accept 'NaN' — persisted and displayed as active but silently ignored by the poller
- **server** · `internal/api/handlers/handlers_settings.go:177` — NaN fails every range comparison, passing write-side guards and failing the poller's `v > 0`. Fix: reject non-finite, or invert checks to `!(v > 0 && v <= max)`.

### L24. GetFlowSamples binds the raw protocol query string against a numeric column — non-numeric value 500s on PG (SQLite silently matches nothing)
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
