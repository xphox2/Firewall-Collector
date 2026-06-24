# Internal Audit — Consolidated Report (2026-06-22)

**Scope:** Both repos in the Firewall-Mon / Firewall-Collector pair.
**Skills:** `design-patterns` (Gang of Four) + `taocp` (Knuth Vol 1–4B).
**Project lessons applied:** `tasks/lessons.md` invariants.

```
Firewall-Mon       →  E:\Golang\OpenCode\Firewall-Mon        (server)
Firewall-Collector →  E:\Golang\OpenCode\Firewall-Collector  (production probe)
```

## Per-repo detail

| Repo | Skill | Grade | Findings | Report |
|---|---|---|---|---|
| Server | design-patterns | **B** | 16 (1 critical, 4 high, 5 medium, 6 low) | `docs/audit-2026-06-22-design-patterns.md` |
| Server | taocp | **B-** | 23 (3 critical, 3 high, 5 medium, 12 low/info) | `docs/audit-2026-06-22-taocp.md` |
| Collector | design-patterns | **B+** | 15 (3 high, 4 medium, 8 low/wins) | `docs/audit-2026-06-22-design-patterns.md` |
| Collector | taocp | **B+** | 13 (2 high, 5 medium, 6 low/info) | `docs/audit-2026-06-22-taocp.md` |

---

## Cross-repo invariants — the wire contract

The two repos share a wire contract. Any mismatch here is a production bug on **both** ends.

| Invariant | Server | Collector | Status |
|---|---|---|---|
| 30s JSON HTTPS batches (wire shape) | receiver at `internal/api/handlers/handlers_data.go` ✓ | sender at `internal/relay/relay.go` ✓ | **PASS** |
| Wire field `omitempty` discipline (new fields optional, server tolerates absence) | `relay.go` parser ✓ | DTOs use `omitempty` on optional fields ✓ | **PASS** |
| sFlow `sampling_rate × bytes` multiplication | `sflow.go:324` stores unscaled `Bytes = uint64(frameLength)` — read path also unscaled | `sflow.go:301-309` multiplies correctly | **FAIL — server-side** |
| sFlow `drops` field surfaced | parser reads comment-only, never stores; no DB table; no NOC widget | parser reads and discards | **FAIL — both ends** |
| 100k samples/sec hot-path shape (SO_REUSEPORT, worker pool, pgx.CopyFrom, SetReadBuffer 8MB, per-agent token bucket, sync.Pool) | single goroutine, GORM `Create`, default kernel buffer, no token bucket | n/a (collector only ships parsed samples) | **FAIL — server-only, owned by Phase 2 of SFLOW-NOC-REDESIGN-PLAN** |
| Retry-backoff helpers reuse | n/a (server side; uses PG advisory locks for singleton work) | `doDirectSend` ignores the 1.2.127 `expBackoff` helper — hardcodes `time.Sleep(2*time.Second)` | **PARTIAL FAIL — collector-only** |
| `Authorization: Bearer` on probe→server | `handlers_probes.go:788` requires it via `subtle.ConstantTimeCompare` | every send adds `Authorization: Bearer ...` | **PASS** |
| CSPRNG for tokens/keys/nonces | `crypto/rand.Int(reader, big.NewInt(n))` (rejection sampling) — Lesson 3.1/3.5 PASS | `crypto/rand.Read` for batch IDs, `mrand.Intn(5000)` for jitter (Go 1.20+ auto-seeds; OK today, intent unclear) | **PASS** |
| Constant-time compare for auth secrets | `subtle.ConstantTimeCompare` + `hmac.Equal` | `subtle.ConstantTimeCompare` for SNMP community | **PASS** |
| CHANGELOG format | Keep-A-Changelog header reference + per-version `## [X.Y.Z] - DATE` sections at top, newest first (`TestChangelog_KeepAChangelogHeader_AUDIT110` was updated 2026-06-11 to enforce a concrete version at the top — NOT a `[Unreleased]` accumulator) | simple `## X.Y.Z - DATE`, newest first (no `[Unreleased]`) | **PASS (per-repo conventions match)** |

**Headline:** the **two critical cross-repo bugs** are (1) `sampling_rate × bytes` not multiplied on the server (every dashboard number is wrong by 1:N), and (2) `drops` field invisible on both ends (agent-side congestion undetectable). Both are owned by Phase 0 of `tasks/SFLOW-NOC-REDESIGN-PLAN.md` and currently unfixed.

---

## Headline findings — both repos

### Critical (3)

| # | Finding | Repo | Files |
|---|---|---|---|
| **C-1** | `Handler` struct in server is a **God Object** — 100+ methods across 9 files, 9 collaborators, late-binding setters guarded by `sync.RWMutex` | server | `internal/api/handlers/handlers.go:24-35` + 8 sibling files |
| **C-2** | sFlow `Bytes` field stored unscaled; read paths use `SUM(bytes)` without the sampling_rate multiplier — every top-N and throughput chart is wrong by 1:N | server | `internal/sflow/sflow.go:324`, `internal/database/flows.go:188-192, 226, 326-377, 559-562` |
| **C-3** | sFlow `drops` field is read-and-discarded end-to-end; agent-side congestion is invisible | both | server: `internal/sflow/sflow.go:258,265,316-326`; `internal/relay/relay.go:68-95`; `internal/models/models.go:673-700`. collector: `internal/sflow/sflow.go:218-227` |

### High (6)

| # | Finding | Repo | Files |
|---|---|---|---|
| **H-1** | `Collector` struct (1,728 lines, 33 methods, 4 mutexes, package-level globals) is a **God Object** — recent 1.2.124–1.2.129 series is the right time to split | collector | `cmd/collector/main.go:93-152, 264-1678` |
| **H-2** | Three near-duplicate retry/approval/registration loops in relay — 1.2.127 extracted the *delay* but not the *policy*; `doDirectSend` was missed entirely and hardcodes `time.Sleep(2*time.Second)` | collector | `internal/relay/relay.go:885-931, 1238-1290, 1510-1555` |
| **H-3** | Approval gate (`!c.approved.Load() { tryReregister() }`) duplicated 10+ times in collector relay; classic Decorator candidate | collector | `internal/relay/relay.go` lines 886, 983, 1033, 1389, 1558, 1578, 1598, 1620, 1644 |
| **H-4** | SNMP OID prefix matching is O(n × m) — 22 `strings.HasPrefix` checks per PDU (~13,000 calls/s at fleet scale); `map[string]handler` would be O(1) | collector | `internal/snmp/snmp.go:283-374` + 5 vendor parsers |
| **H-5** | Single-goroutine sFlow UDP receiver with default kernel buffer; design target 100k samples/sec requires SO_REUSEPORT + worker pool + SetReadBuffer(8MB) + per-agent token bucket | server | `internal/sflow/sflow.go:114-171` |
| **H-6** | Bulk insert uses GORM `Create` not `pgx.CopyFrom`; pgx is already a transitive dependency on disk but no `import "github.com/jackc/pgx/v5"` exists | server | `internal/database/ping.go:189` |

### Medium (high-signal subset)

| Finding | Repo |
|---|---|
| `VendorProfile` service-locator singleton with init-order coupling (non-deterministic `DefaultVendor` map iteration) | server |
| `database.AppVersion` process-global var (should be constructor arg) | server |
| `irc.Bot` state is implicit booleans + status strings, not a real State machine; `RestartBot` race | server |
| AlertManager has 4 near-identical `Check*Status` methods (parallel per-method boilerplate) — Strategy/Template Method candidate | server |
| `internal/database` package is a 54-file bounded-context violation; "split-per-domain into packages" is the next refactor | server |
| `sort.Slice` used where `sort.SliceStable` is needed for top-N stability (Lesson 5.2) | server |
| Circuit breaker scattered as integer count + 3 transition points; State pattern candidate | collector |
| Probe lifecycle FSM implicit (`approved atomic.Bool` + rate-limited/cooldown branches in `tryReregister`); State pattern candidate | collector |
| Three failed-batch requeue paths have diverged (revision queue re-implements loop instead of using `drainAndSend`) | collector |
| `getIndexFromOID` uses `fmt.Sscanf` for single-integer parsing — reflection-driven, alloc-prone | collector |
| `reregisterAttempts` incremented from two sites with no shared invariant — heartbeat branch can race with `tryReregister` | collector |
| `getOrCreateInterface` value-copy + write-back (`map[int]InterfaceStats`); sibling `getOrCreateVPN` already uses pointer semantics — inconsistency | collector |

---

## Cross-cutting patterns — wins on **both** repos

These are the patterns each repo applies correctly. Worth protecting in future PRs.

| Pattern | Server (evidence) | Collector (evidence) |
|---|---|---|
| **Decorator** (cross-cutting concern) | middleware chain `cmd/api/main.go:467-491`; `audit.Middleware`; `metrics.Middleware`; CSP-nonce per-request | `safego.Go` / `safego.AfterFunc` on every long-lived goroutine (17 sites); recoverable panic wrapper |
| **Strategy** (genuine N>1) | `internal/snmp/vendor.go` registry (8 vendors); `internal/configdiff/normalize.go` registry | `internal/snmp/vendor.go` (8 vendors) + 6 optional capability interfaces (`DialupVPNProvider`, `SSLVPNProvider`, `HAProvider`, …) |
| **Adapter** (external boundary) | `internal/notifier/notifier.go` (SMTP/Slack/Discord/Webhook); `internal/snmp/snmp.go` over `gosnmp`; `internal/relay/relay.go` DTOs from wire | `internal/snmp/snmp.go` over `gosnmp`; `internal/sflow/sflow.go` (sFlow v5 decoder); `internal/syslog/syslog.go` (RFC 5424 + FortiGate extension) |
| **Postgres advisory-lock Singleton** (distributed) | `internal/database/database.go:265-409` — 3 distinct keys (`apiSingletonLockKey`, `pollerWorkLockKey`, `startupMigrationLockKey`) | n/a (collector is stateless) |
| **Template Method via generic closures** | n/a directly | `sendMetric[T]` at `cmd/collector/main.go:1226` — 6 collapsed blocks |
| **Bounded-buffer batcher with deterministic shutdown** | `internal/database/batcher.go:23-143` (AUDIT-006 double-checked) | `internal/relay/queue/queue.go` — RAM + BoltDB two-tier (1.2.121 lock-fix) |
| **Multi-linked LRU (Knuth §2.25)** | `internal/api/middleware/middleware.go:42-100` — map + doubly-linked list, `maxEntries` cap, `MoveToFront` | n/a (different concern) |
| **Distributed circuit breaker / token-bucket** | `internal/snmp/trap.go:82-107` — `map[ip]*bucket`, `maxRateLimitedIPs=10000` cap | per-device `failCount` map with skip-on-3-failures |
| **Crypto discipline** | `crypto/rand.Int(reader, big.NewInt(n))` everywhere (no `rand() % n`); `subtle.ConstantTimeCompare` + `hmac.Equal` | `crypto/rand.Read` for batch IDs; `subtle.ConstantTimeCompare` for SNMP community; mTLS private-key permission check |
| **Error wrapping** | `fmt.Errorf("%w")` + `errors.Is` enforced by automated tests (AUDIT-080/081); 42 hits across `internal/database/**` | consistent across `internal/relay`, `internal/snmp` |
| **Atomic.Bool for lifecycle flags** | `internal/syslog/syslog.go:38,395`; `internal/sflow/sflow.go:71`; `internal/database/batcher.go:32-33` | `approved atomic.Bool` on relay client |
| **No hand-rolled sorts/searches/crypto** | no bubble sort, no hand-rolled binary search, no custom GCD — Lesson 4.29/5.1/6.1 PASS | same |
| **Property-based / regression-test discipline** | `TestChangelog_KeepAChangelogHeader_AUDIT110`; `cidr_audit148_test.go`; `fuzz_audit119_test.go`; `bench_audit124_test.go` | `ipv4FromTableIndex` 1.2.129 fix tested across clean/short/quirky/invalid; trap-community-redaction 1.2.123 pinned by test |

---

## Where each repo needs different attention

### Server needs execution, not design

The `tasks/SFLOW-NOC-REDESIGN-PLAN.md` is an excellent plan; the codebase has not caught up. The Phase 0 work (sampling_rate, drops, CopyFrom) and Phase 2 work (SO_REUSEPORT, worker pool, 8MB buffer, token bucket, sync.Pool) are the design target and the receiver is the bottleneck. Two structural cleanups also need to ship: (a) split `Handler` into per-feature handlers, (b) split `internal/database` into per-bounded-context packages.

### Collector needs structural consolidation, not new features

The recent 1.2.124–1.2.129 series shows measured, test-backed improvement. The two structural gaps are: (a) `Collector` is 1,728 lines and 33 methods — split into per-feature services (`Poller`, `SyslogBackupDebouncer`, `TFTPCoordinator`, `HostKeyObserver`, `Lifecycle`); (b) the three retry/approval/registration loops in relay should consolidate behind a `RetryPolicy` Strategy + `requireApproved` Decorator. The retry-backoff helper was extracted but `doDirectSend` was missed — that's the literal "use existing helpers" lesson violation.

---

## Unified priority action list

### P0 — ship the Phase 0 sFlow fixes (server + collector, both ends)

| Action | Repo | Effort | Owner |
|---|---|---|---|
| `Bytes = uint64(frameLength) * uint64(samplingRate)` at insert (`sflow.go:324`) | server | S | Phase 0 |
| Standardise read-path math: `SUM(bytes * sampling_rate)` in `flows.go` | server | M | Phase 0 |
| Replace `SaveFlowSamples` GORM `Create` with `pgx.CopyFrom` | server | M | Phase 0 |
| Add `Drops` field to `ParsedFlow`, `models.FlowSample`, `relay.FlowSample` (wire-side with `omitempty`) | server + collector | L | Phase 0 |
| `SaveAgentDrops` / `RecordSamplingRateChange` + `flow_agent_drops` table + NOC widget | server | L | Phase 0 |
| `doDirectSend` uses `expBackoff` (collector regression on the 1.2.127 refactor) | collector | S | any sprint |

### P1 — Phase 2 hot-path work + structural cleanups

| Action | Repo | Effort | Owner |
|---|---|---|---|
| `SO_REUSEPORT` + `SetReadBuffer(8MB)` + worker pool + per-agent token bucket + `sync.Pool` for `ParsedFlow` | server | L | Phase 2 |
| `internal/sflow/sflow.go:32-44` dead `FlowSample` struct — delete | server | XS | any sprint |
| Counter-sample parser (ifInOctets / ifOutOctets) + `flow_if_counters` table | server | L | Phase 1 |
| Split `Handler` into per-feature handlers; delete `mu sync.RWMutex` + setters | server | L | separate audit |
| Split `internal/database` into per-bounded-context packages | server | L | separate audit |
| Split `Collector` into `Poller` / `SyslogBackupDebouncer` / `TFTPCoordinator` / `HostKeyObserver` / `Lifecycle` | collector | L | separate audit |
| Consolidate 3 retry loops into `RetryPolicy` Strategy + `requireApproved` Decorator | collector | M | any sprint |
| SNMP OID prefix matching → `map[string]handler` (O(1) dispatch) | collector | M | any sprint |
| `getIndexFromOID` → hand-rolled digit loop (no `Sscanf`) | collector | S | any sprint |
| `getOrCreateInterface` → pointer semantics (match `getOrCreateVPN`) | collector | S | any sprint |
| Extract probe lifecycle into `RegistrationState` value type (State pattern) | collector | M | any sprint |

### P2 — incremental polish

| Action | Repo | Effort |
|---|---|---|
| `type AlertType string`, `type Severity string`, `type CommandType string` constants | server | M |
| `sort.Slice` → `sort.SliceStable` in `flows.go:315, 431`, `devices.go:262`, `report/model.go:245` | server | S |
| `RequestLogger` timing → remove (keep failure-only log; `metrics.Middleware` is the timing source) | server | S |
| Drop `validVendors` map (use `snmp.IsKnownVendor()`) | server | S |
| Rename `flow_rollups.sampling_rate_avg` → `sampling_rate_weighted_avg` to match plan §6.1 | server | S |
| `circuitbreaker.Breaker` per device | collector | M |
| `drainAndSend` accepts `perItemRetry` flag → drops inline `syncData` revision-queue loop | collector | S |
| `extractDeviceID` regex narrowed to fortigate-prefixed SD elements | collector | S |
| `parseDurationSeconds` logs warning on parse error | collector | S |
| `sFlow.readLoop` busy-wake fix (close-socket instead of 1s deadline) | collector | S |
| `mrand.Intn(5000)` for jitter → `crypto/rand.Int` (intent-explicit) | collector | S |
| `extractDeviceID` and `parseTimestamp` documented behaviour around fallbacks | collector | S |

### P3 — housekeeping

| Action | Repo | Effort |
|---|---|---|
| Delete `cmd/probe/` (or add deprecation README) | server | XS |
| Bump `internal/sflow` test coverage 8.5% → 50% → 100% (Phase 4) | server | L |
| Bump `cmd/collector` test coverage by adding seams | collector | M |
| `getEnv` duplicated between `cmd/collector/main.go:48-53` and `internal/config/config.go:103-108` — consolidate | collector | XS |

---

## Open questions for the team

1. **Is the `Handler` God-Object split in scope for a single PR, or does it deserve its own audit pass + roadmap entry?** Touches 9 files + every test that constructs `Handler` + the entire `setupRoutes` table.
2. **Is `internal/database` package split on the same roadmap as Phase 0?** It's a separate 54-file bounded-context violation; doing it before Phase 0 risks PR-conflict noise; doing it after risks Phase 0 propagating the god shape.
3. **Should `cmd/probe` deletion ship now (Phase 4) or wait for collector feature parity?** Lessons.md says "until then, treat as read-only legacy" — operators may be waiting for an explicit `then`.
4. **`extractDeviceID` regex matching any bracketed decimal** is documented as a known bug (1.2.90); is the test that pins the buggy behaviour going to be updated, or is the bug going to be marked "won't fix"?
5. **`Collector` God-Object split** — 1.2.124–1.2.129 has been the test-seam series. Is the per-feature service split next, or are there more seams to add first?
6. **`doDirectSend`'s 2-second constant backoff** — was it intentional (polls are periodic, not user-initiated, so constant backoff is fine) or an oversight? A 1-line comment would resolve it either way.
7. **The sFlow `drops` field** — is it actually meaningful on FortiGate exports? Quick packet capture would tell; if always zero, the simpler "ignore drops" implementation is defensible.
8. **The 429 status code is treated as non-retryable** in collector (`isRetryableStatus`) — usually means "back off and retry." Worth re-checking against the server's actual 4xx semantics.

---

## What we'd recommend as the next 30-day cycle

1. **Ship Phase 0 of the sFlow redesign** (sampling_rate × bytes, drops field, CopyFrom). This is the P0 critical work — every dashboard number is wrong until it lands. The plan is in `tasks/SFLOW-NOC-REDESIGN-PLAN.md`; the gap is execution.
2. **Land the `doDirectSend` retry-backoff helper fix** in collector — 2-line change + 5-line test, literal "use existing helpers" lesson.
3. **Land the OID-prefix-match → `map[string]handler`** refactor in collector — M effort, fixes a structural O(n×m) at fleet scale.
4. **Convert stringly-typed `AlertType` / `Severity` / `CommandType` to typed constants** — M effort, makes 6+ files compile-time-safer before the next alert type is added.
5. **Open a separate audit pass for the `Handler` and `internal/database` splits** — they're too large for this PR, but they're the highest-leverage structural cleanups the audit surfaced.

---

**Audit close.** No code changes made. Both repos are in good shape algorithmically and structurally — the headline wins are real and the headline concerns are scoped and owned by existing plans (`tasks/SFLOW-NOC-REDESIGN-PLAN.md` for the sFlow side; separate refactor tickets for the God-Object splits). The single regression-shaped finding is the missed `doDirectSend` retry helper; everything else is either planned, deferred, or a one-line fix.