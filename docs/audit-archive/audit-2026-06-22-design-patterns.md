# Firewall-Collector — Design Patterns Audit (2026-06-22)

**Skill:** `design-patterns` (Gang of Four, 23 patterns + cross-cutting anti-patterns)
**Scope:** `E:\Golang\OpenCode\Firewall-Collector` at version `1.2.129`
**Audit lens:** collector is the production probe; the bundled `cmd/probe` on the server is going away.

---

## Summary

- **Overall grade: B+**
- The recent 1.2.124–1.2.129 series (test seams, `sendMetric` generic, backoff extraction, IP-table fix, SSH host-key observation) is exactly the kind of measured refactor a senior engineer signs off on. Strategy is applied cleanly at the SNMP vendor boundary (8 `VendorProfile` implementations), and the `SpilloverQueue` (in-memory + BoltDB) is a textbook durable-buffer pattern.
- The headline debt is the `Collector` struct in `cmd/collector/main.go` (1,728 lines, 33 methods, four mutexes, package-level globals for `listenerBound` and `lastHeartbeat`). It is a real God-Object-by-incremental-aggregation, and the same release that introduced test seams is the moment a per-feature split pays for itself.
- The second headline debt is **three near-duplicate retry/approval/registration loops** in `internal/relay/relay.go` (1.2.127 extracted the *delay formula* but explicitly did not merge the loops). The `CHANGELOG.md` calls this out as deliberate; it is a defensible call, but it leaves the codebase one PR away from the same bug being fixed three times.

### Top 3 wins
1. **`VendorProfile` Strategy pattern** (`internal/snmp/vendor.go`) — 8 vendors, runtime registration via `init()`, optional capability interfaces (`DialupVPNProvider`, `SSLVPNProvider`, `HAProvider`, `SecurityStatsProvider`, `SDWANProvider`, `LicenseProvider`). This is the cleanest expression of Go Strategy I've seen in a small project; the optional interfaces are the idiomatic Go way to handle "vendor X has feature Y" without exploding into an Abstract Factory.
2. **`sendMetric` generic helper** (`cmd/collector/main.go:1226`) — 1.2.126 collapsed six near-identical "Get → stamp → Send" blocks behind one type-parameterized helper. The closures (`get`/`stamp`/`send`) keep Go's generics limitation visible without becoming a leak.
3. **`SpilloverQueue` (in-memory tier + BoltDB tier)** (`internal/relay/queue/queue.go`) — durable producer-consumer primitive that survives process restarts and central-server outages. FIFO eviction, byte-cap, drop counter. The five callers (4 event streams + revision queue) use one type-erased `[][]byte` so the queue code has zero per-customer knowledge.

### Top 3 concerns
1. **`Collector` is a God Object** — 33 methods, 4 mutexes, 4 receivers, full responsibility for SNMP/SSH/syslog/sFlow/TFTP/ping/device-resolution/IP-cache/observability. `cmd/collector/main.go` is 1,728 lines.
2. **Three duplicated retry/approval/registration loops** — `sendBatch`, `sendOneRevisionWithRetry`, `doDirectSend`, and the 401/403/404 branches in `Register`/`SendHeartbeat`/`SyncData`/etc. Each reimplements the same policy with subtly different state handling. The 1.2.127 release extracted the *delay* but not the *policy* (the CHANGELOG explicitly says "the differing send loops were deliberately not merged"). Defensible; consolidatable.
3. **No State pattern for probe lifecycle** — `approved atomic.Bool` + scattered `if !c.approved.Load()` checks (at least 8 sites in `relay.go`) + `tryReregister` ad-hoc state machine + `failCount` map for the per-device circuit breaker. None of this is wrong, but none of it is a pattern either — it's conditionals over mutable state, the textbook "don't use State for two or three simple states" trap, except we now have six (Pending, Registering, Approved, Lost-Approval, BackingOff, Cooldown).

---

## Findings

### [HIGH] Collector struct is a God Object

- **Pattern violated**: Facade / Mediator (sklearn lesson 1 + cross-cutting anti-pattern #1)
- **File**: `cmd/collector/main.go:93-152` (struct), `cmd/collector/main.go:264-1678` (most behavior)
- **Snippet**:
  ```go
  type Collector struct {
      cfg, relayClient, trapReceiver, syslogTCP, syslogUDP,
      sflowReceiver, pingCollector, tftpServer, metrics, metricsServer ...
      observedHostKeys, failCount, sshLastPoll, ifaceIPMap, lastSuccessfulPoll ...
      cfgBackupTimers, devices, stopChan, stopOnce, pollWg, sshPollWg ...
      // 24 fields, 4 mutexes, 0 constructor logic
  }
  ```
- **Why it's a problem**: 33 methods (`Collector.runHeartbeatLoop`, `snmpPollingLoop`, `runPollCycle`, `sshPollingLoop`, `runSSHPollCycle`, `sshPollDevice`, `startTFTPServer`, `fetchConfigViaTFTP`, `pollDevice`, `recordPollFailure`, `recordObservedHostKey`, `snapshotObservedHostKeys`, `recordPollSuccess`, `deviceRefreshLoop`, `findDeviceByID`, `handleSyslogMessage`, `scheduleConfigBackup`, `resolveDeviceByIP`, `cacheInterfaceAddresses`, `stop`, ...) split across "SNMP poll, SSH poll, syslog, sFlow, TFTP, ping, host-key cache, iface-IP cache, circuit-breaker, debouncer, shutdown." The skill is explicit: "If your facade is hundreds of lines and depends on every module in the codebase, split it into a few targeted facades or per-feature service classes." Tests in `cmd/collector/` are forced to construct `Collector{}` with a half-dozen fields initialized to reach any one method (`polldevice_test.go:106-114`).
- **Suggested fix**: Split into per-feature services held by a thin `Collector` orchestrator. Concrete split:
  - `Poller` — SNMP + SSH polling cycles, semaphore, circuit breaker
  - `SyslogBackupDebouncer` — `handleSyslogMessage`, `scheduleConfigBackup`, `findDeviceByID`, `cacheInterfaceAddresses`, `resolveDeviceByIP`, `ifaceIPMap`
  - `TFTPCoordinator` — `startTFTPServer`, `fetchConfigViaTFTP`, `sendConfigRevisionViaTFTP`, `determineOutboundIP`, `setTFTPServerIP`
  - `HostKeyObserver` — `observedHostKeys`, `recordObservedHostKey`, `snapshotObservedHostKeys`
  - `Lifecycle` — `stop`, drain coordination, signal handling
- **Effort**: L (touches ~20 method receivers; can land as a single rename-then-extract refactor behind the existing `Collector` struct so external callers see no change).

### [HIGH] Three duplicated retry/approval/registration loops

- **Pattern violated**: Strategy (sklearn lesson 1: "multiple legitimate ways to do the same thing — sort, compression, retry policies")
- **File**: `internal/relay/relay.go:885-931` (`doDirectSend`), `internal/relay/relay.go:1238-1290` (`sendBatch`), `internal/relay/relay.go:1510-1555` (`sendOneRevisionWithRetry`)
- **Snippet** (representative; same shape appears in all three):
  ```go
  for attempt := 0; attempt < 3; attempt++ {
      resp, err := c.doAuthenticatedRequest("POST", url, jsonData)
      if err != nil { ... time.Sleep(expBackoff(attempt)); continue }
      if resp.StatusCode >= 200 && resp.StatusCode < 300 { return nil }
      if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
          c.approved.Store(false)
          if c.tryReregister() { continue }
          return ...
      }
      if resp.StatusCode == 400 { ... return ... }  // permanent
      // else: 5xx → retry
      time.Sleep(expBackoff(attempt))
  }
  ```
- **Why it's a problem**: The 1.2.127 release extracted `expBackoff` and `reregisterBackoff` (the *delays*) but kept three copies of the *policy*. The CHANGELOG acknowledges this: "the differing send loops were deliberately **not** merged. … Naming the policies also makes a future decision to standardize them a one-line change." That's exactly the moment for a Strategy. The 400/401/403/404/5xx branching is identical across the three loops; the only true variation is "do I have a JSON payload or not" and "do I need an idempotency key header." Each loop has its own bug surface. `sendOneRevisionWithRetry` line 1544 logs "400 (bad request) ... not retrying" but doesn't enqueue a rejection metric; `sendBatch` line 1277 logs differently; `doDirectSend` doesn't log 400 at all (the caller logs). Easy place for a 4xx-vs-5xx fix to land in two of three.
- **Suggested fix**: Introduce a `RetryPolicy` value with a `classify(status int) RetryAction` (one of `Drop`, `ReRegister`, `Retry`) and a `Run(req func(attempt int) (Status, error)) error` helper. The three callers reduce to "marshal payload, build headers, call `policy.Run`." The `X-Probe-Batch-ID` and the `Authorization: Bearer` belong to `req`, not to the policy. This is the textbook Strategy: same shape as Go's `IComparer<T>` / `IEqualityComparer<T>`.
- **Effort**: M (the three call sites are short once the policy lives elsewhere; the unit tests in `relay_audit054_test.go`, `relay_idempotency_audit042_test.go`, `relay_test.go` already pin the behavior so a refactor is safe).

### [HIGH] Approval gate is duplicated 10+ times

- **Pattern violated**: Decorator / cross-cutting concern (sklearn lesson 1 for Decorator)
- **File**: `internal/relay/relay.go` (lines 886, 983, 1033, 1389, 1558, 1578, 1598, 1620, 1644 — and indirectly in every retry loop via the re-register branch)
- **Snippet**:
  ```go
  // line 886 (doDirectSend):
  if !c.approved.Load() { if !c.tryReregister() { return fmt.Errorf("probe not approved") } }
  // line 1033 (syncData):
  if !c.approved.Load() { log.Println("..."); if !c.tryReregister() { return } }
  // line 1389 (SendConfigRevision):
  if !c.approved.Load() { return fmt.Errorf("probe not approved") }
  ```
- **Why it's a problem**: Every public Send method opens with the same four-line approval gate, then every retry-loop body re-implements the re-register branch. The pattern is the same one the skill describes as the Decorator candidate: "the cleanest way to add cross-cutting concerns (logging, caching, retry, auth checks, compression) at runtime without modifying the wrapped code." A `requireApproved(c *Client, fn func() error) error` decorator would centralize the gate; each Send method becomes "marshal, build URL, `requireApproved(c, func(){ return c.sendWithRetry(...) })`."
- **Suggested fix**: Combine with the Strategy refactor (above). The decorator wraps the policy: `requireApproved → withRetryPolicy(expBackoff, classifier) → call`. Two-line public methods.
- **Effort**: S (depends on the Strategy refactor or stands alone — Decorator on the inner function, no test churn).

### [MEDIUM] Package-level globals for observability state

- **Pattern violated**: Singleton-as-default scope (sklearn cross-cutting anti-pattern #6)
- **File**: `cmd/collector/main.go:37-43`
- **Snippet**:
  ```go
  var (
      listenerBoundMu sync.RWMutex
      listenerBound   = map[string]bool{}

      lastHeartbeatMu sync.RWMutex
      lastHeartbeat   time.Time
  )
  ```
- **Why it's a problem**: The comments say "Only main() ever writes to them" but `markListenerBound` (line 489) is reachable from every receiver Start/Stop and the `runHeartbeatLoop` writes `lastHeartbeat` from a goroutine. They are exactly the "process-global state" the skill warns against: "Singleton breaks testability (you can't substitute a fake without monkey-patching static state) and is a frequent root cause of hidden concurrency bugs." The Collector struct already exists and the comments explicitly mention "the metrics package holds its own copy, but the Collector also reads from this map when (future) code wants to know" — the future is now; move them onto `Collector` or `Metrics`.
- **Suggested fix**: Promote both onto the `Collector` struct (the `Metrics` already tracks listener-bound and last-heartbeat via Prometheus gauges; the package-level copies are duplicates). If the observability callbacks need to read from them before `Collector` exists, pass `nil` and have the callbacks early-return (they already do — see `Metrics.New`'s default `func() bool { return true }`). Move the registration race window out of globals.
- **Effort**: S.

### [MEDIUM] Circuit breaker is scattered enums + conditionals

- **Pattern violated**: State (sklearn lesson 1: "when transitions are explicit and the number of states grows")
- **File**: `cmd/collector/main.go:643-685` (`runPollCycle`), `cmd/collector/main.go:1382-1390` (`recordPollFailure`), `cmd/collector/main.go:1422-1438` (`recordPollSuccess`), `cmd/collector/main.go:129-131` (the `failCount map[uint]int` field itself)
- **Snippet**:
  ```go
  // runPollCycle (line 656):
  // Circuit breaker: skip devices with 3+ consecutive failures (backoff for 4 cycles)
  failures := c.failCount[dev.ID]
  if failures >= 3 {
      // Poll every 5th cycle (skip 4 cycles) when in failure state
      if failures%5 != 0 {
          c.failCount[dev.ID]++
          skippedCount++
          continue
      }
  }
  ```
- **Why it's a problem**: The state is implicit (an integer count), the transitions are scattered (failure → +1 in `recordPollFailure`, success → 0 in `recordPollSuccess`, skip-or-poll → +1 in `runPollCycle`), and the policy ("3 failures opens, poll every 5th, reset on first success") lives in three places. Adding "consecutive 503s for 10 minutes → permanent fault" or "5 successes in a row → close the breaker" means reading three methods to make sure the change is consistent. The state machine has 3-4 states (Healthy, Tripping, BackingOff, PermanentlyFailed); that's exactly the boundary where State pattern starts paying for itself.
- **Suggested fix**: A small `Breaker` per device (struct with `state`, `consecutiveFailures`, `lastSuccess`, `policy`) and a `Breaker.Allow() bool` + `Breaker.OnSuccess()` / `Breaker.OnFailure(error)` API. The `failCount` map becomes `breakers map[uint]*Breaker`. Keeps the same wire behavior; makes "what is the policy?" answerable in one place.
- **Effort**: M.

### [MEDIUM] Probe lifecycle state machine is implicit

- **Pattern violated**: State (related to the circuit-breaker finding — the *probe* has its own FSM)
- **File**: `internal/relay/relay.go` (Approved atomic.Bool at line 357; rate-limited/cooldown FSM inside `tryReregister` at lines 674-709; the `reregisterAttempts` and `lastReregisterAttempt` fields at lines 365-366)
- **Snippet**:
  ```go
  func (c *Client) tryReregister() bool {
      c.mu.Lock()
      elapsed := time.Since(c.lastReregisterAttempt)
      attempts := c.reregisterAttempts

      if attempts >= maxReregisterAttempts {
          if elapsed < 10*time.Minute {
              c.mu.Unlock()
              return false
          }
          log.Println("[Relay] Re-registration cooldown expired, resetting attempt counter")
          c.reregisterAttempts = 0
          attempts = 0
      } else if elapsed < 60*time.Second {
          c.mu.Unlock()
          return false
      }
      c.lastReregisterAttempt = time.Now()
      c.reregisterAttempts++
      c.mu.Unlock()

      backoff := reregisterBackoff(attempts)
      log.Printf("[Relay] Probe lost approval, attempting re-registration (attempt %d/%d) in %v...",
          attempts+1, maxReregisterAttempts, backoff)
      time.Sleep(backoff)

      if err := c.Register(); err != nil {
          log.Printf("[Relay] Re-registration failed: %v", err)
          return false
      }
      log.Println("[Relay] Re-registration successful, probe approved again")
      return true
  }
  ```
- **Why it's a problem**: The state has three meaningful values (Approved, Lost+BackingOff, Lost+Cooldown), transitions depend on `time.Since(lastReregisterAttempt)`, and the "rate-limited < 60s" vs "cooldown < 10m" branches are interleaved with the mutex release/relock pattern. The fields `reregisterAttempts` and `lastReregisterAttempt` are accessed from `tryReregister`, `sendHeartbeatWithStatus` (line 781), and (via `reregisterAttempts++`) from `sendHeartbeatWithStatus` — three writes to two fields under the same mutex. Easy place to introduce a TOCTOU if a future contributor reads without locking. The skill says "Don't use State for two or three simple states — an enum + switch is clearer"; the FSM here is *four* states (Approved, PendingFirstRegister, RateLimited, Cooldown) and the rate-limit/cooldown boundary is exactly the part that is hard to test (see the existing `TestTryReregister_*` in `relay_test.go:256-285`).
- **Suggested fix**: A `RegistrationState` value type with explicit `Step(now time.Time) (action Action, sleep time.Duration)` that returns one of `{RegisterNow, Sleep, GiveUp}`. The state lives on `Client`. The `Register` method and the various retry-loop branches all delegate to it.
- **Effort**: M.

### [MEDIUM] Three failed-batch requeue paths have diverged

- **Pattern violated**: Template Method / Strategy (the *skeleton* — drain → unmarshal → batch → send → requeue-on-failure — is the same in three places; only the payload type and one detail differ)
- **File**: `internal/relay/relay.go:1057-1099` (`syncData`), `internal/relay/relay.go:1141-1161` (`sendBatchesSequential`), `internal/relay/relay.go:1465-1485` (`sendRevisionBatch`)
- **Snippet** (the 3rd copy — the 4 event-queue drains all funnel into the generic `drainAndSend`):
  ```go
  // syncData: revision queue (does NOT use drainAndSend)
  for {
      raw, err := c.revisionQueue.Drain(drainChunk)
      if err != nil { log.Printf(...); break }
      if len(raw) == 0 { break }
      c.sendRevisionBatch(baseURL+"/config-revision", raw)
      if len(raw) < drainChunk { break }
  }
  ```
- **Why it's a problem**: The 4 event queues share `drainAndSend[T]` + `queueDrainSpec[T]` + `unmarshalQueued[T]` (1.2.128 series — well-factored generics). The revision queue re-implements the same loop inline because it needs per-revision retry semantics (`sendRevisionBatch` calls `sendOneRevisionWithRetry` per item). That is the only structural difference; the rest is identical. Adding a 6th queue (a "second-tier alert" the operator has been asking for) means copying one of the two patterns again. The skill's Template Method point: "use when you have a stable algorithm structure with variant steps." The structure IS stable; the variants are `(queue, endpoint, label, interChunkDelay)` + the retry policy.
- **Suggested fix**: `drainAndSend[T]` already takes a `queueDrainSpec[T]`. Add a `perItemRetry bool` (or a `perItemRetryFn func(item *T) bool`) to the spec and let `drainAndSend` route to either `sendBatchesSequential` (per-chunk retry) or `sendRevisionBatch` (per-item retry) under the hood. Drops the inline for-loop in `syncData`.
- **Effort**: S.

### [LOW] Decorator opportunity on the transport

- **Pattern violated**: Decorator (sklearn lesson 1: "the cleanest way to add cross-cutting concerns (logging, caching, retry, auth checks, compression) at runtime")
- **File**: `internal/relay/relay.go:418-428` (`http.Client` construction in `NewClient`)
- **Snippet**:
  ```go
  httpClient: &http.Client{
      Timeout: 60 * time.Second,
      Transport: &http.Transport{
          TLSClientConfig:       tlsConfig,
          MaxIdleConns:          200,
          ...
      },
  },
  ```
- **Why it's a problem**: There is no logging/metrics Decorator wrapping `httpClient.RoundTrip`. Every call site (in `sendBatch`, `doAuthenticatedRequest`, `sendOneRevisionWithRetry`, etc.) logs its own outcome, with its own label ("relay: batch", "relay: heartbeat", "RELAY: revision"). A `roundTripperFunc` wrapper that increments a Prometheus counter (`firewall_collector_http_requests_total{path,outcome}`) and logs once would replace ~6 manual logging branches with one Decorator. The observability package already has the counter scaffold; this is the wire to it.
- **Suggested fix**: Wrap the `http.Transport` in a small `metricsRoundTripper` struct (3 methods: `RoundTrip`, plus a constructor that takes the inner transport and a `Metrics` reference). The Prometheus client already gives you `prometheus.NewCounterVec` for `{path, status_class}`. Optional `logRoundTripper` for debug logs.
- **Effort**: S.

### [LOW] Producer-consumer pipeline is channel-less by design (deliberate, but worth naming)

- **Pattern violated**: None — this is a deliberate trade-off, but it's worth a one-line note
- **File**: `internal/relay/queue/queue.go` (whole file), `cmd/collector/main.go:296-303` (`safego.Go` for `DataSendLoop`)
- **Why it's a problem (or not)**: The textbook Go shape for producer-consumer is `chan T` with a goroutine consumer. The collector uses BoltDB-backed durable queues instead. This is the *correct* call for a probe that must survive crashes AND multi-day outages — channels lose on crash, and an in-memory queue loses on outage. The trade-off is: every drain re-unmarshals JSON, and the `drainAndSend[T]` generic has to know the payload type. There's nothing to fix; the skill's Iterator note applies (`for...range` over the queue would be cleaner than `[][]byte`), but it's a non-issue. Naming it explicitly in `ARCHITECTURE.md` so a future contributor doesn't "simplify" it back to channels.
- **Suggested fix**: Add one sentence to `ARCHITECTURE.md` §"Lifecycle" that says "We deliberately don't use channels for the event streams because durability across process restarts is a hard requirement; see internal/relay/queue/queue.go."
- **Effort**: XS.

### [LOW] `safego` is a clean Decorator — worth noting

- **Pattern used well**: Decorator (sklearn lesson 1 — implicit *Decorator* on every long-lived goroutine)
- **File**: `internal/safego/safego.go:35-50`
- **Why it's worth calling out**: Every `safego.Go(name, fn)` and `safego.AfterFunc(d, name, fn)` wraps the call in a panic-recovering closure. There are **17** call sites in production code (`trap.go:46,68`, `syslog.go:57,90,187`, `sflow.go:59`, `main.go:296,299,339,341,349,674,740, 1557`) and one of them (`sflow.go:59`) is in a tight read loop. This is *the* reason a malformed sFlow datagram doesn't kill the probe. The Decorator is one line per call site and invisible at the call site — exactly the win the skill describes.
- **No fix needed.**

### [LOW] `VendorProfile` Strategy is exemplary

- **Pattern used well**: Strategy + Optional Interfaces (the Go way to do capability-based extension)
- **File**: `internal/snmp/vendor.go:26-91`
- **Why it's worth calling out**: `VendorProfile` is the strategy interface; the 6 optional interfaces (`DialupVPNProvider`, `SSLVPNProvider`, `HAProvider`, `SecurityStatsProvider`, `SDWANProvider`, `LicenseProvider`) are the optional capability pattern in idiomatic Go. `GetVPNStatus` does `if dialupProvider, ok := profile.(DialupVPNProvider); ok { ... }` (line 484). This is exactly the shape the skill recommends: "Program to an interface, not an implementation. Depend on abstractions so that substituting one object for another doesn't ripple through the codebase." 8 vendor profiles share `TestVendorProfile_*` (`internal/snmp/vendor_test.go`).
- **No fix needed.** A new vendor is a single file + an `init()` call (see `CUSTOM-VENDOR.md`).

### [LOW] `sendMetric` generic helper is a clean Template Method

- **Pattern used well**: Template Method (sklearn lesson 1: "function callbacks (Go's `func` fields)" is the modern alternative)
- **File**: `cmd/collector/main.go:1226-1237`
- **Snippet**:
  ```go
  func sendMetric[T any](get func() ([]T, error), stamp func(*T), send func([]T) error, devName, label string) {
      items, err := get()
      if err != nil || len(items) == 0 { return }
      for i := range items { stamp(&items[i]) }
      if err := send(items); err != nil { log.Printf(...) }
  }
  ```
- **Why it's worth calling out**: 1.2.126 collapsed 6 near-identical blocks into this. The skeleton (Get → stamp → Send → log-on-failure) is invariant; the per-type code lives in the closures. Pure Template Method via generics. Well done.
- **No fix needed.**

### [LOW] `SpilloverQueue` is a textbook Producer-Consumer primitive

- **Pattern used well**: Producer-Consumer + Flyweight (the on-disk tier is shared across queues)
- **File**: `internal/relay/queue/queue.go`
- **Why it's worth calling out**: Two-tier (RAM + Bolt), FIFO, byte-cap with drop counter, in-memory `Close()` flushes to disk. The 5 callers (traps/pings/syslog/flows/revisions) use the same type. The `[][]byte` type-erasure is the right shape — the queue doesn't know what it carries.
- **No fix needed.**

### [LOW] No Command, Proxy, or Factory misuse

- **Pattern check**: No misuse found.
- **Command**: Could sample batches be Commands? Yes, but they'd add ceremony without enabling undo or queuing beyond what `SpilloverQueue` already provides. The skill is explicit: "Don't use Command for trivial method calls." Skip.
- **Proxy**: `relay.Client.observedHostKeysFn` is a callback provider, not a Proxy. No object is being "stood in for." Nothing to fix.
- **Factory**: `VendorProfile` registration is a registry pattern, not Factory. `DefaultVendor()` returning "fortigate" is a default fallback, not a factory method. `NewClient` is a constructor. The 8 vendor `init()` calls are plugin registration, which the skill treats as legitimate.

### [LOW] NetFlow/IPFIX not supported — sFlow-only is documented, not a pattern issue

- **File**: `internal/sflow/sflow.go:120-123` (version gate: `if !ok || version != 5 { return }`)
- **Why it's not a pattern issue**: The sFlow v5 parser is hardcoded. The skill says Strategy applies when you have multiple legitimate algorithms to swap. The README, ARCHITECTURE.md, and FEATURES.md all explicitly say "sFlow v5 only" — this is an *intentional* one-algorithm system, not a missed Strategy. The "transport strategies" audit question ("sFlow v5 vs NetFlow v9 vs IPFIX") therefore has a no-for-action answer: the codebase chose sFlow-only by design.
- **Suggested action**: None. Note for the audit report.

### [LOW] `getEnv` is duplicated

- **Pattern check**: Not a GoF pattern, but worth a one-line note.
- **File**: `cmd/collector/main.go:48-53` (duplicates `internal/config/config.go:103-108`).
- **Why it's not a pattern issue**: It's not a GoF violation, just tech debt. The comment "Duplicated from internal/config to avoid modifying that package (out of scope for AUDIT-057)" is the kind of "I'll do it later" comment that becomes permanent. Move to `internal/config` and import.
- **Effort**: XS.

---

## Patterns used well

1. **Strategy — `VendorProfile` + 6 optional capability interfaces** (`internal/snmp/vendor.go`). 8 in-tree vendors, runtime registration via `init()`, capability detection via type assertion. Documented in `docs/CUSTOM-VENDOR.md`. This is the strongest pattern use in the repo.
2. **Template Method via generic closures — `sendMetric[T]`** (`cmd/collector/main.go:1226`). Added in 1.2.126.
3. **Decorator — `safego.Go` / `safego.AfterFunc`** (`internal/safego/safego.go`). 17 production call sites; one Decorator, zero boilerplate at the call site.
4. **Producer-Consumer primitive — `SpilloverQueue`** (`internal/relay/queue/queue.go`). Two-tier (RAM + BoltDB), FIFO, byte-capped, restart-survivable. Reused by 5 callers (4 event streams + revision queue) via `[][]byte` type erasure.
5. **Adapter — `*snmp.SNMPClient`** (`internal/snmp/snmp.go`). Thin wrapper over `gosnmp` that presents the consumer's expected interface (`GetSystemStatus`, `GetInterfaceStats`, ...) and converts `gosnmp.SnmpPDU` into `relay.*` DTOs.
6. **Adapter — sFlow v5 decoder** (`internal/sflow/sflow.go`). Translates raw `[]byte` datagrams into `relay.FlowSample`.
7. **Adapter — RFC 5424 syslog parser** (`internal/syslog/syslog.go`). Including a FortiGate-specific device-ID extractor.
8. **Facade — `Metrics` / `Server` with callback-only inputs** (`internal/observability/metrics.go`). The reverse direction (observability doesn't import `cmd/collector` or `relay`) is enforced via function callbacks in `Config` (`ApprovedFn`, `LastHeartbeatFn`, `ListenerBoundFn`, `EnabledListenersFn`). No God Object, no import cycle.
9. **Adapter — `http.Client` construction in `NewClient`** (`internal/relay/relay.go:418-428`). Builds TLS + idle-conn pool + timeouts from `Config`. Clean.
10. **Template Method — `scheduleConfigBackupWith`** (`cmd/collector/main.go:1543-1567`). Testable seam: takes the `action func()` as a parameter, production injects the real TFTP-fetch closure, tests inject a counter. Extends `safego.AfterFunc` for panic safety.

---

## Open questions

1. **Will the `SpilloverQueue` ever need `PushFront`?** The 1.2.106 CHANGELOG note ("If strict priority matters later, SpilloverQueue can be extended with a `PushFront` primitive") implies yes — but the question to ask before implementing it is: do we want priority semantics at all? Currently the re-queue is FIFO. Priority would require a more invasive change (probably a priority field on the queue item, plus a separate "high priority" bucket). Better to leave PushFront unimplemented and revisit when a real use case appears.

2. **Is the per-collector `metrics.SetQueueDepthSource` wiring actually used?** I see the callback type defined in `internal/observability/metrics.go:129`, the API `SetQueueDepthSource` (line 259), but a grep for callers came up empty outside the tests. If the callback isn't wired in `main.go`, the `firewall_collector_queue_depth` gauge is always zero, which is a silent observability bug. Confirm with the maintainer.

3. **Should the Collector god-object split include the `metrics`, `metricsServer`, and `stopChan`?** They're orthogonal to the feature split (Poller / Debouncer / TFTP / HostKey). My recommendation: yes — promote them to `Lifecycle`, which owns `metrics`, `metricsServer`, `stopChan`, `stopOnce`, `pollWg`, `sshPollWg`. The feature services get `Lifecycle` injected and call `lifecycle.RegisterListener("snmp_trap", bound)`. This is the actual boundary the cleanup code in `stop()` (`main.go:1610-1678`) already implies — the receiver Stop calls already follow the pattern `if x != nil { x.Stop(); markListenerBound("snmp_trap", false); metrics.SetListenerBound(...)` repeated 5 times.

4. **Should the optional `VendorProfile` interfaces be hoisted into one composite?** `DialupVPNProvider`, `SSLVPNProvider`, `HAProvider`, `SecurityStatsProvider`, `SDWANProvider`, `LicenseProvider` are all detected via type assertion at the call site. As more capabilities accumulate, the `if x, ok := profile.(Y); ok` pattern gets noisy. Two options: (a) keep it as-is (idiomatic Go — and the skill approves), (b) introduce a `VendorCapabilities` interface that vendors can optionally implement and check once. The optional-interface pattern is fine; do nothing.

5. **Retry classification: is "retry on 5xx but not on 4xx" the right policy?** `isRetryableStatus` (`relay.go:1229-1236`) lumps 400/401/403/404/405/409/410/422/429 as non-retryable and everything else as retryable. That means 408 (Request Timeout), 425 (Too Early), and 499 (Client Closed) are treated as transient (correct) but 429 (Too Many Requests) is treated as permanent (questionable — usually means "back off and retry"). Audit the list against the server's actual 4xx codes.

6. **The `reregisterAttempts` counter is read with `c.mu` held in `tryReregister` but incremented with `c.mu` held in `sendHeartbeatWithStatus` — but the load in `sendHeartbeatWithStatus` (line 783) and the store in `tryReregister` (line 694) are on different fields. Is there a real race?** I believe no (the mutex protects both fields; the access pattern is "lock both, read/write both, unlock") but the per-field commentary in the code makes it look ambiguous. Worth a careful audit if the FSM refactor (above) lands.

7. **`DeviceInfo` is a fat DTO** (29 fields in `relay.go:272-291`). The skill doesn't have a "fat DTO" anti-pattern explicitly, but the "you need to pass the whole struct around to share two fields" smell is the same one GoF warns about with Facade drift. The `findDeviceByID` and `resolveDeviceByIP` round-trips suggest the Collector is using `DeviceInfo` as a poor-man's cache. Worth a refactor when a feature actually needs a per-device index, but not urgent.

8. **Is the `cmd/probe` legacy alias (per the audit prompt — "the bundled `cmd/probe` in Firewall-Mon is legacy and going away") relevant here?** The Collector has no such alias — `cmd/collector/main.go`, `cmd/diag-backup/main.go`, `cmd/tftp-test/main.go` are the only entry points. Confirm with the maintainer that "going away" doesn't mean a future change in this repo.