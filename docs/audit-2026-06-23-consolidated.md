# Internal Audit — 2026-06-23 (Collector subset + cross-repo)

> **STATUS (updated 2026-06-24, collector at v1.2.137).** This is the live
> tracker for still-open items.
>
> **Resolved & shipped:** H2 (TFTP source-IP allowlist actually wired, v1.2.132),
> H9 (metric spillover queue, v1.2.133), M6 (O(n²) syslog framing, v1.2.136),
> M10 (W3C traceparent injection, v1.2.137), M12 (metric_send_failed_total
> counter, v1.2.133), M13 (alpine base image bumped, v1.2.136).
>
> **Still open (code-verified, 2026-06-24):**
> - **H-trap** — `internal/snmp/trap.go:96` still logs the SNMP community in
>   cleartext (`expected %q, got %q`).
> - **M7** — `internal/relay/queue/queue.go` still fsyncs under the queue mutex
>   (no `db.NoSync`); every `db.Update` runs inside `q.mu.Lock()`.
> - **LOW/INFO tail** — L1 / L2 / L6 / L7 / L8 / L10 / L16 (e.g. duplicated
>   `getEnv` at `cmd/collector/main.go:48` and `internal/config/config.go:103`).

**Scope:** Collector-relevant and cross-repo subset of the 2026-06-23 dual-repo internal audit. Full server-side report: `Firewall-Mon/docs/audit-2026-06-23-consolidated.md`. Feature inventory + industry roadmap: `Firewall-Mon/docs/FEATURE-ROADMAP.md`.

- **Collector** — `Firewall-Collector` (Go module `firewall-collector`, ~v1.2.131): stateless remote edge probe.
- **Server** — `Firewall-Mon` (`firewall-mon`, ~v0.10.476): central store + alerting brain (referenced where the contract crosses).

---

## Executive Summary (collector view)

The collector ingestion and relay paths are robust, but the audit confirmed one **high-severity unauthenticated-input** defect (TFTP), one **high-severity availability/durability** defect (no spillover for primary metrics + invisible loss), and one **high-severity secret-disclosure** (trap community logged in cleartext). The remaining collector findings are performance hot-path issues (keep-alive pool defeat, O(n²) syslog framing, fsync-per-sample, per-cycle ICMP sockets) and hygiene (variadic-as-optional, stale version const, config-Load validation, missing THIRD-PARTY-NOTICES, TLS MinVersion, EOL/unpinned base images).

### Collector + cross-repo counts (subset of the 49 total)

| Severity | Count (collector + cross-repo) |
|---|---|
| High | 3 |
| Medium | 6 |
| Low | 8 |
| Info | 5 |

---

## HIGH

### H2. TFTP config-upload accepts arbitrary content from ANY source IP — AUDIT-050 controls never wired
- `cmd/collector/main.go:879-918`; unused at `internal/tftp/tftp.go:107` (`SetAllowedSourceIPs`), `:128` (`SetMinWRQInterval`)
- `startTFTPServer` binds `0.0.0.0:69` and only calls `SetWriteHandler`. `isSourceAllowed` returns true when the allowlist is nil; rate-limit is a no-op at `minWRQInterval==0`. The write handler wraps attacker bytes as an authoritative `relay.ConfigRevision` for the parsed `device_id` and forwards via `SendConfigRevision`.
- **Impact:** Any host on the management LAN injects a forged config-revision for any `device_id` → poisons the server's config-change detection (phantom alerts, or masking a real change). AUDIT-050 controls are dead code in production.
- **Fix:** After `NewServer`, call `SetAllowedSourceIPs(deviceIPs)` from `c.devices[].IPAddress` + `SetMinWRQInterval(30-60s)`; refresh the allowlist on each device-list refresh (`main.go:312`). Optionally bind to a specific management interface.

### H9. Drops all primary SNMP telemetry on server outage (no spillover queue) · *finalSeverity: medium*
- `internal/relay/relay.go:893-938` (`doDirectSend`); callers `cmd/collector/main.go:1301,1317,1328,1336`
- Traps/pings/syslog/flows/revisions buffer in the durable BoltDB `SpilloverQueue`. The 10 core metric senders (System/Interface/InterfaceAddresses/VPN/HardwareSensors/Processor/HA/Security/SDWAN/License) go through `doDirectSend`, which only returns an error the callers log. The device circuit breaker keys on POLL failures, not SEND failures, so devices keep polling and discarding every sample; `doDirectSend` also burns ~7s backoff per metric per device.
- **Impact:** A server outage loses ALL primary health metrics (CPU/mem/disk/sessions/interface throughput/VPN) for the full outage with no recovery — while lower-value event streams ARE preserved. Inverts data-value priority.
- **Fix:** Route the metric `Send*` through the SpilloverQueue (or a dedicated bounded metric queue), drained on recovery; drop `doDirectSend` retries to 1.

### H-trap. SNMP trap community secret logged in plaintext on every community-mismatch drop
- `internal/snmp/trap.go:96` (`allowCommunity`)
- `log.Printf("[SNMP Trap] Dropped: community mismatch (expected %q, got %q)", t.community, community)` writes the configured trap community (a shared secret) + the attacker-controlled `got` to logs on every mismatched trap. The collector's slog setup (`cmd/collector/main.go:1703`) has NO `ReplaceAttr` redaction; this is raw stdlib `log.Printf`. The CHANGELOG claim "no longer logs the trap community" covered only the parse path. The leak is pinned by `internal/snmp/trap_test.go` `TestTrapReceiver_CommunityMismatch_LogsDrop:52` (asserts BOTH values present).
- **Impact:** Disclosure of the trap-auth secret to logs/log-shipping → enables trap forgery; the drop path is exactly the noisy/attacked path most likely to be shipped.
- **Fix:** Log only non-secret context: `log.Printf("[SNMP Trap] Dropped: community mismatch from %s", srcIP)` (pass the source address in). Update the test to assert the secret is ABSENT. Optionally add a `ReplaceAttr` redaction hook + per-IP rate-limit.

---

## MEDIUM

### M6. TCP syslog framing is O(n²) in messages-per-read (buffer rewind per line)
- `internal/syslog/syslog.go:110-124` — `handleConnection` rewrites the entire remaining tail to the front of the buffer after each extracted line → O(total_bytes * K), bounded by the 64KB window. Worst on the low-power deploy targets. **Fix:** forward scan with an advancing offset, or `bufio.Scanner` with a 64KB token buffer.

### M7. sFlow/event spillover `Push` does a synchronous BoltDB fsync under the queue mutex per overflow item
- `internal/relay/queue/queue.go:188-201,207-242` (BoltDB opened without NoSync at `:76`) — at `MaxMem` (10000), each evict calls `appendToDisk → db.Update` (fsync) under `q.mu`; the single sFlow `readLoop` pushes inline so the fsync stalls flow-receive. Steady-state above ~333 samples/sec at defaults → fsync-per-sample. **Fix:** decouple receive from persistence (RAM channel/ring drained by a writer goroutine); batch overflow writes and/or open with NoSync; raise flow-queue MaxMem.

### M10. Never injects W3C trace context or a request ID — probe→server traces can never connect · *finalSeverity: low*
- `internal/relay/relay.go:580-590` + no otel in go.mod — the server propagates W3C context across the probe→api boundary, but the collector injects none, so the server always starts a fresh root span. `X-Probe-Batch-ID` is dedup-only and not logged on the happy path. **Fix:** a collector RoundTripper injecting `traceparent`+`X-Request-ID`, or correct the server tracing-package doc and log `X-Probe-Batch-ID` on ingestion.

### M12. Metric-send failures have no Prometheus counter · *finalSeverity: low*
- `internal/observability/metrics.go:297-300` — queue byte-cap drops are visible via `firewall_collector_queue_dropped_total`, but `doDirectSend` failures aren't. Combined with H9, the highest-value data is lost AND the loss is invisible. **Fix:** `firewall_collector_metric_send_failed_total{kind=...}` at each `doDirectSend` final-failure.

### M13. alpine:3.19 runtime base image is past end-of-life (cross-repo)
- collector `Dockerfile:14` (and server `Dockerfile:29`) — EOL ~Nov 2025, no apk backports; collector installs ca-certificates/bash/libcap. **Fix:** bump to alpine 3.21/3.22; add Renovate/Dependabot Docker rule.

### M-encbase. (cross-repo) Container bases unpinned floating tags
- collector `Dockerfile:2,14` (and server `Dockerfile:2,29`) — `golang:1.25-alpine` / `alpine:3.19` not pinned by `@sha256`; undermines reproducibility + tamper-evidence. **Fix:** pin by digest via Renovate.

---

## LOW

- **L1. SSH `HostKeyCallback` returns nil + password auth leaks FortiGate creds to a first-connection MITM (alert-only by design)** — `internal/ssh/ssh.go:72-75,97-100` (isNew:false, AUDIT-071). A MITM on the first/any connection harvests the admin password; the server-side host-key alert fires only AFTER disclosure and never on first connect. Prefer key-based auth for managed devices; document the residual risk; consider a local TOFU cache (block-before-disclosure on subsequent connects).
- **L2. SNMP getters use `vendor ...string` variadic to fake an always-supplied optional param** — `internal/snmp/snmp.go:252,461,541,564,653,686,713,740`; 8 identical unpack stanzas; mirrored cross-repo in server `cmd/poller/main.go:29`. Change to plain `vendor string`; update the mirrored server interface in the same change.
- **L3. Build version stale hardcoded `const` (1.2.129) vs CHANGELOG 1.2.131, no ldflags injection** — `cmd/collector/main.go:55`; feeds the startup banner, `firewall_collector_info{version}`, heartbeats. Bump in the release flow, or move to `-ldflags "-X main.version=$BUILD_VERSION"` (Dockerfile passes none).
- **L6. `doDirectSend` closes response body without draining — defeats keep-alive pool on every per-cycle send · *finalSeverity: medium*** — `internal/relay/relay.go:916` (callers 941-979). The server returns non-empty JSON; net/http only pools a connection if the body is read to EOF before Close. Backs 10 hot-path senders (~12 POSTs/device/cycle). Siblings `sendBatch` (`:1264`) and `sendOneRevisionWithRetry` (`:1534`) already drain. **Fix:** `_, _ = io.Copy(io.Discard, resp.Body)` before Close on every path including the 2xx return; add a regression test.
- **L7. Snapshot/detail senders return on 2xx without draining the body** — `relay.go:1578,1598,1621,1644,1667` (`SendProcessSnapshot`/`SendInterfaceErrorSnapshot(s)`/`SendSensorDetails`/`SendLicenseDetails`). Same pool defeat, lower frequency. **Fix:** drain before returning; consolidate the five through a shared drain-and-close helper.
- **L8. Ping opens a fresh raw ICMP socket per device per cycle; every concurrent socket parses all hosts' replies** — `internal/ping/ping.go:182,228-241,105`. Up to 10 concurrent `ip4:icmp` sockets each receive a copy of every inbound ICMP reply (correctness-safe via unique IDs). O(concurrent_pings * total_icmp_traffic) + per-cycle socket churn. **Fix:** one long-lived shared raw socket at `Start` with a demux goroutine routing by `(id,seq)`.
- **L10. Relay HTTPS client TLS sets no `MinVersion` — diverges from server (TLS 1.2 pinned) · *finalSeverity: info*** — `internal/relay/relay.go:523-571`. Not active on Go 1.25 (client default already TLS 1.2); a GODEBUG/toolchain change could regress. **Fix:** `tlsConfig.MinVersion = tls.VersionTLS12` (ideally 1.3).
- **L16. Duplicated `getEnv` helper** — `cmd/collector/main.go:48` + `internal/config/config.go:103` (isNew:false). Export `config.GetEnv`, delete the local copy.

---

## INFO

- **I6. `config.Load()` returns `(*Config, error)` that can never be non-nil; validation lives in the caller** — `internal/config/config.go:54-101`. `parseInt`/`parseBool`/`parseDurationSeconds` silently swallow malformed input (`PROBE_POLL_INTERVAL=6O` → 60s default). RegistrationKey validation lives in `cmd/collector/main.go:167`; ServerURL/port/interval validated nowhere. Contrast `queue.Open` (returns real errors). **Fix:** drop the unused error, or move required-field checks into `Load` and warn on unparseable env — match `queue.Open`'s idiom.
- **I7. (cross-repo) Server doc-DTO `relay.FlowSample` advertises phantom sFlow fields the collector never sends** — server `internal/relay/relay.go:68-102` vs `models.go:727-763`; collector DTO `relay.go:169-194` stops at TCPFlags+Drops. `SamplePool/SampleAlgorithm/EngineID/EngineType/SrcAS/DstAS/SrcMask/DstMask/TOS` are phantom both ends. **Fix:** prune the server doc-DTO to match the collector, or wire AS-path/ToS end-to-end (collector v5 decoder → DTO → `models.FlowSample` columns).
- **I10. Collector has no THIRD-PARTY-NOTICES attribution file (server does)** — repo root. Bundles `prometheus/client_golang` (Apache-2.0 — requires NOTICE propagation), bbolt (MIT), gosnmp (BSD-2), x/crypto & x/net (BSD-3). All permissive; the gap is the missing redistribution NOTICE. **Fix:** generate `THIRD-PARTY-NOTICES.md` (`go-licenses report ./...`), include prometheus' NOTICE.
- **I-cve. (cross-repo) govulncheck CI gate only fails on symbol-reachable vulns** — collector `docker.yml:53-56` (server `ci.yml:119-142`). Import/module-tier CVEs ride green. **Fix:** add a Trivy/Grype image scan (`--exit-code 1 --severity HIGH,CRITICAL`). The collector's x/crypto v0.52.0 is clean (it genuinely uses x/crypto/ssh); the SERVER lags at v0.51.0.
- **I-npm. (cross-repo, server-published) NPM admin GUI on `:81` published on 0.0.0.0 with no bind-restriction/default-cred note** — `Firewall-Mon/docker-compose.proxy.yml:9,16-19`. Relevant to collector operators who deploy the optional proxy. Bind `127.0.0.1:81:81`; warn to change the NPM default login; drop the obsolete `version:` key.

---

## Cross-Repo Wire-Contract Notes (collector-relevant)

The relay contract is HTTP/JSON; the collector's `internal/relay/relay.go` is the complete wire vocabulary and the only client. The server's `relay.go` is now DOC-ONLY (real receiver = `handlers_data.go` → `internal/models`). The `schema_version` handshake is correct both ends (Min=Max=1). Collector-side contract risks:

- **Approval-revocation is invisible to heartbeat:** `ProbeHeartbeat` (server) authenticates by Bearer only and never checks `ApprovalStatus` → returns 200 even for a revoked probe. The collector's heartbeat-driven re-register trigger (`relay.go:788`, 401/403→Register) can never fire from heartbeat; a revoked-then-idle probe keeps heart-beating "online" and only discovers revocation on its next data POST.
- **Direct-send has no idempotency key:** `sendBatch` sends `X-Probe-Batch-ID` (server-side dedup); `doDirectSend` (the 9 SNMP metric types) sends none → a timed-out-but-saved direct send that retries WILL double-insert system/interface/VPN rows server-side. AUDIT-042 idempotency covers only traps/pings/syslog/flows.
- **sFlow `Bytes` is sampling-rate-scaled at source** AND `SamplingRate` is also on the wire, with no contract note — a future server read-path that multiplies by `SamplingRate` would double-scale. Add a one-line comment in the collector DTO.
- **schema_version pinned to one value** ⇒ additive changes (`drops,omitempty` added without a bump) are deliberately NOT gated. Any future BREAKING field MUST bump `SchemaVersionMax` in lockstep in both repos or the 426 gate is bypassed.
- **sFlow agent-drops half-built (server side):** the collector populates `FlowSample.Drops` (`internal/sflow/sflow.go:279`) and sends it; the server stores it per-row but the operator-facing aggregate (`SaveAgentDrops`/`GetAgentDropsRecent`/`flow_agent_drops`) has zero non-test callers. NOC never sees agent congestion despite the data arriving. (Server-side fix — see I1 in the full report.)
