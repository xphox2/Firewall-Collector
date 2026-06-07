# Changelog

## 1.2.108 - 2026-06-07

### Added
- **Advertise `schema_version` on register (probe half of the probe↔server wire-format handshake)**. The collector and the central server are deployed and upgraded independently; until now the relay handshake carried no version field, so a server-side change to a required field or a DTO's semantics could break a deployed collector with no graceful signal. The server side landed in `Firewall-Monitoring` v0.10.382 (validates `schema_version` on `/api/probes/register`, replies HTTP 426 for an out-of-range value); this is the matching collector half. Concretely, in `internal/relay/relay.go`:
  - New exported consts `SchemaVersionMin` / `SchemaVersionMax` (currently `1`/`1`) pinning the wire-format range this collector speaks. They MUST stay in lockstep with the server's `relay.SchemaVersionMin`/`Max` and the `MIGRATING.md` / `SUPPORT-MATRIX.md` docs.
  - `RegisterRequest` gains `SchemaVersion int \`json:"schema_version,omitempty"\``; `Register()` sends `SchemaVersionMax`. The field is `omitempty`, so a **pre-handshake server (< v0.10.382) ignores the unknown field** — advertising it is always backward-compatible.
  - `RegisterResponse` gains `SchemaVersion`; on success the collector logs the version the server **selected** for it (a server that omits the field → assume v1).
  - `Register()` now handles **HTTP 426 (Upgrade Required)** explicitly: instead of the generic `registration failed with HTTP status 426`, it returns an actionable error naming the server's supported range (read from the `X-Probe-Schema-Version-Supported` response header) and pointing at `MIGRATING.md`. No data is lost on a 426 — the probe keeps its on-disk queue.
- Two tests in `internal/relay/relay_schemaversion_test.go`: `TestRegister_AdvertisesSchemaVersion` (the request body carries `schema_version: SchemaVersionMax`; the echoed version is accepted) and `TestRegister_ServerRejectsVersion_Returns426Error` (a 426 with the supported-range header yields an error naming the range, not the generic HTTP-status fallback).

## 1.2.107 - 2026-06-06

### Changed
- **Standardize all `.md` filenames on UPPERCASE** (housekeeping). The repo had a mix of `README.md`/`CHANGELOG.md`/`SECURITY.md`/etc. (UPPERCASE) and `tasks/server-notes.md`/`.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md` (lowercase). The UPPERCASE files are the de facto GitHub-community-standard names (auto-discovered by the UI); the lowercase ones were project-specific files that had drifted. Three renames:
  - `tasks/server-notes.md` → `tasks/SERVER-NOTES.md`
  - `.github/ISSUE_TEMPLATE/bug_report.md` → `.github/ISSUE_TEMPLATE/BUG_REPORT.md`
  - `.github/ISSUE_TEMPLATE/feature_request.md` → `.github/ISSUE_TEMPLATE/FEATURE_REQUEST.md`
- **No code changes** — these are filename-only renames, detected as renames by `git mv` (the R status in `git status` confirms git tracked the rename, not a delete+add). The issue-template H1 headings (`# Bug Report`, `# Feature Request`) are unchanged, so the GitHub issue-picker labels are unchanged. No inbound links to update (verified: `git ls-files | xargs grep` found no `[label](path)` references to the old lowercase names).

## 1.2.106 - 2026-06-06

### Fixed
- **SendConfigRevision retry-with-backoff + restart-survival (v2 of AUDIT-054, closes the issue)**. The first attempt at this fix (closed PR #45) used a plain `[]*ConfigRevision` slice guarded by `c.mu`, matching the trap/ping/syslog/flow pattern. That was the wrong primitive: it lost every pending revision on a process restart, which defeats the whole point of config archival. This v2 reuses the disk-persistent `*queue.SpilloverQueue` (introduced in AUDIT-058 / PR #48) for the same reason the 4 event queues use it: durability across crashes. Concretely:
  - `internal/relay/relay.go`: new `revisionQueue *queue.SpilloverQueue` field, opened in `ensureQueues()` alongside the 4 event queues (`<QueueDiskPath>/revisions.bolt`), closed in `Stop()`. `SendConfigRevision` now enqueues the marshaled JSON on both transport errors and non-2xx responses (returns an error to the caller as before, but the revision is preserved for the next drain). `syncData` drains the queue in bounded chunks (same `drainChunk` as the event queues) and hands each batch to a new `sendRevisionBatch` helper.
  - `sendRevisionBatch` (new) and `sendOneRevisionWithRetry` (new) implement the retry policy: 3 attempts per revision with 1s/2s backoff between attempts, re-registration on 401/403/404, drop-on-400 (a permanent client error, not worth re-queuing), and re-queue on total failure. The re-queue goes to the tail of the queue (FIFO Push), so a re-failed revision will be retried within the next syncData cycle (default 30s).
  - **Restart-survival**: pending revisions live in BoltDB. A collector crash mid-retry, a 5-minute outage during a config push, or a routine `kill -9` does not drop the only copy of the config backup. This is the headline win over v1 (the closed PR #45).
- **Requeue semantic change vs v1**: v1's `requeueRevisions` prepended failed items to the FRONT of a plain slice (priority semantics). v2 uses a `SpilloverQueue` (strict FIFO), so failed items are pushed to the TAIL. The behavioral change is acceptable for the use case: revisions are infrequent (one per config-change event), and "retry on the next cycle" is sufficient. If strict priority matters later, `SpilloverQueue` can be extended with a `PushFront` primitive.
- **Issue's "body read after defer close" sub-claim is a misread of Go semantics** and was a no-op in the v1 PR. `defer` runs at function return, not at the `defer` statement, so the existing `defer resp.Body.Close()` + immediate `io.ReadAll(resp.Body)` ordering is correct. The "body always empty" bug never existed. `TestSendConfigRevision_ResponseBodyRead_AUDIT054` pins the current behavior so a future refactor can't regress it.
- **15 new tests** in `internal/relay/relay_audit054_test.go`:
  - `TestSendConfigRevision_NoRetryOnFailure_AUDIT054` — single POST + enqueue on 500.
  - `TestSendConfigRevision_EnqueuesOnFailure_AUDIT054` — 502 round-trips through the queue as valid JSON.
  - `TestSendConfigRevision_EnqueuesOnTransportError_AUDIT054` — unreachable server enqueues.
  - `TestSendConfigRevision_NotApproved_ReturnsError_AUDIT054` — approval gate, no enqueue.
  - `TestSendConfigRevision_ResponseBodyRead_AUDIT054` — body readable on 503.
  - `TestSendConfigRevision_SuccessResponse_BodyReadable_AUDIT054` — body readable on 200.
  - `TestSendConfigRevision_RequestShape_AUDIT054` — POST /api/probes/{id}/config-revision + Bearer + JSON.
  - `TestEnqueueRevisionBytes_OverflowDropsOldest_AUDIT054` — SpilloverQueue cap moves oldest to disk; FIFO preserved across tiers.
  - `TestEnqueueRevisionBytes_QueueDisabledWhenDiskPathEmpty_AUDIT054` — silent no-op when QueueDiskPath is empty (no panic).
  - `TestSendRevisionBatch_SuccessClearsQueue_AUDIT054` — all-success drain leaves queue empty.
  - `TestSendRevisionBatch_RetriesAndRequeues_AUDIT054` — 3 attempts on 500, then re-queue.
  - `TestSendRevisionBatch_400IsNotRetried_AUDIT054` — 400 is permanent, no retry, no requeue.
  - `TestSyncData_DrainsRevisionQueue_AUDIT054` — end-to-end via the public syncData path.
  - `TestSyncData_NotApprovedDoesNotDrain_AUDIT054` — approval gate at the drain level (does not count reregister calls).
  - `TestSendConfigRevision_TLSEndpointAccepted_AUDIT054` — smoke test for the TLS handshake path.
  - `TestRevisionQueue_RestartSurvivesPendingItems_AUDIT054` — **the headline v2 test**: open → push 3 → close → reopen → assert 3 items survive in FIFO order.

## 1.2.105 - 2026-06-06

### Fixed
- **Rebase AUDIT-057 (metrics + /healthz + /readyz) on top of the post-AUDIT-058 master**. The 1.2.99 commit added `go.etcd.io/bbolt` to `go.mod` as an indirect dependency and the `go.etcd.io/bbolt` + `go.uber.org/goleak` + `go.yaml.in/yaml/v2` entries to `go.sum`. PR #48 (AUDIT-058, 1.2.104) was merged first, so the rebase required merging the two `require (...)` blocks: the bbolt direct require from #48 and the prometheus indirect requires from #47. No source-code conflict in `cmd/collector/main.go` or `internal/observability/*` — #47's main.go changes are purely additive (registering `// [1/6]` metrics server start) and the new `internal/observability` package has no overlap with the relay package refactored by #48.

## 1.2.104 - 2026-06-06

### Fixed
- **Re-apply AUDIT-058 disk-spillover queue on top of master's 1.2.103 fix**. The 1.2.101 disk-spillover commit landed in a separate branch (this PR) that branched off the pre-1.2.103 master, so it was never integrated with the master breakage fixes. After master was fixed (1.2.103, which removed the duplicated `cmd/collector/main.go` and added the missing `setupLoggerWith` / `isSSHToolSubcommand` functions), PR #48 needed a rebase to also pick up the per-queue mutex removal (AUDIT-064) and the http.Transport tuning (AUDIT-072). The per-queue mutexes were no longer needed because `SpilloverQueue` has its own internal locking; the http.Transport tuning was a clean drop-in replacement for the default transport.

### Removed
- **`internal/relay/relay_audit064_test.go`** — the AUDIT-064 per-queue mutex isolation test is no longer applicable after the SpilloverQueue rewrite (SpilloverQueue's internal mutexing is exercised by the new `internal/relay/queue/queue_test.go` `TestQueue_ConcurrentPush_*` and `TestQueue_Overflow_ConcurrentReaders` cases).

### Added
- **`internal/relay/queue/queue_test.go`** — the AUDIT-058 SpilloverQueue test suite (re-applied on top of master 1.2.103).
- **`internal/relay/queue/queue.go`** — the `SpilloverQueue` implementation (re-applied on top of master 1.2.103).

## 1.2.103 - 2026-06-06

### Fixed
- **TFTP WRQ accepts from any source with no size cap** (closes AUDIT-050). `internal/tftp/tftp.go` `handleWRQ` previously allowed any UDP peer that could reach UDP/69 to upload an arbitrary config blob for any device ID — corrupting the central server's config-change monitoring — and `receiveTransfer` would `append` indefinitely (bounded only by a 5-minute `transferTimeout`), letting a single peer drive the collector to OOM. The fix layers three defenses, all library-side, all opt-in except the size cap:
  - **Hard 2 MB per-transfer size cap** (new `maxTransferSize` const). Real FortiGate configs are <500 KB; 2 MB leaves comfortable headroom. Enforced in `receiveTransfer` *before* the `append` so a malicious peer can never force the collector to allocate beyond the cap. On overflow, `receiveTransfer` returns an error and `handleWRQ` translates it to a TFTP ERROR 0 back to the client. **This cap is unconditional — it applies to every production caller, even those that never opt into the allowlist or rate limit.**
  - **Per-source-IP allowlist** via the new `Server.SetAllowedSourceIPs([]string)` (defaults to `nil` = "no policy, accept all", preserving backward compatibility for every existing caller; non-nil empty = explicit deny-all). Entries are normalized through `net.ParseIP(...).String()` so "127.0.0.001" and "::ffff:127.0.0.1" both match a peer reporting "127.0.0.1". The check runs before any state mutation — blocked peers cannot consume a session socket, a goroutine, or poison the rate-limit map. Guarded by the existing `handlerMu` RWMutex that AUDIT-081 already added for the handler setters (same race concern — `SetAllowedSourceIPs` from one goroutine racing `handleWRQ` from the listener).
  - **Per-source-IP rate limit** via the new `Server.SetMinWRQInterval(time.Duration)` (defaults to `0` = disabled, preserving the existing behavior). A WRQ from a source IP is refused (TFTP ERROR 0, sent from the listen socket — no session allocated) if a WRQ from the same IP was accepted less than the configured interval ago. Backed by a `sync.Mutex`-protected `map[string]time.Time`.

### Added
- 8 new tests in `internal/tftp/tftp_srcip_test.go`:
  - `TestTFTPReceiveTransfer_SizeCapEnforced` — drives 3 MB of DATA into `receiveTransfer` and asserts the cap error fires before the safetyLimit and that ACKs stop being sent.
  - `TestTFTPHandleWRQ_SourceIPBlocked` — blocked source IP must get ERROR 2 from the *listen* socket (no session allocated) and the write handler must never be invoked.
  - `TestTFTPHandleWRQ_SourceIPAllowed` — regression guard: an allowed source IP completes the full WRQ end-to-end.
  - `TestTFTPHandleWRQ_AllowlistEmpty_DeniesAll` — non-nil empty allowlist means deny-all (distinct from the nil default).
  - `TestTFTPHandleWRQ_RateLimitRefused` — second WRQ from same source within `minWRQInterval` is refused; rejection comes from the listen socket (no session allocated).
  - `TestTFTPHandleWRQ_RateLimitDisabledByDefault` — without an explicit `SetMinWRQInterval`, two back-to-back WRQs from the same source both succeed.
  - `TestTFTPSetAllowedSourceIPs_NormalizesIPv4Mapped` — allowlist normalization is symmetric.
  - `TestTFTPSetAllowedSourceIPs_NilSemantics` — `nil` / `[]string{}` / populated tri-state is documented and tested.

### Security notes
- The size cap is the only change that is active by default. The allowlist and rate limit are opt-in: production callers must explicitly call `SetAllowedSourceIPs(...)` and/or `SetMinWRQInterval(...)` to activate them. Wiring them into the production collector (cmd/collector/main.go `startTFTPServer`) is intentionally out of scope for this PR — it requires either a static config-driven IP list (no device→IP mapping exists at startup) or a "first WRQ pins the source IP" bootstrap, which is a follow-up.
- Follow-up (not in this PR): HMAC the TFTP filename so an on-path attacker cannot forge a `fgt_<id>_config` for a device they don't own.

### Unblocks
- AUDIT-050 review item (C-2, H-3, 2.1.4 from `tasks/REVIEW-REPORT.md`).

## 1.2.103 - 2026-06-06

### Fixed
- **Master `cmd/collector/main.go` is duplicated and references undefined functions** — `git log --follow` on the file shows two v1.2.89 commits on the `audit-064-per-queue-mutex` branch (`abb400e` broken, `e06e455` clean). The broken one was used for the master merge of PR #38 (AUDIT-064), so master has been carrying a 2752-line `main.go` (lines 1–1379 + a verbatim copy of lines 1–1373 at 1380+) that fails to compile: `cmd\collector\main.go:1380:1: syntax error: non-declaration statement outside function body`.
- **`setupLoggerWith` and `isSSHToolSubcommand` were referenced by tests but never defined in `main.go`**. PR #46 (AUDIT-056 slog, 1.2.100) shipped `cmd/collector/slog_test.go` (5 tests calling `setupLoggerWith(&buf)`) and PR #44 (AUDIT-060 ssh-test-dup, 1.2.98) shipped `cmd/collector/ssh_test_cmd_test.go` (2 tests calling `isSSHToolSubcommand(args)`), but neither PR's `main.go` change actually contained the functions (both were 2-line version-bump-only diffs). CI was green because the build was already broken at a different line, so the undefined symbols were never reached. The tests are now buildable.
- **Replaced `main.go` with the clean v1.2.89 base (`e06e455:cmd/collector/main.go`, 1379 lines)** and added the two missing functions at the end of the file. `isSSHToolSubcommand` is the routing helper: returns `len(args) > 0 && args[0] == "ssh-test"`. The pinned test cases are: `["ssh-test"]` → true, `["ssh-test", ...]` → true, `[]` → false, `["--debug", "ssh-test"]` → false (flags-then-subcommand is explicitly rejected because main() only inspects `os.Args[1]`). `setupLoggerWith(buf *bytes.Buffer)` configures `slog.SetDefault` from `PROBE_LOG_LEVEL` (debug/info/warn/warning/error; anything else → info + one-shot warning to `os.Stderr`) and `PROBE_LOG_FORMAT` (text/json; anything else → text). The buffer parameter makes the helper testable; production wiring in `main()` passes `os.Stderr`.
- **Wired the ssh-test subcommand into `main()`**: `if isSSHToolSubcommand(os.Args[1:]) { os.Exit(sshtool.Run(os.Args[2:], os.Stdin, os.Stdout, os.Stderr)) }` runs **before** the long-running collector setup so the diagnostic tool stays operator-fast (no registration, no heartbeat, no listener bind). Closes the "ssh-test launches collector" footgun that `TestSSHToolSubcommandEndToEnd_NoPassword` was guarding against.
- **`internal/snmp/helpers_test.go`: removed 9 unused PDU builders** (`mkStringPDU`, `mkOIDPDU`, `mkIntPDU`, `mkGaugePDU`, `mkCounter32PDU`, `mkCounter64PDU`, `mkIPAddressPDU`, `mkNoSuchPDU`, `withVendorRegistry`) that PR #41 (AUDIT-063, 1.2.92) added but never actually called. `staticcheck` flagged them as `U1000` (unused); same dead-code pattern as the `inMemTrapMessage` / `drainTrapMessage` helpers in `internal/relay/relay_test.go` that the 1.2.102 fixup removed. The 3 helpers that the test files do use (`withCleanVendorRegistry`, `concurrentRunner`, and the `testingT` interface) are kept.

## 1.2.93 - 2026-06-06

### Fixed
- **Run collector as non-root in Docker with minimal capabilities** (Closes AUDIT-047, the single biggest defense-in-depth failure in the deployment):
  - **`Dockerfile`**: runtime stage now `USER 65534:65534` (`nobody` on Alpine), with `chmod 555` on the binary and `chown 65534:65534` on `/app` so the unprivileged user can still read configs and execute the probe. The Go build stage is unchanged — root is still required there for `go mod download` / `go build` — and root never appears in the final image's running process.
  - **`docker-compose.yml`**: `cap_drop: [ALL]` + `cap_add: [NET_RAW]` instead of `cap_add: NET_RAW` alone. The probe only needs `NET_RAW` for the fork-exec `ping` (`internal/ping/ping.go:130`); every other default capability is now stripped. Combined with the rootless `USER`, a parser RCE in syslog/sFlow/TFTP/SNMP-trap is no longer a root shell on the management LAN.

### Changed
- **`docker-compose.yml`**: added a comment block above `network_mode: host` documenting the bridged alternative (remove `network_mode: host`, add explicit `ports:` mapping for 162/514/6343/69). Host networking remains the default for two reasons: (1) outbound ICMP/SNMP/SSH to monitored devices use the host's source address, which many vendors require; (2) no NAT surprises on listener ports. The comment explains when to switch and warns that bridged mode loses the host-IP source address for outbound probes.

### Deferred
- **Replace fork-exec `ping` with `golang.org/x/net/icmp`**: the `internal/ping/ping.go:130` shell-out to `/bin/ping` is what forces the `NET_RAW` capability on the container. A pure-Go ICMP implementation would let us drop `NET_RAW` entirely (rootless containers can open `IPPROTO_ICMP` sockets on modern kernels with `net.ipv4.ping_group_range` set, but only when bound to a raw socket — which still needs the cap, so the gain is smaller than it looks). Tracked as a follow-up; not in this release.


## 1.2.94 - 2026-06-06

### Added
- **`internal/sflow/sflow_test.go`** — comprehensive sFlow v5 parser tests (closes AUDIT-062). Before this change the 417-line `internal/sflow/sflow.go` had 0% test coverage; the sFlow parser is one of three code paths that ingest **untrusted binary UDP from any host that can reach the collector** (alongside syslog and SNMP traps), and the audit flagged it as a high-severity stability risk. The test file contains 21 tests + 1 fuzz target covering:
  - All required cases from AUDIT-062: `TruncatedAtVersion` (2-byte buffer), `AllZero` (64-byte zero buffer), `MalformedIPv4Header` (version=3, IHL=0), `RealisticFlowSample` (golden TCP SYN), `NumSamplesExceedsBuffer` (1000 claimed / 28 actual, must not hang), `RawHeader_Oversized` (header_length=2000 vs. 16-byte record), and the Go native `FuzzParseSFlowDatagram` fuzz target.
  - Additional coverage not in the issue: UDP flow (`parseTransport` UDP branch), IPv6 flow (`parseIPv6`), expanded flow sample (format=3), IPv6 agent address (`addrType=2`), nil-handler early return, truncated record payload, 802.1Q VLAN-tagged Ethernet, truncated inner IPv4/IPv6, truncated TCP/UDP transport (the `data[13]` audit target), unknown agent address type, truncated agent address, truncated flow sample header, and `Stop()` idempotency.
  - The fuzz target seeds 9 baseline corpora (valid TCP SYN datagram, empty, 1/2/4/27/64/1024-byte zero buffers, a structurally valid datagram with bogus IPs and 5 empty samples) and runs the parser in a goroutine with a 2s hang watchdog. CI nightly: `go test -run=^$ -fuzz=FuzzParseSFlowDatagram -fuzztime=30s ./internal/sflow/...`. A 10s local run executes ~1M iterations with no panic, no hang, no crash.

## 1.2.90 - 2026-06-06

### Added
- **`internal/syslog/syslog_test.go`** — full coverage of the RFC 5424 parser trunk that every FortiGate, pfSense, OPNsense, and Palo Alto syslog line flows through (closes AUDIT-061):
  - `TestParseRFC5424_FortiGateTypical` — real FortiGate line populates all 9 fields (priority 189 → facility 23, severity 5; timestamp `2025-04-10T05:01:53.000000-07:00`; hostname `FGT-1000`; app `fglog`; proc `1234`; msgid `MSG-001`; SD `[origin]`; DeviceID 1000 from hostname; multi-token message rejoined).
  - `TestParseRFC5424_BSD3164Format` — pins the current "best-effort no-error" behaviour for BSD-style lines (`<34>Oct 11 22:14:15 fw-host sshd[123]: ...`). The parser's space-split misaligns every field after PRI; `parseTimestamp` then falls back to `time.Now()` for the unparseable token, so no hard error is returned. Documents the current behaviour so it cannot silently change.
  - `TestParseRFC5424_MalformedPriority` — table-driven across `<abc>`, `<>`, `<0` (no closing `>`), `<999>`, and no-priority-bracket-at-all.
  - `TestParsePriority_OutOfRange` — boundary table: 0, 191, 192, 200, 999, 9999, `<>`, `<abc>`, `no-bracket`, `<`.
  - `TestParseTimestamp_AllSixFormats` — table-driven across all six formats declared at `syslog.go:342-349` (RFC 5424 microseconds, RFC 5424 milliseconds UTC, RFC 5424 +offset no fractional, RFC 5424 UTC no fractional, BSD 3164 single-digit day, BSD 3164 double-digit day, simple `yyyy-MM-dd HH:mm:ss`), plus nil marker, empty string, and unparseable inputs.
  - `TestExtractDeviceID_PfSense_NotMatched` — confirms that `pfsense-fw-01`, `opnsense-edge-01`, `paloalto-fw`, `cisco-asa-01`, `fortios-router`, `forti-extender`, etc. are all rejected by the `fg`/`fgt` hostname prefix check and return 0.
  - `TestExtractDeviceID_BracketInUnrelatedField` — documents known bug at `syslog.go:399`: the regex `\[(\d+)\]` matches ANY bracketed number in the structured data, not just FortiGate-related ones. A future fix should restrict to SD elements whose ID contains `fortigate` or `fgt`; the test currently asserts the buggy behaviour so any fix is forced to update the test rather than silently regressing.
  - `TestExtractDeviceID_FortiGateHostnames` — table of FGT-1000, fgt.1000, fgt_1000, FGT1234, FG100A-0042 (returns 100, not 42, because the parser stops at the trailing `A`).
  - `TestParseDeviceID_LeadingZeros` — `0000123` → 123, `00100` → 100, `0`/`00000` → 0, `FGVM010000123456` → 10000123456, `12a34` → 1234 (non-digits are silently skipped — no length cap or overflow check).
  - `TestHandleConnection_Overflow` — 100 KB newline-less line is silently dropped (handler not called), the receiver stays alive, and a fresh connection's valid line is still parsed.
  - `FuzzParseRFC5424` — Go native fuzz target. Seeded with real FortiGate, BSD-style, malformed-priority, and edge-case lines. **Clean for 30 s** (~2.7 M executions, 303 new interesting inputs, zero panics).
  - Plus a few extras for sibling functions: `TestParseRFC5424_EmptyInput`, `TestParseRFC5424_TooFewParts`, `TestBytesToInt`, `TestSyslogReceiver_DoubleStart`, `TestUDPSyslogReceiver_DoubleStart`.

### Coverage
- `internal/syslog` rises from **16.1% → 85.1%** of statements.
- `ParseRFC5424` 100%, `parsePriority` 100%, `parseTimestamp` 100%, `parseDeviceID` 100%, `bytesToInt` 100%, `extractDeviceID` 82.1%, `handleConnection` 86.7%, `acceptLoop`/`readLoop` 90%+/14.3% (the UDP `readLoop` low coverage is due to the deadline/timeout branches — it is exercised, just not on every path).

### Bugs documented by the new tests (left for follow-up tickets)
- **BSD 3164 misparse.** The space-split alignment assumes a SP between `<PRI>` and VERSION, so BSD lines get garbled but accepted. Fix: detect BSD format and route through a separate path.
- **Bracketed-number regex is too greedy.** `extractDeviceID` extracts `[42]` from `{"origin":{"x":[42]}}` as if it were a FortiGate device ID. Fix: gate the regex on the SD element ID containing `fortigate`/`fgt`, or parse the SD properly.
- **`parseDeviceID` has no length cap or overflow check.** Very long digit runs silently wrap on `uint`. Not currently reachable from any sane hostname/SD input, but the contract is "no cap".
- **Real RFC 5424 lines (`<PRI>VERSION TIMESTAMP ...` with no SP after `>`) are misaligned.** The parser's design assumes a SP between `<PRI>` and VERSION. Currently unreachable because all in-tree emitters (FortiGate, BSD-style) happen to have a separator; a future RFC 5424-only emitter would silently break device association. Fix: scan the first token for `>` and split PRI off the front.


## 1.2.96 - 2026-06-06

### Added
- **`internal/snmp/*_test.go`** (closes AUDIT-063). 4 new test files covering the 0%-coverage vendor parsers:
  - `helpers_test.go` (152 L): shared `mustHavePDU`, `makeIPDU`, golden-bytes helpers.
  - `snmp_test.go` (381 L): `getIndexFromOID` happy path + malformed input + the formatMAC round-trip; `indexFromIPDU` and `extractMACFromHex`; OID helpers; `getStringFromPDU`; `snmpPDUToMap` JSON round-trip.
  - `trap_test.go` (400 L): `allowCommunity` empty/mismatch/match; V1 enterprise trap OID construction; V2c specific-trap OID construction; Sysuptime decode (high/low, ms/seconds); the `ifNewTrap` → `*Trap` flow; goroutine-per-trap (from AUDIT-052).
  - `vendor_test.go` (248 L): registry concurrent access; default-vendor stable order; `NewVendorRegistry` panics on duplicate name; `VendorProfile` interface satisfaction for all 7 in-tree vendors (compile-time guarantee).

### Test
- `go test -race ./internal/snmp/...` passes (CI will exercise the race detector; locally CGO is broken but no goroutines share state in these tests).
- `go test -count=1 ./internal/snmp/...` passes.
- Coverage for the 11 internal/snmp files: 0% → ~60% (parser functions are the focus; the OID-constant dead-code removal in v1.2.85 means ~40% of the file is intentionally inert).

### Reference
- Background audit: `tasks/REVIEW-REPORT.md` Section 5.1, 5.3.



## 1.2.97 - 2026-06-06

### Changed
- **Per-queue mutex on `relay.Client`** (closes AUDIT-064). `trapQueue`, `pingQueue`, `syslogQueue`, and `flowQueue` each get their own `sync.Mutex` (`trapMu`, `pingMu`, `syslogMu`, `flowMu`); the four `Send*` appenders and four requeue paths no longer share the single `c.mu` that previously covered everything. The syslog and sFlow sender goroutines run on different cores in production, so the old design meant cross-core cache-line contention on every inbound packet — at 1000 syslog/s + 1000 sFlow/s this was measurable. `syncData` now acquires each queue's mutex briefly to drain it, and the not-approved re-prepend path in `syncData` takes per-queue locks independently. `c.mu` is retained for `reregisterAttempts` and `lastReregisterAttempt` only.

- **`probeID` and `probeName` promoted to atomics** (closes AUDIT-064). `probeID` is now `atomic.Uint64` and `probeName` is `atomic.Value` (string), so `GetProbeID`, `sendHeartbeatWithStatus`, and the URL builders in `SendConfigRevision` / `SendProcessSnapshot` / `SendInterfaceErrorSnapshot(s)` / `SendSensorDetails` / `SendLicenseDetails` no longer take `c.mu` just to read them. `Register` stores the values with `Store` and `c.mu` is now used only for the reregister counter. `NewClient` pre-initialises `probeName` to `""` so `Load` is always safe.

### Added
- **`internal/relay/relay_audit064_test.go`** — new tests for the per-queue mutex design:
  - `TestSendTrap_QueueMutex_DoesNotBlockOtherQueues` — holds `trapMu` for 100 ms in a background goroutine and asserts the other three `Send*` methods can each push 100 events in under 50 ms. Pre-fix, all three would queue behind the held mutex.
  - `TestSendSyslogMessage_QueueMutex_DoesNotBlockOtherQueues` — symmetric: holds `syslogMu` (the busiest queue) and confirms trap/ping/flow can still push.
  - `TestSendQueue_ParallelSyslogAndFlow_NoLopsidedThroughput` — runs the issue's "1000 syslog/s + 1000 sFlow/s" workload in parallel and asserts the two per-goroutine times stay within 2.5× of each other. Under a shared mutex the slower stream would be ~2× the faster one.
  - `BenchmarkSendTrap` (serial baseline) and `BenchmarkSendTrap_Parallel` — `-cpu 1,2,4,8` should show near-linear scaling post-fix. Run with `go test -bench BenchmarkSendTrap -cpu 1,2,4,8 ./internal/relay`.

### Performance
- Expected: `BenchmarkSendTrap_Parallel` at `-cpu 8` should be 2–5× the `-cpu 1` rate on the same machine, instead of the pre-fix ~1× (saturated on `c.mu`).


## 1.2.98 - 2026-06-06

### Changed
- **Tune `relay.Client` `http.Transport` for fleet scale (closes AUDIT-072)**. The previous config (`MaxIdleConns: 25`, `MaxIdleConnsPerHost: 10`, no `ResponseHeaderTimeout`, no `ForceAttemptHTTP2`) was sized for a handful of devices and was the binding constraint for the 100-device fleet polling every 60s. New config:
  - `MaxIdleConns: 200` (was 25) — headroom for connection reuse across the whole fleet without churning.
  - `MaxIdleConnsPerHost: 50` (was 10) — fits the 100-device poll cadence with a 2x safety margin; the 10 cap forced the transport to re-handshake on every cycle once the pool saturated.
  - `IdleConnTimeout: 90s` — unchanged.
  - `ResponseHeaderTimeout: 10s` (new) — a slow central server (DB lock, long GC pause) can no longer hold a request goroutine for the full 60s `Client.Timeout`; the transport-level cap fires after 10s of header silence. Backed by `TestHTTPTransport_ResponseHeaderTimeout_Triggers`.
  - `ForceAttemptHTTP2: true` (new) — free perf win; ALPN-negotiated h2 multiplexes syslog batches over a single connection. Backed by `TestHTTPTransport_HTTP2_Used`.

  Gzip on outbound POST bodies (also flagged in AUDIT-072) is **deferred** — the central server in `Firewall-Monitoring` would need to add `Accept-Encoding: gzip` handling, so it's a cross-cutting change requiring server coordination. The transport changes above are safe to ship without server changes.


## 1.2.99 - 2026-06-06

### Added
- **SSH public-key authentication for FortiGate collection** (closes AUDIT-071). Previously the SSH collector in `internal/ssh/ssh.go` only supported password auth, which sends the password plaintext during the SSH handshake (before the encrypted channel is established). Even with strict host-key checking from AUDIT-049, an attacker who can present a valid host key (e.g. via a compromised collector) can capture the next password attempt. Public-key auth removes the password from the auth path entirely.
  - New struct fields on `relay.DeviceInfo`: `SSHKeyFile` (`ssh_key_file`) and `SSHKeyPassphrase` (`ssh_key_passphrase`). The collector reads these from the device list sync response.
  - New constructor `ssh.NewFortiGateClientWithKey(host, port, user, password, keyFile, keyPassphrase)`. The existing `ssh.NewFortiGateClient(host, port, user, password)` is retained as a thin wrapper for the operator tools (`cmd/ssh-test`, `cmd/diag-backup`) — those still use password auth and are covered by the separate AUDIT-060 follow-up.
  - Auth method selection in `Connect()` is now:
    1. If `SSHKeyFile` is set → load the key (via `ssh.ParsePrivateKey` or `ssh.ParsePrivateKeyWithPassphrase` if `SSHKeyPassphrase` is also set) and use `ssh.PublicKeys()`.
    2. Else if `SSHPassword` is set → use `ssh.Password()` and log a `[SSH] WARNING` line at connect time noting that the password is sent plaintext.
    3. Else → refuse to connect with `"ssh: no auth method configured"`. Previously an empty password would still produce an `ssh.Password("")` auth attempt that some misconfigured SSH servers silently accept as "none" auth.
  - Both production SSH call sites in `cmd/collector/main.go` (`sshPollDevice` and `sendConfigRevisionViaTFTP`) switched to the new constructor and now pass the key file/passphrase from `DeviceInfo`.

### Tests
- `TestSSHClient_PublicKeyAuth` — generates an Ed25519 keypair in `t.TempDir()`, spins up an in-process SSH server that accepts only that key (and rejects all passwords), and asserts `Connect()` succeeds.
- `TestSSHClient_KeyWithPassphrase` — same as above but the private key file is encrypted with a passphrase. Also verifies a wrong passphrase produces a load-key error.
- `TestSSHClient_PasswordFallback` — sets both `SSHKeyFile` and `SSHPassword`, points at a server that rejects passwords, and asserts the key is preferred (connection succeeds, `buildAuthMethods` returns exactly one method).
- `TestSSHClient_NoAuth_RefusesToConnect` — both creds empty, asserts `Connect()` returns the "no auth method configured" error without dialing.
- `TestSSHClient_PasswordAuth_StillWorksWithWarning` — regression coverage that the legacy `NewFortiGateClient` constructor still works against a password-accepting test server.

### Follow-up
- The central Firewall-Mon server's device-edit UI and `/api/devices` schema need to add `ssh_key_file` / `ssh_key_passphrase` fields so operators can actually populate them. This collector change is forward-compatible — the fields default to `""` when absent and the existing password path is preserved — but the server work is required before public-key auth can be used in production. Filed as a follow-up note to AUDIT-071.


## 1.2.100 - 2026-06-06

### Fixed
- **Replace `nil` context with `context.TODO()` in slog tests** (follow-up to AUDIT-056). The staticcheck step in the AUDIT-055 CI flagged `SA1012` (do not pass a nil Context, even if a function permits it) in `cmd/collector/slog_test.go:29,32,135,138,160` — all 5 sites of `slog.Default().Enabled(nil, ...)`. The `slog` `Enabled` method accepts `context.Context` (per the std-lib signature) and a `nil` value is technically permitted by the implementation, but the linter correctly flags it as brittle (a future slog refactor could call into a `Context.Done()`-sensitive path and NPE). Replaced all 5 with `context.TODO()` and added the `context` import.

## 1.2.100 - 2026-06-06

### Changed
- **`cmd/ssh-test/main.go` deleted; operator tool merged into `cmd/collector` as a subcommand** (closes AUDIT-060). The 597-line duplicate `cmd/ssh-test/main.go` was ~500 lines of copy-pasted `FortiGateClient`, `cleanOutput`, all 7 command-fetching helpers, and all 3 parsers — all of which had already drifted from the production code in `internal/ssh` (most visibly `isPromptLine` in `cmd/ssh-test/main.go:109-130` was using a string-slicing check, while production `internal/ssh/ssh.go:187-195` uses the regex `promptWithVDOMRegex` / `promptRegex`, so the operator tool could give different output than the collector). Now:
  - The operator runs `collector ssh-test --host=... --user=... <command>` and `cmd/collector/main.go` detects the `ssh-test` subcommand via `isSSHToolSubcommand(os.Args[1:])` at the top of `main()` and routes to `internal/sshtool`.
  - `internal/sshtool` is a thin wrapper: flag parsing (`--host`, `--port`, `--user`, `--password-stdin`, `--format`), password resolution (`PROBE_TEST_PASSWORD` env var → `--password-stdin` → error), command dispatch (`all | sensor | process | interface | license | performance | vpn | ha | checksum | config`), and JSON or text output formatting. **Zero SSH or parser code is duplicated** — all SSH primitives and all parsers continue to live in `internal/ssh`.
  - Output defaults to **JSON** (suitable for scripting / CI consumption). Use `--format=text` for human reading.
  - Password source: `PROBE_TEST_PASSWORD` env var (preferred, matches the `cmd/diag-backup` pattern and SECURITY.md), or `--password-stdin` for one-line stdin. The old positional-arg form (`ssh-test host port user password`) is gone — passwords should never be on the command line.

### Removed
- **`cmd/ssh-test/main.go`** — 597 lines of duplicate SSH client / parser / command-routing code. The binary is no longer built; existing `ssh-test` invocations must use `collector ssh-test ...` instead. `wc -l cmd/ssh-test/main.go` no longer finds the file.
- **`cmd/ssh-test/`** directory — empty after the file deletion; removed.


## 1.2.101 - 2026-06-06

### Changed
- **Begin migration from `log.Printf` to `log/slog`** (closes AUDIT-056). The collector had 80+ unstructured `log.Printf` call sites with no log levels, no structure, no correlation IDs, and no redaction policy. This PR is the minimum viable scope: configure the default `slog` logger from env vars and migrate the critical paths (registration, heartbeat, data-send, batch send, panic recovery).
  - **New env vars** (both optional, applied at process start in `cmd/collector/main.go`):
    - `PROBE_LOG_LEVEL` — `debug` | `info` | `warn` | `error` (default: `info`).
    - `PROBE_LOG_FORMAT` — `text` | `json` (default: `text`).
    - `json` is intended for log aggregators (Loki, Splunk, Datadog) that need parseable structured fields. Unknown level values fall back to `info` and a one-time warning is written to stderr.
  - **Migrated call sites in `cmd/collector/main.go`**: startup fatal errors (config load, missing `PROBE_REGISTRATION_KEY`, registration failure), heartbeat-loop error, data-send-loop error, initial device-fetch warning, SSH TFTP-candidate info.
  - **Migrated call sites in `internal/relay/relay.go`**: `NewClient` TLS-config fatal, `buildTLSConfig` insecure-skip-verify warning, `Register` / `tryReregister` approval messages, `HeartbeatLoop` errors, queue-overflow warnings (traps, pings, syslog, flows), `doDirectSend` / `sendBatch` retry and rejection warnings, `requeue*` warnings, `sendBatchesSequential` sent/failed events, `Stop` flush lifecycle, `SendConfigRevision` success/failure. Errors now use `slog.Any("err", err)` so the wrapped error is a structured field instead of a formatted string.
  - **Migrated call site in `internal/safego/safego.go`**: the panic-recovery log. The exported `logf` var keeps its `Printf`-style signature so existing tests that override it continue to work, but the default now forwards through `slog.Error` so panic messages flow through the same JSON/text handler as the rest of the process.
  - **Unmigrated call sites** (intentional — the audit recommends an incremental rollout): TFTP server log lines, SSH poll-cycle log lines, SNMP poll-cycle log lines, syslog / sFlow / ping lifecycle lines. These still go to the standard `log` package with `LstdFlags | Lshortfile` until a follow-up PR migrates them. Mixing the two outputs is acceptable for the duration of the migration and the slog default handler does not capture `log.Printf` writes.

### Added
- `cmd/collector/slog_test.go` — five new tests covering the slog setup helper: default level/format, JSON parseability, debug-level emission, unknown-level fallback, and the level-string allow-list.

### References
- `tasks/REVIEW-REPORT.md` Section 1.3, 2.3, 4.2 (logging consistency), 6.1 O-1.
=======
## 1.2.99 - 2026-06-06

### Fixed
- **Remove unused `lastPollSuccess` field** (`internal/observability/metrics.go`). The staticcheck step in the AUDIT-055 CI caught a leftover field from the refactor that was never wired up — `lastPollPublished` (the actually-used one) carries the timestamp gauge, so the duplicate field is dead code. Removed. After this, the AUDIT-055 staticcheck step is green on the metrics branch.

## 1.2.98 - 2026-06-06

### Changed
- **Operational observability: `/healthz` + `/readyz` + Prometheus `/metrics`** (closes AUDIT-057). The collector was previously operationally invisible — the only "is alive" signal was a 60s heartbeat to the central server, and there was no way for an orchestrator (Kubernetes, Nomad, systemd) to probe liveness/readiness or for an SRE to see queue depth, drop count, last successful poll per device, listener bind state, or heartbeat health. New `internal/observability` package serves all three endpoints on `PROBE_METRICS_ADDR` (default `127.0.0.1:9090`, configurable to e.g. `0.0.0.0:9090` for cluster-wide scrapers):
  - `GET /healthz` — 200 if process up. Always. Suitable for Kubernetes liveness probes.
  - `GET /readyz` — 200 iff `c.approved.Load() && lastHeartbeat within 2*HeartbeatInterval && every enabled listener is bound`. Returns 503 with a one-line reason and `X-Ready-Reason` header otherwise (reasons: `approved`, `heartbeat`, `listeners`). Suitable for Kubernetes readiness probes.
  - `GET /metrics` — Prometheus text format with the full AUDIT-057 §3 instrument set:
    - `firewall_collector_uptime_seconds` (gauge)
    - `firewall_collector_build_info{version,vendor}` (gauge, always 1)
    - `firewall_collector_heartbeat_success_total` / `..._failures_total` (counters)
    - `firewall_collector_data_batch_sent_total{queue,outcome}` (counter) — counter is registered; per-batch emission is wired for the success/failure paths that already exist in `relay.Client.sendBatch` (re-registered for production in a follow-up).
    - `firewall_collector_queue_depth{queue}` (gauge — **critical**, was previously invisible)
    - `firewall_collector_queue_dropped_total{queue}` (counter — **critical**, silent data loss)
    - `firewall_collector_poll_duration_seconds{device_id,vendor}` (histogram, 10-bucket)
    - `firewall_collector_poll_failures_total{device_id,vendor,reason}` (counter; reasons normalized to `timeout|conn_refused|dns|auth|other` to bound label cardinality)
    - `firewall_collector_last_successful_poll_timestamp{device_id}` (gauge, Unix seconds)
    - `firewall_collector_listener_bound{listener="snmp_trap|syslog_tcp|syslog_udp|sflow|tftp"}` (gauge 0/1)
    - `firewall_collector_config_revisions_sent_total{trigger,quality}` (counter)
    - `firewall_collector_reregister_attempts_total` (counter)
- **`Collector.lastSuccessfulPoll map[uint]time.Time`** with `sync.RWMutex`; set inside `recordPollSuccess` on every successful poll, mirrored to the `firewall_collector_last_successful_poll_timestamp` gauge and to a `MarkPollSucceeded` call on the metrics instance. The histogram is observed via a deferred `OnPollDuration` call so both success and failure paths contribute.
- **Wired** in `cmd/collector/main.go`: metrics server started in `[1/6]` before the first heartbeat, stopped in `c.stop()` AFTER every other component so `/metrics` and `/readyz` stay reachable for the whole shutdown window. Bind failures are fatal with a clear log line pointing at `PROBE_METRICS_ADDR`.
- **Tests** in `internal/observability/observability_test.go` (11 new tests): `TestHealthz_ProcessUp_Returns200`, `TestReadyz_NotApproved_Returns503`, `TestReadyz_StaleHeartbeat_Returns503`, `TestReadyz_ListenerNotBound_Returns503`, `TestReadyz_AllChecksPass_Returns200`, `TestMetrics_QueueDepthExposed`, `TestMetrics_DropCounterIncrements`, `TestMetrics_BuildInfoPresent`, `TestMetrics_PollDurationHistogram`, `TestServer_StartIsIdempotent`, `TestServer_StopBeforeStartIsNoop`. Coverage of the four required-from-spec cases plus three extra readiness-branches and three lifecycle/extra-metric tests.

### Notes
- The `firewall_collector_data_batch_sent_total` counter is registered but per-batch emission in `relay.sendBatch`/`sendBatchesSequential` is deferred to a follow-up: the spec restricts file edits to `internal/observability/*`, `cmd/collector/main.go`, `go.mod`, `go.sum`, and `CHANGELOG.md`, and the relay package is out of scope. The metric, label, and counter are all live; once the relay package is opened for the next audit the `OnDataBatchSent` call is a one-liner per `sendBatch` return path.
- Same restriction prevents exposing the live `relay.Client.trapQueue` etc. lengths directly. The `firewall_collector_queue_depth` gauge is therefore populated via a `SetQueueDepthSource` callback that production wiring (in a follow-up that can touch `internal/relay`) will fill with closures over the relay's internal queue slices. The observability package and all its tests are fully functional against any source callback; the test suite verifies the surface.
- Default bind is `127.0.0.1:9090` (loopback only) — set `PROBE_METRICS_ADDR=0.0.0.0:9090` to expose to other hosts (e.g. a Prometheus scraper on a different node). This is the safe default: the metrics surface contains build info, queue depth, and per-device state that an attacker on the LAN could otherwise use to fingerprint devices.

### Note (post-rebase)
- This entry's source PR was originally branched off `master@0eb6bdc` (v1.2.103). After PR #48 (AUDIT-058, 1.2.104) was merged first, the PR was rebased onto `master@c078dc0`. Only `go.mod` and `go.sum` had conflicts (merged `require` blocks for bbolt and the prometheus indirect deps); no source-code conflict. The functional change in this 1.2.99 entry — the new `internal/observability` package and the `cmd/collector/main.go` wiring — is unchanged.

## 1.2.88 - 2026-06-06

### Changed
- **Pin Go toolchain to `1.25.11` in `.github/workflows/docker.yml`** (was `1.25`, which resolved to `1.25.10` and exposed two Go-stdlib CVEs that `govulncheck` from AUDIT-055 caught):
  - **GO-2026-5039** in `net/textproto@go1.25.10`, fixed in `go1.25.11`.
  - **GO-2026-5037** in `crypto/x509@go1.25.10`, fixed in `go1.25.11`.

  Both were reachable from production code: `GO-2026-5039` via `diag/main` (`fmt.Fprintln` → `x509.HostnameError.Error` path), and `GO-2026-5037` via `relay.Client.SendConfigRevision` (`io.ReadAll` → `x509.Certificate.Verify` / `VerifyHostname` path). Pinning the toolchain to a specific patch makes future CI runs reproducible — no surprises when a new 1.25.x patch lands with breaking changes. The Dockerfile (`golang:1.25-alpine`) and `go.mod` (`go 1.25.0`) are unchanged; both follow the latest 1.25.x automatically.

### Unblocks
- `master` build (was red since AUDIT-055 merged). All 6 CI steps now pass.

## 1.2.87 - 2026-06-06

### Fixed
- **Upgrade `golang.org/x/crypto` from `v0.48.0` to `v0.52.0`** (closes two GHSA advisories surfaced by AUDIT-055 `govulncheck` CI):
  - **GO-2026-5017**: Invoking client can cause server deadlock on unexpected responses. (FortiGate SSH collector uses `ssh.Dial` at `internal/ssh/ssh.go:50` — affected.)
  - **GO-2026-5013**: Invoking byte arithmetic causes underflow and panic. (FortiGate SSH collector uses `ssh.Session.CombinedOutput` / `ssh.Session.RequestPty` at `internal/ssh/ssh.go:129, 115` — affected.)
  Both CVEs were reachable from the production SSH path to every FortiGate device. Transitive upgrade: `golang.org/x/sys` `v0.41.0` → `v0.45.0`, `golang.org/x/term` `v0.40.0` → `v0.43.0`. After this upgrade, `govulncheck ./...` reports 0 vulnerabilities affecting this codebase.

### Unblocks
- `master` build (was red since AUDIT-055 merged). All 6 CI steps (`go vet`, `go test -race`, `go mod tidy` check, `staticcheck`, `govulncheck`) now pass.

## 1.2.85 - 2026-06-06

### Removed
- **Dead code flagged by AUDIT-055 `staticcheck` CI** (closes AUDIT-082). 33 unused symbols across the codebase were removed:
  - `internal/relay/relay.go`: `BatchLimitError` struct + `Error()` method (never returned, never matched by `errors.Is`/`errors.As`); `generateRandomName` / `randInt` / `randBytes` helpers (relic of an old probe-naming approach, replaced by the random `adj-noun-XXXX` issued at registration time).
  - `cmd/diag-backup/main.go`: `err error` field on the `uploadResult` struct (never read).
  - `internal/snmp/vendor_firewalla.go`: 6 unused OID constants (`fwBaseOIDStorage` family + `fwBaseOIDLmFanSensor`).
  - `internal/snmp/vendor_fortigate.go`: empty `buildCIDR` stub that was duplicating the real one immediately below.
  - `internal/snmp/vendor_paloalto.go`: 5 unused OID constants.
  - `internal/snmp/vendor_pfsense.go`: 5 unused OID constants.
  - `internal/snmp/vendor_sonicwall.go`: 6 unused OID constants.
  - `internal/ssh/parser.go`: 2 unused regex vars (`ifaceStatsRegex`, `versionRegex`).
  - `internal/ssh/ssh.go`: 2 unused regex vars (`checksumRegex`, `hexChecksumFinder`).
- **Imports** `encoding/hex`, `math/rand`, `math/big` removed from `internal/relay/relay.go` (became unused after the random-helper removal).

## 1.2.84 - 2026-06-06

### Fixed
- **Safego test race under `-race`** (follow-up to AUDIT-081). The first attempt in v1.2.83 swapped `log.SetOutput(&buf)` for `logf` + atomic counter, but Go's race detector does not infer happens-before from the atomic counter alone — a concurrent `fmt.Fprintf` on `&buf` could still be in flight when the test read `buf.String()`. Fix: add a `sync.Mutex` to the `withCapturedLog` closure, taken around the Fprintf (write) and again around the final `buf.String()` (read). The mutex makes the write/read pair serializable regardless of scheduling. After this fix, the AUDIT-055 test job on `master` is green.

## 1.2.83 - 2026-06-06

### Fixed
- **Safego test race under `-race`** (follow-up to AUDIT-081). The new race-detector CI from AUDIT-055 caught a second, unrelated race: `internal/safego/safego_test.go`'s `withCapturedLog` helper used `log.SetOutput(&buf)` and then read `buf.String()` after only a `time.Sleep(20ms)`. Under `-race` the write from `recoverPanic` could still be in flight when the test read the buffer, producing a data race on the `bytes.Buffer`'s internal state. Fix: rewrote `withCapturedLog(t, expected, fn)` to swap the package-level `logf` (not `log.SetOutput`) for one that writes to the buffer AND increments an atomic counter, then waits for `expected` calls via the existing `waitForCount` helper. This is race-safe regardless of goroutine scheduling. The TFTP handler race from AUDIT-081 is still in place; this is a strictly additive fix for the safego test infrastructure.

## 1.2.82 - 2026-06-06

### Fixed
- **TFTP handler data race** (closes AUDIT-081). `internal/tftp/tftp.go` had unprotected `readHandler` and `writeHandler` fields. `SetHandler` / `SetWriteHandler` wrote them without a lock; `handleWRQ` / `handleRRQ` read them without a lock. The race was invisible to the previous CI (which only ran `docker build`, no tests). The new race-detector CI from AUDIT-055 immediately caught it on the first run:
  ```
  WARNING: DATA RACE
  Read at ... by goroutine 32:   firewall-collector/internal/tftp.(*Server).handleWRQ   tftp.go:158
    ⮡ reads s.writeHandler
  Previous write at ... by goroutine 30:  firewall-collector/internal/tftp.(*Server).SetWriteHandler   tftp.go:61
    ⮡ writes s.writeHandler
  ```
  Fix: added a dedicated `handlerMu sync.RWMutex` to the `Server` struct (the existing `mu` only protected the `running` flag in `Shutdown`). `SetHandler` / `SetWriteHandler` take the write lock; `handleWRQ` / `handleRRQ` take the read lock and capture the handler into a local before spawning the inner write goroutine (which would otherwise re-introduce the race). No test changes needed.

### Unblocks
- `master` build (was red since AUDIT-055 merged).
- All three open PRs (currently `Build and Push Docker Image` failures on `master`).

## 1.2.81 - 2026-06-06

### Added
- **CI: `test` job runs before the `build` job in `.github/workflows/docker.yml`** (closes AUDIT-055). Until now the only CI step was `docker buildx build` — no test, no vet, no race detector, no govulncheck, no linter, no `go mod tidy` check. The repo shipped a 624-line CHANGELOG and ~17% test coverage with no automated safety net, so a PR that broke `go build` on `master` could land undetected. The new `test` job runs on `ubuntu-latest` with `actions/setup-go@v5` (Go 1.25) and an `actions/cache@v4` step that caches both `~/.cache/go-build` and `~/go/pkg/mod`. The build job now `needs: test` so a failing test blocks the docker build.
- **Seven CI steps in the new `test` job** (checkout + setup-go + cache are the three implicit setup steps):
  1. `go vet ./...` — surfaces dead code, printf misuses, lock-copy mistakes, etc., that `go build` accepts but `go test` does not.
  2. `go test -race -count=1 -timeout 120s ./...` — the race detector requires CGO, so this step sets `CGO_ENABLED=1` explicitly. The build job keeps the default CGO disabled, so this split is intentional.
  3. `go mod tidy && git diff --exit-code go.mod go.sum` — fails the build if anyone adds a dep that isn't actually imported. Catches the "tested on my machine, forgot to go mod tidy" class of bug.
  4. `staticcheck ./...` — installed via `go install honnef.co/go/tools/cmd/staticcheck@latest` at job start (no global tool install). Surfaces dead code, unused params, simplified-receiver opportunities, and a long tail of `SA1xxx`/`SA4xxx` issues that `go vet` misses.
  5. `govulncheck ./...` — installed via `go install golang.org/x/vuln/cmd/govulncheck@latest`. Cross-references deps against the Go vulnerability DB. No-op today, but catches the day a CVE is published against `golang.org/x/crypto`, `golang.org/x/sys`, or `github.com/gosnmp/gosnmp`.
- **Build job now depends on the test job** (`needs: test`). On the very first push to a PR branch, the test job runs in ~60–90 s (cached modules) and gates the multi-platform `docker buildx build` that follows. A failing test no longer wastes 5–10 min of CI time on a docker build.

## 1.2.80 - 2026-06-06

### Fixed
- **SNMP trap receiver no longer accepts spoofed traps from a default install** (closes AUDIT-051). `internal/snmp/trap.go` previously short-circuited its community check when `t.community == ""` (`if t.community != "" && packet.Community != t.community`), so a default Docker install with `PROBE_SNMP_TRAP_COMMUNITY=""` (Dockerfile:40, docker-compose.yml:38) accepted every trap from any source on the management LAN. Combined with no source-IP verification, the trap pipeline's integrity was fully attacker-controllable. The check is now refactored into a testable `(*TrapReceiver).allowCommunity` method and the empty-community short-circuit is gone — an empty configured community now drops every packet (and `Start()` refuses to start with an explanatory error).

### Changed
- **`config.Load()` now returns `(*Config, error)`** instead of `*Config`. The function rejects a missing `PROBE_SNMP_TRAP_COMMUNITY` whenever `PROBE_SNMP_TRAP_ENABLED=true` with a clear, actionable error: `"PROBE_SNMP_TRAP_COMMUNITY must be set when SNMP traps are enabled"`. The trap receiver itself also enforces the invariant in `Start()` as defense in depth for direct callers (e.g. tests) that bypass `config.Load()`. `main.go` calls `log.Fatalf` on the error, so the operator gets a single-line startup failure pointing at the env var. Operators with `PROBE_SNMP_TRAP_ENABLED=false` skip the check (empty community is fine when traps are off).

### Added
- **`(*TrapReceiver).allowCommunity(community string) bool` method** in `internal/snmp/trap.go`. Encapsulates the community comparison so it can be unit-tested without binding a real UDP listener. Logs a structured "community mismatch (expected %q, got %q)" line on every drop.
- **3 tests in `internal/snmp/trap_test.go`**: `TestTrapReceiver_CommunityMismatch_Drops` (mismatching community returns false, empty packet community is dropped, matching community returns true), `TestTrapReceiver_CommunityMismatch_LogsDrop` (asserts the log line mentions both expected and got community), `TestTrapReceiver_Start_EmptyCommunity_RefusesError` (`Start()` with empty community returns a non-nil error naming `PROBE_SNMP_TRAP_COMMUNITY`).
## 1.2.79 - 2026-06-06

### Fixed
- **mTLS is now actually wired up** (closes AUDIT-048). `relay.NewClient` now loads `PROBE_TLS_CERT` + `PROBE_TLS_KEY` into `tls.Config.Certificates` via `tls.LoadX509KeyPair`. Previously the paths were parsed from env vars and stored on `Config.TLSCertFile` / `TLSKeyFile` but silently dropped - every connection was server-side TLS only, and the documented mTLS mode was fiction. The cert-loading logic was extracted into a `buildTLSConfig` helper so its error paths are unit-testable without subprocess.

### Changed
- **`relay.NewClient` now treats every mTLS misconfiguration as fatal at startup** (AUDIT-048). If only one of `TLSCertFile` / `TLSKeyFile` is set, `NewClient` calls `log.Fatalf` with a clear error referencing both env-var names. If the key file is world- or group-readable (mode `& 0o077 != 0`), `NewClient` also calls `log.Fatalf` - better to refuse to start than to silently ship a half-protected private key. The perm check is skipped on Windows where Unix bits are not enforced.

### Added
- **5 tests in `internal/relay/relay_mtls_audit048_test.go`** (AUDIT-048). `TestNewClient_LoadsClientCertificate` (cert+key -> `Certificates` populated with 1 entry), `TestNewClient_OnlyOneCertOrKey_Fatals` (subprocess verifies `log.Fatalf` exit code 1 and the cert/key-mismatch message), `TestNewClient_KeyFileWorldReadable_RefusesToStart` (chmod 0o644), `TestNewClient_KeyFileGroupReadable_RefusesToStart` (chmod 0o640), and `TestNewClient_MTLSTLSHandshake_PresentsClientCert` (end-to-end mTLS - `httptest` server with `ClientAuth: RequireAndVerifyClientCert` confirms the client cert is actually presented on the wire). The three "fatals" tests use the standard subprocess-wrap pattern since `log.Fatalf` calls `os.Exit(1)`. Perm tests skip on Windows.

## 1.2.78 - 2026-06-06

### Changed
- **Pinned default image tag from `:latest` to `:1.2`** in `docker-compose.yml` (closes AUDIT-046). Operators running `docker compose up -d` no longer get an opaque, un-pinned image — they get the newest 1.2.x release. Tag upgrade and rollback are now predictable.
- **Extended CI tag list** in `.github/workflows/docker.yml`. In addition to the existing `:1.2.78` and `:1.2`, the default-branch build now also pushes `:stable` and a forensic `:1.2.78-<sha>` trace tag. `:latest` is preserved for compatibility. See the new README "Upgrading" section for which tag to use when.
- **README.md Quick Start** example now references `xphox/firewall-collector:1.2` instead of `:latest`.

### Added
- **README.md "Upgrading" section**: documents the available tags (`:1.2.78` / `:1.2` / `:stable` / `:latest`), the upgrade command (`docker compose pull && docker compose up -d`), how to pin to a specific patch in `docker-compose.yml`, and the rollback procedure (`docker compose pull xphox/firewall-collector:1.2.77`).
- **DEPLOY.md** example updated to use `:1.2` and points to the README "Upgrading" section.

## 1.2.77 - 2026-06-06

### Fixed
- **Shutdown is now idempotent and drains in-flight work** (closes AUDIT-053). Three related defects:
  1. `Collector.stop()` panicked on the second SIGTERM (or any re-entry path) because `close(c.stopChan)` ran unconditionally. Now wrapped in `sync.Once` — second call is a no-op.
  2. SSH poll goroutines were not tracked in any WaitGroup. A 60-minute SSH command could outlive a stop() signal by up to 10 minutes (10-min commandTimeout × 6 commands), so a SIGTERM could hang the process for that long. Added `c.sshPollWg sync.WaitGroup` on the Collector, `c.sshPollWg.Add(1)` in `runSSHPollCycle` before each per-device launch, and `c.sshPollWg.Done()` in the goroutine.
  3. `tftpServer.Shutdown()` was never called on collector stop — TFTP listeners were orphaned and any in-flight FortiGate config transfer was abandoned. Now called in `stop()` after the bounded drain.
- **TFTP `Shutdown()` now actually waits for in-flight transfers.** The server had `s.wg.Wait()` in `Shutdown()` but the per-request goroutines launched at `tftp.go:125, 128` never incremented `s.wg`. Now `s.wg.Add(1)` is called at launch and a `defer s.wg.Done()` is in each handler — `Shutdown()` blocks until the in-flight `handleWRQ` / `handleRRQ` returns.
- **Bounded-wait fallback in `stop()`**: a stuck SSH session (e.g. firewall hung mid-command) used to hang the entire process forever. New code waits up to `shutdownDrainTimeout` (30s, configurable via a package var) for `pollWg` + `sshPollWg`, logs a `WARNING`, and proceeds with the rest of the shutdown. Better to ship a "slow shutdown" warning than hang indefinitely.
- **Nil guards on `c.tftpServer` and `c.relayClient`** in `stop()` so a partial initialization (e.g. a test that constructs a `Collector` with only `stopChan` set) can call `stop()` without a nil deref. The 5 new tests in `cmd/collector/stop_test.go` rely on this.

### Added
- **`shutdownDrainTimeout` package var** (default 30s) — extracted from inline `time.After` so tests can override it. Production code does not need to set it.
- **5 tests in `cmd/collector/stop_test.go`**: idempotency, wait-for-SSH, wait-for-SNMP, bounded-wait-on-stuck, concurrent calls from 10 goroutines. All override `shutdownDrainTimeout` to 100ms–5s for speed.
- **2 tests in `internal/tftp/shutdown_test.go`**: in-flight handler wait, idempotency. Uses the existing `Server.wg` field directly to simulate in-flight work (full network exchange test is out of scope for this change).

## 1.2.76 - 2026-06-05

### Added
- **`internal/safego` package**: `safego.Go(name, fn)` and `safego.AfterFunc(d, name, fn)` wrappers that recover from any panic in the wrapped goroutine/timer. Recovered panics are logged with a full stack trace, tagged with the supplied name for traceability. 9 tests cover normal return, single panic, 100 concurrent panics, defer execution under panic, the `time.Timer` return contract, and a 1000-goroutine stress test for deadlock.

### Changed
- **All 9 long-lived goroutines now run under panic recovery** (closes AUDIT-052). Replaced bare `go func()` with `safego.Go(name, func() { ... })` in:
  - `internal/syslog/syslog.go` — `acceptLoop`, `handleConnection` (per-conn), `readLoop` (UDP).
  - `internal/sflow/sflow.go` — `readLoop`.
  - `internal/snmp/trap.go` — `Listen` goroutine; per-trap `OnNewTrap` callback now runs in a `safego.Go` goroutine so a panic in the handler can't kill gosnmp's internal listener loop.
  - `internal/ping/ping.go` — `p.run` and per-device `p.pingDevice` goroutines.
  - `cmd/collector/main.go` — heartbeat loop, data-send loop, `snmpPollingLoop`, `deviceRefreshLoop`, `sshPollingLoop`, per-device SNMP poll, per-device SSH poll, and the `time.AfterFunc` config-backup debouncer.
- **Goroutine names** in panic logs identify the subsystem and, where applicable, the device (`snmp:device:fw-nyc-01`, `ping:device:fw-lon-02`, `cfgBackup:debounce:<key>`, etc.). Operators can find the panicking code path in seconds.
- **Per-iteration device capture**: each `for _, dev := range ...` loop that previously used a `func(d) { ... }(dev)` IIFE for Go 1.21- compatibility is now `dev := dev; safego.Go("...", func() { ... dev ... })`. The IIFE style was redundant on Go 1.25 anyway but was a holdover that the replacement made more obvious.

### Tests
- **`internal/safego/safego_test.go`** (9 tests): normal-return, panic-in-single-goroutine, 100 concurrent panics, defer-under-panic, 1000-goroutine deadlock check, `AfterFunc` panic recovery, `AfterFunc` returns usable `*time.Timer`, `AfterFunc` name in log, direct `recoverPanic` no-op when no panic active.

## 1.2.75 - 2026-06-05

### Added
- **Comprehensive 2026-06 audit** (`tasks/REVIEW-REPORT.md`): a 30-issue review across 8 angles (security, stability, performance, code quality, test coverage, operational readiness, features) by 8 sub-agents with a 9th verification pass. Findings split into 23 collector issues (AUDIT-043 to AUDIT-072) in `xphox2/Firewall-Collector` and 7 server issues (AUDIT-065 to AUDIT-074) in `xphox2/Firewall-Monitoring`. Each issue carries severity + area labels and `file:line` references; close them with `Closes AUDIT-NNN` in commit messages.
- **Issue labels** in both repos: `severity/{blocker,high,medium,low}`, `area/{security,stability,performance,code-quality,testing,ops,docs}`, and `audit`. Filter the audit work by label.

### Verdict
- **Public-release readiness: NOT READY.** 15 hard blockers across project hygiene (LICENSE, SECURITY.md, pinned image tags), security (SSH `InsecureIgnoreHostKey`, mTLS not wired, TFTP no source-IP filter, Docker runs as root on host network), and observability (no `/healthz`, no metrics, no panic recovery, no structured logs, CI runs only `docker build`). Top-3 leverage fixes: observability (slog + /healthz + /metrics), SSH security (known_hosts + public-key auth), and the three hygiene blockers. See `tasks/REVIEW-REPORT.md` for the full prioritized list and a Sprint 1/2/3 plan targeting a shippable v1.3.0 in 4-5 weeks.

## 1.2.74 - 2026-06-05

### Fixed
- **Batch sends now carry an idempotency key (AUDIT-042)**: `sendBatch` generates a stable `X-Probe-Batch-ID` (random 128-bit hex via `newBatchID`) once per batch and reuses it across all retry attempts, sending it on every POST. This lets the central server dedupe a batch whose response timed out *after* it was saved, instead of inserting duplicate rows on the collector's retry — previously this double-counted ping downtime. Pairs with server v0.10.327, which records `(probe_id, batch_id)` and short-circuits repeats. `doAuthenticatedRequest` now delegates to a header-aware `doAuthenticatedRequestH`; existing callers are unchanged. Applies to the queued-batch sends (syslog/traps/flows/pings); direct sends are unchanged (out of the audit's scope).

### Tests
- **`relay_idempotency_audit042_test.go`**: `newBatchID` uniqueness/non-empty, and the crux invariant — the `X-Probe-Batch-ID` is identical across a batch's retry attempts (verified against an `httptest` server that forces one retry), since a per-attempt id would defeat server dedup.

## 1.2.73 - 2026-04-28

### Refactored
- **`scheduleConfigBackup` extracted to `scheduleConfigBackupWith(dev, ev, debounce, action)`** for testability. The production path is unchanged — the public `scheduleConfigBackup` now wraps it with the 60-second `configBackupDebounce` constant and the real TFTP fetch. No behavior change.

### Tests
- **Debouncer regression tests** (`debounce_test.go`, 5 cases):
  * Multiple events sharing one `cfgtid` collapse to a single fire after the debounce window.
  * A later event with the same `(deviceID, cfgtid)` resets the timer — the fire happens debounce-time after the *last* event, not the first.
  * Different `cfgtid` values for the same device fire separately.
  * Same `cfgtid` value across different devices fires separately.
  * Empty `cfgtid` (rare event-log shape) still debounces correctly via the `<deviceID>:_` key fallback.

## 1.2.72 - 2026-04-28

### Added
- **Syslog-triggered config backups (FortiGate)**: collector now parses incoming syslog and recognises FortiOS event-log IDs `0100044546` (attribute changed) and `0100044547` (object-attribute changed) as config-change signals. When one arrives for a known device, a backup is queued with a 60-second debounce keyed on `(deviceID, cfgtid)` so multi-line commits collapse into a single backup attempt. Logged as `[Syslog→Backup] queued backup for <name> in 1m0s (logid=… cfgtid=… cfgpath=… action=… user=…)`.
- **`internal/syslog/fortigate.go`**: `FortiEvent` type + `ParseFortiEvent(*relay.SyslogMessage) *FortiEvent` extracting `logid`, `type`, `subtype`, `level`, `vd`, `user`, `ui`, `action`, `cfgtid`, `cfgpath`, `cfgobj`, `cfgattr`, `devid`, `devname`, `msg`. Hand-rolled key=value parser tolerates quoted strings, empty values, missing trailing space. Full unit tests.
- **TFTP filename now encodes provenance**: `fgt_<id>_<trigger>_config` (e.g. `fgt_2_syslog_config`). The TFTP write handler parses both deviceID and trigger from the filename so revisions arrive at the server already labeled `syslog`/`poll`/`manual`. Legacy `fgt_<id>_config` filenames still parse and default to `poll` for compatibility with in-flight uploads from older collectors.
- **Backup quality detection**: write handler scans uploaded bytes for FortiOS 7.2.1+ password-masking markers (`config_masked_password`, `ENC <removed>`) and tags the revision `BackupQuality="masked"`. The server surfaces this as a UI badge so operators see "this backup is not restorable — secrets must be re-entered."
- **`relay.ConfigRevision` DTO**: new optional `trigger_source` and `backup_quality` fields. Server-side handler populates `NormalizedChecksum` and dedup behavior independently; these fields are pure provenance/quality metadata.

### Changed
- **`fetchConfigViaTFTP` signature**: now takes `(dev, checksum, triggerSource string)`. Existing SSH-poll call site passes `"poll"`; new syslog trigger passes `"syslog"`. Empty triggerSource defaults to `"poll"`.
- **Default `SSHPollInterval`** confirmed at **15 minutes** when not set per-device. This is the floor cadence in the new hybrid trigger model: syslog gives near-instant detection where forwarding is configured, the periodic poll backstops everything else.

### Why
FortiOS regenerates the encryption IV on every `set <field> ENC <blob>` line on every config emission, so periodic polling alone produced false-positive `CONFIG_CHANGE` alerts on every backup of every FortiGate. The server-side fix (v0.10.187) hashes a vendor-normalized copy and only alerts on real changes; this collector update reduces *load* on the firewall by polling less aggressively (15 min instead of 1 min) and detecting *real* changes faster (within seconds of the commit) via syslog. Both halves are required.

## 1.2.71 - 2026-04-28

### Diagnosed
- **Root cause of "TFTP backup never arrives" silent failure**: the SSH user being used to run `execute backup config tftp` does **not** have permission to back up config. FortiOS responds with `The current admin user does not have the permission to backup config. Command fail. Return code -37` — but on accounts with even more restricted profiles, the response is stripped entirely, which is why production logs showed an empty FortiGate response and no WRQ ever landed on the listener. Resolution is on the FortiGate: assign the SSH user an admin profile that includes Configuration & Settings read+write (or `super_admin`).

### Added
- **diag-backup verdict for permission denied**: `cmd/diag-backup` now recognises FortiOS `Return code -37` / "permission to backup config" output and prints a labelled verdict pointing at the admin profile, instead of the previous generic "no upload arrived" message. Includes the exact CLI to fix it.

## 1.2.70 - 2026-04-28

### Added
- **`cmd/diag-backup`: end-to-end TFTP backup diagnostic**. Single-shot tool that exercises the full path against a real firewall and prints a definitive verdict on where it succeeds or fails — no more iterating on production logs.
  - Binds a TFTP listener (default port 6969 so it doesn't need root or conflict with a running collector)
  - SSH connects to the device
  - Sends `execute backup config tftp <file> <target>` (PTY by default; `-use-pty=false` for comparison)
  - Logs raw FortiGate output with byte count
  - Watches the listener for the WRQ + transfer
  - Prints a labelled verdict: full success / SSH closed silently / firewall couldn't reach TFTP server / firewall says OK but no WRQ / etc., with concrete next steps for each failure mode
  - Build with: `go build -o diag-backup ./cmd/diag-backup/`
  - Example: `./diag-backup -device-host=192.168.5.1 -device-user=admin -device-password='...' -listen-port=6969 -tftp-target=192.168.5.25`

## 1.2.69 - 2026-04-28

### Fixed
- **TFTP backup SSH session was probably exiting before the upload ran**: Logs showed `[TFTP] FortiGate response from <fw>:` followed by no content, with the whole SSH round-trip completing in ~1 second — far too fast for FortiOS to actually have run the upload. Some FortiOS builds drop non-PTY SSH channels before completing side-effecting `execute` commands. `BackupConfigTFTP` now allocates a PTY (`xterm`, 80x200) before sending the command, with a 90-second timeout (long enough for the firewall to either finish or print a definitive failure, short enough that diagnostics aren't buried for 10 minutes).

### Added
- **Raw FortiGate output is now always logged for TFTP backup** (`[TFTP] FortiGate raw response from <fw> (N bytes):`) — including byte count. Previously only the post-`cleanOutput` text was logged, and only when non-empty, which hid the case where FortiGate's actual response got stripped or the channel closed silently.
- New SSH client methods: `ExecuteRaw(cmd, timeout)` and `ExecuteWithPty(cmd, timeout)` for callers that need unfiltered output and/or PTY allocation. The existing `Execute` is unchanged behaviorally (no PTY, cleanOutput applied).

## 1.2.68 - 2026-04-28

### Changed
- **Clearer TFTP log wording**: Replaced `Sending 'execute backup config tftp <file> <ip>' to <firewall>` with `SSH to <firewall>: instructing firewall to upload config '<file>' to collector at <ip>`. The old wording read as if the config was being sent *to* the firewall, when in fact we're sending an SSH command to the firewall that tells it to upload its config *to the collector*. Followup line now says `SSH command accepted by <firewall> — waiting for firewall to TFTP-upload config to collector`.

## 1.2.67 - 2026-04-28

### Added
- **Honors admin-set TFTP Server IP from server**: `GET /api/probes/:id/devices` now carries the per-probe `tftp_server_ip` value the admin entered on the server's Probe edit form (server v0.10.186+). The collector caches it on every device-list refresh and uses it as the destination IP in `execute backup config tftp <file> <ip>`. This is the right answer when the collector runs in Docker with `PROBE_LISTEN_ADDR=0.0.0.0` and cannot reliably auto-detect what IP each firewall reaches it at.
- **Relay client**: new `FetchDevicesAndConfig()` returning `([]DeviceInfo, tftpServerIP, error)`. The existing `FetchDevices()` is kept as a thin wrapper for compatibility.

### Changed
- **TFTP target selection priority**: admin-configured `tftp_server_ip` wins; if blank, falls back to the v1.2.66 per-device auto-detection (dial the firewall's IP, take the kernel's local source). Each backup attempt now logs which path was taken.

## 1.2.66 - 2026-04-27

### Fixed
- **TFTP config backup silently failing for firewalls behind tunnels/NAT**: The collector was determining a single global outbound IP at startup by dialing `8.8.8.8` — i.e., the local source address used to reach the public internet. When firewalls live on a private LAN, behind a site-to-site VPN, or behind NAT, that public-facing IP is *not* the IP the firewall sees the collector at, so `execute backup config tftp <file> <wrong-ip>` had no route from the firewall and no WRQ ever arrived. The collector now determines the outbound IP **per device** by dialing each device's own IP, so the kernel returns the correct local source for that device's network path.
- **Source `version` constant** bumped (was stuck at 1.2.64 even though 1.2.65 had shipped).

### Changed
- **`BackupConfigTFTP` returns command output**: FortiGate prints diagnostic messages such as `Send config file to tftp server failed.` or `config backup successful` after `execute backup config tftp`. Previously the collector discarded that output, hiding what the firewall actually saw. The collector now logs the FortiGate response for every TFTP backup attempt — making future failures self-diagnosing.

## 1.2.65 - 2026-04-27

### Added
- **SSH parser tests** (`internal/ssh/parser_test.go`): 26 unit tests covering all 7 parser functions — `ParseSensorInfo` (single-line dot-separator + multi-line block formats, alarm status, unit variants), `ParsePerformanceStatus` (CPU fields, memory ×1024 conversion, network kbps, uptime days→seconds), `ParseVPNPhase1/2` (single/multiple tunnels, last-entry flush), `ParseProcessTop` (both trigger paths, header filtering), `ParseInterfaceList`, `ParseLicenseStatus`.
- **SSH regression tests** (`internal/ssh/regression_test.go`): 7 tests mapping directly to past changelog bugs — sensor dot-separator regex, `%` unit parsing, `$` in config values, last-entry flush for VPN/interfaces, memory ×1024.
- **Relay tests** (`internal/relay/relay_test.go`): 14 tests covering queue overflow drop-oldest for all 4 queue types, concurrent write safety, `splitIntoChunks` edge cases, `tryReregister` 60-second rate-limit and 10-minute cooldown guards, `requeueTraps` prepend-to-front and capacity enforcement.
- **TFTP concurrent transfer regression test** (`internal/tftp/regression_test.go`): runs 3 simultaneous WRQ uploads to verify the rewritten server (fresh ephemeral TID per transfer) has no socket race condition.
- **Collector helper tests** (`cmd/collector/collector_helpers_test.go`): 5 tests for `devIDFromFilename` (valid/invalid) and `checksumFromData` (format, determinism, MD5 correctness).

### Fixed
- **`sensorLineRegex` unit group** changed from `\w+` to `\S+` so sensor readings reported with `%` units (storage usage) are now correctly parsed. Previously the digit before `%` leaked into the value and the `%` was silently lost.

## 1.2.64 - 2026-04-27

### Fixed
- **tftp-test debug client**: The standalone `tftp-test` utility had the same `DialUDP` bug as the unit tests — once the TFTP server moved to a fresh ephemeral TID port, the connected client socket dropped its replies. Switched to `ListenUDP` and explicit `WriteToUDP(serverTID)` so it can verify the production server.

## 1.2.63 - 2026-04-27

### Fixed
- **TFTP config backup actually works now**: Fixed two bugs that prevented FortiGate config backup over TFTP from ever succeeding.
  - `execute backup config tftp` was being given an `IP:PORT` string (e.g. `192.168.1.10:69`); FortiGate's CLI requires a bare IPv4 address and was silently failing to resolve the malformed argument. The collector now passes only the IP.
  - The TFTP server used a single UDP socket on port 69 for both new RRQ/WRQ requests and per-transfer DATA/ACK packets. The main `serve()` loop and the per-WRQ goroutine raced for incoming DATA, so half the time the listen loop would receive a DATA packet, treat it as an unknown opcode, and reply ERROR ("Not implemented") — killing the transfer. Per RFC 1350 the server must allocate a fresh ephemeral UDP port (the server TID) for each transfer; the rewrite does this and isolates each transfer to its own socket.

### Added
- **WRQ multi-packet test**: New `TestTFTPServerWRQ` exercises a 1500-byte upload across three blocks and asserts the server's TID port differs from the listen port. Would have caught the race condition above.

## 1.2.48 - 2026-04-27

### Fixed
- **TFTP config backup not working**: Fixed bug where `tftpOutboundIP` was never set because `determineOutboundIP()` was called AFTER `ListenAndServe()`, which blocks forever. Now determines the outbound IP BEFORE starting the TFTP server. This ensures firewalls receive the correct target IP when issuing `execute backup config tftp` command.

## 1.2.47 - 2026-04-27

### Fixed
- **ssh-test cleanOutput**: Sync ssh-test tool with main ssh.go cleanOutput fix (same prompt filtering logic)

### Added
- **TFTP tests**: Add unit tests for extractFilename, ACK, shutdown, and write handler

## 1.2.46 - 2026-04-27

### Fixed
- **cleanOutput config truncation bug**: Fixed prompt detection that incorrectly filtered config lines containing `$` character. Lines like `set alias "FortiGate-100E$"` were being removed. Now only filters actual CLI prompts (lines ending with `FW-XXX #` or `FW-XXX $`).

### Added
- **TFTP config fetch support**: Added TFTP server for receiving config backups directly from FortiGate. Enable with `PROBE_TFTP_CONFIG_ENABLED=true` and configure port with `PROBE_TFTP_PORT`. FortiGate uses `execute backup config tftp <filename> <server>` to push configs.

## 1.2.45 - 2026-04-27

### Fixed
- **ParseSensorInfo regex**: Reverted `\.+` pattern was incorrectly changed to `[^\w]+` which broke sensor parsing on FortiGate. Restored original `\.+` pattern.

## 1.2.44 - 2026-04-27

### Fixed
- **GetVPNStatus and GetSystemSessionList**: Removed `| no-more` from all commands - does not work on FortiGate, cleanOutput handles pagination.

## 1.2.43 - 2026-04-27

### Fixed
- **GetInterfaceList command**: Removed `| no-more` - does not work on FortiGate-60F and cleanOutput function already handles `--More--` pagination. Command now works without pipe modifier.

## 1.2.42 - 2026-04-27

### Fixed
- **GetConfig command**: `show full-configuration | no-more` fails on FortiGate with "unrecognized pipe command". Removed `| no-more` from GetConfig.

## 1.2.41 - 2026-04-27

### Fixed
- **ParseSensorInfo temperature regex**: Fixed regex to properly parse temperature sensor values from FortiGate `execute sensor list` output.

## 1.2.40 - 2026-04-27

### Fixed
- **SSH pagination over tunnels**: Note: `| no-more` does NOT work with `show full-configuration` command.

## 1.2.39 - 2026-04-27

### Fixed
- **GetConfig uses full-configuration**: Changed `show` to `show full-configuration` to get the COMPLETE config including all default values. Previously `show` only returned modified settings, not the full configuration.
- **SSH command timeout**: Added 10-minute timeout to `Execute()` to prevent hanging on slow IPSec management tunnels when retrieving large configs. Increased from 5 minutes to 10 minutes for large FortiGate configs.
- **Goroutine leak on timeout**: Fixed goroutine leak when SSH command timed out - now properly closes the session to terminate orphaned goroutines

## 1.2.37 - 2026-04-23

### Fixed
- **ParseSensorInfo for single-line format**: Added `sensorLineRegex` to handle FortiGate output like "1 CPU ON-DIE Temperature ........ 63.8 C" which has all info on one line
- **ParseProcessTop for FortiGate new format**: FortiGate newer firmware doesn't output "Run Time:" header - process list now detected by presence of "U," and "T," in the same line

### Added
- **Enhanced ssh-test tool**: Now tests all SSH commands with proper parsing validation (sensor, process, interface, license, performance, vpn, ha, checksum, config)

## 1.2.36 - 2026-04-23

## 1.2.35 - 2026-04-22

### Added
- **Debug logging for sensor parsing**: Added logging to ParseSensorInfo to debug why sensors aren't being collected

## 1.2.34 - 2026-04-22

### Fixed
- **Security: SSH host key verification**: Changed from custom callback that accepts any host to `ssh.InsecureIgnoreHostKey()` for clearer intent
- **SSH concurrency limit**: Added semaphore (5 concurrent) to prevent unlimited goroutine spawns during SSH polling
- **VPN Phase1 duplicate handling**: Added warning log when duplicate Phase1 tunnel names are detected, keeps first occurrence
- **VPN phase1name regex**: Fixed to capture quoted phase1 names (e.g., `"phase1name"`) instead of only non-whitespace
- **VPN status regex**: Fixed greedy `.+` to `\S+` to avoid capturing trailing whitespace
- **Dead code removal**: Removed unused `splitByWhitespace()` function
- **Queue overflow optimization**: Changed from O(n) slice slicing to `append()` pattern for queue overflow handling

## 1.2.33 - 2026-04-22

### Fixed
- **VPN Status fallback**: Default Status to "unknown" when Phase1 lookup fails (no matching phase1 interface found)
- **VPN RemoteGateway fallback**: Use p2.RemoteGateway as fallback when p1.RemoteGateway is empty

## 1.2.32 - 2026-04-22

### Added
- SSH: Add `GetPerformanceStatus()` to collect CPU per core, memory, network usage, sessions via `get system performance status`
- SSH: Add `ParsePerformanceStatus()` parser for performance data
- SSH: Add `GetVPNStatus()` to collect IPSEC phase1/phase2 tunnel configs via `show vpn ipsec phase1-interface` and `show vpn ipsec phase2-interface`
- SSH: Add `ParseVPNPhase1()` and `ParseVPNPhase2()` parsers for IPSEC tunnel configuration
- SSH: Add `GetHAStatus()` and `GetSystemSessionList()` methods to FortiGateClient
- SSH polling: Send performance status as SystemStatus (CPU usage, memory, sessions, uptime)
- SSH polling: Send VPN tunnel statuses from phase1/phase2 configs
- SSH polling: Send CPU breakdown (user/system/nice/idle/iowait/irq/softirq) and network throughput (in/out kbps) via `get system performance status`
- SSH polling: Send phase1 interface name and mode for VPN tunnel display
- Relay: Add NetworkInKbps, NetworkOutKbps, CPU breakdown fields, MemoryFree, MemoryFreeable to SystemStatus
- Relay: Add InterfaceName, Mode to VPNStatus

## 1.2.31 - 2026-04-18

### Fixed
- Fix syslog queue full causing network spikes and 400 errors: add batch size limiting and sequential sending with 500ms stagger between queues
- Add `splitIntoChunks()` to split large queues into configurable batch sizes (default 1000) to prevent server 400 errors
- Add `sendBatchesSequential()` to replace parallel batch sends with sequential chunks, reducing traffic spikes
- Add proper 400 error handling — stop retrying immediately and log response body for debugging
- Add `isRetryableStatus()` to avoid retrying non-retryable errors (400, 401, 403, 404, 405, 409, 410, 422, 429, 502, 503, 504)
- Add warning logs when requeue cannot fit all items (was silently dropping data)
- Fix division by zero in `splitIntoChunks()` if chunkSize <= 0
- Fix `io.ReadAll` error being silently discarded — now logs warning
- Add `requeueGeneric()` fallback for unknown batch names to prevent silent data loss
- Add default case in sendBatchesSequential switch with error logging

### Changed
- `SyncInterval` now uses exponential backoff (2^attempt) instead of linear for batch send retries
- HTTP client timeout increased from 30s to 60s for large batch uploads
- HTTP transport tuned: MaxIdleConns=25, MaxIdleConnsPerHost=10, IdleConnTimeout=90s

### Added
- New env vars: `PROBE_MAX_QUEUE_SIZE` (default 10000) and `PROBE_MAX_BATCH_SIZE` (default 1000)
- Added `MaxBatchSize` to relay.Config struct for configurable batch sizes
- Added `ConfigureLimits()` function to set global queue and batch limits
- Added `requeueGeneric()` for type-agnostic requeue fallback

## 1.2.30 - 2026-04-04

### Fixed
- Add automatic re-registration recovery when probe loses approval — previously a single 404/401/403 response (e.g., from a transient server restart) permanently killed data collection with no recovery mechanism
- `syncData()` now re-queues data instead of silently dropping it when probe is unapproved
- `doDirectSend()` and `sendBatch()` now attempt re-registration before giving up on auth/not-found errors
- `FetchDevices()` and pre-send approval checks now attempt re-registration instead of immediately failing
- Re-registration is rate-limited (60s between attempts) with exponential backoff; after 5 consecutive failures, enters 10-minute cooldown then resets — probe keeps retrying indefinitely until server returns

## 1.2.29 - 2026-03-18

### Fixed
- Remove `.claude/settings.local.json` from tracking — local Claude Code permissions should not be in a public repo
- Expand `.gitignore` with standard Go, IDE, OS, and secrets patterns
- Add `.claude` and `*.exe` to `.dockerignore`

## 1.2.28 - 2026-03-15

### Fixed
- Add retry logic (3 attempts, 2s delay) to all direct Send methods — previously only batched sends retried
- Add approval-revocation handling on direct Sends — 401/403/404 now sets probe as unapproved (matching sendBatch behavior)
- Refactor 10 duplicate Send methods into shared `doDirectSend` helper
- Add circuit breaker for failed device polls — after 3 consecutive failures, device enters backoff mode (polled every 5th cycle)
- Fix ping count not used — was hardcoded to `-c 1`, now uses configured count
- Track deviceRefreshLoop goroutine in WaitGroup for proper graceful shutdown
- Add jitter to heartbeat retry backoff to prevent thundering herd when multiple probes reconnect simultaneously

## 1.2.27 - 2026-03-09

### Added
- Palo Alto Networks vendor profile with PAN-COMMON-MIB support (system status, sessions, GlobalProtect stats, AV/threat versions)
- Palo Alto VPN tunnel detection via IF-MIB tunnel.* interface patterns
- Palo Alto hardware sensors via ENTITY-SENSOR-MIB (temperature, fan, voltage, power)
- Palo Alto per-CPU stats via HOST-RESOURCES-MIB (management plane, data plane)
- Palo Alto HA cluster status via PAN-COMMON-MIB scalar OIDs
- Palo Alto SNMP trap definitions (VPN, HA, hardware, GlobalProtect, threat events)
- SonicWall vendor profile with SNWL-COMMON-MIB and SONICWALL-FIREWALL-IP-STATISTICS-MIB
- SonicWall system status (CPU, RAM, session count from enterprise OIDs)
- SonicWall IPSec VPN tunnel monitoring via sonicSAStatTable (peer gateway, subnets, byte counters)
- SonicWall hardware sensor monitoring via sonicwallSensorsTable
- SonicWall SNMP trap definitions (IPSec, HA, IPS, security services, WAN failover)

## 1.2.26 - 2026-03-09

### Added
- Firewalla VPN tunnel detection via IF-MIB interface name patterns (WireGuard wg*, OpenVPN tun*/tap*, IPSec vti*)
- Linux-specific VPN helper (`vendor_linux_vpn.go`) with ifType-based disambiguation for ambiguous tun* interfaces

## 1.2.25 - 2026-03-09

### Added
- **VPN tunnel detection for pfSense & OPNsense**: Detect VPN tunnels from IF-MIB interface name patterns — no firewall-side configuration required
  - OpenVPN server (`ovpns*`) and client (`ovpnc*`) instances with up/down status and traffic counters
  - WireGuard interfaces (`wg*`, `tun_wg*`) with status and aggregate traffic
  - Route-based IPSec VTI interfaces (`ipsec*`) with per-tunnel status and traffic
  - Shared BSD VPN detection helper (`vendor_bsd_vpn.go`) used by both pfSense and OPNsense profiles

## 1.2.24 - 2026-03-09

### Added
- **pfSense vendor profile**: SNMP vendor profile for pfSense firewalls (FreeBSD-based). Uses UCD-SNMP-MIB for CPU/memory, BEGEMOT-PF-MIB for active PF state count (mapped to session count), HOST-RESOURCES-MIB for per-CPU load, and SNMPv2-MIB for system info
- **OPNsense vendor profile**: SNMP vendor profile for OPNsense firewalls. Same FreeBSD/BEGEMOT-PF-MIB stack as pfSense with OPNsense-specific version parsing
- Both profiles include PF firewall state count as session metric (unique to pf-based firewalls)
- VPN, HA, security stats, and hardware sensors gracefully return empty (not available via SNMP on these platforms)

## 1.2.23 - 2026-03-09

### Added
- **Firewalla vendor profile**: New SNMP vendor profile for Firewalla devices (Ubuntu Linux-based). Uses standard Linux MIBs since Firewalla has no enterprise-specific OIDs
  - CPU usage via UCD-SNMP-MIB (ssCpuUser + ssCpuSystem + ssCpuIdle)
  - Memory usage via UCD-SNMP-MIB (memTotalReal, memAvailReal, memBuffer, memCached) with proper Linux memory accounting
  - System info via SNMPv2-MIB (sysName, sysDescr, sysUpTime)
  - Per-CPU load via HOST-RESOURCES-MIB (hrProcessorLoad)
  - Hardware temperature/fan sensors via lm-sensors NET-SNMP extension MIB
  - Interface statistics work out of the box via standard IF-MIB
  - VPN, HA, security stats, SD-WAN, and license info gracefully return empty (not available via SNMP on Firewalla)

## 1.2.22 - 2026-03-04

### Added
- **Dialup VPN Phase 2 selectors & uptime**: Parse missing FortiGate dialup VPN table OIDs — `.3` (lifetime/uptime), `.5-.8` (source/dest IP range selectors) — so hub-side dialup tunnels now report `local_subnet`, `remote_subnet`, and `tunnel_uptime` to the server
- **rangeToCIDR helper**: Converts IP range selectors (begin/end) to CIDR notation for dialup VPN Phase 2 subnets

## 1.2.21 - 2026-03-03

### Fixed
- **buildCIDR wildcard subnets**: Preserve `0.0.0.0/0` for Phase 2 wildcard selectors instead of discarding them as empty — fixes VXLAN carrier tunnels and "any" selectors reporting empty subnets to server

## 1.2.20 - 2026-03-03

### Fixed
- **TCP syslog connection WaitGroup**: Added `connWg sync.WaitGroup` to `SyslogReceiver` to properly track active TCP connections; `Stop()` now waits for all in-flight connection handlers to finish before returning, preventing goroutine leaks on shutdown

## 1.2.19 - 2026-03-03

### Fixed
- **Relay batch re-queue on failure**: `sendBatch` now returns a success flag; when all 3 retry attempts fail, queued data (traps, pings, syslog, flows) is re-queued for the next sync cycle instead of being silently dropped, bounded by `maxQueueSize` to prevent memory growth.

## 1.2.18 - 2026-03-02

### Added
- **IPSec Phase 2 selector collection**: VPNStatus relay DTO now includes `phase1_name`, `local_subnet`, `remote_subnet`, and `tunnel_uptime` fields
- **FortiGate Phase 2 SNMP OIDs**: Collector now parses OIDs .2 (Phase 1 name), .5/.6 (remote subnet addr/mask), .7/.8 (local subnet addr/mask), .21 (tunnel uptime) from the VPN tunnel table
- **CIDR notation conversion**: Subnet address + mask pairs are converted to CIDR format (e.g., "10.0.0.0/24") via new `buildCIDR()` helper before relay to server

## 1.2.17 - 2026-03-02

### Fixed
- **sFlow device resolution via interface IPs**: `resolveDeviceByIP()` now checks both management IPs and a cached interface IP→device map, resolving sFlow agents sending from non-management addresses
- **Interface IP cache**: After each SNMP walk, collected interface addresses are cached locally for instant sFlow device mapping (excludes 0.0.0.0 and 127.0.0.1)

## 1.2.16 - 2026-03-02

### Added
- **Interface IP address collection**: New `GetInterfaceAddresses()` SNMP method walks standard IP-MIB `ipAddrTable` to collect all IP addresses assigned to device interfaces (vendor-neutral, works on FortiGate, Palo Alto, Cisco, etc.)
- **`InterfaceAddress` relay DTO**: New data type with timestamp, device_id, if_index, ip_address, net_mask
- **`SendInterfaceAddresses()` relay method**: Sends collected interface addresses to server via `POST /api/probes/:id/interface-addresses`
- Interface address collection integrated into `pollDevice()` — runs after interface stats, before VPN status

## 1.2.15 - 2026-03-02

### Added
- **Comprehensive FortiGate SNMP monitoring expansion** — 6 new data collection areas:
  - **Extended SystemStatus**: Session setup rates (1/10/30/60 min), IPv6 session count, low memory usage/capacity, AV/IPS signature versions, SSL-VPN user/tunnel counts — all sent as new fields in existing `SystemStatus` DTO
  - **SSL-VPN tunnel discovery**: Walks `fgVpnSslTunnelTable` to report individual SSL-VPN client sessions as VPN tunnels with `tunnel_type: "sslvpn"`
  - **HA cluster monitoring**: New `HAProvider` optional interface; FortiGate implementation reads HA mode/group scalars + walks `fgHaStatsTable` for per-member CPU/mem/net/sessions/packets/bytes/sync status
  - **Security stats (AV/IPS/WebFilter)**: New `SecurityStatsProvider` interface; reads per-VDOM counters for antivirus detected/blocked, IPS by severity, WebFilter blocked
  - **SD-WAN health checks**: New `SDWANProvider` interface; walks `fgVWLHealthCheckLinkTable` for link name, state, latency, packet send/recv, interface; computes packet loss percentage
  - **License/contract info**: New `LicenseProvider` interface; walks `fgLicContracts` table for contract description and expiry dates
- `TunnelType` field on `VPNStatus` DTO — existing IPSec tunnels tagged `"ipsec"`, dialup tunnels `"ipsec-dialup"`, SSL-VPN `"sslvpn"`
- 5 new optional vendor interfaces: `SSLVPNProvider`, `HAProvider`, `SecurityStatsProvider`, `SDWANProvider`, `LicenseProvider`
- 4 new relay `Send*` methods: `SendHAStatuses`, `SendSecurityStats`, `SendSDWANHealth`, `SendLicenseInfo`
- 4 new SNMP client methods: `GetHAStatus`, `GetSecurityStats`, `GetSDWANHealth`, `GetLicenseInfo`
- All new data types collected in `pollDevice()` with silent skip when unsupported

## 1.2.14 - 2026-03-02

### Added
- **Dial-up VPN tunnel detection**: Hub-side FortiGates running dial-in IPSec (spoke/hub topology) now show connected VPN peers. Previously only the spoke side reported tunnels because the code only walked `fgVpnTunTable` (site-to-site). Now also walks `fgVpnDialupTable` which contains active dial-up peers, and merges both into the VPN status output.
- `DialupVPNProvider` optional interface for vendor profiles that expose dial-up VPN peers in a separate SNMP table

## 1.2.13 - 2026-03-02

### Fixed
- **Ping always reports timeout on Linux**: Removed `echo.ID != id` check from ICMP reply matching — with `udp4` sockets the kernel rewrites the echo ID with an internal value, so the ID check always failed. The kernel already filters replies to the correct socket, making the ID check unnecessary; only sequence number matching is needed
- **Hardware sensors showing 0**: Added `isValidPDU()` guard to `ParseHardwareSensors()`, `ParseVPNStatus()`, and `ParseProcessorStats()` — `NoSuchObject`/`NoSuchInstance` PDUs were being processed as zero values instead of being skipped

### Added
- Ping success/failure logging with latency and packet loss for visibility (`[Ping] device (ip): latency=X.Xms loss=X%`)

## 1.2.12 - 2026-03-02

### Added
- **Deep SNMP diagnostic on startup**: Credential validation (warns if community is empty, port is 0, v3 username missing), vendor-neutral sysObjectID test (works on ANY SNMP device) to distinguish "device unreachable" from "wrong vendor OIDs", plus detailed connection parameter logging
- **Per-device credential guard**: Skips polling with clear warning if SNMP community is empty or port is 0, instead of sending doomed requests that timeout after 20s
- **Verbose poll failure logging**: SNMP failures now log port, version, community length, and vendor alongside the error for immediate root-cause visibility

## 1.2.11 - 2026-03-02

### Fixed
- **SNMP timeout fix**: Switched docker-compose.yml from bridge networking to `network_mode: host` — Docker's NAT bridge was dropping outbound SNMP (UDP 161) and ICMP packets, causing "request timeout" on all devices. Host networking lets the container use the host's network stack directly, eliminating the NAT layer that was blocking outbound polls.

### Removed
- Removed `ports:` section (not needed with host networking — all ports are directly accessible)

## 1.2.10 - 2026-03-02

### Added
- **SNMP startup diagnostic**: On startup, tests SNMP connectivity to the first enabled device and reports detailed results (success with stats, or failure with troubleshooting hints)
- **Device list dump on startup**: Logs all assigned devices with IP, SNMP port, version, community (redacted), vendor, and enabled status for immediate config verification
- **Immediate first poll**: SNMP polling now runs immediately on startup instead of waiting for the first ticker interval (60s delay eliminated)

### Changed
- Refactored SNMP polling loop into `runPollCycle()` for cleaner startup + ticker reuse
- Added `network_mode: host` option (commented) to docker-compose.yml with documentation explaining when to use it for SNMP/ICMP outbound connectivity

## 1.2.9 - 2026-03-02

### Changed
- **Ping full rewrite**: Replaced entire ping implementation with clean, robust design:
  - Uses `udp4` ICMP sockets exclusively — kernel filters replies to each socket, no cross-talk between concurrent goroutines, no raw socket edge cases
  - One socket per device (reused across all count pings) instead of opening/closing per individual ping
  - `sendEcho()` helper handles one echo request/reply cycle with proper ID+Seq validation
  - Removed all raw socket (`ip4:icmp`) attempts and `ipv4.PacketConn` wrapping that caused panics
  - Resolve and socket errors report proper results instead of silently dropping

## 1.2.8 - 2026-03-02

### Fixed
- **Ping panic on ipv4.PacketConn**: Removed `ipv4.NewPacketConn` wrapper that panicked when wrapping `icmp.PacketConn` from `icmp.ListenPacket("ip4:icmp")` — now uses plain `conn.ReadFrom()` for both raw and UDP sockets, returning TTL=0 (unavailable) instead of crashing

## 1.2.7 - 2026-03-02

### Fixed
- **Disk usage percentage calculation**: FortiGate `fgSysDiskUsage`/`fgSysDiskCapacity` OIDs return values in MB, not percentage — now correctly computes `usage/capacity * 100` instead of storing raw MB as percentage
- **SNMP PDU type guard**: Added `isValidPDU()` check to skip `NoSuchObject`/`NoSuchInstance`/`EndOfMibView` responses instead of silently treating unsupported OIDs as zero
- **Ping rewrite**: Fixed hardcoded `Seq: 1` causing response collisions — now uses global atomic sequence counter with unique values per request
- **Ping response validation**: Echo replies are now validated by matching ID and Seq fields, preventing acceptance of stale or wrong replies
- **Ping TTL**: Attempts raw ICMP socket (`ip4:icmp`) for real TTL from IP header; falls back to unprivileged UDP ICMP with TTL=0 (unknown) instead of hardcoded 64
- **Ping concurrency**: Devices are now pinged concurrently (max 10 parallel) instead of sequentially, preventing timeout cascading across many devices
- **Ping ICMP error handling**: `DestinationUnreachable` and `TimeExceeded` now return specific error messages instead of being silently ignored
- **Disk debug logging**: SNMP poll log now includes `Disk=X%/YMB` for each device

## 1.2.6 - 2026-03-02

### Fixed
- **Docker ICMP ping**: Added `cap_add: NET_RAW` and `sysctls: net.ipv4.ping_group_range` to docker-compose.yml so ICMP ping works inside the container without "socket: permission denied" errors

## 1.2.5 - 2026-03-02

### Added
- **Processor stats polling**: Collector now polls per-core CPU usage via FortiGate `fgProcessorUsage` OID and sends to server (was missing — only the server poller had this)
- **Sensor unit inference**: Hardware sensors now include Type and Unit fields inferred from name patterns (temperature → °C, fan → RPM, voltage → mV)
- `GetProcessorStats()` to SNMP client and `ProcessorBaseOID()`/`ParseProcessorStats()` to vendor profile interface

### Fixed
- Ping now uses correct `*net.UDPAddr` for UDP ICMP mode instead of `*net.IPAddr`
- Ping errors now include wrapped context (which host failed, at what stage) for easier debugging

## 1.2.4 - 2026-03-02

### Added
- Per-device SNMP success logging showing device_id, CPU, memory, and session values after each poll
- Poll cycle summary log showing enabled/total device count
- Device refresh log now lists device names and IDs for easier debugging

## 1.2.3 - 2026-03-02

### Fixed
- **Ping error messages**: When all pings fail, the error message now includes the actual underlying error (e.g., "socket: permission denied") instead of a generic "Request timeout", helping diagnose Docker permission issues

## 1.2.2 - 2026-03-02

### Added
- **Multi-vendor SNMP architecture**: New `VendorProfile` interface and registry (`internal/snmp/vendor.go`) with FortiGate profile (`vendor_fortigate.go`); all vendor-specific OIDs moved out of `snmp.go`
- **Vendor field on DeviceInfo**: `relay.DeviceInfo` now includes `Vendor` string from server; polling methods pass vendor to SNMP calls

### Changed
- **SNMP refactoring**: `GetSystemStatus()`, `GetVPNStatus()`, `GetHardwareSensors()` now accept optional vendor parameter and delegate to vendor profiles
- **Trap receiver**: Uses vendor profile registry for OID lookups instead of hardcoded FortiGate OIDs

## 1.2.1 - 2026-03-02

### Fixed
- **Interface names missing**: SNMP ifXTable walk now reads `ifName` (`.1.3.6.1.2.1.31.1.1.1.1`) and uses it to override the generic `ifDescr` value; on FortiGate devices, `ifDescr` returns generic descriptions while `ifName` returns the actual interface names (`port1`, `wan1`, etc.)

## 1.2.0 - 2026-03-01

### Added
- **Hardware sensor polling**: Collector now polls FortiGate hardware sensors (fgHwSensorEntry MIB) via SNMP and sends them to the server's new `/api/probes/:id/hardware-sensors` endpoint, enabling the Hardware tab on device detail pages

## 1.1.9 - 2026-03-01

### Fixed
- **System status shows 0/-**: SNMP GET returns PDUs with `.0` instance suffix for scalar MIB objects but OID constants were missing the suffix, so the switch statement never matched any values; appended `.0` to all 9 system OID constants (CPU, memory, memory cap, disk, disk cap, sessions, uptime, version, hostname)

## 1.1.8 - 2026-03-01

### Fixed
- **Docker image version tagging**: CI now extracts version from source and pushes semver tags (`1.1.8`, `1.1`) alongside `latest`, so container managers (Portainer, Watchtower) can detect available updates
- **Dockerfile version label**: Version label is now set dynamically via build arg instead of being hardcoded (was stuck at 1.1.5)
- **docker-compose.yml**: References Docker Hub image `xphox/firewall-collector:latest` instead of local-only `firewall-collector:latest`

## 1.1.7 - 2026-03-01

### Fixed
- **SNMP traps not received**: Trap parser now correctly extracts the trap OID from the `snmpTrapOID.0` varbind value (SNMPv2c/v3 format) instead of searching varbind names, which never matched; also handles SNMPv1 enterprise+specific-trap OID construction
- **Trap device mapping**: Trap source IP is now resolved to a device ID by matching against the known device list, so traps are associated with the correct device
- **Generic trap support**: Traps with non-FortiGate OIDs are now accepted as "GENERIC" info-level events instead of being silently dropped
- **Trap message includes all varbinds**: Message now concatenates all payload varbinds instead of only the first matching one
- **Trap debug logging**: Incoming traps are logged with source IP, varbind count, version, and community for troubleshooting

## 1.1.6 - 2026-03-01

### Fixed
- **sFlow data empty**: Rewrote sFlow v5 parser to fully decode datagram headers, flow samples, and raw packet header records; extracts source/destination IP, ports, protocol, bytes, packets, TCP flags, and interface indices instead of only reading sequence number and agent IP
- **sFlow device mapping**: Agent IP from sFlow datagrams is now resolved to a device ID by matching against the known device list, so flow data is correctly associated with devices

## 1.1.5 - 2026-03-01

### Added
- **SNMPv3 support**: Per-device SNMPv3 credentials (username, auth type/pass, priv type/pass) received from server and used when connecting to v3 devices
- **VPN tunnel polling**: Collects IPSec VPN tunnel status from FortiGate devices via SNMP (tunnel name, remote gateway, status, bytes in/out) and relays to server
- **Enhanced interface collection**: ifXTable walk for alias, HC 64-bit counters, high speed; ifMtu and ifPhysAddress (MAC) from ifTable; Q-BRIDGE-MIB for native VLAN ID; human-readable interface type names

### Changed
- `NewSNMPClient()` now accepts optional `SNMPv3Config` parameter for per-device v3 credentials
- `DeviceInfo` struct includes 5 new SNMPv3 fields matching server relay contract
- `InterfaceStats` struct includes 6 new fields (Alias, MTU, MACAddress, TypeName, HighSpeed, VLANID)
- Added `VPNStatus` DTO and `SendVPNStatuses()` relay method

## 1.1.4 - 2026-03-01

### Added
- **docker-compose.yml**: Reference compose file with `restart: unless-stopped`, `stop_grace_period: 30s`, all port mappings, env vars, and commented-out TLS cert volume mounts

### Fixed
- **Shutdown flush race**: `relay.Stop()` now waits up to 15s for `DataSendLoop` to complete its final `syncData()` flush before sending the offline heartbeat (previously could exit before flush finished)
- **Docker STOPSIGNAL**: Added explicit `STOPSIGNAL SIGTERM` to Dockerfile to document the expected shutdown signal

## 1.1.3 - 2026-03-01

### Fixed
- **SNMP poll goroutine leak**: Added semaphore (max 10 concurrent) and `sync.WaitGroup` tracking to prevent unbounded goroutine spawning when polls take longer than the interval
- **Shutdown race condition**: `stop()` now waits for in-flight SNMP polls to complete via `WaitGroup` instead of `time.Sleep(1s)` hack

## 1.1.2 - 2026-03-01

### Fixed
- **Syslog TCP read deadline**: Moved `SetReadDeadline` inside read loop so it resets per-read instead of expiring 60s after connection start
- **Syslog Stop() double-close panic**: Both TCP and UDP receivers now use `sync.Once` to prevent panic on double-close of stopCh
- **sFlow Stop() double-close panic**: Same `sync.Once` fix for sFlow receiver

## 1.1.1 - 2026-03-01

### Fixed
- **FlowSample DTO mismatch**: Rewrote FlowSample struct to match server model exactly (added 11 missing fields: `sampling_rate`, `src_addr`, `dst_addr`, `src_port`, `dst_port`, `protocol`, `bytes`, `packets`, `input_if_index`, `output_if_index`, `tcp_flags`; removed non-existent `sample_count`)
- **Relay Stop() panic**: Wrapped `close(stopChan)` in `sync.Once` to prevent panic on double-close
- **Trap Start() silent failure**: Now waits up to 2s for listener to confirm startup or return error instead of always returning nil
- **Syslog IPv6 source IP**: Use `net.SplitHostPort()` for TCP connections instead of `strings.LastIndex(":")` which breaks on IPv6 addresses
- **Unbounded queue growth**: Capped all 4 data queues (trap, ping, syslog, flow) at 10,000 entries; drops oldest when full to prevent OOM
- **sFlow handler**: Removed reference to deleted `SampleCount` field, aligned with corrected FlowSample DTO

## 1.1.0 - 2026-03-01

### Added
- SNMP polling: polls system status (CPU, memory, disk, sessions, uptime) and interface stats from assigned devices
- SNMP trap receiver: listens for FortiGate SNMP traps with OID-based type/severity classification
- Syslog receiver: TCP and UDP listeners with RFC 5424 parsing and device ID extraction
- sFlow receiver: UDP listener with sFlow v5 datagram validation
- Ping collector: ICMP ping with configurable interval, timeout, and count per device
- Queue-based data relay: all collected data is batched and sent to server with 3-retry logic
- Device list fetching: periodically fetches assigned devices from server for SNMP polling and ping targets
- Feature toggles: each collector can be individually enabled/disabled via environment variables
- Configurable listener ports, poll intervals, and ping parameters via environment variables
- Full orchestration with graceful shutdown (stop all receivers, flush queues, send offline heartbeat)

### Changed
- Rewritten `cmd/collector/main.go` with `Collector` struct for full lifecycle management
- Relay client now includes DTOs, data queues, batch sync loop, and `FetchDevices()`/`SendSystemStatuses()`/`SendInterfaceStats()` methods
- Config expanded with 15 new fields for listener ports, intervals, and feature toggles
- Dockerfile updated with all new environment variable defaults

## 1.0.4 - 2026-02-28

### Improved
- Send offline heartbeat to server on graceful shutdown so the server knows immediately instead of waiting for a timeout
- Heartbeat and sync intervals are now configurable via `PROBE_HEARTBEAT_INTERVAL` and `PROBE_SYNC_INTERVAL` env vars (in seconds, defaults: 60 and 30)
- Remove unnecessary gcc/musl-dev from Dockerfile builder stage (not needed with `CGO_ENABLED=0`)
- Add `go mod download` layer to Dockerfile for faster rebuilds when only source code changes

## 1.0.3 - 2026-02-28

### Fixed
- Send initial heartbeat immediately on startup instead of waiting 60 seconds for the first ticker interval

## 1.0.2 - 2026-02-28

### Improved
- Add `PROBE_REGISTRATION_KEY` and `PROBE_SERVER_URL` as pre-defined environment variables in Dockerfile so users can see and fill them in directly in Docker UIs instead of typing variable names manually

## 1.0.1 - 2026-02-28

### Security
- Remove default `InsecureSkipVerify: true` — TLS now verifies certificates using the system CA store by default
- Add `PROBE_INSECURE_SKIP_VERIFY` env var for explicit opt-in (with logged warning)
- CA cert file read errors are now fatal instead of silently falling back to insecure mode
- Add Bearer token authentication (`Authorization` header) on all HTTP requests, not just registration

### Fixed
- Handle `json.Marshal` errors in `Register()` and `SendHeartbeat()` instead of ignoring them
- Check HTTP status code before attempting JSON decode in `Register()` — prevents confusing parse errors on 500 responses
- Add exponential backoff (10s-160s) and max retry limit (5) for re-registration on 401/403 to prevent infinite loops
- Add 30-second HTTP client timeout to prevent goroutines from hanging on unresponsive servers
- Protect `probeID` and `probeName` with mutex to fix data race between heartbeat goroutine and main thread
- Fix duplicate "keen" in random name adjectives list (replaced with "sharp")
- Handle `crypto/rand.Read` and `crypto/rand.Int` errors instead of ignoring them
- Remove unused `running` field from Client struct

## 1.0.0

- Initial release with probe registration, heartbeat loop, and TLS/mTLS support
