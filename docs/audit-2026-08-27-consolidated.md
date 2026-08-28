# Engineering Audit — 2026-08-27 (Firewall-Collector + cross-repo)

**Date:** 2026-08-27  
**Method:** Deep adversarial multi-agent audit. 22 finder lenses (Knuth/`taocp` and GoF/`design-patterns` applied on the algorithmic and abstraction-heavy areas) swept 100% of both repos' source; a dedup + do-not-re-flag screen produced candidates; every candidate faced **three independent refuter lenses** (reproduce-from-source, exploitability/materiality, mitigation-or-intent) and survived only on **≥2 confirmations** (refute-by-default). A completeness-critic loop ran until dry, and the highest-severity findings were re-derived by an independent accuracy pass before publication.

**Confirmed findings in this report: 49** — 2 high · 18 medium · 27 low · 2 info.

| Severity | Count |
|---|---|
| HIGH | 2 |
| MEDIUM | 18 |
| LOW | 27 |
| INFO | 2 |

| Defect class | Count |
|---|---|
| `correctness` | 13 |
| `docs-drift` | 8 |
| `input-hardening` | 7 |
| `data-integrity` | 6 |
| `contract-drift` | 4 |
| `toolchain-ci` | 3 |
| `security` | 3 |
| `concurrency` | 3 |
| `test-gap` | 1 |
| `performance` | 1 |

**Scope:** collector (`Firewall-Collector`) findings plus the cross-repo contract findings that touch the wire protocol / SNMP vendor parity. The full server findings live in the `Firewall-Mon` copy of this report.

## Highest-severity summary

- **AUDIT-175 (HIGH)** — sendBatchesSequential silently drops the drained-but-unsent tail on a transient failure — defeats the AUDIT-058 outage-durability guarantee (`internal/relay/relay.go:1971`)
- **AUDIT-177 (HIGH)** — FortiGate SD-WAN column OIDs omit the table-entry level (.2.1) — every PDU is swallowed by the Name branch, all SD-WAN metrics silently zero/garbage (`internal/snmp/vendor_fortigate.go:122`)

## Confirmed findings

### HIGH (2)

#### AUDIT-175 · HIGH · sendBatchesSequential silently drops the drained-but-unsent tail on a transient failure — defeats the AUDIT-058 outage-durability guarantee

**Firewall-Collector** — `internal/relay/relay.go:1971` · class: `data-integrity`

**Defect.** relay.go:1968-1971: on a transient chunk failure sendBatchesSequential calls requeue(chunk) then a bare `return` at 1971 — chunks[i+1:], already removed by the destructive Drain (queue.go:338/355/372), are never requeued; the comment 'leave the rest for next sync' is false. drainChunk = MaxBatchSize*10 (relay.go:1829) so up to ~9 of 10 chunks (~9,000 items at the 1000 default) are destroyed per failure. drainAndSend does not stop on failure (breaks only when len<drainChunk, 2035), so a full drain loops and repeats the loss. drainMetricQueue by contrast correctly requeues raw[idx:].

**Failure scenario.** Server down while the flow queue holds >MaxBatchSize items (trivial at a busy site): syncData drains 10,000, chunk 1 fails transiently → 1,000 requeued and ~9,000 destroyed; the drain loop repeats while len==drainChunk → a multi-day disk-spool backlog (AUDIT-058) is ~90% shredded within minutes, only per-chunk log lines. Fix: requeue the failed chunk AND all not-yet-attempted chunks, then stop the drain.

**Fix direction.** requeue the failed chunk AND all not-yet-attempted chunks, then stop the drain.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-177 · HIGH · FortiGate SD-WAN column OIDs omit the table-entry level (.2.1) — every PDU is swallowed by the Name branch, all SD-WAN metrics silently zero/garbage

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:122` · class: `correctness`

**Defect.** fgOIDSDWANHealth* = ...101.4.9.{2,4,5,7,8,14} but fgVWLHealthCheckLinkTable columns live at ...4.9.2.1.{...}; fgOIDSDWANHealthName equals the TABLE node so HasPrefix(name, Name+".") matches every column, funneling all PDUs into the Name branch. State/Latency/PktSend/Recv/IfName branches match nothing. No test covers ParseSDWANHealth.

**Failure scenario.** On a FortiGate with SD-WAN health checks, each row has Name overwritten by the last string column, State '', Latency/loss 0 — a dead link reports loss 0% with empty state, no operator signal, no alert. Fix the OIDs to ...4.9.2.1.*.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

### MEDIUM (18)

#### AUDIT-178 · MEDIUM · Collector CI installs staticcheck and govulncheck @latest (unpinned) — server pins both for exactly this failure mode

**Firewall-Collector** — `.github/workflows/docker.yml:61` · class: `toolchain-ci`

**Defect.** docker.yml installs staticcheck@latest and govulncheck@latest; server pins staticcheck@v0.7.0 and govulncheck@v1.6.0 with a comment explaining unpinned tools fail CI out from under unrelated PRs. The collector workflow also has no permissions: block.

**Failure scenario.** A new staticcheck release fires on existing collector code → test job red on an unrelated PR/hotfix → build (needs:test) never runs → image publishing blocked by an upstream release with zero code change; two runs of one commit can disagree, so 'CI was green' isn't reproducible.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-180 · MEDIUM · Collector version facts stale across four docs: README badge 1.3.4, SECURITY.md supports only 1.2.x, FEATURES.md says current is 1.2.x, DEPLOY.md instructs pulling :1.2 images

**Firewall-Collector** — `README.md:13` · class: `docs-drift` · related: `SECURITY.md`, `docs/FEATURES.md`, `DEPLOY.md`, `cmd/collector/main.go`

**Defect.** Badge 1.3.4 vs version 1.3.33; SECURITY.md table lists only 1.2.x (33 1.3.x releases absent) and tells reporters to inspect :1.2.x; FEATURES.md 'current 1.2.x'; DEPLOY.md pulls :1.2 while README default is :1.3.

**Failure scenario.** A user following DEPLOY.md runs :1.2 (frozen: no NetFlow/IPFIX, no disk/load, no command channel, no L2 topology at schema v2) then reports 'missing flows'; a researcher reads SECURITY.md and treats 1.3.x as unsupported/out-of-scope.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-181 · MEDIUM · README states Cisco ASA has no SNMP polling profile, but a full registered profile exists in both repos

**cross-repo** — `README.md:94` · class: `docs-drift`

**Defect.** Firewall-Mon/README.md:92-95 and :46 say Cisco ASA is 'config-diff only (no SNMP polling profile)'. False: internal/snmp/vendor_cisco_asa.go registers a full VendorProfile via init() with SystemOIDs (CPU/mem/session), ParseSystemStatus/ProcessorStats/HAStatus (CISCO-FIREWALL-MIB failover), CDP neighbor discovery — identical in both repos. vendor.go keys by Name() so GetVendorProfile("cisco_asa") returns it; vendor_robustness_test.go enumerates cisco_asa. Collector README also omits ASA from its SNMP-pollable list.

**Failure scenario.** An operator with a Cisco ASA fleet reads the README, concludes ASA cannot be SNMP-health-monitored, and never adds ASA for polling — a fully-built, tested SNMP profile (CPU/mem/sessions/failover/CDP) sits unused because the doc contradicts shipped, reachable code.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-186 · MEDIUM · sFlow samples attributed by in-band agent_address, not bound to the UDP source — intra-fleet cross-device flow/counter forgery

**Firewall-Collector** — `cmd/collector/main.go:557` · class: `data-integrity` · related: `internal/sflow/sflow.go`

**Defect.** sFlow device attribution uses SamplerAddress, which for sFlow is the agent_address parsed from the datagram BODY (sflow.go:357/471), while the only spoofing guard checks the UDP source IP (sflow.go:253). The resolver keys on the in-band value: `sample.DeviceID = c.resolveDeviceByIP(sample.SamplerAddress)`. The allowlist binds only the UDP source, never agent_address, so a datagram from any allowed source may carry any agent_address. (NetFlow is NOT affected — it uses the UDP source as SamplerAddress.)

**Failure scenario.** Collector monitors A and B (both allowlisted). Attacker compromises A (or spoofs A's UDP source) and emits sFlow v5 whose in-band agent_address=B's IP with fabricated flow/counter samples. isSourceAllowed(A) passes; resolveDeviceByIP attributes them to B → forged telemetry drives false threat detections and bogus bandwidth graphs on B, and can game flowdedup.Key(B, B_ip) to suppress B's genuine flows. Same root cause as the TFTP finding: allowlist restricts sender, not claimed identity.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-187 · MEDIUM · TFTP WRQ handler trusts the filename-embedded device ID with no client-address binding — any allowlisted fleet device can forge config revisions for any other device

**Firewall-Collector** — `cmd/collector/main.go:1283` · class: `security` · related: `internal/tftp/tftp.go`

**Defect.** parseUploadFilename derives DeviceID purely from the fgt_<id>_<trigger>_config filename; clientAddr is available (findDeviceByID/resolveDeviceByIP exist) but never cross-checked. The AUDIT-050 allowlist is a flat fleet-wide IP set; checksum is computed over the attacker's own bytes; server ReceiveConfigRevision gates only on probe-assignment.

**Failure scenario.** A compromised/NAT-sharing fleet device passes the allowlist and uploads fgt_<victimID>_manual_config with fabricated text → an authoritative ConfigRevision for the victim: false CONFIG_CHANGE, poisoned diff history, or (if checksum matches) silent overwrite of the victim's backup ciphertext. Fix: bind clientAddr→device (warn/strict) or derive device from source IP.

**Fix direction.** bind clientAddr→device (warn/strict) or derive device from source IP.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-210 · MEDIUM · Collector queue drop/depth/batch metrics are registered as the primary silent-data-loss signal but never fed — permanently zero even during real disk-spillover drops

**Firewall-Collector** — `internal/observability/metrics.go:344` · class: `contract-drift` · related: `internal/relay/queue/queue.go`, `internal/relay/relay.go`, `cmd/collector/main.go`

**Defect.** IncQueueDropped (metrics.go:344), OnDataBatchSent (:331), SetQueueDepth/SetQueueDepthSource (:304) are defined but have NO production callers — verified: grep across the repo returns only the definitions plus internal/observability/observability_test.go. The registered series carry Help text promising alerting: firewall_collector_queue_dropped_total = 'Non-zero values mean silent data loss — investigate immediately.' (:205-208). The real drop counter lives in the spillover queue (internal/relay/queue/queue.go:296/309 do q.dropped++ on disk-cap eviction) and exposes purpose-built Depth()/Dropped() accessors (queue.go:380/438) that are never wired to SetQueueDepthSource. refreshDynamic() only refreshes queue_depth when queueDepthSource != nil, which is always nil in prod. The Send* drop sites in relay.go only log.Printf on enqueue failure and touch no metric.

**Failure scenario.** During a prolonged central-server outage the disk-spillover queue hits PROBE_QUEUE_*_MAX_BYTES and evicts oldest telemetry (real silent data loss). The Prometheus alert the metric's own Help text invites — rate(firewall_collector_queue_dropped_total[5m]) > 0 — never fires because IncQueueDropped is never called, and the queue_depth dashboard reads a flat 0 throughout the backlog. The one metrics surface built to expose data loss reports all-clear while data is being dropped.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-211 · MEDIUM · Server internal/relay DTOs (the declared cross-repo wire-contract source of truth) have drifted from the actual v1-v5 wire: whole Tranche-3 field set missing, phantom fields retained, wrong Drops semantics, missing v5 structs

**cross-repo** — `internal/relay/relay.go:85` · class: `docs-drift` · related: `internal/api/handlers/handlers_data.go`, `internal/models/models.go`, `internal/api/handlers/handlers_probes.go`

**Defect.** The package doc declares itself the MIGRATING.md/SUPPORT-MATRIX source of truth, but server relay.FlowSample omits flow_source, app_name, as_path, next_hop, flow_start/end, firewall_event, flow_end_reason, the 4 post-NAT fields, icmp_type_code, src_vlan/dst_vlan while keeping sample_pool/sample_algorithm/engine_id/type/src_mask/dst_mask the collector never sends; Drops comment says delta but collector corrected it to cumulative; ConfigRevision lacks trigger_source/backup_quality, DevicesResponse lacks tftp_server_ip, Heartbeat/RegistrationRequest agent_version drift; TopologyEntry/Neighbor structs referenced but absent.

**Failure scenario.** An engineer building/auditing against the advertised source of truth omits the entire NetFlow/IPFIX tranche or double-counts Drops, or wastes effort on engine_id fields the server ignores — the lockstep the file demands is honored for version consts but broken for DTOs.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-212 · MEDIUM · Heartbeat command executor runs on a bare `go` without panic recovery, and inFlight is cleared with a plain statement not defer — a panicking command crash-loops the collector via at-least-once redelivery

**Firewall-Collector** — `internal/relay/relay.go:1295` · class: `concurrency` · related: `cmd/collector/commands.go`, `internal/safego/safego.go`

**Defect.** `go c.commandHandlerFn(hb.PendingCommands)` has no recover; safego package doc mandates safego.Go for lifetime goroutines and every other dispatch uses it. Secondary: handleOne sets e.inFlight[id]=true and clears it via a non-deferred statement (commands.go:257), so a recovered/contained panic leaves the CommandID wedged and every redelivery skipped.

**Failure scenario.** A command whose execution panics (malformed device REST response, nil-deref in fwapi) kills the whole collector — all polling/listeners stop; the crashed command is never reported (cache written only after return) and the server redelivers it on next heartbeat → crash loop until it expires (~15 min). Fix: safego.Go + deferred inFlight delete.

**Fix direction.** safego.Go + deferred inFlight delete.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-213 · MEDIUM · Requeue-then-rechunk breaks the M19 content-derived idempotency key — a committed-but-timed-out batch is re-inserted as duplicates

**Firewall-Collector** — `internal/relay/relay.go:1950` · class: `data-integrity`

**Defect.** contentBatchID is derived from the marshaled chunk, but chunk boundaries aren't stable: chunkSlice slices from index 0 while requeueItems pushes the failed chunk's items to the queue TAIL behind newly-arrived items. On the next sync [N new][requeued 1000] re-chunks at 1000 boundaries → the committed items get fresh hashes → server (probe_id,batch_id) dedup misses.

**Failure scenario.** Server commits a 1000-item flow batch but the response is lost; the chunk is requeued, 300 new samples arrive, next drain re-chunks and re-sends the committed items with new hashes → all 1000 rows inserted twice, skewing top-talker/bandwidth — the exact failure M19 closes.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-214 · MEDIUM · Event-queue requeue regroups items into a new batch, changing the content-derived idempotency key and defeating server dedup (duplicate inserts)

**Firewall-Collector** — `internal/relay/relay.go:1978` · class: `correctness`

**Defect.** contentBatchID (936) is documented 'stable across send attempts, requeues, sync cycles' so the server's (probe_id, batch_id) dedup catches a committed-but-lost-response batch. That holds only for byte-identical replays (the metric path stores the exact marshaled body). The EVENT path re-pushes items individually via requeueItems `q.Push(data)` (1990); the next drain regroups them with newly-arrived items before re-marshaling, where `batchID := contentBatchID(jsonData)` (2108) is computed over the whole chunk. Low confidence.

**Failure scenario.** Collector POSTs a batch A,B,C; server commits but the response is lost (transport error) → transient → requeueItems pushes items back; new samples interleave before the next sync; the re-drain produces chunk A,B,C,D,E hashing to a fresh X-Probe-Batch-ID the server has never seen → content-key dedup misses → previously-committed rows re-inserted (skewed flow byte/delta math) — the exact double-count contentBatchID was introduced to prevent, fixed only for the metric path.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-216 · MEDIUM · Collector unrecognized-trap path logs one line per varbind (unbounded) — a crafted trap is a log-volume/disk-fill amplification the server twin does not have

**Firewall-Collector** — `internal/snmp/trap.go:177` · class: `input-hardening`

**Defect.** Verified parseTrap's fall-through for an unrecognized trap (trapOID=='' AND no varbind matches the vendor registry) logs one line for EVERY varbind with no cap: `log.Printf("[SNMP Trap] Unrecognized trap from %s, varbinds:", addr.IP)` then `for _, v := range packet.Variables { log.Printf("[SNMP Trap] OID=%s Type=%d", v.Name, v.Type) }` (trap.go:176-180). The Firewall-Mon twin instead returns nil silently for an unrecognized trap (Firewall-Mon internal/snmp/trap.go `if trap.TrapOID == "" { ... return nil }`, no per-varbind logging). PROBE_TRAP_RATE_LIMIT_PPS (default 500) caps traps/sec/source but places NO bound on log lines per trap; PROBE_SNMP_TRAP_COMMUNITY is an optional allowlist (empty ⇒ allowCommunity returns true), listener binds 0.0.0.0:162, so the path is reachable unauthenticated by default.

**Failure scenario.** An attacker who can reach UDP/162 crafts a v2c trap that omits snmpTrapOID.0 and packs thousands of junk-OID varbinds into a single ~64KB datagram. Each datagram emits thousands of log lines; sustained at the 500 traps/sec/source ceiling this is millions of log lines/sec, filling the collector host disk — the same disk-fill outage class the project has hit before — while the server twin would discard each trap with zero log output.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-217 · MEDIUM · FortiGate dialup columns .7/.8 mapped as DstBegin/DstEnd, but fgVpnDialUpTable has DstAddr(.7)/Vdom(.8) — dialup RemoteSubnet always collapses to a /32

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:61` · class: `correctness`

**Defect.** fgOIDVPNDialupDstBegin/End=...1.1.7/.8 but the MIB entry is {...,DstAddr(7),Vdom(8),InOctets(9),OutOctets(10)} — no dst begin/end pair. Column .8 (Vdom Integer32) → safeString(int) returns '' → rangeToCIDR hits the end=='' branch → begin+"/32". The .3=Lifetime and .9/.10 choices confirm the layout.

**Failure scenario.** A hub FortiGate with a dialup spoke advertising 192.168.50.0/24 emits remote_subnet '192.168.50.0/32' → a single-host claim for a whole subnet, feeding wrong data into VPN views and IPSec selective-subnet canonical keys.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-218 · MEDIUM · Test gap: FortiGate — the production default vendor — has zero parser tests beyond one hardware-sensor regression

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:882` · class: `test-gap`

**Defect.** Only TestFortiGate_ParseHardwareSensors_DisplayStringValue exists; ParseSystemStatus/VPNStatus/DialupVPNStatus/rangeToCIDR/SSLVPNTunnels/HAStatus/SecurityStats/SDWANHealth/LicenseInfo (~700 lines) uncovered while cisco_asa/generic/opnsense have fixture tests. The SD-WAN/SSL-VPN/dialup/packet-loss defects all live in these untested functions.

**Failure scenario.** Any future OID/parse regression in the default profile (resolveVendor maps empty→fortigate) ships undetected because parse output is never asserted; paloalto/sonicwall parsers have no tests at all.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-219 · MEDIUM · SD-WAN packet-loss computed as uint64 subtraction PacketSend-PacketRecv — underflows to ~1.8e19 when Recv>Send from counter timing skew

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:945` · class: `data-integrity`

**Defect.** lost := h.PacketSend - h.PacketRecv on two uint64 read from different table columns (send column walked before recv); a probe answered between reads yields Recv>Send and the unsigned subtraction wraps. MIB provides device-computed fgVWLHealthCheckLinkPacketLoss (...4.9.2.1.9).

**Failure scenario.** Recv exceeds Send by 1 from walk skew → lost=2^64-1 → PacketLoss≈1.8e21% stored and shipped, poisoning the SD-WAN card and any future loss alerting. Latent only because the OID bug keeps both counters 0; fixing that arms this.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-220 · MEDIUM · Uptime unit contract drift: 7-8 non-FortiGate vendor profiles pre-divide sysUpTime by 100, but every server/frontend consumer divides by 100 again — non-FortiGate device uptime displayed 100x too small

**cross-repo** — `internal/snmp/vendor_opnsense.go:96` · class: `contract-drift`

**Defect.** opnsense/paloalto/cisco_asa/sonicwall/pfsense/firewalla/generic store ticks/100 (seconds) while fortigate stores raw hundredths; server uptime.go:203, admin-device-detail.js:2535, public-dashboard.js:346 all divide by 100 again (comment 'timeticks in hundredths'). FortiGate is the only unit the consumers were validated against.

**Failure scenario.** The live prod OPNsense box (or any non-FortiGate) with 100 days uptime displays '1d 0h' (86400/100); a 10-day uptime shows ~2.4h — silent plausible-wrong telemetry for every non-FortiGate vendor; no single-side fix is correct.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-221 · MEDIUM · Palo Alto VPN parser's 64-bit HC counter branches are dead code — GetVPNStatus walks only ifTable, so tunnel byte counters are always 32-bit and wrap at 4 GiB

**Firewall-Collector** — `internal/snmp/vendor_paloalto.go:168` · class: `correctness`

**Defect.** VPNBaseOID returns BaseOIDInterface (ifTable) and snmp.go walks that subtree; the OIDIfHCInOctets/OIDIfHCOutOctets branches test ifXTable OIDs outside the walk → never match. parseBSDVPNFromInterfaces (pfSense/OPNsense) and parseLinuxVPNFromInterfaces (Firewalla) share the 32-bit-only exposure.

**Failure scenario.** A PAN-OS tunnel.N at 100 Mbps wraps ifInOctets every ~5.7 min; with 60s polls the delta pipeline misreads each wrap as a reset and discards/clamps → VPN throughput systematically under-reported on busy tunnels. Fix: walk ifXTable for the VPN base.

**Fix direction.** walk ifXTable for the VPN base.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-222 · MEDIUM · ParseInterfaceList can never parse TX errors/discards — outer gate requires 'rx', making the tx branch unreachable; combined rx/tx lines overwrite RX

**Firewall-Collector** — `internal/ssh/parser.go:213` · class: `correctness`

**Defect.** The block is gated on line containing 'rx', so the inner `else if Contains(line,"tx")` assigning currentOutErrors/Discards is dead and a TX-only line never enters; a line with both groups funnels both matches into In* fields (TX overwrites RX). Tests assert only .Name.

**Failure scenario.** Every SSH interface-error poll ships iface.OutErrors/OutDiscards=0 → TX-side errors (duplex mismatch, congested egress, failing SFP) invisible and never alert; combined-format lines corrupt RX values too. Close the test gap alongside the fix.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-223 · MEDIUM · extractDeviceID compiles a regexp on every syslog message with structured data

**Firewall-Collector** — `internal/syslog/syslog.go:615` · class: `performance`

**Defect.** regexp.MustCompile(`\[(\d+)\]`) inside extractDeviceID, called per non-FortiOS RFC5424 message with non-empty structured data — the only non-hoisted regex in a package whose own comment cites >1000/sec.

**Failure scenario.** Any standards-compliant RFC5424 source with structured data forces a MustCompile per message → measurable CPU recompiling a constant. Hoist to a package var.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

### LOW (27)

#### AUDIT-224 · LOW · No gosec job in collector CI, though the collector parses the most hostile input in the system and the server enforces gosec

**Firewall-Collector** — `.github/workflows/docker.yml:10` · class: `toolchain-ci`

**Defect.** The only workflow runs gofmt/vet/test-race/tidy/staticcheck/govulncheck — no gosec; server enforces gosec@v2.27.1. The collector packages parsing unauthenticated UDP (syslog/sflow/tftp/netflow/snmp) + ssh command construction are never security-scanned, contradicting the Dockerfile's own threat model.

**Failure scenario.** A G-class defect (e.g. G304 traversal from a tainted TFTP filename, or math/rand for a security token) merges with no machine gate; the same bug in the server repo would be caught. Highest-cost location — remote customer management LANs.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-225 · LOW · Collector CHANGELOG.md is missing the v1.3.30 and v1.3.31 entries — history jumps 1.3.32 to 1.3.29

**Firewall-Collector** — `CHANGELOG.md:28` · class: `docs-drift` · related: `CONTRIBUTING.md`

**Defect.** Headings run 1.3.33, 1.3.32, then 1.3.29 — no 1.3.30/1.3.31, though commits 0907817 (IPSec telemetry + phase2 selectors v1.3.30) and 1fd311a (agent version report v1.3.31) are on master.

**Failure scenario.** An operator on 1.3.29 evaluating 1.3.32 sees no record that the collector now sends IPSec telemetry and reports its agent version (new outbound behavior some sites must clear); changelog-derived release notes omit two shipped wire changes.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-226 · LOW · Collector Docker build lacks the server's AUDIT-102 reproducibility flags (-trimpath -buildvcs=false)

**Firewall-Collector** — `Dockerfile:12` · class: `toolchain-ci`

**Defect.** Collector `go build -o firewall-collector ./cmd/collector` omits -trimpath -buildvcs=false; server Dockerfile adds both (AUDIT-102: byte-identical binaries across build hosts).

**Failure scenario.** The shipped collector binary embeds build/module-cache paths and VCS stamping, so the same source yields different bytes per host — an operator can't verify by rebuild-and-compare that a binary on a customer LAN matches the tagged source.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-236 · LOW · commands.go comments still claim IPSec writes are 'FortiGate only' while the code accepts OPNsense

**Firewall-Collector** — `cmd/collector/commands.go:148` · class: `docs-drift`

**Defect.** runIPSecWrite/apply docstrings say 'FortiGate only; any other vendor is rejected' but the code allows `p.Vendor != "fortigate" && p.Vendor != "opnsense"`.

**Failure scenario.** A reviewer auditing the write allowlist for blast radius concludes OPNsense writes are impossible and misses that path when tightening vendor validation.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-237 · LOW · ifaceIPMap is never pruned on device-list refresh — stale IP→device attribution for reused/unassigned devices

**Firewall-Collector** — `cmd/collector/main.go:2306` · class: `data-integrity`

**Defect.** cacheInterfaceAddresses only adds; deviceRefreshLoop prunes throughputCache/snmpARPFlags but nothing prunes ifaceIPMap, consulted by resolveDeviceByIP for every sFlow/NetFlow/syslog/trap. Sibling maps sshLastPoll/failCount/lastBackupAt/observedHostKeys share the gap.

**Failure scenario.** Device 42 decommissioned and its subnet IPs reused by new device 57: until the new device's first successful poll overwrites each entry, every datagram from a reused IP resolves to stale 42 and is relayed misattributed until collector restart.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-238 · LOW · PROBE_LOG_LEVEL / PROBE_LOG_FORMAT are inert in production — slog is never configured because main() never calls setupLoggerWith

**Firewall-Collector** — `cmd/collector/main.go:2427` · class: `docs-drift`

**Defect.** setupLoggerWith (2427-2452) is the only code that reads PROBE_LOG_LEVEL/PROBE_LOG_FORMAT and calls slog.SetDefault; its only callers are slog_test.go — NEVER main(). main()'s sole logging setup is `log.SetFlags(...)` (204); no slog.SetDefault in production. Its signature takes *bytes.Buffer so prod can't even pass os.Stderr as its doc claims. Both vars are documented working knobs (docs/ENV-VARS.md:136-137, README.md:272,219-220).

**Failure scenario.** An operator sets PROBE_LOG_FORMAT=json (documented compose example) and/or PROBE_LOG_LEVEL=debug; because main() never invokes setupLoggerWith, slog keeps Go's zero-config default (text/Info/stderr): no JSON is ever emitted and debug output stays suppressed. Unit tests pass by calling setupLoggerWith directly, masking the gap.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-241 · LOW · Collector ENV-VARS.md ('authoritative reference') omits the live PROBE_NETFLOW_SAMPLING_OVERRIDES operator knob

**Firewall-Collector** — `docs/ENV-VARS.md:8` · class: `docs-drift`

**Defect.** ENV-VARS.md titles itself 'authoritative reference' and says 'Every variable on this page is wired [in config.go].' PROBE_NETFLOW_SAMPLING_OVERRIDES is a live knob absent from the page: config.go:184 `parseSamplingOverrides("PROBE_NETFLOW_SAMPLING_OVERRIDES")`, consumed in cmd/collector/main.go:606. It pins per-exporter NetFlow sampling rates.

**Failure scenario.** An operator whose NetFlow exporter advertises a wrong/zero sampling rate needs to override it, reads the 'authoritative' ENV-VARS.md, finds no such variable, and cannot correct the sampled-counter scaling without reading source — the documented-complete reference hides a shipped correctness knob.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-242 · LOW · Collector ENV-VARS.md (authoritative reference) omits PROBE_NETFLOW_SAMPLING_OVERRIDES and points at a removed server cmd/probe/main.go

**Firewall-Collector** — `docs/ENV-VARS.md:145` · class: `docs-drift` · related: `internal/config/config.go`

**Defect.** The file claims every wired var is listed, but PROBE_NETFLOW_SAMPLING_OVERRIDES (config.go:184, format only in a code comment) is absent — the exact knob SUPPORT-MATRIX.md prescribes for the MikroTik ROS 6.49.x byte-order bug; and the sibling-repo pointer names cmd/probe/main.go which was removed.

**Failure scenario.** A MikroTik ROS 6.49.x operator whose flow bytes are ~16M× inflated is told to set a per-exporter override, finds no such var in the authoritative reference, and concludes the mitigation doesn't exist — corrupt magnitudes persist in every rollup.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-253 · LOW · Eight metric endpoints silently truncate at 500 items then mark the batch ID processed, while the collector clamps to (and documents) a 1000-item server cap — a >500-row VPN batch loses its tail permanently and invisibly

**cross-repo** — `internal/api/handlers/handlers_data.go:924` · class: `contract-drift`

**Defect.** ReceiveVPNStatuses and 7 siblings (ProcessorStats/DiskUsage/LoadAverage/HardwareSensors/HAStatuses/SecurityStats/SDWANHealth) do statuses=statuses[:500] not truncateProbeBatch (whose M1 comment says silent truncation+marking lost tails 'permanently and invisibly'); they run batchDedupCheck/markBatchIfOK so even a resend dedup-drops. Collector const serverMaxBatchItems=1000; VPN batch is one POST/device combining IPSec+dialup+SSL-VPN rows.

**Failure scenario.** A hub with >500 combined dialup+SSL-VPN rows POSTs its VPN batch; rows 501+ dropped with no log/alert and the batch ID recorded so the tail can't resend — tunnels past index 500 never get rows, ever-up gate never arms, outages undetectable. The M1 class reintroduced on 8 endpoints.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-263 · LOW · parseBool silently maps any unrecognized value (True/TRUE) to false, disabling default-on listeners with no warning

**Firewall-Collector** — `internal/config/config.go:276` · class: `input-hardening` · related: `cmd/collector/main.go`

**Defect.** parseBool returns v=="true"||"1"||"yes" (case-sensitive); any non-matching non-empty value returns false, not the default, with no log — unlike parseSamplingOverrides/setupLoggerWith which warn. M23 shows this class already bit PROBE_INSECURE_SKIP_VERIFY.

**Failure scenario.** `PROBE_SYSLOG_ENABLED: True` in docker-compose (YAML habit) returns false for a default-true flag → syslog listeners silently never start, syslog-triggered backups stop, no log explains it. Same for every default-on toggle.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-282 · LOW · IPFIX field-spec parser pre-allocates slice capacity from an unvalidated attacker-controlled count

**Firewall-Collector** — `internal/netflow/ipfix.go:110` · class: `input-hardening` · related: `internal/netflow/v9.go`, `internal/netflow/template.go`

**Defect.** make([]templateField,0,count) with count = raw field-count word, validated only AFTER alloc (off+4>len(rem)); templateField is 8 bytes so count=65535→~512KB. The v9 path validates len(rem)<need before make.

**Failure scenario.** A ~24-byte IPFIX datagram with fieldCount=0xFFFF and no records → ~512KB alloc then immediate nil return; ~20,000× packet-to-allocation amplification at the per-source rate ceiling (~512 MB/s transient GC churn per spoofed source; UDP source forgeable to a monitored IP). Fix: bound count by remaining bytes before make.

**Fix direction.** bound count by remaining bytes before make.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-283 · LOW · seqTracker caps its state map but never evicts — forged observation domains permanently starve sequence-loss detection

**Firewall-Collector** — `internal/netflow/seq.go:73` · class: `input-hardening` · related: `internal/netflow/netflow.go`, `internal/netflow/template.go`

**Defect.** observe() refuses new keys once len>=4096 but seq.go has no delete/sweep; every sibling cache (template/sampler/flowdedup) evicts. The key's domain field is an unauthenticated packet value.

**Failure scenario.** A sender enumerates the domain word across 4096+ values (spoofing a monitored IP or any source when allowlist off); the map fills and never shrinks → every genuine new (exporter,domain,version) returns "" → seq_gap/seq_resync detection permanently disabled until restart. Fix: TTL/idle sweep on the maintenance ticker.

**Fix direction.** TTL/idle sweep on the maintenance ticker.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-284 · LOW · v9 template field with Length 0xFFFF bypasses the field-width quarantine and is mis-decoded as an IPFIX variable-length field

**Firewall-Collector** — `internal/netflow/template.go:153` · class: `input-hardening`

**Defect.** templateCache.put's quarantine exempts the varlen sentinel: `if f.Length != varlenFieldLen && f.Length > maxFieldLen` (153, varlenFieldLen=0xFFFF). put() is shared by v9 and IPFIX. NetFlow v9 has no variable-length encoding (IPFIX-only, RFC 7011 §7), yet parseV9TemplateSet reads Length verbatim with no v9-specific 0xFFFF rejection. A v9 field Length=0xFFFF is neither quarantined nor rejected, and decodeDataRecord (record.go:326) then reads a nonexistent 1-byte varlen prefix.

**Failure scenario.** A broken/hostile v9 exporter (attributed by spoofable UDP source IP) registers a template with field Length=0xFFFF. Every data record is mis-framed: decodeDataRecord consumes a varlen chunk not present in v9 wire format, shifting all subsequent field offsets and desyncing the data-set walk → that exporter's records dropped as malformed and/or emit garbage values. Bounded to that exporter's set (no cross-record OOB). Fix: reject Length==0xFFFF in the v9 template parsers (or pass an isV9 flag).

**Fix direction.** reject Length==0xFFFF in the v9 template parsers (or pass an isV9 flag).

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-287 · LOW · isRetryableStatus treats 413/414 (payload too large) as transient — an oversized batch is requeued and retried forever

**Firewall-Collector** — `internal/relay/relay.go:2081` · class: `correctness`

**Defect.** isRetryableStatus's switch omits 413/414 → default:return true; sendBatch replays the byte-identical body (content-derived batch ID), so a body exceeding a proxy/server cap once exceeds it every retry. doDirectSend has the same hole for metric payloads.

**Failure scenario.** Behind an nginx client_max_body_size 1MiB a 1000-item syslog batch 413s → requeued as transient → rejected again every 30s forever, burning 3 attempts+backoff each cycle and (with the drained-tail bug) destroying the rest of every drain it heads.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-288 · LOW · One 404 on /flow-counters permanently collapses the negotiated schema to v1, silently disabling v3-v5 features (disk/load, command channel incl. IPSec deploys, topology) until a collector restart

**Firewall-Collector** — `internal/relay/relay.go:2136` · class: `correctness`

**Defect.** sendBatch stores negotiatedSchema=1 on a /flow-counters 404 but leaves approved=true, so Register() (the only re-negotiation) never re-runs. Every higher feature gates on that same atomic (handlePendingCommands <4, SendDiskUsage/LoadAverage <3, Topology <5), while the server keeps using probe.SchemaVersion (persisted 5).

**Failure scenario.** A brief server rollback or a proxy/deploy 404 on one /flow-counters POST → collector stores schema=1: SendDiskUsage/LoadAverage return nil successfully (no log), topology skipped, heartbeat pending_commands ignored while the server re-delivers admin-enqueued IPSec deploy/status commands until they expire — recovery needs a restart. The intended effect needed only a v2 gate.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-289 · LOW · Six relay Send* methods read c.probeID without c.mu, racing the mutex-guarded write in finishRegister during re-registration

**Firewall-Collector** — `internal/relay/relay.go:2274` · class: `concurrency` · related: `cmd/collector/main.go`

**Defect.** SendConfigRevision (2274), SendProcessSnapshot (2456), SendInterfaceErrorSnapshot (2476/2499), SendSensorDetails (2522), SendLicenseDetails (2545) use bare fmt.Sprint(c.probeID); the field is written under c.mu in finishRegister (concurrently on heartbeat/dataSend/poll re-register paths). The GetProbeID() accessor exists and is used by every other sender.

**Failure scenario.** During a server-forced re-registration that changes the probe ID, an SSH-poll send reads c.probeID concurrently — a data race -race flags; in the torn window a stale ID posts to the wrong /api/probes/:id/ path → 404/403 bouncing a config backup into retry and churning re-registration. Mechanical fix: use c.GetProbeID().

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-293 · LOW · Shared IfTypeNames maps have drifted: collector lacks 47/gre and 209/bridge, leaving TypeName empty for FortiGate LAN (bridge) and GRE at the source — currently masked by a server-side ingest backfill

**cross-repo** — `internal/snmp/snmp.go:70` · class: `contract-drift`

**Defect.** Collector map (10 entries) lacks 47:gre and 209:bridge that the server map has; the server heals it at ingest (handlers_data.go:888). Type 209 is where FortiGate LAN IPs live. Vendor registry and TrapOIDs maps are otherwise in parity.

**Failure scenario.** No live misbehavior (server backfill compensates), but the 'same' maps already diverged unnoticed; any collector-side TypeName consumer sees '' for bridge/GRE, and if the backfill is ever removed FortiGate LAN type_name goes empty, breaking connection-map direct-link coloring. Fix: add 47/209 or pin with a cross-repo parity test.

**Fix direction.** add 47/209 or pin with a cross-repo parity test.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-294 · LOW · GetInterfaceStats packet/error counters read only 32-bit ifInUcastPkts although the code already walks ifXTable where ifHCInUcastPkts live

**Firewall-Collector** — `internal/snmp/snmp.go:345` · class: `data-integrity`

**Defect.** InPackets/OutPackets read Counter32 ifInUcastPkts/ifOutUcastPkts; the ifXTable walk (384-422) upgrades bytes to ifHCInOctets but never reads ifHCInUcastPkts(.7)/ifHCOutUcastPkts(.11).

**Failure scenario.** A LAN port at ~200 Kpps wraps the 32-bit packet counter every ~6h; each wrap looks like a reset to the delta pipeline → packet-rate samples periodically discarded/clamped on the busiest interfaces (byte charts unaffected). One-line fix in the existing ifXTable walk.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-295 · LOW · dot1qPvid is indexed by dot1dBasePort but the code uses the index as ifIndex — VLAN IDs attach to the wrong interface on devices where bridge-port numbering diverges

**Firewall-Collector** — `internal/snmp/snmp.go:425` · class: `correctness`

**Defect.** dot1qPvid instances are indexed by dot1dBasePort; the code indexes the ifIndex-keyed interfaces map directly with the base-port number, missing the dot1dBasePortIfIndex mapping.

**Failure scenario.** On a switch/bridge where base ports are offset from ifIndex, PVID 20 for base port 3 is written onto ifIndex 3 (a different interface) — wrong VLAN attribution into L2VLAN typing; when no ifIndex matches the VLAN silently vanishes. Both invisible without device cross-check.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-298 · LOW · Firewalla fan-sensor parsing is dead code — walk base OID excludes the fan subtree

**Firewall-Collector** — `internal/snmp/vendor_firewalla.go:202` · class: `correctness` · related: `internal/snmp/snmp.go`

**Defect.** HWSensorBaseOID() returns only the temperature subtree fwBaseOIDLmTempSensor = .1.3.6.1.4.1.2021.13.16.2.1; GetHardwareSensors does a single WalkAll(baseOID) (snmp.go:586). The fan branches match fwOIDLmFanSensorDescr/Value under .13.16.3.1 — a sibling subtree the .13.16.2.1 walk never enters. The comment hedges 'if present in same walk — different subtree.'

**Failure scenario.** A Firewalla exposing lm-sensors fan data via snmpd is polled; the subtree walk terminates before reaching .13.16.3.1, so no fan OIDs return and the fan-parsing branches (202-222) never execute → fan RPM silently absent with no error, while the code reads as if fan monitoring works.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-299 · LOW · rangeToCIDR validates only XOR contiguity, not that begin is the network address — non-aligned IP ranges are misrendered as wrong CIDR blocks

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:477` · class: `correctness`

**Defect.** The function checks only that begin^end is 0...01...1 and never that begin's host bits are zero: rangeToCIDR('10.0.1.255','10.0.2.0')→XOR 0x03FF passes→'10.0.1.255/22' (a 2-address range rendered as 1024 addresses).

**Failure scenario.** A FortiGate dialup phase-2 iprange selector (not subnet-aligned) produces a Local/RemoteSubnet CIDR covering up to 512× more/different space than selected, feeding wrong data to the IPSec map and canonical keys. Fix: require begin&hostmask==0 or fall back to begin-end form.

**Fix direction.** require begin&hostmask==0 or fall back to begin-end form.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-300 · LOW · FortiGate voltage sensors labeled unit "mV" while fgHwSensorEntValue reports volts

**Firewall-Collector** — `internal/snmp/vendor_fortigate.go:572` · class: `correctness`

**Defect.** inferSensorUnit voltage case sets `s.Type="voltage"; s.Unit="mV"`. The value comes from safeFloat(pdu.Value) where fgHwSensorEntValue is a DisplayString float like '52.500000' (the code's own comment, line 529). FortiGate voltage rails report decimal volts (e.g. '12.070000', '3.300000'), not integer millivolts — value in volts, unit says mV.

**Failure scenario.** A +12V rail returns '12.070000'; safeFloat yields 12.07 and inferSensorUnit stamps Unit='mV', so it stores/displays '12.07 mV' — a 1000x mislabel corrupting any voltage display or threshold comparison that trusts the unit. FortiGate is the user's primary vendor.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-302 · LOW · PaloAlto hardware-sensor 'alarm' status is unreachable: status==3 rows are skipped before the alarm branch that tests status==3 (server + collector copies)

**cross-repo** — `internal/snmp/vendor_paloalto.go:306` · class: `correctness`

**Defect.** Loop `if sd.status==2 || sd.status==3 { continue }` precedes `if sd.status==3 { alarmStatus="alarm" }`, so nonoperational(3) sensors are dropped and the alarm assignment is dead; every emitted PA sensor is hardcoded 'normal'. Identical in Firewall-Collector/internal/snmp/vendor_paloalto.go:279.

**Failure scenario.** A PA fan/PSU goes nonoperational(3) → the sensor silently disappears from telemetry instead of reporting Status 'alarm' → no hardware alert exactly when a sensor matters — failure-reads-as-healthy.

*Verification: 4/4 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-303 · LOW · ParsePerformanceStatus truncates FortiOS uptime to whole days — hours/minutes discarded, fresh-booted devices report Uptime=0 for 24h

**Firewall-Collector** — `internal/ssh/parser.go:423` · class: `correctness`

**Defect.** uptimeRegex captures only `(\d+)\s+days` from 'Uptime: 20 days, 3 hours, 26 minutes' → info.Uptime=days*86400, dropping up to 23h59m.

**Failure scenario.** perf.Uptime feeds the SSH system_status writer; a firewall rebooted 2h ago shows uptime 0 all day, and a same-day reboot produces no observable uptime decrease from this source — masking restarts from consecutive-uptime comparisons. Extend the regex to capture hours/minutes.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-305 · LOW · UDP syslog logs one line per malformed datagram — the exact log-flood vector the TCP path's M16 fix removed

**Firewall-Collector** — `internal/syslog/syslog.go:411` · class: `input-hardening`

**Defect.** UDP path log.Printf's every ParseRFC5424 error; the TCP path (202-204) deliberately `continue`s without logging (M16: 'a flood would DoS the log'). The UDP rate limiter bounds volume but at the legitimate-traffic budget.

**Failure scenario.** A LAN host streams garbage UDP just under the syslog PPS budget → a log.Printf per datagram fills the journal/disk at the full allowed rate indefinitely. Fix: drop the per-datagram log, count via metric.

**Fix direction.** drop the per-datagram log, count via metric.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-306 · LOW · TFTP writeHandler runs on an untracked goroutine — Shutdown() returns while a just-received config upload is still being relayed

**Firewall-Collector** — `internal/tftp/tftp.go:319` · class: `concurrency`

**Defect.** handleWRQ launches the handler in a `go func(){...}()` not registered with s.wg, so Shutdown()'s s.wg.Wait() doesn't wait for it (the device already got its final ACK before the handler runs).

**Failure scenario.** Collector shutdown right after a firewall completes a TFTP upload: Shutdown returns while the prod handler is mid-SendConfigRevision → the revision is silently lost though the firewall believes the backup succeeded. Fix: s.wg.Add(1)/Done around it or run synchronously.

**Fix direction.** s.wg.Add(1)/Done around it or run synchronously.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-307 · LOW · TFTP handleRRQ bypasses the AUDIT-050 source-IP allowlist and rate limit that handleWRQ enforces

**Firewall-Collector** — `internal/tftp/tftp.go:334` · class: `input-hardening`

**Defect.** handleRRQ runs the read handler with no isSourceAllowed()/checkAndUpdateRateLimit() (handleWRQ has both); serve() also logs one line per RRQ/WRQ before any allowlist check.

**Failure scenario.** Today latent (no SetHandler in prod), but the SetAllowedSourceIPs doc says only WRQs are restricted; the first future ReadHandler (e.g. serving a config back for restore) exposes data to every host reachable on UDP/69 with no rate limit. Cheap fix: gate handleRRQ identically and move the per-packet log after the check.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

### INFO (2)

#### AUDIT-309 · INFO · Collector still on go1.25.12 with 5 reachable stdlib CVEs the server already patched; CI go-version hardcode has drifted

**Firewall-Collector** — `go.mod:3` · class: `security`

**Defect.** go.mod:3 `go 1.25.12` vs server 1.25.13 (v0.11.208 bump); verified GOTOOLCHAIN=go1.25.12 govulncheck ./... reports 5 reachable stdlib vulns (GO-2026-6218 net/url, 6090 crypto/tls, 6089 net/http, 5972 encoding/asn1, 5026 net/http) via fwapi/observability/relay TLS. docker.yml:20 also hardcodes go-version 1.25.11 instead of go-version-file.

**Failure scenario.** Deployed collector images embed the vulnerable net/http/tls/asn1 on hosts inside customer management LANs; the next push to collector master fails the govulncheck gate (GOTOOLCHAIN=auto resolves 1.25.12) and since build needs:test, ALL releases block until go.mod bumps to 1.25.13.

*Verification: 3/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

#### AUDIT-317 · INFO · Collector trap community check uses non-constant-time != — the server twin's AUDIT-012 subtle.ConstantTimeCompare hardening never propagated to the actual network-facing receiver

**Firewall-Collector** — `internal/snmp/trap.go:114` · class: `security`

**Defect.** allowCommunity compares attacker-supplied community against the shared secret with a plain short-circuiting `if community != t.community { ...; return false }` (trap.go:114-121). The Firewall-Mon twin was explicitly hardened under AUDIT-012 with subtle.ConstantTimeCompare and a comment explaining the prefix-length leak the != caused; the collector never imports crypto/subtle and never got the fix, despite being the ACTUAL deployed network-facing trap receiver. Documented server-side hardening that drifted out of twin parity. NOTE: exploitability is essentially nil today — SNMP traps are one-way with no response whose latency reflects the compare — so this is a parity/hygiene note, load-bearing only if a future change adds an observable per-trap timing signal.

**Failure scenario.** With a community configured, the byte-by-byte short-circuit compare's duration correlates with the guessed prefix length — the side channel AUDIT-012 closed server-side. Not directly observable over one-way UDP today, but any later addition of an observable per-trap timing signal (metrics, response, downstream effect) resurrects the leak the server already fixed on the twin.

*Verification: 2/3 independent refuter lenses confirmed (survives the ≥2-confirm bar).*

## Appendix A — Refuted candidates (do NOT re-flag)

These candidates were raised by a finder but **killed by ≥2 refuter lenses**. Recorded so future audits don't re-raise them.

- **ReceiveLicenseInfo is the only replay-exposed direct-send endpoint without the AUDIT-042 batch dedup — a timeout-after-commit replay inserts** — `internal/api/handlers/handlers_data.go:1079` — refuted: misread-behavior.
- **Flows detection modal fetches nonexistent route /admin/api/flows/samples — sampled-flows section always fails** — `cmd/api/static/js/admin-flows.js:705` — refuted: mitigated-elsewhere, overstated-no-residual.
- **Collector CI hardcodes go-version 1.25.11 instead of go-version-file, silently defeating the 'bump go.mod is the whole fix' patch flow** — `.github/workflows/docker.yml:20` — refuted: misread-behavior, mitigated-elsewhere, overstated-no-residual.
- **device-detail esc() leaves quotes unescaped → attribute-injection stored XSS from device-supplied strings** — `cmd/api/static/js/admin-device-detail.js:2556` — refuted: mitigated-elsewhere.
- **In-flight device-WRITE commands are neither drained on shutdown nor deduped across restart — SIGTERM mid-apply + at-least-once redelivery re** — `cmd/collector/commands.go:256` — refuted: mitigated-elsewhere.
- **Forged/spoofed LINK_UP trap silently auto-resolves AND auto-acknowledges a genuine LINK_DOWN alert, bypassing every policy/severity/cooldown** — `internal/alerts/alerts.go:540` — refuted: misread-behavior, mitigated-elsewhere, unrealistic-preconditions.
- **digestSecrets breaks the 1:1 line-count invariant MaskVolatileLines depends on, disabling all volatile folding (and re-leaking secrets) for ** — `internal/configdiff/vendor_opnsense.go:228` — refuted: overstated-no-residual, unreachable.
- **UpsertAutoConnection uses the documented Model(loaded).Updates(map) FK-clobber anti-pattern while its sibling UpsertAutoL2Connection uses th** — `internal/database/devices.go:326` — refuted: misread-behavior, overstated-no-residual.
- **FortiGate SSL-VPN user/tunnel scalars use scalar suffix .0 on VDOM-indexed table columns — fgVpnSslStatsLoginUsers/ActiveTunnels always NoSu** — `internal/snmp/vendor_fortigate.go:36` — refuted: intended-and-documented.
- **Server-side FortiGate VPN SNMP OID mappings (dialup table + site-to-site mask columns) are wrong and drift from the collector's correct mapp** — `internal/snmp/vendor_fortigate.go:45` — refuted: intended-and-documented, unreachable.
- **BackupConfigSCP embeds the SCP password in the FortiOS CLI command line (device-audit-logged) — and is dead code with no caller** — `internal/ssh/ssh.go:410` — refuted: unreachable.

## Appendix B — Standing do-not-re-flag (accepted-risk / by-design)

Carried from prior audits and confirmed still intentional: HSTS-behind-proxy; threat-feed env-only URL; proxy rate-limit (AUDIT-097); NOC SSE admin-only ceiling; SSH alert-only TOFU (AUDIT-071); AuthManager bcrypt mutex / login-map pruner; single-admin `user_id=1` fallback; MD5 config-checksum; documented `gosec` excludes; FortiGate SSL-VPN OID 12.3.1.1 (WONTFIX — feature unused, returns `noSuchObject`→0); `tunnel_uptime` FortiGate semantics; dashboard `computing`-sentinel; poller-as-alert-engine split; obsolete server `cmd/probe`.
