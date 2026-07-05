# 2026-07-04 Logic & Consistency Audit

Dual-repo audit (Firewall-Mon server + Firewall-Collector) targeting logical flaws and
inconsistencies accumulated over the last three months of feature work (server
v0.10.x -> v0.11.21, collector -> v1.3.0), with emphasis on the Tranche 1 access-control,
Tranche 2 alerting, MFA/profile, and Tranche 3 NetFlow/IPFIX waves and their interaction
with pre-existing code.

**Method:** 13-dimension multi-agent sweep (cross-repo contract, NetFlow/IPFIX pipeline,
alerting lifecycle, RBAC coverage, auth state machines, migrations, retention, time/units
math, concurrency, frontend/backend agreement, config coherence, sibling divergence,
stale artifacts) + completeness-critic gap round. Every finding adversarially verified by
2-3 independent refutation lenses (correctness / design-intent / reachability-impact);
high-severity findings required 2-of-3 confirmation.

**Stats:** 64 raw findings -> 51 after dedup -> 50 confirmed + 3 gap-round findings = 53
confirmed (51 unique after cross-dimension merges), 1 refuted.

Finding IDs are LC-nn. Severity counts (unique): HIGH 5 / MEDIUM 26 / LOW 20.

---

This copy lists the findings that touch the collector repo (`repo: collector` or `both`). The full 51-finding report lives in the server repo at `docs/audit-2026-07-04-logic-consistency.md`.

---

### LC-00 [MEDIUM] (collector) — Dual-export flow dedup keys sFlow by in-band agent address but NetFlow by UDP source IP — suppression silently no-ops when they differ, defeating the Tranche 3 double-count defense

**Status:** RESOLVED (collector v1.3.2)

**Location:** `cmd/collector/main.go:505` · Dimension: cross-repo-contract

The v1.3.0 flowdedup tracker is supposed to be a per-device source preference (design record: server docs/flow-protocol-research-2026-07-03.md line 113 'Per-device source preference'; FortiGate is called out as 'primary dedup vendor'). The implementation keys both families by SamplerAddress strings with DIFFERENT semantics: the sFlow parser sets SamplerAddress from the datagram's in-band agent address field (sflow.go parses agent IP out of the payload), while the NetFlow/IPFIX parsers set it from the UDP source address (remoteAddr.IP). On FortiGate — the one vendor the feature targets — the sFlow agent-address and the NetFlow export source IP are independently configurable and commonly differ (agent-address defaults to a management/loopback identity; NetFlow leaves from the egress interface). When they differ, flowdedup.Tracker sees two unrelated 'exporters', SuppressSFlowFlow/SuppressNetFlow never observe cross-family activity, and both families are relayed — every byte double-counted in device-agnostic server aggregates. The failure is silent on the server too: ReceiveFlowSamples resolves device_id by exact ip_address match, so at most one of the two addresses maps to the device row, and GetMixedFlowSourceDevices (the advisory banner) filters `device_id > 0` HAVING COUNT(DISTINCT flow_source) > 1 — with one family stuck at device_id=0 the mixed-source warning never fires either.

**Evidence:** Collector main.go:505 `if c.flowDedup.SuppressSFlowFlow(sample.SamplerAddress, time.Now())` vs main.go:549 `if c.flowDedup.SuppressNetFlow(sample.SamplerAddress, time.Now())`. sFlow side: internal/sflow/sflow.go:318-330 parses `agentIP` from the datagram payload (`agentIP = net.IP(data[offset:offset+4]).To16()`), sflow.go:357 `agentAddr := agentIP.String()`, sflow.go:471 `SamplerAddress: agentAddr`. NetFlow side: internal/netflow/netflow.go:376 `r.handleDatagram(buf[:n], remoteAddr.IP)`; v5.go:47-48 'exporterIP is the UDP source address (always the SamplerAddress — v5 has no in-band agent address)'; record.go:464 `SamplerAddress: ctx.key.exporter`. Server banner blind spot: internal/database/flows.go:80-83 `SELECT device_id FROM flow_samples WHERE timestamp > ? AND device_id > 0 GROUP BY device_id HAVING COUNT(DISTINCT flow_source) > 1`; ingest device resolution is exact-IP only (handlers_data.go:213-231 ResolveDevicesByIPs on SamplerAddress).

**Suggested fix:** Key the dedup tracker by resolved device (resolveDeviceByIP result, falling back to address only when unresolved), or track both the in-band agent address and the UDP source per exporter. Server-side, extend the mixed-source query to also group unattributed rows by sampler_address.

### LC-01 [MEDIUM] (both) — Decommissioned probe returns 410 on heartbeat/register but 403 on all 20 data-plane endpoints — collector taxonomy reads 403 as 're-register', producing a permanent re-register/requeue loop instead of the documented non-retryable quiesce

**Status:** OPEN

**Location:** `internal/api/handlers/handlers_probes.go:820` · Dimension: cross-repo-contract

The M7 fix (2026-07-01 audit) gated all three planes against decommissioned/disabled probes, but the three server handlers diverged on status code for the SAME lifecycle state: RegisterProbe and ProbeHeartbeat return 410 Gone (explicitly documented as 'non-retryable — the probe is gone on purpose, not that its auth is transiently broken'), while validateProbe — the gate in front of every ingestion endpoint (/syslog, /flows, /pings, all 20) — returns 403 Forbidden. The collector's status taxonomy assigns those two codes opposite semantics: 410 is a permanent 4xx (isRetryableStatus → drop batch), but 403 triggers `c.approved.Store(false)` + tryReregister and, on re-registration failure, returns (delivered=false, permanent=false) → requeue as TRANSIENT. Net behavior after an admin decommissions a probe: every batch send gets 403 → collector deapproves, calls Register → Register gets 410 → error → tryReregister false → batch requeued; repeat every sync cycle forever, with re-registration attempts every 60s plus 10-minute cooldown cycles indefinitely, and all queues spooling to the disk byte cap. The server's own 410 convention never reaches the data plane where the collector's permanent/transient decision is actually made, so the M7 'non-retryable' contract is unimplementable from the collector's side.

**Evidence:** Server: handlers_probes.go:547 `probeErr(c, http.StatusGone, "Probe is decommissioned or disabled — re-commission it in the admin UI first")` (RegisterProbe) and :686 `probeErr(c, http.StatusGone, "Probe is rejected or decommissioned — heartbeat refused")` with comment '410 tells the collector the probe is gone on purpose (non-retryable)' vs :820 `c.JSON(http.StatusForbidden, response.Error("Probe is decommissioned or disabled"))` (validateProbe, all ingestion routes). Collector: internal/relay/relay.go:1701 classifies 410 non-retryable/permanent (`case 400, 401, 403, 404, 405, 409, 410, 422: return false`), relay.go:1760-1768 `if resp.StatusCode == 404 || resp.StatusCode == 401 || resp.StatusCode == 403 { ... c.approved.Store(false); if c.tryReregister() { continue }; return false, false }` (transient → requeue); tryReregister relay.go:924-957 resets its counter every 10 minutes forever.

**Suggested fix:** Make validateProbe return 410 for DecommissionedAt/!Enabled like its two siblings (keep 403 for not-approved), and teach the collector an explicit 410 branch: stop re-registering, keep spooled data, log once, and back off to a slow recommission probe.

### LC-02 [MEDIUM] (both) — Collector heartbeat treats every non-401/403 response as success — server's 410 Gone, 429, 400 and 5xx are silently counted as healthy heartbeats, so /readyz and Prometheus report success while the server refuses to update last_seen and marks the probe offline

**Status:** OPEN

**Location:** `internal/relay/relay.go:1049` · Dimension: cross-repo-contract

sendHeartbeatWithStatus checks only `resp.StatusCode == 401 || resp.StatusCode == 403`; every other status — including the server's deliberate 410 Gone for a rejected/decommissioned probe (which returns BEFORE writing last_seen/status), a 429 from the /api group rate limiter, a 400 'Invalid status value', or any 5xx — falls through to `return nil`. runHeartbeatLoop then records `*last = time.Now()` (read by /readyz) and calls metrics.OnHeartbeatSuccess(). Consequences: (a) the server stops refreshing last_seen, MarkStaleProbesOffline flips the probe to offline in the admin UI, yet the collector's readiness endpoint and heartbeat-success metric report a fully healthy relay — the exact monitoring signals an operator would check first point the wrong way; (b) the 410 signal the server added in M7 ('heartbeat refused') has no consumer at all — the collector keeps POSTing heartbeats at full cadence forever with zero log output, because the refusal is swallowed as success.

**Evidence:** Collector: internal/relay/relay.go:1032 `if resp.StatusCode == 401 || resp.StatusCode == 403 {` is the ONLY status branch in sendHeartbeatWithStatus; relay.go:1049 `return nil` for everything else (no logging, body not read). cmd/collector/main.go:611-618 `if err := c.relayClient.SendHeartbeat(); err != nil { ... OnHeartbeatFailure() } else { *last = time.Now(); ... OnHeartbeatSuccess() }`. Server: handlers_probes.go:685-687 `if probe.ApprovalStatus == "rejected" || probe.DecommissionedAt != nil || !probe.Enabled { probeErr(c, http.StatusGone, ...) }` returns before the last_seen/status update at :702-705, and :692-694 returns 400 for an invalid status value — both swallowed as success by the collector.

**Suggested fix:** In sendHeartbeatWithStatus, return an error for any non-2xx (with the server's error body), add a distinct 410 branch that stops the re-register churn, and only then let runHeartbeatLoop count success/refresh the /readyz timestamp.

### LC-06 [MEDIUM] (collector) — Sampling-rate override (documented precedence step 1, the MikroTik ROS6 escape hatch) is unreachable dead code — no config knob, no caller

**Status:** RESOLVED (collector v1.3.3)

**Location:** `internal/netflow/netflow.go:168` · Dimension: netflow-ipfix

The sampler-resolution chain is documented as '1. operator override for the exporter IP (SetSamplingOverride — the escape hatch for MikroTik ROS6's little-endian rate bug…)' (template.go:210-215), and the persistence section asserts 'operator overrides do NOT persist — they are configuration, re-applied at startup by the caller' (template.go:300-302). But nothing ever calls NetFlowReceiver.SetSamplingOverride: cmd/collector/main.go never invokes it, internal/config/config.go has no PROBE_*SAMPLING* variable, and ENV-VARS.md has no entry. Step 1 of the documented four-step precedence is unreachable; a MikroTik ROS6 exporter with the byte-swapped rate bug (which the design explicitly says both goflow2 and Akvorado refuse to auto-guess) has no operator remedy — its flows are silently mis-scaled by the bogus learned rate with no way to pin the correct one.

**Evidence:** netflow.go:168-173 `// SetSamplingOverride pins the sampling rate for an exporter IP… func (r *NetFlowReceiver) SetSamplingOverride(exporterIP string, rate uint32)`; template.go:301-302 `operator overrides do NOT persist — they are configuration, re-applied at startup by the caller.`; `grep -rn SetSamplingOverride` over the collector repo matches only internal/netflow/{netflow.go:171-172, template.go:210,235,238} and tests — zero call sites in cmd/ or config; config.go:164-173 defines only NetFlowEnabled/Port/IPFIXPort/RateLimit/FlowDedupPolicy.

**Suggested fix:** Add a PROBE_NETFLOW_SAMPLING_OVERRIDES env (e.g. "ip=rate,ip=rate") parsed in config.go and applied in main.go after netflowReceiver construction (and re-applied on settings refresh), or delete the API and the step-1 documentation.

### LC-41 [MEDIUM] (collector) — sFlow/NetFlow source-IP allowlist silently never applied when TFTP is disabled (early return couples all receiver allowlists to the TFTP server)

**Status:** OPEN

**Location:** `cmd/collector/main.go:1109` · Dimension: sibling-divergence

applyTFTPAllowlist() is the single 'push the fleet allowlist to every receiver' hook (its own comment at main.go:1131-1133 says so), but it still begins with the pre-M2 guard `if c.tftpServer == nil { return }`. c.tftpServer is only set when PROBE_TFTP_CONFIG_ENABLED=true (main.go:341-346). With TFTP disabled, every call site (startup line 369, sFlow start line 525, NetFlow start line 569, device refresh line 1681) returns before reaching the sFlow/NetFlow SetAllowedSourceIPs blocks, so allowedSrcIPs stays nil = allow-any (sflow.go:30, netflow.go:70). The call-site comments claim 'Deny-all until devices are known', but the receivers actually accept spoofed flow datagrams from any source forever — the exact forgery scenario audit M2 (sFlow) and the Tranche 3 NetFlow comment (main.go:1128-1131) say the allowlist exists to prevent. Classic sibling drift: the sFlow (v1.2.x) and NetFlow (v1.3.0) allowlist blocks were appended to a function whose original TFTP-only early-return no longer matches its widened responsibility.

**Evidence:** cmd/collector/main.go:1108-1111: `func (c *Collector) applyTFTPAllowlist() {\n\tif c.tftpServer == nil {\n\t\treturn\n\t}` — followed at 1123-1126 by `if c.sflowReceiver != nil { c.sflowReceiver.SetAllowedSourceIPs(ips, ...) }` and at 1134-1136 by `if c.netflowReceiver != nil { c.netflowReceiver.SetAllowedSourceIPs(ips, ...) }`. TFTP server only created when enabled: main.go:341-343 `if probeCfg.TFTPConfigEnabled { ... c.startTFTPServer() }`. Receiver default is allow-all: internal/sflow/sflow.go:30 `allowedSrcIPs map[string]bool // nil = allow any (back-compat)` and internal/netflow/netflow.go:70 same. Call-site comment contradicted: main.go:522-525 `// ... without this the receiver would accept any source until the first device refresh. Deny-all until devices are known.\nc.applyTFTPAllowlist()`.

**Suggested fix:** Move the `c.tftpServer == nil` check to guard only the TFTP-specific statements (lines 1115-1117); always run the sFlow/NetFlow SetAllowedSourceIPs blocks. Add a regression test with TFTPConfigEnabled=false asserting the receivers get a non-nil allowlist.

### LC-43 [MEDIUM] (both) — Vendor registry drift: cisco_asa and generic are valid device vendors in the API/UI but have no SNMP profile in either repo — both silently poll FortiGate enterprise OIDs; roadmap doc asserts the server profile exists

**Status:** RESOLVED (server v0.11.27 + collector v1.3.4)

**Location:** `internal/api/handlers/handlers.go:273` · Dimension: sibling-divergence

The four parallel vendor lists have drifted. validVendors (server handlers.go:273-282) and the admin UI dropdown (web/admin/admin.html:1384-1392) accept all 8 vendors including cisco_asa and generic; configdiff registers cisco_asa as a RICH normalizer (vendor_cisco_asa.go:17). But the SNMP VendorProfile registry — in BOTH repos — registers only 6 profiles (fortigate, paloalto, sonicwall, firewalla, pfsense, opnsense); there is no vendor_cisco_asa.go or vendor_generic.go in internal/snmp of either repo. resolveVendor falls back to DefaultVendor() = the FortiGate profile (server snmp.go:198-206, vendor.go:79-90; collector snmp.go:241-248), so a device the operator explicitly configures as cisco_asa or generic is polled with Fortinet enterprise OIDs (.1.3.6.1.4.1.12356...) and has FortiGate TrapOIDs applied to its traps — yielding permanently empty system status/VPN/HA/sensor data with no warning, instead of at least standard MIB-II. docs/FEATURE-ROADMAP.md:18 makes the drift explicit by claiming the SERVER registry includes 'cisco_asa ... generic' and that only the collector lacks cisco_asa, and line 211 plans to 'port the cisco_asa profile to the collector' — a profile that does not exist server-side either.

**Evidence:** internal/api/handlers/handlers.go:273-282: `var validVendors = map[string]bool{ "fortigate": true, "paloalto": true, "cisco_asa": true, "sonicwall": true, "firewalla": true, "pfsense": true, "opnsense": true, "generic": true }`. Registered SNMP profiles (grep RegisterVendor, both repos): only firewalla/paloalto/fortigate/opnsense/pfsense/sonicwall — no cisco_asa, no generic (server internal/snmp/vendor_*.go; collector internal/snmp/vendor_*.go). Fallback: server internal/snmp/snmp.go:198-206 `profile := GetVendorProfile(vendor); if profile == nil { profile = DefaultVendor() }` with vendor.go:79-81 `// DefaultVendor returns the FortiGate vendor profile.` Contradicting doc: docs/FEATURE-ROADMAP.md:18 'Server: fortigate/paloalto/cisco_asa/pfsense/opnsense/sonicwall/firewalla/generic/linux_vpn/bsd_vpn. Collector ships a subset — **no cisco_asa**.'

**Suggested fix:** Add a standard-MIB (HOST-RESOURCES/IF-MIB) 'generic' profile and register it; route cisco_asa to it (or a real ASA profile) instead of the FortiGate fallback; fix FEATURE-ROADMAP.md:18/211; add a test asserting every validVendors entry resolves to a non-FortiGate-fallback profile or is explicitly documented.

### LC-45 [MEDIUM] (collector) — Collector docker-compose.yml pins image :1.2 while configuring 1.3.0-only NetFlow features — documented deploy path silently ships a collector without the NetFlow receiver

**Status:** OPEN

**Location:** `docker-compose.yml:3` · Dimension: dead-stale

The collector released v1.3.0 (NetFlow v5/v9 + IPFIX receiver) but the committed docker-compose.yml still pulls the moving major.minor tag `:1.2`. The Docker publish workflow generates `{{major}}.{{minor}}` tags from the source version const, so `:1.2` is frozen at the last 1.2.x image forever and will never receive the NetFlow code. The SAME compose file sets `PROBE_NETFLOW_PORT`, `PROBE_IPFIX_PORT`, `PROBE_NETFLOW_ENABLED`, and `PROBE_FLOW_DEDUP` — env vars a 1.2.x binary silently ignores. An operator following the shipped compose (which README calls the default: ':1.2 ... default in docker-compose.yml', README.md:286) deploys Tranche 3, points firewalls at UDP/2055-4739, and gets no flows with no error. README tag guidance (lines 128, 199, 286) and the ':1.2.108' pin example are equally stale.

**Evidence:** docker-compose.yml:3 `image: xphox/firewall-collector:1.2`; docker-compose.yml:68-69 `PROBE_NETFLOW_PORT: "2055"` / `PROBE_IPFIX_PORT: "4739"`, :82 `PROBE_NETFLOW_ENABLED: "true"`, :88 `PROBE_FLOW_DEDUP: "prefer-netflow"`. cmd/collector/main.go:48 `const version = "1.3.0"`; CHANGELOG.md:3 `## 1.3.0 - 2026-07-04` (the NetFlow release). .github/workflows/docker.yml:99-100 `type=semver,pattern={{version}}` + `type=semver,pattern={{major}}.{{minor}}` — proves :1.2 stops updating once version is 1.3.0. README.md:286 `| :1.2 | moving major.minor | gets every 1.2.x patch automatically (default in docker-compose.yml) |`, README.md:199 'The pinned :1.2 tag tracks the latest 1.2.x patch automatically.'

**Suggested fix:** Bump docker-compose.yml to `xphox/firewall-collector:1.3` (or :1.3.0) and update the README tag table/run examples (lines 128, 199, 285-286) in the same commit; consider a CI guard test that the compose tag's major.minor matches the version const.

### LC-51 [MEDIUM] (collector) — Collector NetFlow pipeline has no firewall-event gate: ASA NSEL flow-update records are emitted as full flows on top of teardown records, double/multi-counting every byte — contradicting the repo's own 'teardown-only' Tranche 3 design

**Status:** RESOLVED (collector v1.3.3)

**Location:** `internal/netflow/record.go:400` · Dimension: gap-sweep

The project's own design record (docs/flow-protocol-research-2026-07-03.md, server repo) flags the ASA NSEL 'update+teardown double-count trap' in its vendor matrix and lists Tranche 4 item 7 as 'NSEL update-accumulate reconciliation (upgrade from teardown-only)' — i.e., the shipped Tranche 3 behavior is supposed to be teardown-only byte counting. The code never implemented that gate: emitRecord reads dec.fwEvent only to STORE it (record.go:485) and for the zero-counter skip check (record.go:447); there is no branch anywhere in internal/netflow that drops or discounts counters based on event type (grep for fwEvent.v/fwEvent.ok returns exactly those two sites; grep -i teardown across the netflow+flowdedup packages matches only a fields.go comment and tests). So an ASA configured with flow-export event-type all (a standard config) sends periodic flow-update records carrying IE 231/232 byte counters PLUS a teardown carrying the flow totals, and each becomes an independent relay.FlowSample whose bytes the server sums into rollups, top-talkers, and the data_exfil/capacity detectors — inflating ASA byte accounting by at least 2x (far more for long flows updated every interval, since updates accumulate). Secondary effect of the same missing gate: flow-create (event 1) records are also emitted as zero-byte rows, so every ASA session is counted as >=2 'flows' in every COUNT(*)-based aggregate. The v9 conformance suite only tests teardown (want 2) and denied (want 3) — event 5 is never exercised, which is how the divergence from the documented design went unnoticed.

**Evidence:** record.go emits counters regardless of event type: `case dec.initOctets.ok: fwdBytes = dec.initOctets.v // ASA: bytes only...` (internal/netflow/record.go:400-402) then `Bytes: fwdBytes * uint64(rate),` (record.go:475) and `FirewallEvent: uint8(dec.fwEvent.v),` (record.go:485) — the only two uses of fwEvent besides `eventPresent := dec.fwEvent.ok || dec.natEvent.ok` (record.go:447). fields.go:67 documents `ieFirewallEvent = 233 // NSEL: 0 ignore/1 created/2 deleted/3 denied/4 alert/5 update`. Design intent, server repo docs/flow-protocol-research-2026-07-03.md: vendor matrix row 'Cisco ASA/FTD (NSEL) ... update+teardown double-count trap' (line ~170) and Tranche 4 backlog item 7 'NSEL update-accumulate reconciliation (upgrade from teardown-only)' (line ~149). Tests cover only teardown/denied: `t.Errorf("FirewallEvent = %d, want 2 (teardown)", ...)` (internal/netflow/v9_test.go:578) and TestParseV9_ASADeniedZeroCounters (v9_test.go:599); no test sends event 5.

**Suggested fix:** Implement the documented teardown-only contract: when fwEvent is present, emit byte/packet counters only for event 2 (deleted/teardown); emit create/update/denied as zero-counter event rows (or drop create/update entirely) until the Tranche 4 update-accumulate reconciliation lands. Add an event-5 conformance test.

### LC-07 [LOW] (collector) — samplerCache has no size cap and no sweep — the one flow cache exempt from the memory-bounding discipline its siblings document, and it grows the persisted cache file forever

**Status:** RESOLVED (collector v1.3.3)

**Location:** `internal/netflow/template.go:220` · Dimension: netflow-ipfix

Every other network-fed map in the flow pipeline is explicitly capped with the same stated rationale: templateCache (maxTemplatesPerExporter=256 / maxTemplatesTotal=8192, template.go:20-21, plus a 30-min TTL sweep at template.go:184-198), seqTracker (maxSeqStates=4096, seq.go:19 'same memory-DoS rationale as the template-cache caps'), flowdedup (maxExporters=4096), and the rate limiter. samplerCache alone has no cap and is never swept: setSamplerRate/setDomainRate (template.go:249-272) insert unconditionally, keyed by (exporter IP, sourceID). Because templates DO expire and free cap headroom every 30 minutes, a rotating set of spoofed exporter IPs/ODIDs (allowlist is nil=allow-any until the fleet list is pushed, netflow.go:134) can accumulate sampler entries indefinitely across template-cap generations — entries for long-gone exporters are also never removed in normal operation. All of them are serialized by SaveTo every 5 minutes (template.go:362-374), so netflow-templates.json grows monotonically for the life of the install.

**Evidence:** template.go:249-261 `func (s *samplerCache) setSamplerRate(…) { … m[samplerID] = rate }` and template.go:265-272 `setDomainRate` — no len() check, contrast template.go:159-163 `if c.perExporter[key.exporterKey] >= maxTemplatesPerExporter { return putRejectExporter } if len(c.templates) >= maxTemplatesTotal { return putRejectTotal }`; sweep only exists on templateCache (template.go:184 `func (c *templateCache) sweep`); seq.go:18-19 states the shared rationale ('same memory-DoS rationale as the template-cache caps') that samplerCache violates; SaveTo template.go:362-374 persists every perDomain/perSampler entry unconditionally.

**Suggested fix:** Cap samplerCache at the template-cache scale (e.g. 8192 domains) and evict sampler entries in the maintenance sweep when their exporterKey no longer has any live template (or after a TTL since last rateFor/set).

### LC-08 [LOW] (collector) — clampFlowTimes validates only flow END — a plausible end lets an absurd or inverted flow_start (epoch-1970, negative duration, wrap-miscorrection) be stored verbatim

**Status:** RESOLVED (collector v1.3.3)

**Location:** `internal/netflow/record.go:635` · Dimension: netflow-ipfix

clampFlowTimes checks the derived END against ±15 min of receive time and, only in that clamped branch, bounds the duration to maxPlausibleFlowDurationMs (24h). When the end IS plausible, the function returns `time.UnixMilli(startMs)` with zero validation: startMs may be 0 (an exporter sending flowStartMilliseconds=0 with a sane flowEndMilliseconds yields flow_start=1970-01-01 and an implied ~56-year duration), may exceed endMs (negative duration — nothing enforces start<=end anywhere in resolveFlowTimes), or may be one 2^32-ms wrap off after v5's heuristic wrap corrections (resolveV5Times, v5.go:176-191, feeds this same function and can subtract uptimeWrapMs from startMs only). The doc comment on clampFlowTimes claims durations are kept only 'when it is believable', but believability is enforced exclusively in the broken-end branch. flow_start is persisted raw to the new v29 column and is the input to the planned Tranche 4 duration-aware bucketing and flow stitching — garbage stored now is the exact 'single biggest semantic difference from sFlow' failure the research doc (§ 'Top 5 things that would have shipped broken', item 3) set out to avoid.

**Evidence:** record.go:635-646: `func clampFlowTimes(startMs, endMs int64, now time.Time) … if skew := end.Sub(now); skew > flowTimeSkewLimit || skew < -flowTimeSkewLimit { end = now; if durationMs >= 0 && durationMs <= maxPlausibleFlowDurationMs { return end.Add(-…), end } return end, end } return time.UnixMilli(startMs), end` — the final return path applies neither the duration bound nor any start-side skew check; resolveFlowTimes (record.go:598-606) fills a missing side from the other but never orders or bounds start vs end.

**Suggested fix:** In the plausible-end branch, apply the same duration test: if endMs-startMs is negative or exceeds maxPlausibleFlowDurationMs, set start=end (or end-duration-cap) before returning, mirroring the clamped branch.

### LC-48 [LOW] (collector) — Collector README tells users the sibling server ships a `fwmon-probe` binary (removed) and that 'the current release' is 1.2.x

**Status:** OPEN

**Location:** `README.md:28` · Dimension: dead-stale

The repo-comparison table in the collector README lists the server's binaries as `fwmon-api, fwmon-poller, fwmon-trap, fwmon-probe`, but cmd/probe was removed from the server (server cmd/ contains only api, poller, trap-receiver, configcheck; server FEATURES.md explicitly documents the removal). An operator provisioning the HQ side from this table will look for a binary/Docker target that does not exist. Line 35 also anchors the entire feature list to 'the current `1.2.x` release' although the current release is 1.3.0 and the list itself includes 1.3.0-only NetFlow features (line 67), making the version framing self-contradictory.

**Evidence:** Firewall-Collector README.md:28 '| Binaries | `firewall-collector`, ... | `fwmon-api`, `fwmon-poller`, `fwmon-trap`, `fwmon-probe` |' and :35 'Every feature below is shipped in the current `1.2.x` release.' vs server /Users/xphox/Projects/Firewall-Mon/docs/FEATURES.md:198 '| Binaries built | 3 fwmon daemons | `cmd/{api,poller,trap-receiver}` (`cmd/configcheck` is a CLI; `cmd/probe` was removed) |' and server cmd/ listing (api, configcheck, poller, trap-receiver only). Collector cmd/collector/main.go:48 `const version = "1.3.0"`; README.md:67 documents the '[Both] NetFlow v5/v9 + IPFIX receiver' (1.3.0 feature).

**Suggested fix:** Drop fwmon-probe from the server binaries cell and change '1.2.x' to '1.3.x' (or an unversioned phrase) in the same doc pass as the compose tag bump.

