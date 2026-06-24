# Firewall-Collector — Audit Summary (2026-06)

This is the **summary** of the 2026-06 audit. The full 1,100-line review is not committed to the repo — it lives in 30 individual GitHub issues (listed below) so each finding can be tracked, assigned, and closed independently. Use `git log --grep=AUDIT` to find PRs that close issues.

---

## Public-release verdict: **NOT READY**

15 hard blockers across 3 categories. The collector is well-engineered and the recent TFTP / syslog-triggered work is excellent, but a public release requires the items in the **Blockers** section below.

## 30 audit issues (use these for tracking)

Issues are split across two repos, with `severity/{blocker,high,medium,low}` and `area/{security,stability,performance,code-quality,testing,ops,docs}` labels. Filter by label or by `AUDIT-NNN` in commit messages.

### Firewall-Collector (23 issues)

| ID | Severity | Area | Title | GitHub |
|---|---|---|---|---|
| AUDIT-043 | blocker | docs | Add LICENSE file | [#6](https://github.com/xphox2/Firewall-Collector/issues/6) |
| AUDIT-044 | blocker | docs | Add SECURITY.md with disclosure policy | [#1](https://github.com/xphox2/Firewall-Collector/issues/1) |
| AUDIT-045 | blocker | docs | Add project hygiene files (CONTRIBUTING, CoC, issue templates, CODEOWNERS) | [#2](https://github.com/xphox2/Firewall-Collector/issues/2) |
| AUDIT-046 | blocker | ops | Pin image tag in docker-compose.yml; document upgrade procedure | [#3](https://github.com/xphox2/Firewall-Collector/issues/3) |
| AUDIT-047 | blocker | security | Run collector as non-root in Docker with minimal capabilities | [#4](https://github.com/xphox2/Firewall-Collector/issues/4) |
| AUDIT-048 | blocker | security | Wire up mTLS client cert/key loading in relay.NewClient | [#5](https://github.com/xphox2/Firewall-Collector/issues/5) |
| AUDIT-049 | blocker | security | Add SSH known_hosts host key verification (opt-in strict mode) | (folded into #7 below) |
| AUDIT-050 | blocker | security | TFTP source-IP allowlist + 2MB size cap | [#7](https://github.com/xphox2/Firewall-Collector/issues/7) |
| AUDIT-051 | blocker | security | Require PROBE_SNMP_TRAP_COMMUNITY when SNMP traps are enabled | [#8](https://github.com/xphox2/Firewall-Collector/issues/8) |
| AUDIT-052 | blocker | stability | Panic recovery on all 9 long-lived goroutines | [#9](https://github.com/xphox2/Firewall-Collector/issues/9) |
| AUDIT-053 | blocker | stability | c.stop() idempotency + SSH WaitGroup + TFTP Shutdown | [#10](https://github.com/xphox2/Firewall-Collector/issues/10) |
| AUDIT-054 | blocker | stability | SendConfigRevision retry-with-backoff (currently zero retry) | [#11](https://github.com/xphox2/Firewall-Collector/issues/11) |
| AUDIT-055 | blocker | testing | Add CI: go test -race, vet, gofmt, govulncheck, coverage gate | [#12](https://github.com/xphox2/Firewall-Collector/issues/12) |
| AUDIT-056 | blocker | ops | slog JSON logging + PROBE_LOG_LEVEL + PROBE_LOG_FORMAT | [#13](https://github.com/xphox2/Firewall-Collector/issues/13) |
| AUDIT-057 | blocker | ops | /healthz + /readyz + Prometheus /metrics | [#14](https://github.com/xphox2/Firewall-Collector/issues/14) |
| AUDIT-058 | high | stability | Disk-spillover queue (BoltDB) for 4 in-memory queues | [#15](https://github.com/xphox2/Firewall-Collector/issues/15) |
| AUDIT-059 | high | code-quality | go mod tidy + remove unused testify/yaml.v3 deps | [#16](https://github.com/xphox2/Firewall-Collector/issues/16) |
| AUDIT-060 | high | code-quality | Delete cmd/ssh-test duplication, merge as subcommand | [#17](https://github.com/xphox2/Firewall-Collector/issues/17) |
| AUDIT-061 | high | testing | Add internal/syslog/syslog_test.go (RFC 5424 parser) | [#18](https://github.com/xphox2/Firewall-Collector/issues/18) |
| AUDIT-062 | high | testing | Add internal/sflow/sflow_test.go (sFlow v5 parser) | [#19](https://github.com/xphox2/Firewall-Collector/issues/19) |
| AUDIT-063 | high | testing | Add internal/snmp/*_test.go (vendor parsers) | [#20](https://github.com/xphox2/Firewall-Collector/issues/20) |
| AUDIT-064 | high | performance | Per-queue mutex + atomic.Uint64 probeID | [#21](https://github.com/xphox2/Firewall-Collector/issues/21) |
| AUDIT-071 | high | security | SSH public-key auth support | [#22](https://github.com/xphox2/Firewall-Collector/issues/22) |
| AUDIT-072 | high | performance | Tune http.Transport: HTTP/2, gzip, larger idle pool | [#23](https://github.com/xphox2/Firewall-Collector/issues/23) |

### Firewall-Monitoring (7 issues — server-side, requires cross-repo coordination)

| ID | Severity | Area | Title | GitHub |
|---|---|---|---|---|
| AUDIT-065 | blocker | code-quality | Server-side DTO schema_version field + version negotiation | [#1](https://github.com/xphox2/Firewall-Monitoring/issues/1) |
| AUDIT-066 | blocker | docs | Server-side data retention disclosure for TFTP configs | [#2](https://github.com/xphox2/Firewall-Monitoring/issues/2) |
| AUDIT-067 | blocker | security | Server-side per-tenant authorization | [#3](https://github.com/xphox2/Firewall-Monitoring/issues/3) |
| AUDIT-068 | blocker | ops | Server-side support matrix doc (collector x server compatibility) | [#4](https://github.com/xphox2/Firewall-Monitoring/issues/4) |
| AUDIT-069 | high | code-quality | Server-side accept + surface ConfigRevision.BackupQuality | [#5](https://github.com/xphox2/Firewall-Monitoring/issues/5) |
| AUDIT-070 | high | testing | Server-side X-Probe-Batch-ID handling (AUDIT-042 dedup) | [#6](https://github.com/xphox2/Firewall-Monitoring/issues/6) |
| AUDIT-074 | high | security | Server-side HTTPS certificate rotation policy | [#7](https://github.com/xphox2/Firewall-Monitoring/issues/7) |

**Note:** AUDIT-049 (SSH known_hosts) was rolled into AUDIT-050 in the same TFTP/security fix set; issues 65-72 on the server side are split with 73-80 reserved for follow-up reviews.

---

## Critical findings (the 5 most dangerous)

1. **TFTP no source-IP filter, no auth, no size cap** — any host on the management LAN can submit a fake "config change" for any device, or OOM the collector. → AUDIT-050.
2. **SSH `InsecureIgnoreHostKey` + plaintext password only** — passive on-path attacker captures the FortiGate admin password and exfiltrates the entire config. → AUDIT-049 (folded into AUDIT-050) + AUDIT-071.
3. **Docker runs as root on host network with `NET_RAW`** — single CVE in any of the 4 inbound parsers = root shell on the management LAN. → AUDIT-047.
4. **`c.stop()` panics on second SIGTERM** + TFTP `Shutdown()` never called + SSH poll goroutines not joined → shutdown can hang 60 min. → AUDIT-053.
5. **`SendConfigRevision` has zero retry** — most important payload (config backup) has weakest delivery semantics. → AUDIT-054.

## Top 3 must-fix (highest leverage)

1. **Observability** — slog JSON + `/healthz` + `/metrics` (AUDIT-056, 057). Without this you can't operate at scale.
2. **SSH security** — `known_hosts` + public-key auth (AUDIT-049/050, 071). ~150 lines, removes the most embarrassing security finding.
3. **Project hygiene** — LICENSE + SECURITY.md + pinned image tags (AUDIT-043, 044, 046). Cheap, unblocks every procurement and operations conversation.

## Coverage snapshot

| Package | LoC | Test % | Biggest gap |
|---|---|---|---|
| `internal/syslog` (syslog.go) | 432 | ~16% | RFC 5424 parser |
| `internal/sflow` | 417 | 0% | untrusted binary UDP |
| `internal/snmp` (all 11 files) | ~3500 | 0% | largest untested area |
| `internal/relay` | 1283 | ~12% | Send* methods, SendConfigRevision |
| `internal/ping` | 166 | 0% | shelling to system ping |
| `internal/config` | 128 | 0% | config bugs fail silently |
| `cmd/collector` (main) | 1331 | ~5% | orchestration, shutdown |
| `internal/ssh` | 868 | ~66% | good |
| `internal/tftp` | 437 | ~68% | good |
| `internal/syslog/fortigate` | 140 | 100% | good |
| **Repo average** | ~12000 | **~17%** | |

## CI snapshot

`.github/workflows/docker.yml` runs only `docker build`. **No `go test`, no race detector, no `go vet`, no `govulncheck`, no linter.** AUDIT-055 adds the missing steps.

## Full review (not in repo)

The full 1,100-line audit report with 8 sub-agent angle reviews (security, stability, performance, code quality, test coverage, operational readiness, features) is preserved in `tasks/REVIEW-REPORT.md` (untracked) and lives in the issue bodies. Each issue has a `file:line` reference and a concrete fix.

## Recommended release sequencing

**Sprint 1 (1-2 weeks):** items in **Blockers** (AUDIT-043 to AUDIT-057). Get to "shippable."
**Sprint 2 (2-3 weeks):** items in **High** (AUDIT-058 to AUDIT-072 + server AUDIT-065 to AUDIT-074). Get to "operationally mature."
**Sprint 3+:** features — NetFlow, more vendors, disk durability, multi-server, etc.

Realistic target for a credible public release: end of Sprint 2 (4-5 weeks from kickoff).
