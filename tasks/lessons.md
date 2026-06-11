# Lessons learned

## 2026-06-07 — Doc-unification project

Rules to follow when editing or extending documentation across the
Firewall-Collector and Firewall-Mon repos. Read at session start.

### Structural rules

1. **The two repos are siblings, not parent/child.** Neither contains
   the other. Cross-references go through `xphox2/Firewall-Collector` or
   `xphox2/Firewall-Monitoring` (the org's actual repo name) on github.com.

2. **Cross-cutting docs (MIGRATING, SUPPORT-MATRIX, ARCHITECTURE) live
   ONLY in `xphox2/Firewall-Monitoring/docs/`.** Firewall-Collector
   mirrors the URL but does NOT duplicate the file. This was the
   user's explicit decision; do not "fix" it by duplicating.

3. **Both READMEs share the same section headings in the same order.**
   When adding a new section to one README, add it to the other in the
   same position. Tag every feature with `[Probe side]`, `[Server side]`,
   or `[Both]`.

4. **All doc filenames are UPPERCASE on disk** (e.g. `README.md`,
   `CHANGELOG.md`, `OPERATIONS.md`). Per the 1.2.107 collector commit
   standardizing `.md` filenames on UPPERCASE. Do not introduce
   lowercase names.

5. **Every doc page starts with a "Where this lives" line** at the top
   that points to the cross-cutting canonical doc when one exists.
   Example: `> Canonical home: [xphox2/Firewall-Monitoring/docs/ARCHITECTURE.md](...)`

### Anti-patterns to avoid

- Don't quote features in one repo's README that aren't in code.
  Before claiming a feature in a doc, grep the other repo to confirm
  the server-side counterpart exists.
- Don't claim a version supports a feature unless that version's
  CHANGELOG entry says so. When in doubt, link the CHANGELOG entry.
- Don't introduce a new env var in docs without grepping
  `internal/config/config.go` and the matching `*.example` file in
  the other repo to keep them in sync.

### Workflow

- **Before any doc PR**, run `go build ./...` in both repos to confirm
  the code still compiles (docs can drift onto non-existent function
  names when copy-pasted). This is a sanity check, not a code change.
- **Before committing a doc-only change**, update CHANGELOG.md in the
  SAME repo with a new top entry (no version bump for docs-only).
  Verify with `Get-Content CHANGELOG.md | Select-String "## "` that
  the newest entry is at the top.
- **Never add `Co-Authored-By:` trailers** to commits.

### Inventory of cross-references to keep in sync

| Topic | Canonical location |
|---|---|
| Probe↔server wire format | `xphox2/Firewall-Monitoring/MIGRATING.md` |
| Version compatibility | `xphox2/Firewall-Monitoring/docs/SUPPORT-MATRIX.md` |
| Combined architecture | `xphox2/Firewall-Monitoring/docs/ARCHITECTURE.md` |
| Operator runbook | `xphox2/Firewall-Monitoring/docs/OPERATIONS.md` |
| Data retention | `xphox2/Firewall-Monitoring/docs/DATA-RETENTION.md` |
| FortiGate SNMP setup | `xphox2/Firewall-Monitoring/docs/FORTIGATE-SNMP-SETUP.md` |
| Custom vendor profile | `xphox2/Firewall-Monitoring/docs/CUSTOM-VENDOR.md` |
| TLS / probe credential rotation | `xphox2/Firewall-Monitoring/docs/CERT-ROTATION.md` |
| Paired-repo CTO audit | `xphox2/Firewall-Monitoring/tasks/CTO-LOOP-2026-06-11.md` |

## 2026-06-11 — Disambiguate `internal/relay/relay.go` in any audit

When reading or citing `internal/relay/relay.go`, **always disambiguate
which repo**. The two repos have independent copies that have diverged
enough to be different code:

- `Firewall-Collector/internal/relay/relay.go` — the production client.
  Sets `Authorization: Bearer` on every authenticated request at line 568.
- `Firewall-Mon/internal/relay/relay.go` — a stale fork used by the
  server's bundled `cmd/probe`. Does **not** set `Authorization: Bearer`
  (9 sites: 265, 307, 475, 653, 676, 699, 773, 793, 813).

The 2026-06-10 CTO loop at `tasks/CTO-LOOP-2026-06-10.md` cited
"internal/relay/relay.go" without disambiguating and attributed the
H-3 bug to the wrong repo. The 06-11 paired-repo audit (in
`xphox2/Firewall-Monitoring/tasks/CTO-LOOP-2026-06-11.md`) corrected
this and added XR-1 (delete the bundled probe) as the actual fix.

**Rule:** when grepping for `Authorization` in the relay packages, run
two greps with the repo path explicit:
```
grep -n 'Authorization' E:/Golang/OpenCode/Firewall-Collector/internal/relay/relay.go
grep -n 'Authorization' E:/Golang/OpenCode/Firewall-Mon/internal/relay/relay.go
```

## 2026-06-11 — The server's CHANGELOG has `[Unreleased]` at the top, not a versioned entry

The Firewall-Monitoring repo's static guard
`TestChangelog_KeepAChangelogHeader_AUDIT110` enforces that
`[Unreleased]` is the **first** version section — a versioned
entry like `## [0.10.412]` must go UNDER it, not above it. This
contradicts the collector (which puts versioned entries at the top
because it doesn't have an `[Unreleased]` section) and the user's
own CLAUDE.md which says "MUST be placed at the VERY TOP" — the
canonical truth is the static guard. When bumping a server version
with a docs-only change, add a new bullet under `[Unreleased]`
and bump `const ServerVersion` in `cmd/api/main.go`. The static
guard test will fail if you put a versioned section above
`[Unreleased]`.
