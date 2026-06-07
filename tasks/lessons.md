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
