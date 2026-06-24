# Doc-Unification Plan (cross-repo)

Goal: make Firewall-Collector and Firewall-Mon read like the same project
without merging them. Same section headings, same naming conventions,
no contradictions, and a website-ready feature inventory in each.

## Decisions (signed off 2026-06-07)

1. **Cross-cutting docs live only in Firewall-Mon.**
   MIGRATING.md, SUPPORT-MATRIX.md, ARCHITECTURE.md, OPERATIONS.md,
   DATA-RETENTION.md, FORTIGATE-SNMP-SETUP.md, CUSTOM-VENDOR.md,
   CERT-ROTATION.md stay in `xphox2/Firewall-Mon/docs/`.
   Firewall-Collector's README and docs/ link to them with absolute
   GitHub URLs.

2. **READMEs mirror each other.**
   Both have the same section headings in the same order. Each section
   is tagged `[Probe side]`, `[Server side]`, or `[Both]`. Operators
   can scan both side by side.

3. **FEATURES.md exists in both repos.**
   Website-ready, with a status column (`Stable` / `Beta` / `Planned`)
   and a role column. The two FEATURES.md files are complementary —
   the collector's lists every probe-side feature, the server's lists
   every server-side feature, and both reference the cross-cutting
   compatibility matrix in Firewall-Mon.

4. **Stray files removed.**
   - `session-ses_1613.md` in Firewall-Collector (leaked transcript, 4939 lines)
   - `tasks/SERVER-NOTES.md` in Firewall-Collector (wrong repo — describes server-side code)
   - `docs/CSS.md` in Firewall-Mon (raw govulncheck dump)
   - `docs/SCAN.md` in Firewall-Mon (raw govulncheck dump, duplicate of CSS.md)

## Final layout

### Firewall-Collector (top-level)

```
README.md                  — mirror of Firewall-Mon's, role-tagged
CHANGELOG.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
CODEOWNERS
DEPLOY.md
LICENSE
SECURITY.md
docs/
  STRUCTURE.md             — index of where every topic lives (collector + server)
  ARCHITECTURE.md          — collector-side architecture only; links to server ARCHITECTURE
  COMPATIBILITY.md         — 1-line: see Firewall-Mon/docs/SUPPORT-MATRIX.md
  FEATURES.md              — website-ready, probe-side only
  CUSTOM-VENDOR.md         — collector-side vendor profile tutorial (links to server's)
  FORTIGATE-SETUP.md       — collector-side FortiGate config snippet + links to server doc
  ENV-VARS.md              — authoritative env-var reference for the probe
  SHIP-A-CHECK.md          — pre-release checklist
.github/
  ISSUE_TEMPLATE/
  PULL_REQUEST_TEMPLATE.md
  workflows/docker.yml
Dockerfile
docker-compose.yml
```

### Firewall-Mon (top-level)

```
README.md                  — mirror of Firewall-Collector's, role-tagged
CHANGELOG.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
LICENSE
SECURITY.md
THIRD-PARTY-NOTICES.md
MIGRATING.md               — probe↔server wire-format compat (was already there)
KNOWN-ISSUES.md
IRC-FORMAT.txt
docs/
  STRUCTURE.md             — index of where every topic lives (both repos)
  ARCHITECTURE.md          — combined architecture, mentions both binaries
  SUPPORT-MATRIX.md        — version compatibility table (the single source of truth)
  OPERATIONS.md            — operator runbook (server focus)
  DATA-RETENTION.md
  FORTIGATE-SNMP-SETUP.md
  CUSTOM-VENDOR.md
  CERT-ROTATION.md
  partition-migration.md
  FEATURES.md              — website-ready, server-side focus + cross-references
  ENV-VARS.md              — authoritative env-var reference for the server
  nginx.conf
.github/
  CODEOWNERS
  workflows/ci.yml
  workflows/release.yml
Dockerfile
docker-compose.yml
docker-compose.proxy.yml
Makefile
deploy.sh
entrypoint.sh
config.env.example
.env.example
```

## Section order for both READMEs

1. Title + one-line tagline
2. Status badges (CI, version, license)
3. **Overview** — what this repo is, with link to the sibling repo
4. **Sibling project** — short block linking to Firewall-Collector/Mon
5. **Features** — bulleted, role-tagged
6. **Architecture** — ASCII + link to full doc
7. **Quick start** — Docker first, native second
8. **Configuration** — link to `docs/ENV-VARS.md`
9. **Compatibility** — link to `docs/SUPPORT-MATRIX.md`
10. **Operations** — link to `docs/OPERATIONS.md` (server) or quick-only (collector)
11. **Security** — link to SECURITY.md + threat model summary
12. **API / Interfaces** — endpoint table (server) or wire format (collector)
13. **Contributing** — link to CONTRIBUTING.md
14. **License**
15. **Support**

## Changelog entries

Both repos get a new top entry (no version bump — this is docs only):

- Firewall-Collector: 1.2.109 — doc unification (this PR)
- Firewall-Mon: 0.10.386 — doc unification (this PR)
  (Per repo's own versioning policy: collector uses 1.2.x patch, server uses 0.10.x patch.)
