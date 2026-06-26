# Contributing to firewall-collector

Thanks for your interest. The collector is a single-binary Go probe that
runs on customer networks to monitor firewalls and relay data to a
central server. Most contributions fall into one of four buckets.

## 1. Adding a new firewall vendor

The collector has a vendor-profile registry. To add a new vendor:

1. Create `internal/snmp/vendor_<name>.go` (e.g. `vendor_cisco_asa.go`).
2. Implement the `VendorProfile` interface defined in
   `internal/snmp/vendor.go:26`:

   ```go
   type VendorProfile interface {
       Name() string
       SystemOIDs() []string
       ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus
       VPNBaseOID() string
       ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus
       HWSensorBaseOID() string
       ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor
       ProcessorBaseOID() string
       ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats
       TrapOIDs() map[string]TrapDef
   }
   ```

   Features your device doesn't expose are one-line stubs (`""` for a
   `*BaseOID()`, `nil` for the matching `Parse*`). Richer features
   (dial-up/SSL VPN, HA, security/SD-WAN/license stats) are exposed by
   implementing the optional sub-interfaces also declared in `vendor.go`
   (`DialupVPNProvider`, `SSLVPNProvider`, `HAProvider`,
   `SecurityStatsProvider`, `SDWANProvider`, `LicenseProvider`).

3. Register the profile from the file's `init()` with
   `RegisterVendor(&<Name>Profile{})` (see any existing
   `vendor_*.go`). The registry is a name-keyed map — there is no
   ordering; the device's configured `vendor` selects the profile via
   `GetVendorProfile(name)`, and FortiGate is the `DefaultVendor()`
   fallback.
4. Add tests in `internal/snmp/vendor_<name>_test.go` covering
   happy-path, sysObjectID detection, and graceful-empty returns for
   the optional interfaces (VPN, HA, sensors, etc.).
5. Add the vendor to the supported list in `README.md`.

If the new vendor uses SSH (not just SNMP), extend
`internal/ssh/parser.go` with a new parser, and add a parse
function call in `c.sshPollDevice`.

## 2. Adding a new data source

The collector has these inbound listeners: SNMP trap, syslog TCP+UDP,
sFlow, TFTP (for config backup), and outbound: SNMP, SSH, ICMP ping.
To add a new data source:

- **Inbound protocol (e.g. NetFlow, gNMI, syslog-over-TLS):** add
  a new package under `internal/`, following the pattern of
  `internal/syslog/`. Register a typed `Send*` method on
  `internal/relay/relay.go` that the periodic sync sends.
- **Outbound protocol:** add a poller under `internal/`, called
  from `cmd/collector/main.go` (similar to `snmpPollingLoop`).

## 3. Fixing bugs

1. Open an issue describing the bug (use the `bug_report.md` template).
2. Reference the issue in your commit: `Fixes #N` or `Closes #N`.
3. Add a regression test that fails before your fix and passes after.
4. Run `go test -race ./...` locally. The CI will gate on it.
5. If the bug is security-related, **do not** open a public issue —
   follow `SECURITY.md` instead.

## 4. Improving documentation / CI

- README, DEPLOY, SECURITY, CHANGELOG — feel free to fix typos,
  clarify, or add examples. CI: see `.github/workflows/docker.yml`.
- Issues labeled `good first issue` are appropriate for first-time
  contributors.

## Local development

```bash
go build ./...
go test -race ./...        # race detector on (matches CI)
go vet ./...
go mod tidy && git diff --exit-code go.mod go.sum   # no drift
staticcheck ./...          # install: go install honnef.co/go/tools/cmd/staticcheck@latest
govulncheck ./...          # install: go install golang.org/x/vuln/cmd/govulncheck@latest
```

If your editor is writing CRLF line endings, set
`git config core.autocrlf false` and `git config core.eol lf`. Master
uses LF; CRLF will appear as a "modified" file in CI.

## Pull request process

1. Branch from `master`: `git checkout -b audit-NNN-short-name`.
2. Make your changes. Add tests. Bump `const version` in
   `cmd/collector/main.go:45` per the patch-versioning rule
   (1.2.74 → 1.2.75 → 1.2.76). Add a `## 1.2.x` section to
   `CHANGELOG.md` at the top, matching the existing style.
3. Commit. Do **not** include a `Co-Authored-By:` trailer.
4. Push. Open a PR. Use the PR template.
5. Wait for CI to pass (all 6 steps: vet, test -race, mod tidy,
   staticcheck, govulncheck, build).
6. Request a review from a maintainer (CODEOWNERS will auto-assign).

## Code style

- Standard `gofmt` + `goimports`.
- All exported types, functions, methods, and package-level vars
  get a doc comment.
- Errors are wrapped with context: `fmt.Errorf("doing X: %w", err)`.
  Use `errors.Is` / `errors.As` to check, not string matching.
- Use `log/slog` for new code; older `log.Printf` calls are
  acceptable for the duration of the slog migration.
- Prefer stdlib. Add a dependency only when the stdlib is genuinely
  insufficient. New deps must be in `go.mod` and the CI must pass
  `go mod tidy` (no diff) and `govulncheck`.
- For long-lived goroutines, use `internal/safego.Go(name, fn)` so
  a panic doesn't take down the process. Tag the goroutine with a
  short, unique name (e.g. `snmp:device:fw-nyc-01`).

## Reporting security issues

See `SECURITY.md`. Do not file public issues for security
vulnerabilities.

## Code of conduct

See `CODE_OF_CONDUCT.md`. Be excellent to each other.
