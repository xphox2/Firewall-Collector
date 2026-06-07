# Pull Request

## What

One-paragraph summary of the change.

## Why

Link the issue this closes (`Closes #N`, `Fixes #N`) and explain
*why* this change is needed, not just what it does. Reference the
audit issue (e.g. `AUDIT-NNN`) if this is a follow-up.

## How

Briefly describe the implementation approach. Note any non-obvious
decisions, alternatives you considered, and tradeoffs.

## Test

- [ ] `go build ./...`
- [ ] `go test -race -count=1 ./...`
- [ ] `go vet ./...`
- [ ] `go mod tidy` produces no diff
- [ ] `staticcheck ./...` (if you have it installed)
- [ ] `govulncheck ./...` (if you have it installed)
- [ ] New tests added (if behavior changed) — list them:
  -
  -

## Audit / Issue Reference

- Closes #N
- AUDIT-NNN (if applicable)

## Changelog

- [ ] `const version` in `cmd/collector/main.go` bumped
- [ ] `CHANGELOG.md` updated at the top, matching the existing style
- [ ] PR title starts with `AUDIT-NNN:` or the issue number, e.g.
      `AUDIT-055: Add CI test job`

## Checklist

- [ ] No `Co-Authored-By:` trailer
- [ ] No force-pushes (use rebase and merge if main moves under you)
- [ ] LF line endings (master is LF; CRLF will show as a spurious
      file change in CI)
- [ ] Branch is from a recent `master` (last 24h)
