# Bug Report

Thanks for taking the time to file a bug. Please use this template so
we have the context we need to reproduce and fix it quickly.

## Summary

A short, one-line description of the bug.

## Environment

- **Collector version:** (output of `firewall-collector --version` or
  the `## 1.2.x` heading of `CHANGELOG.md`)
- **Docker image digest:** (`docker inspect --format '{{.Id}}' xphox/firewall-collector:1.2.x`)
- **OS / distro:**
- **Go version (if building from source):**
- **Central server version:** (from the server's `CHANGELOG.md`)

## Firewall being monitored

- **Vendor / model:** (FortiGate 60F, Palo Alto PA-3220, etc.)
- **Firmware version:**
- **Management IP / hostname:** (redact if sensitive)
- **Number of devices in `FetchDevices()`:** (approximate)

## Reproducer

The smallest set of steps to reproduce. Include:

- The exact `docker run` / `docker-compose up` invocation, with
  secrets redacted.
- Relevant environment variables (`PROBE_LISTEN_ADDR`,
  `PROBE_SERVER_URL`, etc.)
- Steps in time order: "started the collector at X, configured
  device Y on the server, observed Z."
- Approximate timing (how long after start, what triggered it).

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Paste relevant log lines from the collector
or the central server.

## Logs

```
[Collector log lines, with secrets redacted — NEVER paste PROBE_REGISTRATION_KEY, device passwords, or full TFTP-uploaded configs]
```

## Severity

- [ ] Blocker — collector won't start, or all data is lost
- [ ] High — one vendor / one data source / one feature broken
- [ ] Medium — degraded but not broken
- [ ] Low — minor / cosmetic

## Acceptance criteria

What would you accept as a fix? (e.g. "after this fix, I expect
config-revision to retry at least 3 times before giving up")

## Logs / PCAPs / Attachments

Attach files via drag-and-drop. If a PCAP is large, attach to a
shared drive (do not paste binary into the issue) and link here.
