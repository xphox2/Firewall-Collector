# Security Policy

## Supported Versions

The following versions of `firewall-collector` receive security updates:

| Version | Supported          |
|---------|--------------------|
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

We follow [Semantic Versioning](https://semver.org/). The latest minor
release receives security fixes. Older minors receive fixes on a
best-effort basis at the maintainer's discretion.

## Reporting a Vulnerability

**Please do not file public issues for security vulnerabilities.**

Report privately to:

- **Email:** security@xphox.net
- **PGP key:** [available on request]
- **Subject line:** `[SECURITY] firewall-collector <short-description>`

You should receive an acknowledgement within 72 hours. If you do not
(e.g. because the mailbox is unavailable), follow up via the public
issue tracker only with a non-sensitive summary.

When reporting, please include:

- The collector version (output of `firewall-collector --version` or
  the `## 1.2.x` heading of `CHANGELOG.md` on the running build)
- The OS and Docker image digest (`docker inspect --format '{{.Id}}' xphox/firewall-collector:1.2.x`)
- A reproducer (collector log lines, packet capture, screenshot — please
  redact customer-specific data such as device serial numbers, public IPs,
  FortiGate admin passwords, and full config backups)
- An impact assessment (what an attacker can do, and at what blast radius)
- Your preferred disclosure timeline (default: 90 days from acknowledgement)

We will not pursue legal action against researchers who follow this
policy in good faith.

## Coordinated Disclosure Timeline

| Day  | Event                                                     |
|------|-----------------------------------------------------------|
| 0    | You send the report privately.                            |
| 3    | Maintainer acknowledges receipt (target).               |
| 10   | Maintainer confirms the issue and starts a fix (target).  |
| 30   | Maintainer ships a patched release on `master` + a CVE ID  |
| 30–90| Embargo. We will not pre-announce. We will coordinate with  |
|      | you on the disclosure date.                              |
| 90   | Public disclosure: GitHub Security Advisory + CHANGELOG.   |

We may extend the embargo for actively-exploited issues, fixes that
require complex coordination with downstream consumers, or at your
request.

## Threat Model (in scope)

The collector is a long-running probe that:

- Receives inbound traffic on UDP 162 (SNMP traps), TCP+UDP 514
  (syslog), UDP 6343 (sFlow), UDP 69 (TFTP config backups), and
  optionally SSH / SNMP outbound polling on TCP 22 and UDP 161 to
  managed firewalls.
- Sends outbound HTTPS to a single configurable central server
  (`PROBE_SERVER_URL`) carrying syslog, SNMP, ping, sFlow, and
  config-revision payloads. Bearer-token auth, optional mTLS.
- Runs on the management network of an enterprise firewall
  deployment. Often in a privileged position (can read full firewall
  configs, can trigger config pulls via SSH, can read SNMPv3
  credentials per device).
- May run inside Docker with `network_mode: host` and
  `cap_add: NET_RAW` (for ICMP ping). See `Dockerfile` and
  `docker-compose.yml`.

In-scope vulnerabilities are those that:

- Allow an unauthenticated network attacker to read or modify
  customer data, including firewall config backups.
- Allow a low-privileged authenticated probe operator to escalate
  privilege (e.g. container escape, RCE in the probe process).
- Compromise probe identity (e.g. bearer token disclosure, mTLS
  bypass).
- Cause loss of customer data (e.g. queue overflow without
  telemetry, silent requeue dropping).

Out of scope:

- The **central server** (`xphox2/Firewall-Monitoring`) has its own
  SECURITY.md.
- Vulnerabilities in **third-party libraries** (`gosnmp`,
  `golang.org/x/crypto`, `golang.org/x/sys`) — please report to the
  upstream maintainer, with a CC to us if the impact is on the
  collector.
- Vulnerabilities in the **firewalls being monitored** (FortiGate,
  Palo Alto, etc.) — please report to the vendor directly.
- Issues requiring physical access to the probe host.
- Social-engineering attacks against probe operators.

## Hardening Recommendations

The default `docker-compose.yml` is the **bare minimum** for evaluation.
For production deployments, the probe maintainers recommend:

1. **Bind listeners to a specific interface** via
   `PROBE_LISTEN_ADDR=<management-iface-ip>` rather than `0.0.0.0`.
2. **Run as a non-root user inside the container** — see
   `Dockerfile` and the `cap_drop` / `cap_add` directives in
   `docker-compose.yml`.
3. **Use mTLS** to the central server by setting `PROBE_TLS_CERT`
   and `PROBE_TLS_KEY` to a per-deployment client cert.
4. **Restrict TFTP source IPs** at the network layer (firewall
   rules) to only the management IPs of the firewalls you manage.
5. **Set a strong `PROBE_SNMP_TRAP_COMMUNITY`** when traps are
   enabled — an empty community accepts every trap.
6. **Run on a dedicated management VLAN** with port-level ACLs
   blocking SNMP (UDP 161) and SSH (TCP 22) from outside the
   managed-firewall population.
7. **Enable Docker Content Trust** (`DOCKER_CONTENT_TRUST=1`) to
   verify image signatures on pull.
8. **Subscribe to releases** (GitHub Watch → Releases only) so
   security advisories reach you.

## Acknowledgements

We thank the following researchers for responsibly disclosing
vulnerabilities (this section will be populated as advisories are
disclosed — see `CHANGELOG.md` and the GitHub Security Advisories tab).
