# Documentation Structure

> Canonical home for cross-cutting topics: [xphox2/Firewall-Monitoring/docs/STRUCTURE.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/STRUCTURE.md).
> This file mirrors the canonical index for the case where you've cloned **only** the collector.

The Firewall-Monitoring project is split across two sibling repositories.
This is **not** a parent/child relationship — each repo is a standalone Go
module that builds and runs on its own, and the two are coupled only at
runtime (the collector talks HTTP to the server).

| Repo | Role | GitHub |
|---|---|---|
| **Firewall-Collector** (this repo) | Lightweight probe that runs at a remote site, listens for syslog / SNMP-trap / sFlow / ICMP, SSH- and TFTP-polls FortiGates, and relays everything to the server. | [xphox2/Firewall-Collector](https://github.com/xphox2/Firewall-Collector) |
| **Firewall-Monitoring** (server) | Central server: stores data, renders dashboards, runs the alert engine, sends notifications, exposes the admin UI. | [xphox2/Firewall-Monitoring](https://github.com/xphox2/Firewall-Monitoring) |

## Which doc lives where

| Topic | Collector (this repo) | Server (canonical) |
|---|---|---|
| Index of where every topic lives | [STRUCTURE.md](STRUCTURE.md) (this file) | [STRUCTURE.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/STRUCTURE.md) |
| Combined architecture (data flow, sequence diagrams) | [ARCHITECTURE.md](ARCHITECTURE.md) (collector-side view) | [**architecture.md**](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/architecture.md) (full) |
| Feature inventory (website-ready) | [FEATURES.md](FEATURES.md) (probe-side) | [FEATURES.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/FEATURES.md) (server-side) |
| Version compatibility table | [COMPATIBILITY.md](COMPATIBILITY.md) (1-pager) | [**SUPPORT-MATRIX.md**](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/SUPPORT-MATRIX.md) (full) |
| Probe↔server wire format (`schema_version`) | see server's MIGRATING.md | [**MIGRATING.md**](https://github.com/xphox2/Firewall-Monitoring/blob/master/MIGRATING.md) |
| Environment variables | [ENV-VARS.md](ENV-VARS.md) (this repo) | [config.env.example](https://github.com/xphox2/Firewall-Monitoring/blob/master/config.env.example) (server) |
| Operator runbook (server) | n/a | [docs/OPERATIONS.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/OPERATIONS.md) |
| Data retention / PII | n/a | [docs/DATA-RETENTION.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/DATA-RETENTION.md) |
| TLS / probe-credential rotation | n/a | [docs/CERT-ROTATION.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/CERT-ROTATION.md) |
| Custom SNMP vendor profile | [CUSTOM-VENDOR.md](CUSTOM-VENDOR.md) (collector-side walkthrough) | [docs/custom-vendor.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/custom-vendor.md) (server-side walkthrough) |
| FortiGate device setup (SNMP, syslog, SSH, TFTP) | [FORTIGATE-SETUP.md](FORTIGATE-SETUP.md) (collector side) | [docs/FORTIGATE-SNMP-SETUP.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/FORTIGATE-SNMP-SETUP.md) (server side) |
| Database migrations | n/a | [docs/partition-migration.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/partition-migration.md) |
| Production-hardened nginx config | n/a | [docs/nginx.conf](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/nginx.conf) |
| Adding a new SNMP vendor | [CUSTOM-VENDOR.md](CUSTOM-VENDOR.md) | [docs/custom-vendor.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/custom-vendor.md) |
| Production upgrade runbook | n/a | [docs/UPGRADE-2026-06.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/UPGRADE-2026-06.md) |

**Rule of thumb:** if a topic only matters to operators of the **server**
(retention, backups, JWT rotation, the admin UI), it lives in
**`xphox2/Firewall-Monitoring`** only. If it only matters to operators of
the **probe** (which env vars, which port to open), it lives in **this
repo** only. If it spans both, the canonical version lives in the
**server** repo and the collector gets a 1-page pointer.

The cross-repo pointers all use absolute GitHub URLs so links resolve
both on github.com and in any rendered README.
