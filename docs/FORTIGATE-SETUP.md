# FortiGate setup (collector side)

> Server-side FortiGate setup (SNMP/SNMP-trap on the box, required OIDs,
> recommended poll intervals): [xphox2/Firewall-Monitoring/docs/FORTIGATE-SNMP-SETUP.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/FORTIGATE-SNMP-SETUP.md).
> This file is the **collector-side** walkthrough: which env vars to set,
> which ports to forward, and how to drive the SSH/TFTP-backup paths
> that the collector is responsible for.

## What the collector needs from the FortiGate

The collector is configured per-device from the server admin UI
(Device → SNMP community / SSH credentials / TFTP server IP). The
device side just needs:

- **SNMP** enabled (the collector polls it directly; for a remote
  collector, the SNMP listener runs on the **collector** and the
  FortiGate sends traps to the collector's IP).
- **Syslog** target set to the collector's IP.
- **sFlow** target set to the collector's IP (optional).
- **SSH** reachable from the collector on port 22, with an account the
  collector can run `show` (running config) and `diagnose sys csum`.
- **TFTP** initiated **from the FortiGate** to the collector on
  UDP/69, in response to a syslog-triggered config-change event
  (the collector uses `execute backup config tftp` over SSH).

## Syslog-triggered config backup

When the collector sees a FortiGate syslog line with
`logid=0100044546` (config-change) or `logid=0100044547`
(config-object-change), it schedules a debounced TFTP config backup
(keyed on `<deviceID>:<cfgtid>`, 60-second debounce). The collector
SSHes into the device and runs `execute backup config tftp
<server-ip> <filename>`, then the FortiGate pushes the config via TFTP
WRQ. The collector receives it and POSTs the config revision to the
server (with `backup_quality="masked"` if the FortiGate is masking
passwords, which is the default on FortiOS 7.2.1+).

See [FORTIGATE-SNMP-SETUP.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/FORTIGATE-SNMP-SETUP.md)
for the device-side walkthrough (SNMP/SNMP-trap config, required
OIDs by category, recommended poll intervals, test commands).

## Verifying the SSH path

`collector ssh-test` exercises the SSH side end-to-end without
involving the server:

```bash
PROBE_TEST_PASSWORD='your-fortigate-password' \
  ./firewall-collector ssh-test \
    --host=fortigate.example.com \
    --user=monitor \
    --format=json \
    all
```

Subcommands: `all` / `checksum` / `config` / `process` / `interface` /
`sensor` / `license` / `performance` / `vpn` / `ha`. JSON is the default
(suitable for CI); use `--format=text` for human reading.

## Verifying the TFTP path

`firewall-collector-diag-backup` is a single-shot diagnostic binary
that SSHes into the device, runs `execute backup config tftp`, waits
for the upload, and emits a `VERDICT:` line. Useful when a probe is
configured but config backups never appear on the server.

```bash
./firewall-collector-diag-backup \
  -device-host=fortigate.example.com \
  -device-user=monitor \
  -device-password='...'
```

## Vendor profile

The collector's default vendor is FortiGate. Other vendors supported
by the collector: see [FEATURES.md](FEATURES.md#vendor-profiles).
