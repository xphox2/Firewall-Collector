# Firewall Collector

Lightweight probe for collecting firewall data at remote sites and relaying to central monitoring server.

## Features

- **SNMP Polling** — Polls system status (CPU, memory, disk, sessions, uptime) and interface stats from assigned devices
- **SNMP Trap Receiver** — Listens for FortiGate SNMP traps with automatic type/severity classification
- **Syslog Receiver** — TCP and UDP listeners with RFC 5424 parsing
- **sFlow Receiver** — UDP listener with sFlow v5 datagram support
- **Ping Collector** — ICMP ping monitoring with latency and packet loss tracking
- **Queue-Based Relay** — Batches collected data and sends to server with retry logic
- **Feature Toggles** — Each collector can be individually enabled/disabled

## Quick Start

### 1. Generate Registration Key (in Server Admin Panel)

Go to **Admin > Probes** and generate a registration key.

### 2. Deploy Collector

**Docker:**
```bash
docker run -d \
  --name firewall-collector \
  -e PROBE_REGISTRATION_KEY=your-registration-key \
  -p 162:162/udp \
  -p 514:514/udp \
  -p 514:514/tcp \
  -p 6343:6343/udp \
  firewall-collector:latest
```

**Binary:**
```bash
PROBE_REGISTRATION_KEY=your-registration-key ./firewall-collector
```

### 3. Map to Site (in Server Admin Panel)

Once the collector connects, it will appear in **Pending Approvals**. Approve it, then edit the probe to assign it to a site. Assigned devices will be automatically polled via SNMP and pinged.

## Environment Variables

### Server Connection

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROBE_REGISTRATION_KEY` | Yes | — | Registration key from server |
| `PROBE_SERVER_URL` | No | `https://stats.technicallabs.org` | Central server URL |
| `PROBE_TLS_CERT` | No | — | TLS certificate for mTLS |
| `PROBE_TLS_KEY` | No | — | TLS key for mTLS |
| `PROBE_CA_CERT` | No | — | CA cert to verify server |
| `PROBE_INSECURE_SKIP_VERIFY` | No | `false` | Skip TLS verification (not for production) |

### Intervals (seconds)

| Variable | Default | Description |
|----------|---------|-------------|
| `PROBE_HEARTBEAT_INTERVAL` | `60` | Heartbeat frequency |
| `PROBE_SYNC_INTERVAL` | `30` | Data batch send frequency |
| `PROBE_POLL_INTERVAL` | `60` | SNMP poll frequency per device |
| `PROBE_DEVICE_REFRESH_INTERVAL` | `300` | Device list refresh frequency |
| `PROBE_PING_INTERVAL` | `60` | Ping frequency per device |
| `PROBE_PING_TIMEOUT` | `5` | Ping timeout per attempt |
| `PROBE_PING_COUNT` | `4` | Number of pings per device per cycle |

### Listener Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PROBE_LISTEN_ADDR` | `0.0.0.0` | Bind address for all listeners |
| `PROBE_SNMP_TRAP_PORT` | `162` | SNMP trap listener port |
| `PROBE_SYSLOG_PORT` | `514` | Syslog listener port (TCP + UDP) |
| `PROBE_SFLOW_PORT` | `6343` | sFlow listener port |
| `PROBE_SNMP_TRAP_COMMUNITY` | *(empty)* | SNMP community string filter (empty = accept all) |

### Feature Toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `PROBE_SNMP_TRAP_ENABLED` | `true` | Enable SNMP trap receiver |
| `PROBE_SYSLOG_ENABLED` | `true` | Enable syslog receiver |
| `PROBE_SFLOW_ENABLED` | `true` | Enable sFlow receiver |
| `PROBE_PING_ENABLED` | `true` | Enable ping collector |

## How It Works

1. Registers with the server using the registration key
2. Sends heartbeat every 60 seconds
3. Fetches assigned device list from server every 5 minutes
4. Polls each device via SNMP every 60 seconds (system status + interface stats)
5. Listens for SNMP traps, syslog messages, and sFlow datagrams
6. Pings each device every 60 seconds
7. Batches all collected data and sends to server every 30 seconds
8. All configuration (which devices to monitor) is managed from the server admin panel
