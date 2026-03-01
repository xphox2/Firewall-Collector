# Firewall Collector

Lightweight probe for collecting firewall data at remote sites and relaying to central monitoring server.

## Quick Start

### 1. Generate Registration Key (in Server Admin Panel)

Go to **Admin > Probes** and generate a registration key.

### 2. Deploy Collector

**Docker:**
```bash
docker run -d \
  --name firewall-collector \
  -e PROBE_REGISTRATION_KEY=your-registration-key \
  firewall-collector:latest
```

**Binary:**
```bash
PROBE_REGISTRATION_KEY=your-registration-key ./firewall-collector
```

### 3. Map to Site (in Server Admin Panel)

Once the collector connects, it will appear in **Pending Approvals**. Approve it, then edit the probe to assign it to a site.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROBE_REGISTRATION_KEY` | Yes | - | Registration key from server |
| `PROBE_SERVER_URL` | No | `https://stats.technicallabs.org` | Central server URL |
| `PROBE_TLS_CERT` | No | - | TLS certificate for mTLS |
| `PROBE_TLS_KEY` | No | - | TLS key for mTLS |
| `PROBE_CA_CERT` | No | - | CA cert to verify server |

## What It Does

1. Registers with the server using the registration key
2. Sends heartbeat every 60 seconds
3. Ready to receive SNMP traps, syslog, sFlow, and ping data
4. All configuration is done on the server side after registration
