# Server-Side Changes for Firewall-Mon

## Summary
Added probe data flow monitoring to detect when probes stop sending data despite being online.

## Changes Made

### 1. Probe Model - Added `LastDataReceived` field
File: `internal/models/models.go`
- Added `LastDataReceived time.Time` with index to Probe struct
- Auto-migrated via GORM

### 2. Alert Model - Added `ProbeID` field
File: `internal/models/models.go`
- Added `ProbeID *uint` with index to Alert struct for probe-specific alerts

### 3. AlertManager - Added `CheckProbeDataFlow`
File: `internal/alerts/alerts.go`
- Checks all approved probes
- Alerts when `LastDataReceived` is older than `PROBE_DATA_LAG_ALERT_MINUTES` (default: 60 min)
- Alert type: `PROBE_DATA_LAG`
- Sends recovery when data flow resumes

### 4. AlertManager - Added `RecordProbeDataTruncation`
File: `internal/alerts/alerts.go`
- Called when batch is truncated (only if original > 1200 items)
- Alerts if truncation happens频繁 (within 5 min)
- Alert type: `PROBE_DATA_TRUNCATED`

### 5. handlers_data.go - Track data receipt
File: `internal/api/handlers/handlers_data.go`
- `ReceiveSyslogMessages`: tracks truncation, calls `RecordProbeDataTruncation`
- `ReceiveTrapEvents`: tracks truncation, calls `RecordProbeDataTruncation`
- All handlers update `last_data_received` timestamp in `validateProbe()`

### 6. handlers_probes.go - Update last_data_received
File: `internal/api/handlers/handlers_probes.go`
- `validateProbe()` now updates both `last_seen` and `last_data_received`

### 7. Config - Added `ProbeDataLagAlertMinutes`
File: `internal/config/config.go`
- New config: `ProbeDataLagAlertMinutes` (env: `PROBE_DATA_LAG_ALERT_MINUTES`, default: 60)

### 8. Database - Added `GetApprovedProbes`
File: `internal/database/database.go`
- New method to get all approved probes for data flow checking

### 9. Poller - Call CheckProbeDataFlow
File: `cmd/poller/main.go`
- Called at end of each poll cycle alongside `CheckEscalations()`

## New Environment Variable
```
PROBE_DATA_LAG_ALERT_MINUTES=60  # Alert when probe sends no data for this many minutes
```

## Alert Types
| Type | Severity | Trigger |
|------|----------|---------|
| `PROBE_DATA_LAG` | configurable (default warning) | No data received for configured minutes |
| `PROBE_DATA_TRUNCATED` | warning | Batch truncated and happens again within 5 min |