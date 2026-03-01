# Changelog

## 1.0.2 - 2026-02-28

### Improved
- Add `PROBE_REGISTRATION_KEY` and `PROBE_SERVER_URL` as pre-defined environment variables in Dockerfile so users can see and fill them in directly in Docker UIs instead of typing variable names manually

## 1.0.1 - 2026-02-28

### Security
- Remove default `InsecureSkipVerify: true` — TLS now verifies certificates using the system CA store by default
- Add `PROBE_INSECURE_SKIP_VERIFY` env var for explicit opt-in (with logged warning)
- CA cert file read errors are now fatal instead of silently falling back to insecure mode
- Add Bearer token authentication (`Authorization` header) on all HTTP requests, not just registration

### Fixed
- Handle `json.Marshal` errors in `Register()` and `SendHeartbeat()` instead of ignoring them
- Check HTTP status code before attempting JSON decode in `Register()` — prevents confusing parse errors on 500 responses
- Add exponential backoff (10s-160s) and max retry limit (5) for re-registration on 401/403 to prevent infinite loops
- Add 30-second HTTP client timeout to prevent goroutines from hanging on unresponsive servers
- Protect `probeID` and `probeName` with mutex to fix data race between heartbeat goroutine and main thread
- Fix duplicate "keen" in random name adjectives list (replaced with "sharp")
- Handle `crypto/rand.Read` and `crypto/rand.Int` errors instead of ignoring them
- Remove unused `running` field from Client struct

## 1.0.0

- Initial release with probe registration, heartbeat loop, and TLS/mTLS support
