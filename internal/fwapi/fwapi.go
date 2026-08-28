// Package fwapi implements the collector-side READ-ONLY vendor REST transport
// for the IPSec deploy preflight (PR-C1). It authenticates to a firewall's
// management REST API and runs a set of GETs (an auth/version check plus reads
// of the objects a deploy WOULD create) to surface reachability, auth, and
// name/VTI/connection collisions BEFORE any write exists.
//
// SECURITY: every request is a GET — this package performs NO writes. The API
// token is used only to build the auth header and is NEVER logged. TLS
// verification is on by default; it is skipped only when the operator opted a
// device into InsecureTLS (self-signed mgmt cert on a trusted segment).
package fwapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PreflightStep is one read-only check (mirrors the server's ipsec.PreflightStep
// JSON contract). ExpectAbsent means a present/200 result is a COLLISION.
//
// ReturnBody asks for the response body to be echoed back in the report so the
// SERVER can parse it (vendor knowledge stays in the server's driver, as with
// StatusProbe/ParseStatus). Steps carrying it are advisory reads: they never set
// ExpectAbsent, so they can neither raise a collision nor abort an apply.
type PreflightStep struct {
	Check        string `json:"check"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	ExpectAbsent bool   `json:"expect_absent"`
	ReturnBody   bool   `json:"return_body,omitempty"`
}

// maxReturnedBody caps an echoed body. The whole report must fit the server's
// 64 KiB command-result column, and a truncated body would be unparseable JSON
// that could be misread; so an oversize body is DROPPED entirely (with a note)
// rather than cut, and the server simply raises no advisory from it.
const maxReturnedBody = 24 << 10

// PreflightPayload is the decrypted command payload the server enqueues.
type PreflightPayload struct {
	TunnelID    uint            `json:"tunnel_id"`
	TunnelName  string          `json:"tunnel_name"`
	End         int             `json:"end"`
	Vendor      string          `json:"vendor"`
	DeviceID    uint            `json:"device_id"`
	BaseURL     string          `json:"base_url"`
	APIToken    string          `json:"api_token"`
	InsecureTLS bool            `json:"insecure_tls"`
	Steps       []PreflightStep `json:"steps"`
}

// StepResult is the outcome of one preflight GET.
type StepResult struct {
	Check         string `json:"check"`
	Path          string `json:"path"`
	StatusCode    int    `json:"status_code"`
	OK            bool   `json:"ok"`            // request reached the API and was authorized
	Present       bool   `json:"present"`       // the object exists (only meaningful for collision checks)
	Collision     bool   `json:"collision"`     // ExpectAbsent step whose object is definitely present
	Indeterminate bool   `json:"indeterminate"` // collision check could not be decided (auth/VDOM/5xx)
	Note          string `json:"note,omitempty"`
	// Body is the verbatim response, echoed back only for steps that asked for it
	// (ReturnBody) and only on a 2xx. It carries device config the operator can
	// already read via the API — never a token or PSK, which are request-side.
	Body string `json:"body,omitempty"`
}

// PreflightReport is the structured result returned to the server as the
// command result. It contains NO secrets (no token, no PSK).
type PreflightReport struct {
	Vendor        string       `json:"vendor"`
	End           int          `json:"end"`
	DeviceID      uint         `json:"device_id"`
	Reachable     bool         `json:"reachable"`
	AuthOK        bool         `json:"auth_ok"`
	OSVersion     string       `json:"os_version,omitempty"`
	Conflict      bool         `json:"conflict"`      // at least one collision check is definitely present
	Indeterminate bool         `json:"indeterminate"` // at least one collision check could not be decided
	Checks        []StepResult `json:"checks"`
	Error         string       `json:"error,omitempty"`
}

// RunPreflight executes the payload's read-only steps and returns a structured
// report. It never returns an error to the caller for a device-side failure —
// the report captures reachability/auth/collision; a returned error means the
// payload itself was unusable.
func RunPreflight(ctx context.Context, p PreflightPayload) PreflightReport {
	rep := PreflightReport{Vendor: p.Vendor, End: p.End, DeviceID: p.DeviceID}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: p.InsecureTLS}, // #nosec G402 -- InsecureTLS is a documented per-device operator opt-in for self-signed management certs (AUDIT-224: was //nolint:gosec, which standalone gosec ignores)
			ForceAttemptHTTP2: true,
		},
	}

	for i := 0; i < len(p.Steps); i++ {
		step := p.Steps[i]
		sr := StepResult{Check: step.Check, Path: step.Path}
		status, body, err := doGet(ctx, client, p, step)
		if err != nil {
			sr.Note = friendlyNetErr(err)
			rep.Checks = append(rep.Checks, sr)
			// A transport failure on the auth/reachability probe means the whole
			// API is unreachable — the remaining collision GETs would fail the same
			// way, so skip them (fail fast) instead of waiting out N more timeouts.
			if step.Check == "auth" {
				rep.Error = "device API unreachable: " + friendlyNetErr(err)
				for j := i + 1; j < len(p.Steps); j++ {
					rep.Checks = append(rep.Checks, StepResult{
						Check: p.Steps[j].Check, Path: p.Steps[j].Path,
						Note: "skipped — device API unreachable",
					})
				}
				break
			}
			continue
		}
		sr.StatusCode = status
		sr.OK = status != http.StatusUnauthorized && status != http.StatusForbidden && status < 500
		if status >= 200 && status < 300 {
			rep.Reachable = true
		} else if status == http.StatusUnauthorized || status == http.StatusForbidden {
			rep.Reachable = true // we reached it; auth was rejected
		}
		switch {
		case step.Check == "auth":
			rep.AuthOK = status >= 200 && status < 300
			if rep.AuthOK {
				rep.OSVersion = extractVersion(body)
			} else {
				sr.Note = "authentication failed"
			}
		case step.ReturnBody:
			// An advisory read. Deliberately skips collision interpretation: it is
			// not an ExpectAbsent step, so "present" is meaningless for it and
			// setting it would muddy the report's conflict semantics. Echo the body
			// for the server to parse; a non-2xx or oversize body yields no body and
			// the server raises no advisory (never a false all-clear, because an
			// advisory only ever asserts something it positively observed).
			switch {
			case status < 200 || status >= 300:
				sr.Note = fmt.Sprintf("advisory read returned HTTP %d — check skipped", status)
			case len(body) > maxReturnedBody:
				sr.Note = fmt.Sprintf("advisory read returned %d bytes (cap %d) — check skipped", len(body), maxReturnedBody)
			default:
				sr.Body = string(body)
			}
		default:
			present, indeterminate := objectPresent(p.Vendor, status, body, p.TunnelName)
			sr.Present = present
			sr.Indeterminate = indeterminate
			switch {
			case step.ExpectAbsent && present:
				sr.Collision = true
				rep.Conflict = true
				sr.Note = "an object with this name already exists on the device"
			case step.ExpectAbsent && indeterminate:
				rep.Indeterminate = true
				sr.Note = fmt.Sprintf("collision check inconclusive (HTTP %d) — verify API-user read access / VDOM", status)
			}
		}
		rep.Checks = append(rep.Checks, sr)
	}
	return rep
}

// friendlyNetErr turns a raw transport error into a short, actionable message
// (the raw "context deadline exceeded while awaiting headers" is unhelpful to an
// operator). Kept vendor-neutral but with FortiGate's common admin-port gotcha.
func friendlyNetErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "Client.Timeout") || strings.Contains(s, "i/o timeout") || strings.Contains(s, "TLS handshake timeout"):
		return "connection timed out — the API did not respond. Check that HTTPS admin access is enabled on the device interface facing the collector, that the API Port matches the device's admin HTTPS port (FortiGate admin is often 8443/4443, not 443), and that the REST API admin's trusthost includes the collector."
	case strings.Contains(s, "connection refused"):
		return "connection refused — nothing is listening on that host:port. Verify the API Port and that HTTPS admin access is enabled."
	case strings.Contains(s, "no route to host") || strings.Contains(s, "network is unreachable"):
		return "no route to the device — the collector cannot reach that IP/subnet."
	case strings.Contains(s, "x509") || strings.Contains(s, "certificate") || strings.Contains(s, "tls:"):
		return "TLS error: " + s + " — enable 'Allow self-signed TLS certificate' on the device if it uses a self-signed cert."
	default:
		return s
	}
}

func doGet(ctx context.Context, client *http.Client, p PreflightPayload, step PreflightStep) (int, []byte, error) {
	return doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, http.MethodGet, step.Path, "")
}

// doRequest is the general vendor-REST transport: it builds an authenticated
// request (optionally with a JSON body + Content-Type), executes it, and returns
// the status + a size-capped body. Shared by the read-only preflight GETs and
// the apply/remove writes. It performs no interpretation — the caller decides
// what a status means.
func doRequest(ctx context.Context, client *http.Client, vendor, token, baseURL, method, path, body string) (int, []byte, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(baseURL, "/")+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	applyAuth(req, vendor, token)
	req.Header.Set("Accept", "application/json")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	// Cap the read — a cmdb response is small JSON; never buffer megabytes. The
	// read error is NOT discarded: a mid-body transport failure yields a
	// truncated body that a parser could misread as a verdict (e.g. an OPNsense
	// `{"result":"failed"` cut short), so propagate it as a transport error.
	// Read one byte past the cap so a silently-truncated oversize body is also
	// an error rather than a parse of incomplete JSON.
	rbody, rerr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if rerr != nil {
		return 0, nil, fmt.Errorf("reading response body: %w", rerr)
	}
	if len(rbody) > 1<<20 {
		return 0, nil, fmt.Errorf("response body exceeds the 1 MiB cap")
	}
	return resp.StatusCode, rbody, nil
}

// applyAuth sets the vendor auth header. FortiGate uses a Bearer token;
// OPNsense uses HTTP basic with "key:secret" (split on the first colon).
func applyAuth(req *http.Request, vendor, token string) {
	if vendor == "opnsense" {
		key, secret, found := strings.Cut(token, ":")
		if found {
			req.SetBasicAuth(key, secret)
			return
		}
		// No colon — treat the whole token as the key (secret empty).
		req.SetBasicAuth(token, "")
		return
	}
	// fortigate (and default): Bearer token.
	req.Header.Set("Authorization", "Bearer "+token)
}

// objectPresent decides whether a collision-check GET indicates the object
// already exists. It returns (present, indeterminate): only an authoritative
// answer sets present; anything ambiguous (auth/VDOM/5xx, or unparseable
// search output) is indeterminate so the caller never reports a false "clear".
//
//   - FortiGate cmdb: 200 → present; 404 → absent; anything else (401/403/424/
//     4xx/5xx — e.g. an API user without vpn.ipsec read access, or a
//     wrong-VDOM GET) → indeterminate.
//   - OPNsense search: 2xx with a parseable rows array → present iff a row has
//     a field value EXACTLY equal to the tunnel name (never a raw-body
//     substring — "fwm-t7" must not match a deployed "fwm-t70"); a non-2xx or
//     unparseable body → indeterminate.
func objectPresent(vendor string, status int, body []byte, tunnelName string) (present, indeterminate bool) {
	if vendor == "opnsense" {
		if status < 200 || status >= 300 {
			return false, true
		}
		matched, ok := opnsenseRowsMatch(body, tunnelName)
		if !ok {
			return false, true // couldn't parse the search result → don't claim "clear"
		}
		return matched, false
	}
	// fortigate cmdb
	switch {
	case status == http.StatusNotFound:
		return false, false
	case status >= 200 && status < 300:
		return true, false
	default:
		return false, true
	}
}

// opnsenseRowsMatch parses an OPNsense search response ({"rows":[{...}],...})
// and reports whether any row has a string field EXACTLY equal to name. The
// second return is false when the body can't be parsed as a rows array (so the
// caller treats it as indeterminate rather than a false negative).
func opnsenseRowsMatch(body []byte, name string) (matched, parsed bool) {
	if name == "" {
		return false, true
	}
	var resp struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, false
	}
	for _, row := range resp.Rows {
		for _, v := range row {
			if s, ok := v.(string); ok && s == name {
				return true, true
			}
		}
	}
	return false, true
}

// extractVersion best-effort pulls a version string from an auth/status body.
// FortiGate monitor/system/status → {"version":"v7.6.7",...}; OPNsense
// firmware/status → {"product_version":"26.1",...} (or {"product":{...}}).
func extractVersion(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	for _, k := range []string{"version", "product_version"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	if res, ok := m["results"].(map[string]any); ok {
		if v, ok := res["version"].(string); ok {
			return v
		}
	}
	if prod, ok := m["product"].(map[string]any); ok {
		if v, ok := prod["product_version"].(string); ok {
			return v
		}
	}
	return ""
}

// Summary renders a one-line human status for the command result log context
// (never includes secrets).
func (r PreflightReport) Summary() string {
	return fmt.Sprintf("end=%d vendor=%s reachable=%t auth_ok=%t version=%q conflict=%t",
		r.End, r.Vendor, r.Reachable, r.AuthOK, r.OSVersion, r.Conflict)
}
