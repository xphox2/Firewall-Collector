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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PreflightStep is one read-only check (mirrors the server's ipsec.PreflightStep
// JSON contract). ExpectAbsent means a present/200 result is a COLLISION.
type PreflightStep struct {
	Check        string `json:"check"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	ExpectAbsent bool   `json:"expect_absent"`
}

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
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: p.InsecureTLS}, //nolint:gosec // opt-in per device for self-signed mgmt certs
			ForceAttemptHTTP2: true,
		},
	}

	for _, step := range p.Steps {
		sr := StepResult{Check: step.Check, Path: step.Path}
		status, body, err := doGet(ctx, client, p, step)
		if err != nil {
			sr.Note = err.Error()
			rep.Checks = append(rep.Checks, sr)
			continue
		}
		sr.StatusCode = status
		sr.OK = status != http.StatusUnauthorized && status != http.StatusForbidden && status < 500
		if status >= 200 && status < 300 {
			rep.Reachable = true
		} else if status == http.StatusUnauthorized || status == http.StatusForbidden {
			rep.Reachable = true // we reached it; auth was rejected
		}
		switch step.Check {
		case "auth":
			rep.AuthOK = status >= 200 && status < 300
			if rep.AuthOK {
				rep.OSVersion = extractVersion(body)
			} else {
				sr.Note = "authentication failed"
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

func doGet(ctx context.Context, client *http.Client, p PreflightPayload, step PreflightStep) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.BaseURL, "/")+step.Path, nil)
	if err != nil {
		return 0, nil, err
	}
	applyAuth(req, p.Vendor, p.APIToken)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	// Cap the read — a preflight response is small JSON; never buffer megabytes.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
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
