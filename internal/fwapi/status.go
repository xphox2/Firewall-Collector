package fwapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// StatusPayload is the ipsec_status command payload (C2b-2b): a READ-ONLY SA
// liveness probe of one deployed tunnel end. The server renders the probe steps
// (vendor driver's StatusProbe); the collector executes the GETs and returns the
// raw device documents for the SERVER to interpret (ParseStatus stays
// server-side, so collector and server never drift on what "up" means).
type StatusPayload struct {
	Vendor     string `json:"vendor"`
	DeviceID   uint   `json:"device_id,omitempty"`
	TunnelName string `json:"tunnel_name,omitempty"`
	BaseURL    string `json:"base_url"`
	// APIToken is the device management API token. NEVER logged; the payload is
	// encrypted at rest by the server and decrypted only for wire delivery.
	APIToken    string            `json:"api_token"`
	InsecureTLS bool              `json:"insecure_tls,omitempty"`
	Steps       []StatusProbeStep `json:"steps"`
}

// StatusProbeStep is one read-only probe (mirrors the server's ipsec.ProbeStep;
// only the http_api shape is used today).
type StatusProbeStep struct {
	Kind   string `json:"kind,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// StatusStepResult is the outcome of one probe step: the HTTP status and the
// RAW body. The body is device telemetry (session lists), not configuration —
// but it is still never logged.
type StatusStepResult struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Body   string `json:"body,omitempty"`
	Note   string `json:"note,omitempty"`
}

// StatusReport is the ipsec_status command result. Error captures a
// transport-level failure (device unreachable, auth rejected at the HTTP
// layer); per-step results are otherwise always recorded so the server sees
// exactly what the device said.
type StatusReport struct {
	Vendor string             `json:"vendor"`
	Steps  []StatusStepResult `json:"steps,omitempty"`
	Error  string             `json:"error,omitempty"`
}

// maxStatusBody caps each stored step body so a bloated monitor endpoint can't
// push the command result past the server's result-size cap. SA/session
// documents are small; 256 KiB is generous.
const maxStatusBody = 256 << 10

// RunStatusProbe executes the read-only SA-liveness probe: one GET per step,
// raw bodies returned for server-side parsing. A single attempt is deliberate —
// the command rides the heartbeat (delivered 0–60s after the deploy finished),
// which dwarfs any IKE negotiation time, so a settle-retry loop would only add
// latency, not accuracy. Read-only: unlike RunApply it takes no device mutex
// (consistent with RunPreflight — GETs never interleave dangerously).
func RunStatusProbe(ctx context.Context, p StatusPayload) StatusReport {
	rep := StatusReport{Vendor: p.Vendor}
	if p.Vendor != "fortigate" && p.Vendor != "opnsense" {
		rep.Error = fmt.Sprintf("status probe not supported for vendor %q", p.Vendor)
		return rep
	}
	if len(p.Steps) == 0 {
		rep.Error = "no probe steps shipped"
		return rep
	}
	client := newClient(p.InsecureTLS)
	for _, s := range p.Steps {
		method := s.Method
		if method == "" {
			method = http.MethodGet
		}
		if !strings.EqualFold(method, http.MethodGet) {
			// Defense in depth: a status probe must never mutate. A non-GET step
			// is a server-side bug; refuse it loudly rather than executing.
			rep.Steps = append(rep.Steps, StatusStepResult{Path: s.Path, Note: "refused: status probe steps must be GET"})
			rep.Error = "non-GET probe step refused (" + method + " " + s.Path + ")"
			return rep
		}
		sr := StatusStepResult{Path: s.Path}
		status, body, err := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, method, s.Path, "")
		if err != nil {
			sr.Note = friendlyNetErr(err)
			rep.Steps = append(rep.Steps, sr)
			rep.Error = "device API unreachable during status probe: " + friendlyNetErr(err)
			return rep
		}
		sr.Status = status
		if len(body) > maxStatusBody {
			body = body[:maxStatusBody]
			sr.Note = "body truncated at 256 KiB"
		}
		sr.Body = string(body)
		rep.Steps = append(rep.Steps, sr)
	}
	return rep
}
