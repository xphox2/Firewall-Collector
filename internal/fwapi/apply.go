package fwapi

// Apply/remove is the collector-side WRITE transport for the IPSec deploy saga
// (C2b-1, FortiGate only). It is deliberately conservative:
//
//  1. checksum-verify the steps against the server-computed checksum — refuse to
//     write anything on mismatch (the bytes that run are provably the bytes the
//     operator previewed);
//  2. collision-precheck (the same read-only GETs the preflight used, expecting
//     ABSENT) — abort BEFORE any write if an object already exists or the check
//     is indeterminate (fail-safe);
//  3. execute the ordered write steps, stopping on the first non-2xx;
//  4. verify — re-run the collision GETs expecting PRESENT (skip the auth step).
//
// Remove reverses an apply from the server-stored snapshot, but never deletes an
// object it doesn't own: it GETs each target first and skips anything whose
// FortiOS comment/comments/name isn't this tunnel's fwm-t<ID> tag.
//
// SECURITY: the API token builds the auth header and is NEVER logged; the
// ApplyReport carries only per-step op/path/status — never request bodies or the
// PSK.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ApplyStep mirrors the server's ipsec.ApplyStep JSON contract. The checksum is
// computed over exactly these fields (see checksumSteps) — it MUST match the
// server byte-for-byte.
type ApplyStep struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	CLI         string `json:"cli,omitempty"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	Body        string `json:"body,omitempty"`
}

// ApplyPayload is the decrypted command payload for a WRITE (apply or remove).
// For an apply, Steps carry the PSK-bearing cmdb bodies (which is why the command
// payload is encrypted at rest + TLS-delivered + never logged) and CollisionSteps
// are the read-only ExpectAbsent GETs. For a remove, Steps are body-less DELETEs
// and OwnerTag scopes the ownership guard.
type ApplyPayload struct {
	TunnelID       uint            `json:"tunnel_id"`
	TunnelName     string          `json:"tunnel_name"`
	End            int             `json:"end"`
	Vendor         string          `json:"vendor"`
	DeviceID       uint            `json:"device_id"`
	BaseURL        string          `json:"base_url"`
	Op             string          `json:"op"` // "apply" | "remove"
	OwnerTag       string          `json:"owner_tag"`
	APIToken       string          `json:"api_token"`
	InsecureTLS    bool            `json:"insecure_tls"`
	Steps          []ApplyStep     `json:"steps"`
	Checksum       string          `json:"checksum"`
	CollisionSteps []PreflightStep `json:"collision_steps,omitempty"`
}

// checksumSteps MUST produce the identical hash to the server's
// ipsec.ChecksumSteps: SHA-256 over "Kind\0CLI\0Method\0Path\0Body\x1e" per step
// (Description is excluded on both sides).
func checksumSteps(steps []ApplyStep) string {
	h := sha256.New()
	for _, s := range steps {
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x1e", s.Kind, s.CLI, s.Method, s.Path, s.Body)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ApplyStepResult is one write/verify/precheck outcome. Compact by design (no
// request body / secret) so a full report stays well under the server's result
// size cap even at the maximum protected-subnet count.
type ApplyStepResult struct {
	Op     string `json:"op"` // precheck | apply | verify | remove
	Path   string `json:"path"`
	Status int    `json:"status"`
	OK     bool   `json:"ok"`
	Note   string `json:"note,omitempty"`
}

// ApplyReport is the structured command result. No secrets, no request bodies.
type ApplyReport struct {
	Vendor     string            `json:"vendor"`
	End        int               `json:"end"`
	DeviceID   uint              `json:"device_id"`
	Op         string            `json:"op"`
	Applied    bool              `json:"applied"`  // all write steps returned 2xx
	Verified   bool              `json:"verified"` // post-write objects confirmed present
	Aborted    bool              `json:"aborted"`  // refused BEFORE any write (checksum/collision/auth)
	Conflict   bool              `json:"conflict"` // a pre-existing colliding object was found
	Collisions []string          `json:"collisions,omitempty"`
	Steps      []ApplyStepResult `json:"steps"`
	Error      string            `json:"error,omitempty"`
}

func newClient(insecure bool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // opt-in per device for self-signed mgmt certs
			ForceAttemptHTTP2: true,
		},
	}
}

func is2xx(status int) bool { return status >= 200 && status < 300 }

// RunApply writes one end's config: checksum → collision-precheck → ordered
// writes → verify. It never returns an error — the report captures every outcome;
// a device-side failure is data, not a transport error.
func RunApply(ctx context.Context, p ApplyPayload) ApplyReport {
	rep := ApplyReport{Vendor: p.Vendor, End: p.End, DeviceID: p.DeviceID, Op: "apply"}

	// (1) Checksum gate — refuse to write anything the operator didn't approve.
	if checksumSteps(p.Steps) != p.Checksum {
		rep.Aborted = true
		rep.Error = "artifact checksum mismatch — refusing to write (the steps do not match what the server rendered)"
		return rep
	}

	client := newClient(p.InsecureTLS)

	// (2) Collision-precheck: the same GETs, expecting ABSENT. Abort (no write) on
	// any present object OR any indeterminate check OR an auth failure.
	for _, cs := range p.CollisionSteps {
		status, body, err := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, http.MethodGet, cs.Path, "")
		sr := ApplyStepResult{Op: "precheck", Path: cs.Path, Status: status}
		if err != nil {
			rep.Aborted = true
			rep.Error = "device API unreachable during precheck: " + friendlyNetErr(err)
			sr.Note = friendlyNetErr(err)
			rep.Steps = append(rep.Steps, sr)
			return rep
		}
		if cs.Check == "auth" {
			if !is2xx(status) {
				rep.Aborted = true
				rep.Error = fmt.Sprintf("authentication/reachability check failed (HTTP %d) — refusing to write", status)
				sr.Note = "auth failed"
				rep.Steps = append(rep.Steps, sr)
				return rep
			}
			sr.OK = true
			rep.Steps = append(rep.Steps, sr)
			continue
		}
		present, indeterminate := objectPresent(p.Vendor, status, body, p.TunnelName)
		switch {
		case cs.ExpectAbsent && present:
			rep.Conflict = true
			rep.Collisions = append(rep.Collisions, cs.Path)
			sr.Note = "object already exists — not overwriting"
		case cs.ExpectAbsent && indeterminate:
			rep.Aborted = true
			rep.Error = fmt.Sprintf("collision check inconclusive (HTTP %d) — refusing to write; verify API-user read access / VDOM", status)
			sr.Note = "indeterminate"
			rep.Steps = append(rep.Steps, sr)
			return rep
		default:
			sr.OK = true
		}
		rep.Steps = append(rep.Steps, sr)
	}
	if rep.Conflict {
		rep.Aborted = true
		rep.Error = "one or more objects already exist on the device (see collisions) — roll back the existing deployment before re-deploying, or resolve the object on the device if it is not ours"
		return rep
	}

	// (3) Execute the ordered write steps; stop on the first non-2xx.
	for _, s := range p.Steps {
		status, _, err := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, s.Method, s.Path, s.Body)
		sr := ApplyStepResult{Op: "apply", Path: s.Path, Status: status}
		if err != nil {
			sr.Note = friendlyNetErr(err)
			rep.Steps = append(rep.Steps, sr)
			rep.Error = "write failed: " + friendlyNetErr(err) + " — the device MAY be partially configured; roll back"
			return rep
		}
		sr.OK = is2xx(status)
		rep.Steps = append(rep.Steps, sr)
		if !sr.OK {
			rep.Error = fmt.Sprintf("write step returned HTTP %d — the device MAY be partially configured; roll back", status)
			return rep
		}
	}
	rep.Applied = true

	// (4) Verify: the same collision GETs, now expecting PRESENT (skip auth).
	verified := true
	for _, cs := range p.CollisionSteps {
		if cs.Check == "auth" || !cs.ExpectAbsent {
			continue
		}
		status, body, err := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, http.MethodGet, cs.Path, "")
		sr := ApplyStepResult{Op: "verify", Path: cs.Path, Status: status}
		if err != nil {
			verified = false
			sr.Note = friendlyNetErr(err)
			rep.Steps = append(rep.Steps, sr)
			continue
		}
		present, _ := objectPresent(p.Vendor, status, body, p.TunnelName)
		sr.OK = present
		if !present {
			verified = false
			sr.Note = "expected object not found after write"
		}
		rep.Steps = append(rep.Steps, sr)
	}
	rep.Verified = verified
	if !verified {
		rep.Error = "applied, but post-write verification did not confirm all objects — check the device"
	}
	return rep
}

// RunRemove deletes one end's objects from the server-stored snapshot. It is
// ownership-guarded: each target is GETted first and skipped (not deleted) unless
// its FortiOS comment/comments/name matches this tunnel's OwnerTag, so a rollback
// can never destroy a pre-existing operator object that happens to share a key.
// A 404 (already gone) is treated as success.
func RunRemove(ctx context.Context, p ApplyPayload) ApplyReport {
	rep := ApplyReport{Vendor: p.Vendor, End: p.End, DeviceID: p.DeviceID, Op: "remove"}

	if checksumSteps(p.Steps) != p.Checksum {
		rep.Aborted = true
		rep.Error = "remove-steps checksum mismatch — refusing to delete"
		return rep
	}

	client := newClient(p.InsecureTLS)
	allOK := true
	for _, s := range p.Steps {
		sr := ApplyStepResult{Op: "remove", Path: s.Path}
		// Ownership check: GET the object first.
		gstatus, gbody, gerr := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, http.MethodGet, s.Path, "")
		if gerr != nil {
			allOK = false
			sr.Note = "unreachable: " + friendlyNetErr(gerr)
			rep.Steps = append(rep.Steps, sr)
			continue
		}
		if gstatus == http.StatusNotFound {
			sr.OK = true
			sr.Status = gstatus
			sr.Note = "already absent"
			rep.Steps = append(rep.Steps, sr)
			continue
		}
		if !is2xx(gstatus) {
			allOK = false
			sr.Status = gstatus
			sr.Note = fmt.Sprintf("ownership check inconclusive (HTTP %d) — not deleting", gstatus)
			rep.Steps = append(rep.Steps, sr)
			continue
		}
		if !ownedBy(gbody, p.OwnerTag) {
			// A foreign object occupies this key — DO NOT delete it.
			sr.Status = gstatus
			sr.Note = "foreign object (not tagged " + p.OwnerTag + ") — not removed"
			rep.Steps = append(rep.Steps, sr)
			continue
		}
		// Owned → delete. 404 (raced/already gone) counts as success.
		dstatus, _, derr := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, http.MethodDelete, s.Path, "")
		sr.Status = dstatus
		if derr != nil {
			allOK = false
			sr.Note = "delete failed: " + friendlyNetErr(derr)
		} else if is2xx(dstatus) || dstatus == http.StatusNotFound {
			sr.OK = true
		} else {
			allOK = false
			sr.Note = fmt.Sprintf("delete returned HTTP %d", dstatus)
		}
		rep.Steps = append(rep.Steps, sr)
	}
	rep.Applied = allOK
	if !allOK {
		rep.Error = "one or more objects could not be removed — see steps"
	}
	return rep
}

// ownedBy reports whether a FortiOS cmdb GET body describes an object tagged for
// this tunnel. FortiOS wraps a single-mkey GET as {"results":[{...}]}; the tag
// lives in comment (routes), comments (policies), or the object name/mkey
// (phase1/phase2 are named after the tunnel). The comparison is exact on
// comment/comments and exact-or-prefix on name ("fwm-t7" owns "fwm-t7-out").
func ownedBy(body []byte, tag string) bool {
	if tag == "" {
		return false
	}
	obj, ok := fortiResult(body)
	if !ok {
		return false // unparseable → fail safe, do not delete
	}
	for _, k := range []string{"comment", "comments"} {
		if s, ok := obj[k].(string); ok && s == tag {
			return true
		}
	}
	if n, ok := obj["name"].(string); ok {
		if n == tag || (len(n) > len(tag) && n[:len(tag)] == tag && n[len(tag)] == '-') {
			return true
		}
	}
	return false
}

// fortiResult extracts the first object from a FortiOS cmdb GET envelope. Handles
// results as an array ([{...}]) or a bare object ({...}); returns ok=false when
// neither parses.
func fortiResult(body []byte) (map[string]any, bool) {
	var env struct {
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Results) == 0 {
		return nil, false
	}
	var arr []map[string]any
	if err := json.Unmarshal(env.Results, &arr); err == nil {
		if len(arr) == 0 {
			return nil, false
		}
		return arr[0], true
	}
	var obj map[string]any
	if err := json.Unmarshal(env.Results, &obj); err == nil {
		return obj, true
	}
	return nil, false
}

// Summary renders a one-line human status for the command log (no secrets).
func (r ApplyReport) Summary() string {
	return fmt.Sprintf("op=%s end=%d vendor=%s applied=%t verified=%t aborted=%t conflict=%t",
		r.Op, r.End, r.Vendor, r.Applied, r.Verified, r.Aborted, r.Conflict)
}
