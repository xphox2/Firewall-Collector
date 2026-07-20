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
	"regexp"
	"strings"
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
	// CaptureAs names the token bound to this create's device-assigned uuid (see
	// the server's ipsec.ApplyStep). NOT part of checksumSteps.
	CaptureAs string `json:"capture_as,omitempty"`
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
	// Substitutions resolves <uuid:NAME> tokens for a REMOVE (the UUIDs captured
	// when the tunnel was applied, stored server-side). Empty for apply (captured
	// live) and for FortiGate (no tokens).
	Substitutions map[string]string `json:"substitutions,omitempty"`
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
//
// It is COMPACT by design: only NON-OK steps are listed (failures/skips/
// collisions), while successful steps are counted in StepsOK/StepsTotal. A fully
// successful deploy — even at the maximum 49 protected subnets (~300 steps) —
// therefore produces a tiny report that stays well under the server's result
// size cap; without this, the verbose per-step form crossed the cap around 18
// subnets, got truncated to invalid JSON, and made a healthy deploy read as an
// error. Listed steps and collisions are additionally hard-capped.
type ApplyReport struct {
	Vendor       string            `json:"vendor"`
	End          int               `json:"end"`
	DeviceID     uint              `json:"device_id"`
	Op           string            `json:"op"`
	Applied      bool              `json:"applied"`  // all write steps returned 2xx
	Verified     bool              `json:"verified"` // post-write objects confirmed present
	Aborted      bool              `json:"aborted"`  // refused BEFORE any write (checksum/collision/auth)
	Conflict     bool              `json:"conflict"` // a pre-existing colliding object was found
	Collisions   []string          `json:"collisions,omitempty"`
	StepsOK      int               `json:"steps_ok"`
	StepsTotal   int               `json:"steps_total"`
	StepsOmitted int               `json:"steps_omitted,omitempty"` // non-OK steps beyond the cap
	Steps        []ApplyStepResult `json:"steps"`                   // NON-OK steps only (capped)
	Error        string            `json:"error,omitempty"`
	// CapturedUUIDs maps each <uuid:NAME> token to the device-assigned UUID read
	// from a CaptureAs step's response during apply (OPNsense; empty for FortiGate).
	// The server persists these so a later rollback can delete what was created.
	CapturedUUIDs map[string]string `json:"captured_uuids,omitempty"`
}

// report bounds so a worst-case (all-failing) report can't blow the result cap.
const (
	maxReportSteps      = 40
	maxReportCollisions = 40
)

// record counts every step and lists only the non-OK ones (capped). Successful
// steps — including a remove's "already absent" — are counted, never listed.
func (r *ApplyReport) record(sr ApplyStepResult) {
	r.StepsTotal++
	if sr.OK {
		r.StepsOK++
		return
	}
	if len(r.Steps) < maxReportSteps {
		r.Steps = append(r.Steps, sr)
	} else {
		r.StepsOmitted++
	}
}

// addCollision records a colliding object path, capped.
func (r *ApplyReport) addCollision(path string) {
	r.Conflict = true
	if len(r.Collisions) < maxReportCollisions {
		r.Collisions = append(r.Collisions, path)
	}
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

// tokenRe matches a <uuid:NAME> placeholder; uuidRe validates a captured value
// before it is spliced into a subsequent request (bounds a hostile/garbled
// device response — F7). OPNsense UUIDs are RFC-4122 lowercase.
var (
	tokenRe = regexp.MustCompile(`<uuid:([a-zA-Z0-9_]+)>`)
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// substitute replaces every <uuid:NAME> in s from m; the second return lists any
// token with no mapping (caller decides: apply-time = error, remove-time = skip).
func substitute(s string, m map[string]string) (string, []string) {
	var unresolved []string
	out := tokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		name := tokenRe.FindStringSubmatch(tok)[1]
		if v, ok := m[name]; ok {
			return v
		}
		unresolved = append(unresolved, name)
		return tok
	})
	return out, unresolved
}

// writeOK decides whether a write/delete/apply step succeeded. FortiGate cmdb =
// HTTP 2xx. OPNsense returns 200 EVEN ON validation failure, so its body must be
// inspected: a create is `{"result":"saved","uuid":…}`, a delete `{"result":
// "deleted"}` or the idempotent `{"result":"not found"}`, a reconfigure
// `{"status":"ok"}`; a failure is `{"result":"failed","validations":{…}}` or
// `{"status":"failed"}`.
func writeOK(vendor string, status int, body []byte) bool {
	if !is2xx(status) {
		return false
	}
	if vendor != "opnsense" {
		return true
	}
	var r struct {
		Result      string          `json:"result"`
		Status      string          `json:"status"`
		Validations json.RawMessage `json:"validations"`
	}
	if json.Unmarshal(body, &r) != nil {
		return true // a 2xx we can't parse — rare; don't manufacture a failure
	}
	if strings.EqualFold(r.Result, "failed") || strings.EqualFold(r.Result, "error") {
		return false
	}
	if strings.EqualFold(r.Status, "failed") || strings.EqualFold(r.Status, "error") {
		return false
	}
	if v := strings.TrimSpace(string(r.Validations)); v != "" && v != "null" && v != "{}" && v != "[]" {
		return false
	}
	return true
}

// opnsenseResult extracts the short result/status token from an OPNsense response
// body for a compact error note (never includes bodies/secrets).
func opnsenseResult(body []byte) string {
	var r struct {
		Result string `json:"result"`
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &r) != nil {
		return "unparseable"
	}
	if r.Result != "" {
		return "result=" + r.Result
	}
	if r.Status != "" {
		return "status=" + r.Status
	}
	return "no result"
}

// captureUUID reads a created object's device-assigned uuid from an OPNsense
// response; the second return is false if absent or not a valid UUID.
func captureUUID(body []byte) (string, bool) {
	var r struct {
		UUID string `json:"uuid"`
	}
	if json.Unmarshal(body, &r) != nil || r.UUID == "" {
		return "", false
	}
	return r.UUID, uuidRe.MatchString(r.UUID)
}

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
			rep.record(sr)
			return rep
		}
		if cs.Check == "auth" {
			if !is2xx(status) {
				rep.Aborted = true
				rep.Error = fmt.Sprintf("authentication/reachability check failed (HTTP %d) — refusing to write", status)
				sr.Note = "auth failed"
				rep.record(sr)
				return rep
			}
			sr.OK = true
			rep.record(sr)
			continue
		}
		present, indeterminate := objectPresent(p.Vendor, status, body, p.TunnelName)
		switch {
		case cs.ExpectAbsent && present:
			rep.addCollision(cs.Path)
			sr.Note = "object already exists — not overwriting"
		case cs.ExpectAbsent && indeterminate:
			rep.Aborted = true
			rep.Error = fmt.Sprintf("collision check inconclusive (HTTP %d) — refusing to write; verify API-user read access / VDOM", status)
			sr.Note = "indeterminate"
			rep.record(sr)
			return rep
		default:
			sr.OK = true
		}
		rep.record(sr)
	}
	if rep.Conflict {
		rep.Aborted = true
		rep.Error = "one or more objects already exist on the device (see collisions) — roll back the existing deployment before re-deploying, or resolve the object on the device if it is not ours"
		return rep
	}

	// (3) Execute the ordered write steps; stop on the first failure. For UUID-
	// chained vendors, substitute <uuid:NAME> from the live capture map BEFORE
	// sending, and capture this step's returned uuid AFTER a success. A failure
	// after the first write leaves Aborted=false — the device MAY be partially
	// configured, which is a rollback case, not the "nothing written" abort.
	captured := map[string]string{}
	for _, s := range p.Steps {
		path, up := substitute(s.Path, captured)
		body, ub := substitute(s.Body, captured)
		sr := ApplyStepResult{Op: "apply", Path: path, Status: 0}
		if len(up)+len(ub) > 0 {
			sr.Note = fmt.Sprintf("unresolved uuid token(s) %v — chaining failed", append(up, ub...))
			rep.record(sr)
			rep.Error = "internal: " + sr.Note + " — the device MAY be partially configured; roll back"
			rep.CapturedUUIDs = captured
			return rep
		}
		status, respBody, err := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, s.Method, path, body)
		sr.Status = status
		if err != nil {
			sr.Note = friendlyNetErr(err)
			rep.record(sr)
			rep.Error = "write failed: " + friendlyNetErr(err) + " — the device MAY be partially configured; roll back"
			rep.CapturedUUIDs = captured
			return rep
		}
		sr.OK = writeOK(p.Vendor, status, respBody)
		if sr.OK && s.CaptureAs != "" {
			uuid, ok := captureUUID(respBody)
			if !ok {
				sr.OK = false
				sr.Note = "created but returned no valid uuid — cannot chain"
			} else {
				captured[s.CaptureAs] = uuid
			}
		}
		rep.record(sr)
		if !sr.OK {
			if sr.Note == "" {
				sr.Note = fmt.Sprintf("write step returned HTTP %d", status)
			}
			rep.Error = sr.Note + " — the device MAY be partially configured; roll back"
			rep.CapturedUUIDs = captured
			return rep
		}
	}
	rep.Applied = true
	rep.CapturedUUIDs = captured

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
			rep.record(sr)
			continue
		}
		present, _ := objectPresent(p.Vendor, status, body, p.TunnelName)
		sr.OK = present
		if !present {
			verified = false
			sr.Note = "expected object not found after write"
		}
		rep.record(sr)
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

	// OPNsense: delete by the UUID captured at apply time (substituted from the
	// server-stored map). No ownership GET is needed — we only ever delete UUIDs
	// WE created, so there is no foreign-object risk. A step whose token has no
	// stored UUID means that object was never created → SKIP (success). Reconfigure
	// steps carry no token and always run. Idempotent: OPNsense returns 200
	// {"result":"not found"} for an already-gone object (there is no 404).
	if p.Vendor == "opnsense" {
		allOK := true
		for _, s := range p.Steps {
			path, unresolved := substitute(s.Path, p.Substitutions)
			sr := ApplyStepResult{Op: "remove", Path: path}
			if len(unresolved) > 0 {
				sr.OK = true // object was never created — nothing to remove
				sr.Note = "not created — skipped"
				rep.record(sr)
				continue
			}
			status, body, err := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, s.Method, path, s.Body)
			sr.Status = status
			if err != nil {
				allOK = false
				sr.Note = "delete failed: " + friendlyNetErr(err)
			} else if writeOK(p.Vendor, status, body) {
				sr.OK = true
			} else {
				allOK = false
				sr.Note = fmt.Sprintf("delete returned HTTP %d / %s", status, opnsenseResult(body))
			}
			rep.record(sr)
		}
		rep.Applied = allOK
		if !allOK {
			rep.Error = "one or more objects could not be removed — see steps"
		}
		return rep
	}

	// FortiGate: ownership-guarded GET-before-DELETE by deterministic mkey.
	allOK := true
	for _, s := range p.Steps {
		sr := ApplyStepResult{Op: "remove", Path: s.Path}
		// Ownership check: GET the object first.
		gstatus, gbody, gerr := doRequest(ctx, client, p.Vendor, p.APIToken, p.BaseURL, http.MethodGet, s.Path, "")
		if gerr != nil {
			allOK = false
			sr.Note = "unreachable: " + friendlyNetErr(gerr)
			rep.record(sr)
			continue
		}
		if gstatus == http.StatusNotFound {
			sr.OK = true
			sr.Status = gstatus
			sr.Note = "already absent"
			rep.record(sr)
			continue
		}
		if !is2xx(gstatus) {
			allOK = false
			sr.Status = gstatus
			sr.Note = fmt.Sprintf("ownership check inconclusive (HTTP %d) — not deleting", gstatus)
			rep.record(sr)
			continue
		}
		if !ownedBy(gbody, p.OwnerTag) {
			// A foreign object occupies this key — DO NOT delete it. This is NOT a
			// rollback failure: our footprint at this key is absent (the foreign
			// object isn't ours), so removing OUR objects is complete. Flipping the
			// rollback to failed here would keep the deploy record and leave the
			// tunnel stuck (uneditable/undeletable, rollback repeating forever) after
			// a deploy that collision-aborted on a pre-existing foreign object. The
			// skip is still LISTED (so the operator sees the foreign object remains),
			// just not counted as a failure.
			sr.Status = gstatus
			sr.Note = "foreign object (not tagged " + p.OwnerTag + ") — left in place"
			rep.record(sr) // sr.OK is false → listed (operator sees it), allOK untouched
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
		rep.record(sr)
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
