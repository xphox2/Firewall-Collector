package fwapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// applyFortiGate is a stateful fake FortiGate cmdb: POST/PUT create objects,
// GET reflects presence, DELETE removes them. Objects are keyed by request path
// (for creates, the collision GET path the collector checks). It requires Bearer
// "good".
type applyFortiGate struct {
	mu      sync.Mutex
	objects map[string]string // collision-GET path -> JSON body (envelope inner)
	srv     *httptest.Server
	// forceStatus, when set for a path+method, overrides the response status.
	failWrite string // a write path that should return 500
}

func newApplyFortiGate(t *testing.T) *applyFortiGate {
	t.Helper()
	f := &applyFortiGate{objects: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		switch r.Method {
		case http.MethodGet:
			if p == "/api/v2/monitor/system/status" {
				_, _ = w.Write([]byte(`{"version":"v7.6.7"}`))
				return
			}
			if body, ok := f.objects[p]; ok {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"results":[` + body + `]}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost, http.MethodPut:
			if f.failWrite != "" && p == f.failWrite {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// A POST to a table creates the object at its mkey collision path; for
			// this fake we register presence at the SAME collision paths the test's
			// CollisionSteps use (the test wires them to match).
			for _, cp := range collisionForWrite(p) {
				f.objects[cp] = `{"name":"fwm-t7","comment":"fwm-t7","comments":"fwm-t7"}`
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			delete(f.objects, p)
			w.WriteHeader(http.StatusOK)
		}
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// collisionForWrite maps a write path to the collision-GET path(s) it should make
// present. For phase1/phase2/interface the GET-by-mkey path equals the object's
// own path; for table POSTs (route/policy) the collision path is the mkey path.
// The tests below use GET-by-mkey paths for everything, so a write registers its
// own path.
func collisionForWrite(writePath string) []string {
	return []string{writePath}
}

func applyPayload(base string, steps []ApplyStep, collision []PreflightStep) ApplyPayload {
	return ApplyPayload{
		TunnelID: 7, TunnelName: "fwm-t7", End: 0, Vendor: "fortigate",
		DeviceID: 1001, BaseURL: base, APIToken: "good", InsecureTLS: true,
		OwnerTag: "fwm-t7", Op: "apply",
		Steps:          steps,
		Checksum:       "", // set by caller
		CollisionSteps: collision,
	}
}

// For simplicity the tests use collision GET paths that equal the write paths, so
// a successful write flips them present and verify sees them.
func fixtureApply() ([]ApplyStep, []PreflightStep) {
	steps := []ApplyStep{
		{Kind: "http_api", Method: "POST", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7", Body: `{"name":"fwm-t7"}`},
		{Kind: "http_api", Method: "POST", Path: "/api/v2/cmdb/router/static/40000", Body: `{"seq-num":40000}`},
	}
	collision := []PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"},
		{Check: "phase1", Method: "GET", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7", ExpectAbsent: true},
		{Check: "route", Method: "GET", Path: "/api/v2/cmdb/router/static/40000", ExpectAbsent: true},
	}
	return steps, collision
}

func TestRunApply_HappyPath(t *testing.T) {
	f := newApplyFortiGate(t)
	steps, coll := fixtureApply()
	p := applyPayload(f.srv.URL, steps, coll)
	p.Checksum = checksumSteps(steps)

	rep := RunApply(context.Background(), p)
	if rep.Aborted {
		t.Fatalf("unexpected abort: %+v", rep)
	}
	if !rep.Applied || !rep.Verified {
		t.Fatalf("want applied+verified, got applied=%t verified=%t err=%q", rep.Applied, rep.Verified, rep.Error)
	}
}

func TestRunApply_ChecksumMismatch_NoWrite(t *testing.T) {
	f := newApplyFortiGate(t)
	steps, coll := fixtureApply()
	p := applyPayload(f.srv.URL, steps, coll)
	p.Checksum = "deadbeef" // wrong

	rep := RunApply(context.Background(), p)
	if !rep.Aborted || rep.Applied {
		t.Fatalf("checksum mismatch must abort with no write: %+v", rep)
	}
	f.mu.Lock()
	n := len(f.objects)
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("no object should have been written, got %d", n)
	}
}

func TestRunApply_CollisionPrecheck_Aborts(t *testing.T) {
	f := newApplyFortiGate(t)
	steps, coll := fixtureApply()
	// Pre-seed the phase1 object so the precheck sees a collision.
	f.objects["/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7"] = `{"name":"fwm-t7"}`
	p := applyPayload(f.srv.URL, steps, coll)
	p.Checksum = checksumSteps(steps)

	rep := RunApply(context.Background(), p)
	if !rep.Aborted || rep.Applied {
		t.Fatalf("collision must abort before writing: %+v", rep)
	}
	if !rep.Conflict || len(rep.Collisions) == 0 {
		t.Errorf("want conflict + named collisions, got %+v", rep)
	}
}

func TestRunApply_IndeterminatePrecheck_Aborts(t *testing.T) {
	// A collision GET returning 403 is indeterminate → fail-safe abort.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/monitor/system/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"v7.6.7"}`))
	})
	mux.HandleFunc("/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	steps := []ApplyStep{{Kind: "http_api", Method: "POST", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7", Body: `{}`}}
	coll := []PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"},
		{Check: "phase1", Method: "GET", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7", ExpectAbsent: true},
	}
	p := applyPayload(srv.URL, steps, coll)
	p.Checksum = checksumSteps(steps)

	rep := RunApply(context.Background(), p)
	if !rep.Aborted {
		t.Fatalf("indeterminate precheck must abort: %+v", rep)
	}
}

func TestRunApply_MidSequenceFailure_Stops(t *testing.T) {
	f := newApplyFortiGate(t)
	steps, coll := fixtureApply()
	f.failWrite = "/api/v2/cmdb/router/static/40000" // the 2nd write 500s
	p := applyPayload(f.srv.URL, steps, coll)
	p.Checksum = checksumSteps(steps)

	rep := RunApply(context.Background(), p)
	if rep.Applied {
		t.Fatalf("a mid-sequence 500 must not report applied: %+v", rep)
	}
	if rep.Error == "" {
		t.Errorf("want an error describing the failed write")
	}
}

func TestRunRemove_OwnershipGuard(t *testing.T) {
	f := newApplyFortiGate(t)
	// One owned object (tagged fwm-t7) and one FOREIGN object (different tag) at a
	// path the remove will target.
	ownedPath := "/api/v2/cmdb/router/static/40000"
	foreignPath := "/api/v2/cmdb/firewall/policy/40100"
	f.objects[ownedPath] = `{"seq-num":40000,"comment":"fwm-t7"}`
	f.objects[foreignPath] = `{"policyid":40100,"comments":"operator-owned"}`

	steps := []ApplyStep{
		{Kind: "http_api", Method: "DELETE", Path: foreignPath},
		{Kind: "http_api", Method: "DELETE", Path: ownedPath},
	}
	p := ApplyPayload{
		TunnelID: 7, TunnelName: "fwm-t7", Vendor: "fortigate", DeviceID: 1001,
		BaseURL: f.srv.URL, APIToken: "good", InsecureTLS: true, OwnerTag: "fwm-t7", Op: "remove",
		Steps: steps, Checksum: checksumSteps(steps),
	}
	rep := RunRemove(context.Background(), p)

	f.mu.Lock()
	_, foreignStill := f.objects[foreignPath]
	_, ownedGone := f.objects[ownedPath]
	f.mu.Unlock()
	if !foreignStill {
		t.Errorf("foreign object must NOT be deleted")
	}
	if ownedGone {
		t.Errorf("owned object should have been deleted")
	}
	// The foreign skip is LISTED (operator sees it) but does NOT fail the rollback —
	// our footprint was fully removed, so leaving a foreign object at our key must
	// not make the tunnel unrecoverable.
	var sawForeignSkip bool
	for _, s := range rep.Steps {
		if s.Path == foreignPath && strings.Contains(s.Note, "foreign") {
			sawForeignSkip = true
		}
	}
	if !sawForeignSkip {
		t.Errorf("expected a 'foreign object' skip note for %s, got %+v", foreignPath, rep.Steps)
	}
	if !rep.Applied {
		t.Errorf("rollback that removed our object and skipped a foreign one must report Applied=true (recoverable), got %+v", rep)
	}
}

func TestRunRemove_404Tolerant(t *testing.T) {
	f := newApplyFortiGate(t)
	// Nothing seeded → every GET 404s → treated as already-absent success.
	steps := []ApplyStep{{Kind: "http_api", Method: "DELETE", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7"}}
	p := ApplyPayload{
		TunnelID: 7, TunnelName: "fwm-t7", Vendor: "fortigate", DeviceID: 1001,
		BaseURL: f.srv.URL, APIToken: "good", InsecureTLS: true, OwnerTag: "fwm-t7", Op: "remove",
		Steps: steps, Checksum: checksumSteps(steps),
	}
	rep := RunRemove(context.Background(), p)
	if !rep.Applied {
		t.Fatalf("a 404 (already gone) must count as success: %+v", rep)
	}
}

func TestRunRemove_ChecksumMismatch_NoDelete(t *testing.T) {
	f := newApplyFortiGate(t)
	f.objects["/api/v2/cmdb/router/static/40000"] = `{"comment":"fwm-t7"}`
	steps := []ApplyStep{{Kind: "http_api", Method: "DELETE", Path: "/api/v2/cmdb/router/static/40000"}}
	p := ApplyPayload{
		TunnelID: 7, TunnelName: "fwm-t7", Vendor: "fortigate", DeviceID: 1001,
		BaseURL: f.srv.URL, APIToken: "good", InsecureTLS: true, OwnerTag: "fwm-t7", Op: "remove",
		Steps: steps, Checksum: "wrong",
	}
	rep := RunRemove(context.Background(), p)
	if !rep.Aborted {
		t.Fatalf("checksum mismatch must abort remove: %+v", rep)
	}
	f.mu.Lock()
	_, still := f.objects["/api/v2/cmdb/router/static/40000"]
	f.mu.Unlock()
	if !still {
		t.Errorf("object must NOT be deleted on checksum mismatch")
	}
}

func TestRunApply_RejectsNonFortiGateAtHandler(t *testing.T) {
	// The vendor gate lives in the collector command handler, but assert the
	// ownedBy/parse helpers are FortiGate-shaped and don't false-positive on a
	// bare object.
	if ownedBy([]byte(`{"results":[{"name":"other"}]}`), "fwm-t7") {
		t.Error("ownedBy must not match a foreign name")
	}
	if !ownedBy([]byte(`{"results":[{"comment":"fwm-t7"}]}`), "fwm-t7") {
		t.Error("ownedBy must match on comment")
	}
	if !ownedBy([]byte(`{"results":[{"name":"fwm-t7-out"}]}`), "fwm-t7") {
		t.Error("ownedBy must match name prefix fwm-t7-*")
	}
	if ownedBy([]byte(`not json`), "fwm-t7") {
		t.Error("unparseable body must be treated as NOT owned (fail-safe)")
	}
}

// TestChecksumSteps_ParityWithServer pins the exact hash for a fixed step set.
// The server's ipsec package has an identical pin (same input → same hash), so a
// change to the serialization on either side breaks one of the two tests — the
// collector MUST recompute the same checksum the server sent or every write is
// refused.
func TestChecksumSteps_ParityWithServer(t *testing.T) {
	steps := []ApplyStep{
		{Kind: "http_api", Method: "POST", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface", Body: `{"name":"fwm-t7"}`},
		{Kind: "http_api", Method: "DELETE", Path: "/api/v2/cmdb/router/static/40000"},
	}
	const want = "c55b02d2f55baad85110bd051d22a479dd2402e9ec8fd0191cdee90996c6b820"
	if got := checksumSteps(steps); got != want {
		t.Fatalf("checksum = %s, want %s (server/collector serialization drifted)", got, want)
	}
}

// TestWriteOK_Verdicts pins the write-verdict truth table, including the
// fail-safe flip: an unparseable OPNsense 2xx body is NOT a success (the
// device's write endpoints always answer with a JSON verdict, so no verdict =
// unknown outcome = failure).
func TestWriteOK_Verdicts(t *testing.T) {
	cases := []struct {
		name   string
		vendor string
		status int
		body   string
		want   bool
	}{
		{"fortigate 2xx any body", "fortigate", 200, `whatever`, true},
		{"fortigate non-2xx", "fortigate", 500, ``, false},
		{"opnsense saved", "opnsense", 200, `{"result":"saved","uuid":"x"}`, true},
		{"opnsense deleted", "opnsense", 200, `{"result":"deleted"}`, true},
		{"opnsense not found (idempotent)", "opnsense", 200, `{"result":"not found"}`, true},
		{"opnsense reconfigure ok", "opnsense", 200, `{"status":"ok"}`, true},
		{"opnsense result failed", "opnsense", 200, `{"result":"failed","validations":{"x":"bad"}}`, false},
		{"opnsense status failed", "opnsense", 200, `{"status":"failed"}`, false},
		{"opnsense non-empty validations", "opnsense", 200, `{"result":"saved","validations":{"f":"bad"}}`, false},
		{"opnsense unparseable 2xx = NOT ok", "opnsense", 200, `<html>proxy error</html>`, false},
		{"opnsense truncated json 2xx = NOT ok", "opnsense", 200, `{"result":"sa`, false},
		{"opnsense non-2xx", "opnsense", 500, `{"result":"saved"}`, false},
	}
	for _, tc := range cases {
		if got := writeOK(tc.vendor, tc.status, []byte(tc.body)); got != tc.want {
			t.Errorf("%s: writeOK(%s, %d) = %v, want %v", tc.name, tc.vendor, tc.status, got, tc.want)
		}
	}
}

// TestApplyReport_CompactAtMaxSubnets proves a fully-successful apply at the
// server's maximum 49 protected subnets (~300 write steps + ~100 collision GETs)
// produces a report well under the server's result-size cap — the verbose
// per-step form used to blow the 10 KB cap around 18 subnets and truncate to
// invalid JSON.
func TestApplyReport_CompactAtMaxSubnets(t *testing.T) {
	f := newApplyFortiGate(t)
	const n = 49
	var steps []ApplyStep
	var coll []PreflightStep
	coll = append(coll, PreflightStep{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"})
	for i := 0; i < n*2+2; i++ { // routes(2N) + 2 policies
		p := "/api/v2/cmdb/router/static/" + strconv.Itoa(40000+i)
		steps = append(steps, ApplyStep{Kind: "http_api", Method: "POST", Path: p, Body: `{"seq-num":1}`})
		coll = append(coll, PreflightStep{Check: "route", Method: "GET", Path: p, ExpectAbsent: true})
	}
	p := applyPayload(f.srv.URL, steps, coll)
	p.Checksum = checksumSteps(steps)

	rep := RunApply(context.Background(), p)
	if !rep.Applied || !rep.Verified {
		t.Fatalf("want applied+verified, got %+v (err=%q)", rep, rep.Error)
	}
	blob, _ := json.Marshal(rep)
	if len(blob) > 8000 {
		t.Fatalf("report is %d bytes at %d subnets — must stay compact (well under the 64KB cap)", len(blob), n)
	}
	if rep.StepsTotal < n {
		t.Errorf("StepsTotal=%d, want the step count recorded", rep.StepsTotal)
	}
	if len(rep.Steps) != 0 {
		t.Errorf("a fully-successful apply must list 0 non-OK steps, got %d", len(rep.Steps))
	}
}
