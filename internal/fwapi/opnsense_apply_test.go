package fwapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeOPNsense models the MVC apply plane: add* returns {"result":"saved",
// "uuid":…} and marks the object's description present for its search endpoint;
// search* returns rows so the collision precheck (absent before) / verify
// (present after) work; reconfigure/apply returns {"status":"ok"}; del*/<uuid>
// returns {"result":"deleted"} (or {"result":"not found"} if unknown). Requires
// basic auth key:secret.
type fakeOPNsense struct {
	mu      sync.Mutex
	present map[string]bool   // search path -> description present
	byUUID  map[string]string // uuid -> search path it belongs to (for del)
	seq     int
	srv     *httptest.Server
	desc    string
	failAdd string // an add path that returns result:failed
}

var addToSearch = map[string]string{
	"/api/ipsec/connections/addConnection": "/api/ipsec/connections/searchConnection",
	"/api/ipsec/pre_shared_keys/addItem":   "/api/ipsec/pre_shared_keys/searchItem",
	"/api/interfaces/vti_settings/addItem": "/api/interfaces/vti_settings/searchItem",
	"/api/routing/settings/addGateway":     "/api/routing/settings/searchGateway",
	"/api/routes/routes/addroute":          "/api/routes/routes/searchroute",
	"/api/firewall/filter/addRule":         "/api/firewall/filter/searchRule",
}

func newFakeOPNsense(t *testing.T, desc string) *fakeOPNsense {
	t.Helper()
	f := &fakeOPNsense{present: map[string]bool{}, byUUID: map[string]string{}, desc: desc}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "key" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch {
		case p == "/api/core/firmware/status":
			_, _ = w.Write([]byte(`{"product_version":"26.1"}`))
		case strings.Contains(p, "/search"):
			if f.present[p] {
				_, _ = w.Write([]byte(`{"rows":[{"description":"` + f.desc + `","uuid":"x"}],"total":1}`))
			} else {
				_, _ = w.Write([]byte(`{"rows":[],"total":0}`))
			}
		case strings.HasSuffix(p, "/reconfigure") || strings.HasSuffix(p, "/apply"):
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case strings.Contains(p, "/add"):
			if f.failAdd != "" && p == f.failAdd {
				_, _ = w.Write([]byte(`{"result":"failed","validations":{"x":"bad"}}`))
				return
			}
			f.seq++
			uuid := fmt.Sprintf("%08d-0000-4000-8000-000000000000", f.seq)
			if sp, ok := addToSearch[p]; ok {
				f.present[sp] = true
				f.byUUID[uuid] = sp
			}
			_, _ = w.Write([]byte(`{"result":"saved","uuid":"` + uuid + `"}`))
		case strings.Contains(p, "/del"):
			// path = /.../delX/<uuid>
			parts := strings.Split(p, "/")
			uuid := parts[len(parts)-1]
			if sp, ok := f.byUUID[uuid]; ok {
				delete(f.present, sp)
				delete(f.byUUID, uuid)
				_, _ = w.Write([]byte(`{"result":"deleted"}`))
			} else {
				_, _ = w.Write([]byte(`{"result":"not found"}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// opnsenseApplyFixture is a minimal 1-subnet OPNsense apply: connection (+conn
// capture) → local/remote/child (reference <uuid:conn>) → psk → vti → gw → route
// → rule → per-subsystem reconfigure. Collision/verify search the full footprint.
func opnsenseApplyFixture(base string) ApplyPayload {
	step := func(desc, path, body, cap string) ApplyStep {
		return ApplyStep{Kind: "http_api", Description: desc, Method: "POST", Path: path, Body: body, CaptureAs: cap}
	}
	steps := []ApplyStep{
		step("conn", "/api/ipsec/connections/addConnection", `{"connection":{"description":"fwm-t7"}}`, "conn"),
		step("local", "/api/ipsec/connections/addLocal", `{"local":{"connection":"<uuid:conn>"}}`, "local"),
		step("remote", "/api/ipsec/connections/addRemote", `{"remote":{"connection":"<uuid:conn>"}}`, "remote"),
		step("child", "/api/ipsec/connections/addChild", `{"child":{"connection":"<uuid:conn>"}}`, "child"),
		step("psk", "/api/ipsec/pre_shared_keys/addItem", `{"preSharedKey":{"Key":"secretpsk"}}`, "psk"),
		step("vti", "/api/interfaces/vti_settings/addItem", `{"vti":{"description":"fwm-t7"}}`, "vti"),
		step("gw", "/api/routing/settings/addGateway", `{"gateway":{"description":"fwm-t7"}}`, "gw"),
		step("route", "/api/routes/routes/addroute", `{"route":{"description":"fwm-t7"}}`, "route0"),
		step("rule", "/api/firewall/filter/addRule", `{"rule":{"description":"fwm-t7"}}`, "rule0"),
		{Kind: "http_api", Description: "apply ipsec", Method: "POST", Path: "/api/ipsec/connections/reconfigure", Body: "{}"},
	}
	coll := []PreflightStep{
		{Check: "auth", Method: "GET", Path: "/api/core/firmware/status"},
		{Check: "connection", Method: "GET", Path: "/api/ipsec/connections/searchConnection", ExpectAbsent: true},
		{Check: "psk", Method: "GET", Path: "/api/ipsec/pre_shared_keys/searchItem", ExpectAbsent: true},
		{Check: "vti", Method: "GET", Path: "/api/interfaces/vti_settings/searchItem", ExpectAbsent: true},
		{Check: "gateway", Method: "GET", Path: "/api/routing/settings/searchGateway", ExpectAbsent: true},
		{Check: "route", Method: "GET", Path: "/api/routes/routes/searchroute", ExpectAbsent: true},
		{Check: "rule", Method: "GET", Path: "/api/firewall/filter/searchRule", ExpectAbsent: true},
	}
	return ApplyPayload{
		TunnelID: 7, TunnelName: "fwm-t7", End: 1, Vendor: "opnsense", DeviceID: 1002,
		BaseURL: base, APIToken: "key:secret", InsecureTLS: true, Op: "apply",
		Steps: steps, Checksum: checksumSteps(steps), CollisionSteps: coll,
	}
}

func TestOPNsenseApply_HappyPath_CapturesAndVerifies(t *testing.T) {
	f := newFakeOPNsense(t, "fwm-t7")
	p := opnsenseApplyFixture(f.srv.URL)
	rep := RunApply(context.Background(), p)
	if rep.Aborted || !rep.Applied || !rep.Verified {
		t.Fatalf("want applied+verified, got %+v", rep)
	}
	for _, name := range []string{"conn", "local", "remote", "child", "psk", "vti", "gw", "route0", "rule0"} {
		if _, ok := rep.CapturedUUIDs[name]; !ok {
			t.Errorf("missing captured uuid for %q: %+v", name, rep.CapturedUUIDs)
		}
	}
}

func TestOPNsenseApply_ChildBodyGetsSubstitutedUUID(t *testing.T) {
	// The child steps must reach the device with the REAL conn uuid, not the
	// <uuid:conn> placeholder.
	var childBodies []string
	var mu sync.Mutex
	mux := http.NewServeMux()
	seq := 0
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case p == "/api/core/firmware/status":
			_, _ = w.Write([]byte(`{"product_version":"26.1"}`))
		case strings.Contains(p, "/search"):
			_, _ = w.Write([]byte(`{"rows":[],"total":0}`)) // never present (precheck only in this test)
		case strings.HasSuffix(p, "/reconfigure"):
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case strings.Contains(p, "addLocal") || strings.Contains(p, "addRemote") || strings.Contains(p, "addChild"):
			b := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(b)
			childBodies = append(childBodies, string(b))
			seq++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"result":"saved","uuid":"%08d-0000-4000-8000-000000000000"}`, seq)))
		case strings.Contains(p, "/add"):
			seq++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"result":"saved","uuid":"%08d-0000-4000-8000-000000000000"}`, seq)))
		default:
			_, _ = w.Write([]byte(`{"result":"saved","uuid":"00000009-0000-4000-8000-000000000000"}`))
		}
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	p := opnsenseApplyFixture(srv.URL)
	// Only run apply far enough to send the children; verify will fail (search
	// empty) but that doesn't matter for this assertion.
	_ = RunApply(context.Background(), p)
	if len(childBodies) != 3 {
		t.Fatalf("want 3 child bodies, got %d", len(childBodies))
	}
	for _, b := range childBodies {
		if strings.Contains(b, "<uuid:conn>") {
			t.Errorf("child body still has the placeholder: %s", b)
		}
		if !strings.Contains(b, "00000001-0000-4000-8000-000000000000") {
			t.Errorf("child body missing the substituted conn uuid: %s", b)
		}
	}
}

func TestOPNsenseApply_ResultFailed_NotApplied(t *testing.T) {
	f := newFakeOPNsense(t, "fwm-t7")
	f.failAdd = "/api/interfaces/vti_settings/addItem" // the VTI create 200s with result:failed
	p := opnsenseApplyFixture(f.srv.URL)
	rep := RunApply(context.Background(), p)
	if rep.Applied {
		t.Fatalf("a 200 {result:failed} must NOT be applied: %+v", rep)
	}
	if rep.Aborted {
		t.Errorf("a mid-write failure is not a pre-write abort")
	}
}

func TestOPNsenseApply_MissingUUID_WriteFailureNotAbort(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/core/firmware/status":
			_, _ = w.Write([]byte(`{"product_version":"26.1"}`))
		case strings.Contains(r.URL.Path, "/search"):
			_, _ = w.Write([]byte(`{"rows":[],"total":0}`))
		default:
			_, _ = w.Write([]byte(`{"result":"saved"}`)) // saved but NO uuid
		}
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	p := opnsenseApplyFixture(srv.URL)
	rep := RunApply(context.Background(), p)
	if rep.Applied {
		t.Fatalf("a CaptureAs step returning no uuid must fail: %+v", rep)
	}
	if rep.Aborted {
		t.Errorf("a create-without-uuid is a write failure, not a pre-write abort")
	}
}

func TestOPNsenseRemove_ByUUID_Idempotent_And_SkipUnresolved(t *testing.T) {
	f := newFakeOPNsense(t, "fwm-t7")
	// Seed one object present (a route) with a known uuid; leave others absent.
	f.present["/api/routes/routes/searchroute"] = true
	const routeUUID = "00000001-0000-4000-8000-000000000000"
	f.byUUID[routeUUID] = "/api/routes/routes/searchroute"

	del := func(desc, path string) ApplyStep {
		return ApplyStep{Kind: "http_api", Description: desc, Method: "POST", Path: path}
	}
	steps := []ApplyStep{
		del("del route", "/api/routes/routes/delroute/<uuid:route0>"),
		del("del gw (never created)", "/api/routing/settings/delGateway/<uuid:gw>"),
		{Kind: "http_api", Description: "apply", Method: "POST", Path: "/api/ipsec/connections/reconfigure", Body: "{}"},
	}
	p := ApplyPayload{
		TunnelID: 7, TunnelName: "fwm-t7", Vendor: "opnsense", DeviceID: 1002,
		BaseURL: f.srv.URL, APIToken: "key:secret", InsecureTLS: true, Op: "remove",
		Steps: steps, Checksum: checksumSteps(steps),
		Substitutions: map[string]string{"route0": routeUUID}, // gw has NO mapping → skip
	}
	rep := RunRemove(context.Background(), p)
	if !rep.Applied {
		t.Fatalf("remove should succeed (route deleted, gw skipped, reconfigure ok): %+v", rep)
	}
	f.mu.Lock()
	_, routeStill := f.byUUID[routeUUID]
	f.mu.Unlock()
	if routeStill {
		t.Errorf("route should have been deleted by uuid")
	}
	// The unresolved gw step (no mapping) must be skipped as success, not fail the
	// rollback — it counts toward StepsOK/StepsTotal, not the listed failures.
	if len(rep.Steps) != 0 {
		t.Errorf("a clean remove (delete + skip + reconfigure) should list no failures, got %+v", rep.Steps)
	}
	if rep.StepsTotal != 3 {
		t.Errorf("StepsTotal = %d, want 3 (route delete + gw skip + reconfigure)", rep.StepsTotal)
	}
	// A second remove (idempotent) — route now unknown → 200 not-found → success.
	rep2 := RunRemove(context.Background(), p)
	if !rep2.Applied {
		t.Errorf("idempotent re-remove must succeed (not found = deleted): %+v", rep2)
	}
}

func TestOPNsenseRemove_ChecksumOnPlaceholderForm(t *testing.T) {
	// The checksum is over the placeholder-form steps (what the server rendered);
	// substitution happens after verify. A wrong checksum aborts with no delete.
	f := newFakeOPNsense(t, "fwm-t7")
	steps := []ApplyStep{{Kind: "http_api", Method: "POST", Path: "/api/routes/routes/delroute/<uuid:route0>"}}
	p := ApplyPayload{
		Vendor: "opnsense", BaseURL: f.srv.URL, APIToken: "key:secret", InsecureTLS: true, Op: "remove",
		Steps: steps, Checksum: "wrong", Substitutions: map[string]string{"route0": "x"},
	}
	rep := RunRemove(context.Background(), p)
	if !rep.Aborted {
		t.Fatalf("checksum mismatch must abort the remove: %+v", rep)
	}
}
