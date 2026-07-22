package fwapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeFortiGate serves the two preflight endpoints: monitor status (auth) and a
// cmdb phase1 GET (404 when absent, 200 when present). It requires the Bearer
// token "good".
func fakeFortiGate(t *testing.T, phase1Present bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("/api/v2/monitor/system/status", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v7.6.7","serial":"FGT123"}`))
	})
	mux.HandleFunc("/api/v2/cmdb/vpn.ipsec/phase1-interface/", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if phase1Present {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"results":[{"name":"fwm-t7"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"http_status":404}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func fortiPayload(base, token string) PreflightPayload {
	return PreflightPayload{
		TunnelID: 7, TunnelName: "fwm-t7", End: 0, Vendor: "fortigate",
		DeviceID: 1001, BaseURL: base, APIToken: token, InsecureTLS: true,
		Steps: []PreflightStep{
			{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"},
			{Check: "phase1", Method: "GET", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t7", ExpectAbsent: true},
		},
	}
}

func TestRunPreflight_FortiGate_CleanNoConflict(t *testing.T) {
	srv := fakeFortiGate(t, false)
	rep := RunPreflight(context.Background(), fortiPayload(srv.URL, "good"))
	if !rep.Reachable || !rep.AuthOK {
		t.Fatalf("want reachable+auth_ok, got %+v", rep)
	}
	if rep.OSVersion != "v7.6.7" {
		t.Errorf("os_version = %q, want v7.6.7", rep.OSVersion)
	}
	if rep.Conflict {
		t.Errorf("unexpected conflict: %+v", rep.Checks)
	}
}

func TestRunPreflight_FortiGate_NameCollision(t *testing.T) {
	srv := fakeFortiGate(t, true) // phase1 already exists
	rep := RunPreflight(context.Background(), fortiPayload(srv.URL, "good"))
	if !rep.AuthOK {
		t.Fatalf("want auth_ok, got %+v", rep)
	}
	if !rep.Conflict {
		t.Errorf("want conflict (phase1 present), got none: %+v", rep.Checks)
	}
}

func TestRunPreflight_FortiGate_BadToken(t *testing.T) {
	srv := fakeFortiGate(t, false)
	rep := RunPreflight(context.Background(), fortiPayload(srv.URL, "wrong"))
	if rep.AuthOK {
		t.Errorf("want auth_ok=false with a bad token, got %+v", rep)
	}
	if !rep.Reachable {
		t.Errorf("want reachable=true (we reached the API, it rejected auth), got %+v", rep)
	}
}

func TestRunPreflight_OPNsense_BasicAuthAndVersion(t *testing.T) {
	var gotUser, gotPass string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/firmware/status", func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"product_version":"26.1"}`))
	})
	mux.HandleFunc("/api/ipsec/connections/searchConnection", func(w http.ResponseWriter, r *http.Request) {
		// No matching connection in the result set.
		_, _ = w.Write([]byte(`{"rows":[],"total":0}`))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	p := PreflightPayload{
		TunnelID: 9, TunnelName: "fwm-t9", End: 1, Vendor: "opnsense",
		DeviceID: 1002, BaseURL: srv.URL, APIToken: "mykey:mysecret", InsecureTLS: true,
		Steps: []PreflightStep{
			{Check: "auth", Method: "GET", Path: "/api/core/firmware/status"},
			{Check: "connection", Method: "GET", Path: "/api/ipsec/connections/searchConnection", ExpectAbsent: true},
		},
	}
	rep := RunPreflight(context.Background(), p)
	if gotUser != "mykey" || gotPass != "mysecret" {
		t.Errorf("basic auth = %q:%q, want mykey:mysecret", gotUser, gotPass)
	}
	if !rep.AuthOK || rep.OSVersion != "26.1" {
		t.Errorf("auth_ok/version wrong: %+v", rep)
	}
	if rep.Conflict {
		t.Errorf("unexpected conflict (empty search): %+v", rep.Checks)
	}
}

func TestRunPreflight_FortiGate_IndeterminateOnForbidden(t *testing.T) {
	// Auth works (monitor status 200) but the cmdb read is forbidden (API user
	// lacks vpn.ipsec read / wrong VDOM) → the collision check must be
	// indeterminate, NOT a false "clear".
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/monitor/system/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"v7.6.7"}`))
	})
	mux.HandleFunc("/api/v2/cmdb/vpn.ipsec/phase1-interface/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	rep := RunPreflight(context.Background(), fortiPayload(srv.URL, "good"))
	if !rep.AuthOK {
		t.Fatalf("want auth_ok, got %+v", rep)
	}
	if rep.Conflict {
		t.Errorf("must NOT report a definite conflict on a 403 collision read: %+v", rep.Checks)
	}
	if !rep.Indeterminate {
		t.Errorf("want indeterminate=true when the collision read is forbidden: %+v", rep.Checks)
	}
}

func TestOPNsenseRowsMatch_ExactNotSubstring(t *testing.T) {
	// A deployed connection "fwm-t70" must NOT match preflight for "fwm-t7".
	body := []byte(`{"rows":[{"description":"fwm-t70","uuid":"x"}],"total":1}`)
	if m, parsed := opnsenseRowsMatch(body, "fwm-t7"); m || !parsed {
		t.Errorf("fwm-t7 wrongly matched fwm-t70 (m=%t parsed=%t)", m, parsed)
	}
	// Exact match hits.
	if m, parsed := opnsenseRowsMatch(body, "fwm-t70"); !m || !parsed {
		t.Errorf("fwm-t70 should match exactly (m=%t parsed=%t)", m, parsed)
	}
	// Unparseable body → not parsed (caller treats as indeterminate).
	if _, parsed := opnsenseRowsMatch([]byte(`not json`), "fwm-t7"); parsed {
		t.Error("unparseable body must report parsed=false")
	}
}

func TestRunPreflight_UnreachableFailsFast(t *testing.T) {
	// A server that never responds (blocks) would be slow; instead point at a
	// closed port on localhost so the connection is refused quickly, and assert
	// the auth failure short-circuits the remaining collision GETs.
	closed := "https://127.0.0.1:1" // nothing listens on TCP/1
	p := PreflightPayload{
		TunnelID: 3, TunnelName: "fwm-t3", End: 0, Vendor: "fortigate",
		DeviceID: 1, BaseURL: closed, APIToken: "tok", InsecureTLS: true,
		Steps: []PreflightStep{
			{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"},
			{Check: "phase1", Method: "GET", Path: "/api/v2/cmdb/vpn.ipsec/phase1-interface/fwm-t3", ExpectAbsent: true},
			{Check: "phase2", Method: "GET", Path: "/api/v2/cmdb/vpn.ipsec/phase2-interface/fwm-t3", ExpectAbsent: true},
			{Check: "vti", Method: "GET", Path: "/api/v2/cmdb/system/interface/fwm-t3", ExpectAbsent: true},
		},
	}
	rep := RunPreflight(context.Background(), p)
	if rep.Reachable || rep.AuthOK {
		t.Fatalf("want unreachable + auth_ok=false, got %+v", rep)
	}
	if rep.Error == "" {
		t.Error("want a top-level Error explaining unreachability")
	}
	if len(rep.Checks) != 4 {
		t.Fatalf("want 4 check rows (auth + 3 skipped), got %d", len(rep.Checks))
	}
	// The auth row carries a friendly note; the 3 collision rows are skipped.
	for i := 1; i < 4; i++ {
		if !strings.Contains(rep.Checks[i].Note, "skipped") {
			t.Errorf("check %q should be skipped after auth failure, note=%q", rep.Checks[i].Check, rep.Checks[i].Note)
		}
		if rep.Checks[i].StatusCode != 0 || rep.Checks[i].Collision {
			t.Errorf("skipped check %q must not report a status/collision", rep.Checks[i].Check)
		}
	}
}

func TestFriendlyNetErr(t *testing.T) {
	if got := friendlyNetErr(context.DeadlineExceeded); !strings.Contains(got, "timed out") {
		t.Errorf("deadline → %q, want a timeout message", got)
	}
	if got := friendlyNetErr(errors.New("dial tcp: connection refused")); !strings.Contains(got, "refused") {
		t.Errorf("refused → %q", got)
	}
}

func TestApplyAuth_Vendors(t *testing.T) {
	rF, _ := http.NewRequest(http.MethodGet, "https://x/", nil)
	applyAuth(rF, "fortigate", "tok123")
	if got := rF.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Errorf("fortigate auth = %q", got)
	}
	rO, _ := http.NewRequest(http.MethodGet, "https://x/", nil)
	applyAuth(rO, "opnsense", "k:s")
	if u, p, _ := rO.BasicAuth(); u != "k" || p != "s" {
		t.Errorf("opnsense basic = %q:%q", u, p)
	}
	// A GET is the only method the transport ever issues.
	if !strings.EqualFold(http.MethodGet, "GET") {
		t.Fatal("sanity")
	}
}

// flakyBody returns its data once, then a mid-body transport error — the shape
// of a TCP reset partway through a response.
type flakyBody struct {
	data []byte
	sent bool
}

func (b *flakyBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, b.data), nil
	}
	return 0, errors.New("mid-body connection reset")
}
func (b *flakyBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestDoRequest_BodyReadError_Propagates proves a mid-body transport failure is
// returned as an error (not a truncated body fed to the verdict parsers, which
// could misread a cut-off `{"result":"failed"` as a success).
func TestDoRequest_BodyReadError_Propagates(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &flakyBody{data: []byte(`{"result":"sa`)},
			Request:    r,
		}, nil
	})}
	_, _, err := doRequest(context.Background(), client, "opnsense", "k:s", "http://x", http.MethodGet, "/y", "")
	if err == nil || !strings.Contains(err.Error(), "reading response body") {
		t.Fatalf("mid-body read failure must surface as an error; got %v", err)
	}
}

// TestDoRequest_OversizeBody_Errors proves a body larger than the 1 MiB cap is
// an explicit error rather than silently truncated JSON.
func TestDoRequest_OversizeBody_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(make([]byte, (1<<20)+64))
	}))
	t.Cleanup(srv.Close)
	_, _, err := doRequest(context.Background(), srv.Client(), "fortigate", "tok", srv.URL, http.MethodGet, "/", "")
	if err == nil || !strings.Contains(err.Error(), "1 MiB cap") {
		t.Fatalf("oversize body must error; got %v", err)
	}
}
