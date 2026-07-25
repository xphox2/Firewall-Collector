package fwapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// advisoryServer serves the auth endpoint plus a route-table endpoint returning
// whatever body the test supplies, at the given status.
func advisoryServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/monitor/system/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v7.6.7"}`))
	})
	mux.HandleFunc("/api/v2/cmdb/router/static", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runAdvisory(t *testing.T, srv *httptest.Server) StepResult {
	t.Helper()
	rep := RunPreflight(context.Background(), PreflightPayload{
		TunnelID: 9, TunnelName: "fwm-t9", Vendor: "fortigate", DeviceID: 4,
		BaseURL: srv.URL, APIToken: "good", InsecureTLS: true,
		Steps: []PreflightStep{
			{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"},
			{Check: "route_table", Method: "GET", Path: "/api/v2/cmdb/router/static", ReturnBody: true},
		},
	})
	for _, c := range rep.Checks {
		if c.Check == "route_table" {
			// An advisory read must never be able to raise a conflict — that is what
			// aborts an apply, and advisory findings are the operator's call.
			if c.Collision || rep.Conflict {
				t.Fatalf("advisory read must never set a collision: %+v", c)
			}
			return c
		}
	}
	t.Fatal("route_table step missing from report")
	return StepResult{}
}

// A 2xx advisory read echoes its body verbatim so the SERVER can parse it —
// vendor knowledge stays in the server driver, the collector stays transport.
func TestRunPreflight_ReturnBodyEchoesBody(t *testing.T) {
	body := `{"results":[{"seq-num":1,"dst":"192.168.5.0 255.255.255.0","device":"port3","distance":10}]}`
	got := runAdvisory(t, advisoryServer(t, http.StatusOK, body))
	if got.Body != body {
		t.Errorf("body not echoed verbatim:\n got %q\nwant %q", got.Body, body)
	}
	if got.Present || got.Indeterminate {
		t.Errorf("advisory read must skip collision interpretation entirely, got %+v", got)
	}
}

// A non-2xx yields no body and a note. The server then raises no advisory, which
// is correct: an advisory may only assert device state actually observed.
func TestRunPreflight_ReturnBodyNon2xxIsSkipped(t *testing.T) {
	got := runAdvisory(t, advisoryServer(t, http.StatusForbidden, `{"error":"no read access"}`))
	if got.Body != "" {
		t.Errorf("no body should be echoed for a non-2xx, got %q", got.Body)
	}
	if !strings.Contains(got.Note, "403") {
		t.Errorf("note should name the status so the operator can fix API perms, got %q", got.Note)
	}
}

// An oversize body is DROPPED whole rather than truncated: the report must fit
// the server's 64 KiB result column, and truncated JSON could be misparsed.
func TestRunPreflight_ReturnBodyOversizeIsDroppedNotTruncated(t *testing.T) {
	huge := `{"results":[` + strings.Repeat(`{"seq-num":1,"dst":"10.0.0.0 255.0.0.0"},`, 4000) + `{}]}`
	if len(huge) <= maxReturnedBody {
		t.Fatalf("fixture must exceed the %d-byte cap; it is %d", maxReturnedBody, len(huge))
	}
	got := runAdvisory(t, advisoryServer(t, http.StatusOK, huge))
	if got.Body != "" {
		t.Errorf("oversize body must be dropped entirely, got %d bytes", len(got.Body))
	}
	if !strings.Contains(got.Note, "cap") {
		t.Errorf("note should explain the check was skipped, got %q", got.Note)
	}
}

// A step WITHOUT ReturnBody must never leak its body into the report — bodies
// are echoed only where the server explicitly asked for one.
func TestRunPreflight_BodyNotEchoedUnlessRequested(t *testing.T) {
	srv := advisoryServer(t, http.StatusOK, `{"results":[{"seq-num":1}]}`)
	rep := RunPreflight(context.Background(), PreflightPayload{
		TunnelName: "fwm-t9", Vendor: "fortigate", BaseURL: srv.URL, APIToken: "good", InsecureTLS: true,
		Steps: []PreflightStep{
			{Check: "auth", Method: "GET", Path: "/api/v2/monitor/system/status"},
			{Check: "route", Method: "GET", Path: "/api/v2/cmdb/router/static", ExpectAbsent: true},
		},
	})
	for _, c := range rep.Checks {
		if c.Body != "" {
			t.Errorf("step %q echoed a body without ReturnBody: %q", c.Check, c.Body)
		}
	}
}
