package fwapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRunStatusProbe_HappyPath proves the probe GETs each step with vendor auth
// and returns the raw device document untouched (the server parses it).
func TestRunStatusProbe_HappyPath(t *testing.T) {
	const doc = `{"results":[{"name":"fwm-t7","proxyid":[{"status":"up"}]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("status probe must only GET, got %s", r.Method)
		}
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)

	rep := RunStatusProbe(context.Background(), StatusPayload{
		Vendor: "fortigate", BaseURL: srv.URL, APIToken: "tok",
		Steps: []StatusProbeStep{{Method: "GET", Path: "/api/v2/monitor/vpn/ipsec?vdom=root"}},
	})
	if rep.Error != "" {
		t.Fatalf("unexpected error: %s", rep.Error)
	}
	if len(rep.Steps) != 1 || rep.Steps[0].Status != 200 {
		t.Fatalf("expected one 200 step, got %+v", rep.Steps)
	}
	if rep.Steps[0].Body != doc {
		t.Errorf("raw body must be returned untouched; got %q", rep.Steps[0].Body)
	}
}

// TestRunStatusProbe_Unreachable proves a transport failure lands in Error
// (the server treats it as inconclusive, never a false up/down).
func TestRunStatusProbe_Unreachable(t *testing.T) {
	rep := RunStatusProbe(context.Background(), StatusPayload{
		Vendor: "fortigate", BaseURL: "http://127.0.0.1:1", APIToken: "tok",
		Steps: []StatusProbeStep{{Method: "GET", Path: "/x"}},
	})
	if rep.Error == "" {
		t.Fatalf("unreachable device must set Error; got %+v", rep)
	}
}

// TestRunStatusProbe_RefusesNonGET proves a mutating step is refused outright —
// a status probe must never write, even if the server shipped a bad step.
func TestRunStatusProbe_RefusesNonGET(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	t.Cleanup(srv.Close)
	rep := RunStatusProbe(context.Background(), StatusPayload{
		Vendor: "opnsense", BaseURL: srv.URL, APIToken: "k:s",
		Steps: []StatusProbeStep{{Method: "POST", Path: "/api/ipsec/service/reconfigure"}},
	})
	if rep.Error == "" || !strings.Contains(rep.Error, "non-GET") {
		t.Fatalf("non-GET step must be refused; got %+v", rep)
	}
	if hit {
		t.Error("refused step must never reach the device")
	}
}

// TestRunStatusProbe_VendorGate rejects unsupported vendors before any device
// contact, matching the apply handler's gate.
func TestRunStatusProbe_VendorGate(t *testing.T) {
	rep := RunStatusProbe(context.Background(), StatusPayload{
		Vendor: "paloalto", BaseURL: "http://127.0.0.1:1", APIToken: "tok",
		Steps: []StatusProbeStep{{Method: "GET", Path: "/x"}},
	})
	if !strings.Contains(rep.Error, "not supported") {
		t.Fatalf("unsupported vendor must be rejected; got %+v", rep)
	}
}

// TestRunStatusProbe_NoSteps rejects an empty step list (a server bug) rather
// than reporting a vacuous success.
func TestRunStatusProbe_NoSteps(t *testing.T) {
	rep := RunStatusProbe(context.Background(), StatusPayload{
		Vendor: "fortigate", BaseURL: "http://127.0.0.1:1", APIToken: "tok",
	})
	if !strings.Contains(rep.Error, "no probe steps") {
		t.Fatalf("empty steps must error; got %+v", rep)
	}
}
