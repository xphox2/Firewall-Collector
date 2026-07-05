package relay

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// These tests pin the LC-02 fix (2026-07-04 audit): sendHeartbeatWithStatus
// used to treat EVERY non-401/403 response as success — the server's 410 Gone
// (probe decommissioned), 429 backpressure, 400, and 5xx all fell through to
// `return nil`, so runHeartbeatLoop refreshed the /readyz timestamp and
// counted a Prometheus heartbeat success while the server refused to update
// last_seen and marked the probe offline.

func heartbeatClient(srv *httptest.Server) *Client {
	return &Client{
		Config:     Config{ServerURL: srv.URL, RegistrationKey: "test"},
		httpClient: srv.Client(),
	}
}

// TestSendHeartbeat_2xxIsSuccess: 2xx is the ONLY outcome that may return nil
// (and thereby refresh /readyz + the success counter).
func TestSendHeartbeat_2xxIsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := heartbeatClient(srv).SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat on 200 = %v, want nil (success)", err)
	}
}

// TestSendHeartbeat_FailureStatusesReturnError: 400, 429, and 5xx are FAILED
// heartbeats — an error so the caller counts OnHeartbeatFailure and /readyz
// goes stale — and none of them may trigger the 401/403 re-register path.
func TestSendHeartbeat_FailureStatusesReturnError(t *testing.T) {
	for _, status := range []int{400, 429, 500, 502, 503} {
		var registers atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/probes/register" {
				registers.Add(1)
			}
			w.WriteHeader(status)
		}))

		err := heartbeatClient(srv).SendHeartbeat()
		if err == nil {
			t.Errorf("SendHeartbeat on %d = nil — counted as a healthy heartbeat while the server refused to update last_seen", status)
		}
		if n := registers.Load(); n != 0 {
			t.Errorf("SendHeartbeat on %d attempted %d re-registration(s); only 401/403 may re-register", status, n)
		}
		srv.Close()
	}
}

// TestSendHeartbeat_410QuiescesWithoutReregister: 410 Gone is the server's
// deliberate, non-retryable "probe rejected/decommissioned/disabled" refusal
// (server audit M7). It must (a) NOT count as success, (b) NOT churn
// re-registration, and (c) quiesce the heartbeat POSTs for the cooldown
// instead of hammering at full cadence. A subsequent successful registration
// (admin re-commissioned the probe) lifts the quiesce immediately.
func TestSendHeartbeat_410QuiescesWithoutReregister(t *testing.T) {
	var heartbeats, registers atomic.Int32
	var recommissioned atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/probes/heartbeat":
			heartbeats.Add(1)
			if recommissioned.Load() {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			w.Write([]byte(`{"error":"Probe is rejected or decommissioned — heartbeat refused"}`))
		case "/api/probes/register":
			registers.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"probe_id":7,"probe_name":"p","approved":true,"schema_version":2}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := heartbeatClient(srv)

	if err := c.SendHeartbeat(); err == nil {
		t.Fatal("SendHeartbeat on 410 = nil — the decommission refusal was swallowed as success")
	}
	if n := heartbeats.Load(); n != 1 {
		t.Fatalf("expected exactly 1 heartbeat POST, got %d", n)
	}
	if n := registers.Load(); n != 0 {
		t.Errorf("410 triggered %d re-registration(s); it is non-retryable and must not churn the register path", n)
	}
	c.mu.Lock()
	until := c.heartbeatQuiescedUntil
	c.mu.Unlock()
	if !until.After(time.Now()) {
		t.Error("410 did not set heartbeatQuiescedUntil into the future")
	}

	// While quiesced: still an error (failure counted), but NO network POST.
	if err := c.SendHeartbeat(); err == nil {
		t.Error("quiesced SendHeartbeat = nil, want error so /readyz + metrics see the outage")
	}
	if n := heartbeats.Load(); n != 1 {
		t.Errorf("quiesced heartbeat still POSTed to the server (%d total POSTs, want 1)", n)
	}

	// Admin re-commissions the probe; a successful registration lifts the
	// quiesce and heartbeats resume immediately (no restart, no cooldown wait).
	recommissioned.Store(true)
	if err := c.Register(); err != nil {
		t.Fatalf("Register after re-commission failed: %v", err)
	}
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat after successful re-registration = %v, want nil", err)
	}
	if n := heartbeats.Load(); n != 2 {
		t.Errorf("expected heartbeat POSTs to resume after re-registration (got %d total, want 2)", n)
	}
}
