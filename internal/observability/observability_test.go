package observability

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newTestServer starts a Server bound to 127.0.0.1:<random>. Returns
// the server, its base URL, and a teardown that callers defer to shut
// it down cleanly between tests.
func newTestServer(t *testing.T, cfg Config) (*Server, string, func()) {
	t.Helper()
	metrics := New(cfg)
	srv := NewServer(metrics, "127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	url := "http://" + srv.Addr().String()
	teardown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}
	return srv, url, teardown
}

// get is a tiny HTTP helper that returns the response body as a
// string. Fails the test on transport errors.
func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// TestHealthz_ProcessUp_Returns200 — /healthz must return 200 any
// time the metrics server itself is running. Orchestrators use this
// as the liveness signal.
func TestHealthz_ProcessUp_Returns200(t *testing.T) {
	_, url, teardown := newTestServer(t, Config{
		Version: "test",
		Vendor:  "unit",
	})
	defer teardown()

	status, body := get(t, url+"/healthz")
	if status != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200 (body=%q)", status, body)
	}
	if body != "ok" {
		t.Errorf("/healthz body = %q, want %q", body, "ok")
	}
}

// TestReadyz_NotApproved_Returns503 — /readyz must fail closed when
// the probe is not approved. A second test below covers the "approved
// but stale heartbeat" branch.
func TestReadyz_NotApproved_Returns503(t *testing.T) {
	_, url, teardown := newTestServer(t, Config{
		Version:            "test",
		Vendor:             "unit",
		HeartbeatInterval:  60 * time.Second,
		ApprovedFn:         func() bool { return false },
		LastHeartbeatFn:    func() time.Time { return time.Now() },
		EnabledListenersFn: func() []string { return nil },
	})
	defer teardown()

	status, body := get(t, url+"/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503 (body=%q)", status, body)
	}
	if !strings.Contains(body, "not approved") {
		t.Errorf("/readyz body = %q, want substring %q", body, "not approved")
	}
}

// TestReadyz_StaleHeartbeat_Returns503 covers the second readiness
// branch: probe is approved but the last heartbeat is too old.
func TestReadyz_StaleHeartbeat_Returns503(t *testing.T) {
	_, url, teardown := newTestServer(t, Config{
		Version:            "test",
		Vendor:             "unit",
		HeartbeatInterval:  60 * time.Second,
		ApprovedFn:         func() bool { return true },
		LastHeartbeatFn:    func() time.Time { return time.Now().Add(-10 * time.Minute) },
		EnabledListenersFn: func() []string { return nil },
	})
	defer teardown()

	status, body := get(t, url+"/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503 (body=%q)", status, body)
	}
	if !strings.Contains(body, "heartbeat") {
		t.Errorf("/readyz body = %q, want substring %q", body, "heartbeat")
	}
}

// TestReadyz_ListenerNotBound_Returns503 covers the third readiness
// branch: probe is approved and heartbeat is fresh, but an enabled
// listener failed to bind.
func TestReadyz_ListenerNotBound_Returns503(t *testing.T) {
	_, url, teardown := newTestServer(t, Config{
		Version:            "test",
		Vendor:             "unit",
		HeartbeatInterval:  60 * time.Second,
		ApprovedFn:         func() bool { return true },
		LastHeartbeatFn:    func() time.Time { return time.Now() },
		EnabledListenersFn: func() []string { return []string{"snmp_trap"} },
		ListenerBoundFn:    func(name string) bool { return name != "snmp_trap" },
	})
	defer teardown()

	status, body := get(t, url+"/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503 (body=%q)", status, body)
	}
	if !strings.Contains(body, "listener") {
		t.Errorf("/readyz body = %q, want substring %q", body, "listener")
	}
}

// TestReadyz_AllChecksPass_Returns200 is the happy path: every
// readiness check is green and /readyz returns 200 with body "ready".
func TestReadyz_AllChecksPass_Returns200(t *testing.T) {
	_, url, teardown := newTestServer(t, Config{
		Version:            "test",
		Vendor:             "unit",
		HeartbeatInterval:  60 * time.Second,
		ApprovedFn:         func() bool { return true },
		LastHeartbeatFn:    func() time.Time { return time.Now() },
		EnabledListenersFn: func() []string { return []string{"snmp_trap", "sflow"} },
		ListenerBoundFn:    func(string) bool { return true },
	})
	defer teardown()

	status, body := get(t, url+"/readyz")
	if status != http.StatusOK {
		t.Errorf("/readyz status = %d, want 200 (body=%q)", status, body)
	}
	if body != "ready" {
		t.Errorf("/readyz body = %q, want %q", body, "ready")
	}
}

// TestMetrics_QueueDepthExposed — the spec calls out queue depth as
// "critical, currently invisible." The test publishes a known value
// (5) and asserts the Prometheus output reflects it.
func TestMetrics_QueueDepthExposed(t *testing.T) {
	// We can't import relay from a unit test without spinning up an
	// HTTP server, so we test the surface by setting a source
	// callback that returns 5 for the "traps" queue. This is exactly
	// the path production code uses (a closure over the relay
	// client's internal queue length).
	metrics := New(Config{Version: "test", Vendor: "unit"})
	metrics.SetQueueDepthSource(func(queue string) int {
		if queue == "traps" {
			return 5
		}
		return 0
	})
	srv := NewServer(metrics, "127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	status, body := get(t, "http://"+srv.Addr().String()+"/metrics")
	if status != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200 (body=%q)", status, body)
	}
	want := `firewall_collector_queue_depth{queue="traps"} 5`
	if !strings.Contains(body, want) {
		t.Errorf("/metrics body missing %q\n--- body ---\n%s\n--- end ---", want, body)
	}
}

// TestMetrics_DropCounterIncrements — fill the queue (simulated by
// calling IncQueueDropped five times) and assert the counter shows 5.
// In production this method is called from the relay client's
// "queue full" branches (the lines that already log "queue full,
// dropping oldest entry").
func TestMetrics_DropCounterIncrements(t *testing.T) {
	metrics := New(Config{Version: "test", Vendor: "unit"})
	for i := 0; i < 5; i++ {
		metrics.IncQueueDropped("traps")
	}
	srv := NewServer(metrics, "127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	status, body := get(t, "http://"+srv.Addr().String()+"/metrics")
	if status != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", status)
	}
	want := `firewall_collector_queue_dropped_total{queue="traps"} 5`
	if !strings.Contains(body, want) {
		t.Errorf("/metrics body missing %q\n--- body ---\n%s\n--- end ---", want, body)
	}
}

// TestMetrics_BuildInfoPresent — the build_info gauge must always
// render a series, even before any other event has happened. This is
// what lets dashboards show "version 1.2.99, vendor acme" at all
// times, including immediately after a scrape while the probe is
// still warming up.
func TestMetrics_BuildInfoPresent(t *testing.T) {
	metrics := New(Config{Version: "1.2.99", Vendor: "acme"})
	srv := NewServer(metrics, "127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	_, body := get(t, "http://"+srv.Addr().String()+"/metrics")
	// Prometheus sorts label keys alphabetically, so the exposition
	// is {vendor=...,version=...} regardless of registration order.
	want := `firewall_collector_build_info{vendor="acme",version="1.2.99"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("/metrics body missing %q\n--- body ---\n%s\n--- end ---", want, body)
	}
}

// TestMetrics_PollDurationHistogram — verifies that OnPollDuration
// populates the histogram and MarkPollSucceeded updates the
// last_successful_poll gauge. Both are needed for SLO dashboards
// (P95 latency) and per-device liveness checks respectively.
func TestMetrics_PollDurationHistogram(t *testing.T) {
	metrics := New(Config{Version: "test", Vendor: "unit"})
	metrics.OnPollDuration(42, "fortigate", 250*time.Millisecond)
	metrics.OnPollDuration(42, "fortigate", 750*time.Millisecond)
	metrics.OnPollDuration(7, "paloalto", 3*time.Second)
	metrics.MarkPollSucceeded(42)
	metrics.MarkPollSucceeded(7)

	srv := NewServer(metrics, "127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	_, body := get(t, "http://"+srv.Addr().String()+"/metrics")

	// Histogram: two observations for device 42 (one in 0.5s bucket,
	// one in 1s bucket) and one for device 7 (in 5s bucket). We don't
	// assert exact bucket counts — Prometheus exposition format
	// changes with version — just that the count and sum series
	// appear.
	wantCount42 := `firewall_collector_poll_duration_seconds_count{device_id="42",vendor="fortigate"} 2`
	if !strings.Contains(body, wantCount42) {
		t.Errorf("/metrics body missing %q\n--- body ---\n%s\n--- end ---", wantCount42, body)
	}
	// last_successful_poll gauge: should be set to a recent Unix
	// timestamp for device 42 and 7.
	if !strings.Contains(body, `firewall_collector_last_successful_poll_timestamp{device_id="42"}`) {
		t.Errorf("/metrics body missing last_successful_poll series for device 42")
	}
	if !strings.Contains(body, `firewall_collector_last_successful_poll_timestamp{device_id="7"}`) {
		t.Errorf("/metrics body missing last_successful_poll series for device 7")
	}
}

// TestServer_StartIsIdempotent — calling Start twice should not
// panic and should not open a second listener. Production code
// shouldn't hit this, but a misbehaving caller (e.g. a future retry
// loop) shouldn't be able to crash the probe.
func TestServer_StartIsIdempotent(t *testing.T) {
	metrics := New(Config{Version: "test", Vendor: "unit"})
	srv := NewServer(metrics, "127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Errorf("second Start returned %v, want nil", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

// TestServer_StopBeforeStartIsNoop — Stop is safe to call even if
// Start was never invoked. Lets callers write defer srv.Stop(...) at
// the top of a function without worrying about init order.
func TestServer_StopBeforeStartIsNoop(t *testing.T) {
	metrics := New(Config{Version: "test", Vendor: "unit"})
	srv := NewServer(metrics, "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Stop before Start returned %v, want nil", err)
	}
}
