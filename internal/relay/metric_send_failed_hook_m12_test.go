package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDoDirectSend_FiresMetricSendFailedHook_M12 is the regression for the
// 2026-06-23 audit M12 finding: primary-metric send failures now increment an
// observability counter (firewall_collector_metric_send_failed_total) via the
// hook, labeled by metric kind.
func TestDoDirectSend_FiresMetricSendFailedHook_M12(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // transient → buffered + counted
	}))
	defer srv.Close()

	c := newMetricQueueClient(t, srv)
	var kinds []string
	c.SetMetricSendFailedHook(func(kind string) { kinds = append(kinds, kind) })

	if err := c.SendSystemStatuses([]SystemStatus{{DeviceID: 1}}); err == nil {
		t.Fatal("expected an error on a 503")
	}
	if len(kinds) != 1 || kinds[0] != "system statuses" {
		t.Errorf("hook kinds = %v, want [\"system statuses\"]", kinds)
	}

	// A successful send must NOT increment the counter.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()
	c2 := newMetricQueueClient(t, srv2)
	var count int
	c2.SetMetricSendFailedHook(func(string) { count++ })
	if err := c2.SendInterfaceStats([]InterfaceStats{{DeviceID: 1}}); err != nil {
		t.Fatalf("unexpected error on 200: %v", err)
	}
	if count != 0 {
		t.Errorf("hook fired %d times on success, want 0", count)
	}
}
