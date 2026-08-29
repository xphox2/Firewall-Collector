package relay

import (
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-collector/internal/observability"
)

// scrapeMetrics renders the Prometheus /metrics exposition text for assertions.
func scrapeMetrics(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("/metrics returned %d", rec.Code)
	}
	return rec.Body.String()
}

// TestAudit210_QueueDropAndDepthWired is the AUDIT-210 regression: the queue
// depth gauge and the drop counter — registered but never fed before this fix —
// are now actually driven by the live relay queues opened in ensureQueues.
func TestAudit210_QueueDropAndDepthWired(t *testing.T) {
	metrics := observability.New(observability.Config{Version: "test", Vendor: "test"})

	c := NewClient(Config{
		ServerURL:     "http://127.0.0.1:0",
		QueueDiskPath: t.TempDir(),
		QueueMaxBytes: 1, // any item spilled to disk exceeds the cap and is dropped
	})

	// QueueDepth must be 0 before the queues are opened (queuesReady still false).
	if got := c.QueueDepth("traps"); got != 0 {
		t.Fatalf("QueueDepth before ensureQueues = %d; want 0", got)
	}

	// Wire exactly as main() does.
	c.SetQueueDropHook(metrics.IncQueueDropped)
	c.SetDataBatchSentHook(metrics.OnDataBatchSent)
	metrics.SetQueueDepthSource(c.QueueDepth)

	c.ensureQueues()
	if c.trapQueue == nil {
		t.Fatal("ensureQueues did not open the trap queue")
	}

	// Fill past MaxMem so the overflow items spill to disk, where MaxBytes=1
	// drops them — firing the queue's OnDrop → c.onQueueDrop → IncQueueDropped.
	const overflow = 5
	for i := 0; i < maxQueueSize+overflow; i++ {
		if err := c.trapQueue.Push([]byte("x")); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}

	// QueueDepth returns the in-memory tier (capped at MaxMem).
	if got := c.QueueDepth("traps"); got != maxQueueSize {
		t.Errorf("QueueDepth(traps) = %d; want %d", got, maxQueueSize)
	}
	if got := c.QueueDepth("does-not-exist"); got != 0 {
		t.Errorf("QueueDepth(unknown) = %d; want 0", got)
	}

	body := scrapeMetrics(t, metrics)
	// The drop counter must reflect the overflow evictions.
	if !strings.Contains(body, `firewall_collector_queue_dropped_total{queue="traps"}`) {
		t.Errorf("scrape missing traps drop series:\n%s", body)
	}
	// The depth gauge must reflect the live queue via the source callback.
	if !strings.Contains(body, `firewall_collector_queue_depth{queue="traps"} 10000`) {
		t.Errorf("scrape missing/incorrect traps depth gauge:\n%s", body)
	}
}

// TestAudit210_DataBatchSentWired verifies the data-batch-sent counter reaches
// the metric through the relay hook.
func TestAudit210_DataBatchSentWired(t *testing.T) {
	metrics := observability.New(observability.Config{Version: "test", Vendor: "test"})
	c := NewClient(Config{ServerURL: "http://127.0.0.1:0"})
	c.SetDataBatchSentHook(metrics.OnDataBatchSent)

	c.fireDataBatchSent("metrics", "success")
	c.fireDataBatchSent("metrics", "failure")

	body := scrapeMetrics(t, metrics)
	if !strings.Contains(body, `firewall_collector_data_batch_sent_total{outcome="success",queue="metrics"} 1`) {
		t.Errorf("scrape missing success batch series:\n%s", body)
	}
	if !strings.Contains(body, `firewall_collector_data_batch_sent_total{outcome="failure",queue="metrics"} 1`) {
		t.Errorf("scrape missing failure batch series:\n%s", body)
	}
}
