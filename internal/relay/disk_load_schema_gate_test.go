package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestSendDiskLoad_SchemaV3Gate pins the load-bearing compatibility mechanism:
// SendDiskUsage/SendLoadAverage must NOT hit the wire until the negotiated
// schema is ≥ 3 (a server without those endpoints would otherwise 404 and flap
// re-registration), and must send once the schema is 3.
func TestSendDiskLoad_SchemaV3Gate(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	newClient := func(schema int32) *Client {
		c := &Client{Config: Config{ServerURL: srv.URL, RegistrationKey: "k"}, httpClient: srv.Client()}
		c.probeID = 7
		c.approved.Store(true)
		c.negotiatedSchema.Store(schema)
		return c
	}

	// Negotiated v2 (or anything < 3): gate closed, zero POSTs.
	c := newClient(2)
	if err := c.SendDiskUsage([]DiskUsage{{Mount: "/"}}); err != nil {
		t.Fatalf("SendDiskUsage@v2: %v", err)
	}
	if err := c.SendLoadAverage([]LoadAverage{{Load1: 1}}); err != nil {
		t.Fatalf("SendLoadAverage@v2: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("schema 2: %d POST(s), want 0 (gate must suppress)", got)
	}

	// Negotiated v3: gate open, both send.
	c = newClient(3)
	if err := c.SendDiskUsage([]DiskUsage{{Mount: "/"}}); err != nil {
		t.Fatalf("SendDiskUsage@v3: %v", err)
	}
	if err := c.SendLoadAverage([]LoadAverage{{Load1: 1}}); err != nil {
		t.Fatalf("SendLoadAverage@v3: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("schema 3: %d POST(s), want 2", got)
	}
}
