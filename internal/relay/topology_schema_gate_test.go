package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestSendTopology_SchemaV5Gate pins the v5 compatibility gate:
// SendTopologyEntries/SendTopologyNeighbors must NOT hit the wire until the
// negotiated schema is ≥ 5 (a server without those endpoints would otherwise
// 404 and flap re-registration), and must send once the schema is 5.
func TestSendTopology_SchemaV5Gate(t *testing.T) {
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

	entry := []TopologyEntry{{EntryType: "arp", MACAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.1"}}
	nbr := []TopologyNeighbor{{Protocol: "lldp", RemoteChassisID: "aa:bb:cc:dd:ee:00"}}

	// Negotiated v4: gate closed, zero POSTs.
	c := newClient(4)
	if err := c.SendTopologyEntries(entry); err != nil {
		t.Fatalf("SendTopologyEntries@v4: %v", err)
	}
	if err := c.SendTopologyNeighbors(nbr); err != nil {
		t.Fatalf("SendTopologyNeighbors@v4: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("schema 4: %d POST(s), want 0 (gate must suppress)", got)
	}

	// Negotiated v5: gate open, both send.
	c = newClient(5)
	if err := c.SendTopologyEntries(entry); err != nil {
		t.Fatalf("SendTopologyEntries@v5: %v", err)
	}
	if err := c.SendTopologyNeighbors(nbr); err != nil {
		t.Fatalf("SendTopologyNeighbors@v5: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("schema 5: %d POST(s), want 2", got)
	}
}

// TestSendTopology_NeverSpools pins the stale-replay guard: a failed topology
// snapshot send must be DROPPED, not spilled to the metric queue — a spooled
// old snapshot replayed after a newer live one would revert the device's
// topology under the server's replace semantics.
func TestSendTopology_NeverSpools(t *testing.T) {
	// Server that always 500s (a retryable status doDirectSend WOULD spool).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Client{Config: Config{ServerURL: srv.URL, RegistrationKey: "k"}, httpClient: srv.Client()}
	c.probeID = 7
	c.approved.Store(true)
	c.negotiatedSchema.Store(5)

	if err := c.SendTopologyEntries([]TopologyEntry{{EntryType: "fdb", MACAddress: "aa:bb:cc:dd:ee:ff"}}); err == nil {
		t.Fatal("expected an error from a 500 response")
	}
	// ensureQueues was never forced by the snapshot path; even if a queue
	// exists it must hold nothing.
	if c.metricQueue != nil {
		if raw, _ := c.metricQueue.Drain(10); len(raw) != 0 {
			t.Fatalf("topology snapshot was spooled (%d items) — must be dropped", len(raw))
		}
	}
}
