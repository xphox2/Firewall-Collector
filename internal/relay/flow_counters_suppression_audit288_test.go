package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for AUDIT-288: a 404 on /flow-counters is endpoint-level evidence and
// must suppress ONLY that endpoint — self-expiring, cleared by re-registration
// — never collapse negotiatedSchema (which also disabled the unrelated v3
// disk/load, v4 command-channel, and v5 topology features until restart).

// TestFlowCounters404_OtherSchemaFeaturesUnaffected proves the suppression is
// endpoint-scoped: after a /flow-counters 404 at schema 5, disk/load (v3),
// the command channel (v4), and topology (v5) must all keep working.
func TestFlowCounters404_OtherSchemaFeaturesUnaffected(t *testing.T) {
	var diskCalls, loadCalls, topoCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/flow-counters"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/disk-usage"):
			atomic.AddInt32(&diskCalls, 1)
			_, _ = w.Write([]byte(`{"success":true}`))
		case strings.HasSuffix(r.URL.Path, "/load-average"):
			atomic.AddInt32(&loadCalls, 1)
			_, _ = w.Write([]byte(`{"success":true}`))
		case strings.HasSuffix(r.URL.Path, "/topology-entries"):
			atomic.AddInt32(&topoCalls, 1)
			_, _ = w.Write([]byte(`{"success":true}`))
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"pending_commands":[` +
				`{"command_id":"cmd-1","device_id":3,"type":"noop","payload":"{}","expires_at":"2030-01-01T00:00:00Z"}]}`))
		default:
			_, _ = w.Write([]byte(`{"success":true}`))
		}
	}))
	defer srv.Close()

	c := commandChannelClient(srv, 5)

	// The 404 arms the endpoint suppression…
	delivered, _ := c.sendBatch(srv.URL+"/api/probes/7/flow-counters", "flow-counters", []map[string]any{{"if_index": 1}})
	if !delivered {
		t.Fatal("flow-counters 404 batch must be consumed (dropped), not requeued")
	}
	if c.flowCountersEnabled() {
		t.Fatal("flowCountersEnabled() = true right after the 404 — suppression not armed")
	}

	// …but every other schema-gated feature is untouched.
	if got := c.negotiatedSchema.Load(); got != 5 {
		t.Fatalf("negotiatedSchema = %d, want 5 (the 404 must not collapse the schema)", got)
	}
	if err := c.SendDiskUsage([]DiskUsage{{Mount: "/"}}); err != nil {
		t.Errorf("SendDiskUsage after flow-counters 404: %v", err)
	}
	if err := c.SendLoadAverage([]LoadAverage{{Load1: 1}}); err != nil {
		t.Errorf("SendLoadAverage after flow-counters 404: %v", err)
	}
	if err := c.SendTopologyEntries([]TopologyEntry{{EntryType: "arp", MACAddress: "aa:bb:cc:dd:ee:ff"}}); err != nil {
		t.Errorf("SendTopologyEntries after flow-counters 404: %v", err)
	}
	if atomic.LoadInt32(&diskCalls) != 1 || atomic.LoadInt32(&loadCalls) != 1 || atomic.LoadInt32(&topoCalls) != 1 {
		t.Errorf("disk/load/topology POSTs = %d/%d/%d, want 1/1/1 — v3/v5 sends must still hit the wire",
			atomic.LoadInt32(&diskCalls), atomic.LoadInt32(&loadCalls), atomic.LoadInt32(&topoCalls))
	}
	if !c.TopologySupported() {
		t.Error("TopologySupported() = false after a flow-counters 404 — the v5 gate must be unaffected")
	}

	// The v4 command channel still dispatches.
	received := make(chan struct{}, 1)
	c.SetCommandHandler(func(cmds []PendingCommand) { received <- struct{}{} })
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("command handler not invoked after a flow-counters 404 — the v4 channel was collapsed")
	}
}

// TestFlowCountersSuppression_SelfExpires proves the suppression lifts on its
// own after flowCountersOffWindow — no restart, no re-registration.
func TestFlowCountersSuppression_SelfExpires(t *testing.T) {
	origWindow := flowCountersOffWindow
	flowCountersOffWindow = time.Nanosecond
	defer func() { flowCountersOffWindow = origWindow }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := commandChannelClient(srv, 2)
	if delivered, _ := c.sendBatch(srv.URL+"/flow-counters", "flow-counters", []map[string]any{{"if_index": 1}}); !delivered {
		t.Fatal("404 batch must be consumed")
	}
	time.Sleep(10 * time.Millisecond) // comfortably past the shrunk window
	if !c.flowCountersEnabled() {
		t.Error("suppression did not self-expire after the window lapsed")
	}
}

// TestFlowCountersSuppression_ClearedByRegistration proves a successful
// (re-)registration lifts the suppression immediately — fresh evidence about
// the server, mirroring the heartbeatQuiescedUntil reset.
func TestFlowCountersSuppression_ClearedByRegistration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"probe_id":7,"probe_name":"p","approved":true,"schema_version":2}`))
	}))
	defer srv.Close()

	c := commandChannelClient(srv, 2)
	c.flowCountersOffUntil.Store(time.Now().Add(time.Hour).UnixNano())
	if c.flowCountersEnabled() {
		t.Fatal("setup: suppression not armed")
	}

	if err := c.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := c.flowCountersOffUntil.Load(); got != 0 {
		t.Errorf("flowCountersOffUntil = %d after registration, want 0 (cleared)", got)
	}
	if !c.flowCountersEnabled() {
		t.Error("flowCountersEnabled() = false after a successful registration at schema 2")
	}
}
