package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for the relay schema-v4 command channel: heartbeat-response
// pending_commands parsing (gated on negotiated schema ≥ 4) and the
// SendCommandResult gate (mirrors the disk/load v3 gate — no wire traffic
// below a negotiated v4).

func commandChannelClient(srv *httptest.Server, schema int32) *Client {
	c := &Client{
		Config:     Config{ServerURL: srv.URL, RegistrationKey: "k"},
		httpClient: srv.Client(),
	}
	c.probeID = 7
	c.approved.Store(true)
	c.negotiatedSchema.Store(schema)
	return c
}

// TestHeartbeat_PendingCommandsParsedAtV4 pins that a schema-v4 heartbeat
// response's pending_commands reach the registered handler (async), with the
// payload intact.
func TestHeartbeat_PendingCommandsParsedAtV4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"pending_commands":[` +
			`{"command_id":"cmd-1","device_id":3,"type":"noop","payload":"{\"x\":1}","expires_at":"2030-01-01T00:00:00Z"}]}`))
	}))
	defer srv.Close()

	c := commandChannelClient(srv, 4)
	var mu sync.Mutex
	var got []PendingCommand
	received := make(chan struct{}, 1)
	c.SetCommandHandler(func(cmds []PendingCommand) {
		mu.Lock()
		got = append(got, cmds...)
		mu.Unlock()
		received <- struct{}{}
	})

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("command handler was not invoked for a v4 heartbeat carrying pending_commands")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("handler got %d command(s), want 1", len(got))
	}
	cmd := got[0]
	if cmd.CommandID != "cmd-1" || cmd.Type != "noop" || cmd.DeviceID != 3 || cmd.Payload != `{"x":1}` {
		t.Errorf("parsed command = %+v, want the wire values intact", cmd)
	}
}

// TestHeartbeat_PendingCommandsGatedBelowV4 pins the downgrade path: below a
// negotiated schema 4 the collector must NOT parse/dispatch pending_commands,
// even if a (buggy/foreign) server attaches them.
func TestHeartbeat_PendingCommandsGatedBelowV4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"pending_commands":[` +
			`{"command_id":"cmd-x","type":"noop","payload":"p"}]}`))
	}))
	defer srv.Close()

	c := commandChannelClient(srv, 3)
	invoked := make(chan struct{}, 1)
	c.SetCommandHandler(func(cmds []PendingCommand) { invoked <- struct{}{} })

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	select {
	case <-invoked:
		t.Fatal("command handler invoked at negotiated schema 3 — the v4 gate leaked")
	case <-time.After(200 * time.Millisecond):
		// gate held
	}
}

// TestSendCommandResult_SchemaV4Gate mirrors the disk/load v3 gate test:
// SendCommandResult must not hit the wire below a negotiated schema 4 (the
// server has no such route — 404s would churn re-registration), and must POST
// the result document at v4.
func TestSendCommandResult_SchemaV4Gate(t *testing.T) {
	var calls int32
	var lastPath string
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		lastPath = r.URL.Path
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"applied":true}}`))
	}))
	defer srv.Close()

	res := CommandResult{CommandID: "cmd-9", Status: "succeeded", Result: "noop executed"}

	// Below v4: gate closed, zero POSTs, nil error (deliberate no-op).
	c := commandChannelClient(srv, 3)
	if err := c.SendCommandResult(res); err != nil {
		t.Fatalf("SendCommandResult@v3: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("schema 3: %d POST(s), want 0 (gate must suppress)", got)
	}

	// v4: gate open — result POSTed to the probe-scoped route.
	c = commandChannelClient(srv, 4)
	if err := c.SendCommandResult(res); err != nil {
		t.Fatalf("SendCommandResult@v4: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("schema 4: %d POST(s), want 1", got)
	}
	if lastPath != "/api/probes/7/command-result" {
		t.Errorf("POST path = %q, want /api/probes/7/command-result", lastPath)
	}
	var sent CommandResult
	if err := json.Unmarshal(lastBody, &sent); err != nil {
		t.Fatalf("unmarshal sent body: %v", err)
	}
	if sent != res {
		t.Errorf("sent %+v, want %+v", sent, res)
	}

	// Non-2xx must surface as an error (callers log-and-rely-on-redelivery).
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()
	c = commandChannelClient(srv500, 4)
	if err := c.SendCommandResult(res); err == nil {
		t.Error("SendCommandResult on 500 = nil, want error")
	}
}
