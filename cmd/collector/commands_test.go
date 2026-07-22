package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// Tests for the schema-v4 command executor: noop round-trip, unknown-type
// failure, redelivery dedup (cached result re-POST, no re-execution), and the
// expired-command refusal.

type fakeResultSink struct {
	mu      sync.Mutex
	results []relay.CommandResult
	err     error
}

func (f *fakeResultSink) SendCommandResult(res relay.CommandResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, res)
	return f.err
}

func (f *fakeResultSink) all() []relay.CommandResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]relay.CommandResult, len(f.results))
	copy(out, f.results)
	return out
}

func TestCommandExecutor_NoopSucceedsAndReports(t *testing.T) {
	sink := &fakeResultSink{}
	e := newCommandExecutor(sink)

	e.HandleCommands([]relay.PendingCommand{{
		CommandID: "cmd-noop",
		Type:      "noop",
		Payload:   `{"anything":"ignored"}`,
		ExpiresAt: time.Now().Add(time.Hour),
	}})

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("reported %d result(s), want 1", len(got))
	}
	if got[0].CommandID != "cmd-noop" || got[0].Status != "succeeded" {
		t.Errorf("result = %+v, want cmd-noop/succeeded", got[0])
	}
}

func TestCommandExecutor_UnknownTypeFails(t *testing.T) {
	sink := &fakeResultSink{}
	e := newCommandExecutor(sink)

	e.HandleCommands([]relay.PendingCommand{{
		CommandID: "cmd-mystery",
		Type:      "apply_ipsec", // not implemented in PR-1
	}})

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("reported %d result(s), want 1", len(got))
	}
	if got[0].Status != "failed" {
		t.Errorf("unknown type status = %q, want failed (crisp failure, not silent drop)", got[0].Status)
	}
}

// TestCommandExecutor_RedeliveryDedup pins the at-least-once contract: a
// redelivered CommandID is NEVER re-executed — the cached result is re-POSTed
// instead (which is how a lost result POST recovers).
func TestCommandExecutor_RedeliveryDedup(t *testing.T) {
	sink := &fakeResultSink{}
	e := newCommandExecutor(sink)
	var executions int
	e.handlers["counting"] = func(cmd relay.PendingCommand) (string, error) {
		executions++
		return "ran", nil
	}

	cmd := relay.PendingCommand{CommandID: "cmd-dup", Type: "counting"}
	e.HandleCommands([]relay.PendingCommand{cmd})
	e.HandleCommands([]relay.PendingCommand{cmd}) // server redelivery

	if executions != 1 {
		t.Fatalf("command executed %d times, want exactly 1 (dedup by CommandID)", executions)
	}
	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("reported %d result(s), want 2 (original + cached re-POST)", len(got))
	}
	if got[0] != got[1] {
		t.Errorf("re-POSTed result %+v differs from original %+v — must re-send the CACHED result", got[1], got[0])
	}
}

func TestCommandExecutor_ExpiredCommandRefused(t *testing.T) {
	sink := &fakeResultSink{}
	e := newCommandExecutor(sink)
	var executions int
	e.handlers["never"] = func(cmd relay.PendingCommand) (string, error) {
		executions++
		return "", nil
	}

	e.HandleCommands([]relay.PendingCommand{{
		CommandID: "cmd-stale",
		Type:      "never",
		ExpiresAt: time.Now().Add(-time.Minute),
	}})

	if executions != 0 {
		t.Fatal("expired command was EXECUTED — a stale command must never run (future types write config)")
	}
	got := sink.all()
	if len(got) != 1 || got[0].Status != "failed" {
		t.Fatalf("expired command results = %+v, want one failed report", got)
	}
}

// TestCommandExecutor_IPSecStatus proves the ipsec_status handler (C2b-2b) runs
// the probe against the device API and reports the raw-body JSON envelope.
func TestCommandExecutor_IPSecStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rows":[{"status":"established"}]}`))
	}))
	t.Cleanup(srv.Close)

	sink := &fakeResultSink{}
	e := newCommandExecutor(sink)
	payload := `{"vendor":"opnsense","base_url":"` + srv.URL + `","api_token":"k:s",` +
		`"steps":[{"method":"GET","path":"/api/ipsec/sessions/searchPhase1"}]}`
	e.HandleCommands([]relay.PendingCommand{{
		CommandID: "cmd-status", Type: "ipsec_status", Payload: payload,
	}})

	got := sink.all()
	if len(got) != 1 || got[0].Status != "succeeded" {
		t.Fatalf("ipsec_status results = %+v, want one succeeded report", got)
	}
	if !strings.Contains(got[0].Result, `"status":200`) || !strings.Contains(got[0].Result, "established") {
		t.Errorf("report must carry the step status + raw device body; got %q", got[0].Result)
	}
}

// TestCommandExecutor_IPSecStatus_BadPayload proves a malformed payload fails
// crisply instead of panicking or silently succeeding.
func TestCommandExecutor_IPSecStatus_BadPayload(t *testing.T) {
	sink := &fakeResultSink{}
	e := newCommandExecutor(sink)
	e.HandleCommands([]relay.PendingCommand{{
		CommandID: "cmd-status-bad", Type: "ipsec_status", Payload: `{not json`,
	}})
	got := sink.all()
	if len(got) != 1 || got[0].Status != "failed" {
		t.Fatalf("bad-payload results = %+v, want one failed report", got)
	}
}
