package main

import (
	"strings"
	"testing"

	"firewall-collector/internal/relay"
)

// Tests for AUDIT-212 in the executor itself: a panicking command handler must
// yield exactly one `failed` result (ending the server's at-least-once
// redelivery on attempt 1 of 5) with neither the stack trace nor the payload
// in it, must not wedge the inFlight map, and must not abort the rest of the
// batch.

const secretPayload = `{"api_token":"super-secret-token"}`

func newPanicExecutor(sink *fakeResultSink) (*commandExecutor, *int) {
	e := newCommandExecutor(sink)
	executions := 0
	e.handlers["panicker"] = func(cmd relay.PendingCommand) (string, error) {
		executions++
		panic("nil map write in handler")
	}
	return e, &executions
}

func TestCommandExecutor_PanickingHandler_ReportsFailed(t *testing.T) {
	sink := &fakeResultSink{}
	e, executions := newPanicExecutor(sink)

	e.HandleCommands([]relay.PendingCommand{{
		CommandID: "cmd-panic",
		Type:      "panicker",
		Payload:   secretPayload,
	}})

	if *executions != 1 {
		t.Fatalf("handler executed %d times, want 1", *executions)
	}
	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("reported %d result(s), want exactly 1", len(got))
	}
	if got[0].CommandID != "cmd-panic" || got[0].Status != "failed" {
		t.Errorf("result = %+v, want cmd-panic/failed", got[0])
	}
	// The result text is stored server-side: it must carry neither the local
	// stack trace nor the command payload (which may hold credentials).
	if strings.Contains(got[0].Result, "goroutine") || strings.Contains(got[0].Result, ".go:") {
		t.Errorf("result leaks a stack trace: %q", got[0].Result)
	}
	if strings.Contains(got[0].Result, "super-secret-token") {
		t.Errorf("result leaks the command payload: %q", got[0].Result)
	}
	if !strings.Contains(got[0].Result, "panicked") {
		t.Errorf("result should name the panic crisply, got %q", got[0].Result)
	}
}

// A panic must not leave the CommandID wedged in inFlight: a redelivery of the
// same command re-POSTs the cached failed result (never re-executes, never a
// silent drop).
func TestCommandExecutor_PanickingHandler_NoInFlightWedge(t *testing.T) {
	sink := &fakeResultSink{}
	e, executions := newPanicExecutor(sink)

	cmd := relay.PendingCommand{CommandID: "cmd-panic-redeliver", Type: "panicker", Payload: secretPayload}
	e.HandleCommands([]relay.PendingCommand{cmd})
	e.HandleCommands([]relay.PendingCommand{cmd}) // server redelivery

	if *executions != 1 {
		t.Fatalf("handler executed %d times, want 1 (redelivery must hit the completed cache, not re-run or no-op)", *executions)
	}
	e.mu.Lock()
	wedged := e.inFlight[cmd.CommandID]
	e.mu.Unlock()
	if wedged {
		t.Fatal("CommandID still marked inFlight after the panic — every redelivery would be a silent no-op")
	}
	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("reported %d result(s), want 2 (original failed + cached re-POST)", len(got))
	}
	if got[0] != got[1] {
		t.Errorf("re-POSTed result %+v differs from original %+v — must re-send the CACHED result", got[1], got[0])
	}
	if got[0].Status != "failed" {
		t.Errorf("cached status = %q, want failed", got[0].Status)
	}
}

// A panic in one command must not abort the rest of the batch.
func TestCommandExecutor_PanickingHandler_BatchContinues(t *testing.T) {
	sink := &fakeResultSink{}
	e, _ := newPanicExecutor(sink)

	e.HandleCommands([]relay.PendingCommand{
		{CommandID: "cmd-first-panics", Type: "panicker", Payload: secretPayload},
		{CommandID: "cmd-second-runs", Type: "noop"},
	})

	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("reported %d result(s), want 2 (the panic must not abort the batch)", len(got))
	}
	if got[0].CommandID != "cmd-first-panics" || got[0].Status != "failed" {
		t.Errorf("result[0] = %+v, want cmd-first-panics/failed", got[0])
	}
	if got[1].CommandID != "cmd-second-runs" || got[1].Status != "succeeded" {
		t.Errorf("result[1] = %+v, want cmd-second-runs/succeeded", got[1])
	}
}
