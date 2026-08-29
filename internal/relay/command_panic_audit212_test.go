package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHeartbeat_CommandHandlerPanic_ProcessSurvives pins AUDIT-212 at the
// dispatch layer: the pending-commands handler runs under safego.Go, so a
// panicking executor is recovered (were it a bare `go`, the panic would kill
// this whole test process) and the NEXT heartbeat's batch still dispatches —
// the command channel keeps working.
func TestHeartbeat_CommandHandlerPanic_ProcessSurvives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"pending_commands":[` +
			`{"command_id":"cmd-boom","device_id":3,"type":"noop","payload":"{}","expires_at":"2030-01-01T00:00:00Z"}]}`))
	}))
	defer srv.Close()

	c := commandChannelClient(srv, 4)
	received := make(chan struct{}, 2)
	c.SetCommandHandler(func(cmds []PendingCommand) {
		received <- struct{}{}
		panic("command executor exploded")
	})

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat #1: %v", err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("first heartbeat batch was not dispatched")
	}

	// The panic above is recovered on the safego dispatch goroutine; a second
	// heartbeat batch must still reach the handler.
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat #2: %v", err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("second heartbeat batch was not dispatched — the executor panic broke command dispatch")
	}
}
