package relay

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestSnapshotSenders_DrainBodyForKeepAlive_L7 is the regression for the
// 2026-06-23 audit L7 finding: the snapshot/detail senders closed the response
// body without reading it to EOF, so net/http could not return the connection to
// the keep-alive pool and opened a fresh TCP/TLS connection on every per-cycle
// send. With the body drained (via drainAndClose), sequential sends reuse one
// connection.
func TestSnapshotSenders_DrainBodyForKeepAlive_L7(t *testing.T) {
	var newConns int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A non-empty response body is exactly what defeats keep-alive when the
		// client doesn't drain it.
		_, _ = io.WriteString(w, `{"ok":true,"note":"non-empty body the client must drain"}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := &Client{Config: Config{ServerURL: srv.URL, RegistrationKey: "k"}, httpClient: srv.Client()}
	c.approved.Store(true)
	c.probeID = 1

	for i := 0; i < 3; i++ {
		if err := c.SendProcessSnapshot(&ProcessSnapshot{}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	if n := atomic.LoadInt32(&newConns); n != 1 {
		t.Errorf("opened %d connections for 3 sequential sends, want 1 (body not drained → keep-alive defeated)", n)
	}
}
