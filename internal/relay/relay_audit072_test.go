package relay

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestHTTPTransport_MaxIdleConns_Respected pins the AUDIT-072 per-host idle
// pool cap (50, was 10). 60 concurrent requests to the same host must leave
// the transport with at most 50 idle connections to that host; the transport
// closes the overflow as soon as the response is read, which is observable
// from the server side via ConnState.
func TestHTTPTransport_MaxIdleConns_Respected(t *testing.T) {
	c := NewClient(Config{RegistrationKey: "test"})
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if tr.MaxIdleConns != 200 {
		t.Errorf("MaxIdleConns = %d, want 200 (AUDIT-072)", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 50 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 50 (AUDIT-072)", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}

	var mu sync.Mutex
	idle := make(map[net.Conn]struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		switch state {
		case http.StateIdle:
			idle[conn] = struct{}{}
		case http.StateClosed:
			delete(idle, conn)
		}
	}
	srv.Start()
	defer srv.Close()

	const N = 60
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			resp, err := c.httpClient.Get(srv.URL)
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			_, _ = resp.Body.Read(make([]byte, 1))
			resp.Body.Close()
		}()
	}
	wg.Wait()

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	n := len(idle)
	mu.Unlock()

	if n > 50 {
		t.Errorf("idle conns to host = %d, want <= 50 (MaxIdleConnsPerHost cap)", n)
	}
}

// TestHTTPTransport_ResponseHeaderTimeout_Triggers pins the AUDIT-072 10s
// header timeout. Structural assertion checks the production value;
// behavioral assertion uses a tighter timeout (200ms vs. a 2s server stall)
// so the test completes in well under a second. The mechanism that fires at
// 200ms is the same that fires at 10s in production.
func TestHTTPTransport_ResponseHeaderTimeout_Triggers(t *testing.T) {
	c := NewClient(Config{RegistrationKey: "test"})
	tr := c.httpClient.Transport.(*http.Transport)
	if tr.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 10s (AUDIT-072)", tr.ResponseHeaderTimeout)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fast := &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 200 * time.Millisecond,
		ForceAttemptHTTP2:     true,
	}
	client := &http.Client{Transport: fast, Timeout: 10 * time.Second}

	start := time.Now()
	resp, err := client.Get(srv.URL)
	elapsed := time.Since(start)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("request took %v, want < 1.5s (ResponseHeaderTimeout should fire ~200ms)", elapsed)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("request returned too fast: %v (server delay was 2s)", elapsed)
	}
}

// TestHTTPTransport_HTTP2_Used pins the AUDIT-072 ForceAttemptHTTP2 flag.
// Go 1.25's net/http server speaks HTTP/2 automatically when the TLS config
// advertises "h2" in NextProtos — no external dependency required.
func TestHTTPTransport_HTTP2_Used(t *testing.T) {
	c := NewClient(Config{RegistrationKey: "test", InsecureSkipVerify: true})
	tr := c.httpClient.Transport.(*http.Transport)
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false, want true (AUDIT-072 tuning missing)")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	defer srv.Close()

	resp, err := c.httpClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.Proto != "HTTP/2.0" {
		t.Errorf("resp.Proto = %q, want %q (ForceAttemptHTTP2 ineffective?)", resp.Proto, "HTTP/2.0")
	}
}
