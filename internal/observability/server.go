package observability

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server wraps the HTTP server that serves /healthz, /readyz, and
// /metrics. It is started once at collector startup and shut down
// during c.stop().
//
// Lifecycle: NewServer → Start (in a goroutine) → Stop. Start is
// idempotent — a second call is a no-op, so a misbehaving caller
// can't open two listeners on the same port.
type Server struct {
	metrics *Metrics
	addr    string

	httpServer *http.Server
	listener   net.Listener

	startOnce sync.Once
	stopOnce  sync.Once
	started   chan struct{}
	stopped   chan struct{}
	startErr  error
}

// NewServer returns a Server bound to addr (e.g. ":9090"). The server
// does not begin listening until Start is called.
func NewServer(m *Metrics, addr string) *Server {
	return &Server{
		metrics: m,
		addr:    addr,
		started: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// Start binds the listener and serves in a goroutine. It returns
// immediately once the listener is bound (or once an error is
// observed). The actual read loop continues in the background; callers
// wait on the started channel to know when /metrics is reachable.
//
// Bind errors are returned synchronously: a second Start call returns
// nil (idempotent) and a Start against an already-bound port returns
// the underlying error so the operator can fix the config and restart.
func (s *Server) Start() error {
	s.startOnce.Do(func() {
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			s.startErr = fmt.Errorf("metrics: bind %s: %w", s.addr, err)
			close(s.started)
			return
		}
		s.listener = ln
		s.httpServer = &http.Server{
			Handler:           s.metrics.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		log.Printf("[Observability] Metrics server listening on %s", ln.Addr())
		close(s.started)
		go s.serve()
	})
	<-s.started
	return s.startErr
}

// serve runs the HTTP loop until the listener is closed. Errors
// other than the expected ErrServerClosed are logged so the operator
// can see unexpected shutdowns in the journal.
func (s *Server) serve() {
	defer close(s.stopped)
	err := s.httpServer.Serve(s.listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[Observability] metrics server stopped unexpectedly: %v", err)
	}
}

// Stop performs a graceful shutdown. It is safe to call multiple
// times and safe to call even if Start was never called (in which
// case it returns nil immediately).
//
// The supplied context bounds the shutdown wait. The default http
// library has no timeout of its own; in practice Shutdown returns
// within a few ms once the listener is closed.
func (s *Server) Stop(ctx context.Context) error {
	var err error
	s.stopOnce.Do(func() {
		if s.httpServer == nil {
			return
		}
		err = s.httpServer.Shutdown(ctx)
		// Wait for serve() to actually exit so we don't race the next
		// startup with stale goroutines. Bounded by the context.
		select {
		case <-s.stopped:
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
		}
	})
	return err
}

// Addr returns the actual bound address. Only valid after Start has
// returned nil. Useful for tests that bind to ":0" and need to know
// the kernel-assigned port.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}
