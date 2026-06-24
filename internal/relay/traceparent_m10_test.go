package relay

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var w3cTraceparent = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`)

// TestNewTraceContext_Format_M10 pins the W3C traceparent shape and that the
// request ID is the trace ID (2026-06-23 audit, M10).
func TestNewTraceContext_Format_M10(t *testing.T) {
	tp, rid := newTraceContext()
	if !w3cTraceparent.MatchString(tp) {
		t.Errorf("traceparent %q is not W3C-valid (00-<32hex>-<16hex>-01)", tp)
	}
	if !strings.HasPrefix(tp, "00-"+rid+"-") {
		t.Errorf("requestID %q is not the trace ID of %q", rid, tp)
	}
	if tp2, _ := newTraceContext(); tp == tp2 {
		t.Error("two trace contexts must be unique")
	}
}

// TestDoAuthenticatedRequest_InjectsTraceContext_M10 verifies the relay sets the
// traceparent + X-Request-ID headers on outgoing requests.
func TestDoAuthenticatedRequest_InjectsTraceContext_M10(t *testing.T) {
	var gotTP, gotRID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTP = r.Header.Get("traceparent")
		gotRID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{Config: Config{ServerURL: srv.URL, RegistrationKey: "k"}, httpClient: srv.Client()}
	resp, err := c.doAuthenticatedRequest("POST", srv.URL, []byte("{}"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if !w3cTraceparent.MatchString(gotTP) {
		t.Errorf("server saw traceparent %q, want W3C-valid", gotTP)
	}
	if gotRID == "" || !strings.Contains(gotTP, gotRID) {
		t.Errorf("X-Request-ID %q is not embedded in traceparent %q", gotRID, gotTP)
	}
}
