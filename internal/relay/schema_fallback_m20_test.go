package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestParseSchemaRange_M20 covers the server support-header parser.
func TestParseSchemaRange_M20(t *testing.T) {
	cases := []struct {
		in       string
		min, max int
		ok       bool
	}{
		{"1-2", 1, 2, true},
		{"1-1", 1, 1, true},
		{"2", 2, 2, true},
		{"", 0, 0, false},
		{"garbage", 0, 0, false},
		{"3-1", 0, 0, false}, // inverted
	}
	for _, c := range cases {
		lo, hi, ok := parseSchemaRange(c.in)
		if ok != c.ok || (ok && (lo != c.min || hi != c.max)) {
			t.Errorf("parseSchemaRange(%q) = (%d,%d,%v), want (%d,%d,%v)", c.in, lo, hi, ok, c.min, c.max, c.ok)
		}
	}
}

// TestRegister_FallsBackToV1OnUpgradeRequired_M20 pins the 2026-07-01 audit M20
// fix: a v2 collector registering against a v1-only server must NOT hard-fail
// (which crash-looped and stopped all site telemetry). It re-registers at the
// highest mutually-supported version (v1) and succeeds.
func TestRegister_FallsBackToV1OnUpgradeRequired_M20(t *testing.T) {
	var mu sync.Mutex
	var advertised []int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SchemaVersion int `json:"schema_version"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		advertised = append(advertised, body.SchemaVersion)
		mu.Unlock()

		// v1-only server: reject anything above 1 with 426 + the supported range.
		if body.SchemaVersion > 1 {
			w.Header().Set("X-Probe-Schema-Version-Supported", "1-1")
			w.WriteHeader(http.StatusUpgradeRequired)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"probe_id":7,"probe_name":"p","approved":true,"schema_version":1}`))
	}))
	defer srv.Close()

	c := &Client{Config: Config{RegistrationKey: "k", ServerURL: srv.URL}, httpClient: srv.Client()}
	if err := c.Register(); err != nil {
		t.Fatalf("Register must fall back to v1 and succeed, got: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(advertised) != 2 || advertised[0] != SchemaVersionMax || advertised[1] != 1 {
		t.Errorf("advertised versions = %v, want [%d 1] (v2 then a v1 retry)", advertised, SchemaVersionMax)
	}
	if got := c.negotiatedSchema.Load(); got != 1 {
		t.Errorf("negotiated schema = %d, want 1", got)
	}
}
