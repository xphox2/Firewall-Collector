package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestSchemaVersionMax_IsFramingContract pins the wire-format range this
// collector speaks: v6 is the syslog framing contract (collector 1.3.50 /
// server 0.11.296) and Min stays 1 so mixed fleets keep working. The server's
// relay.SchemaVersionMax / SchemaVersionMin must match (MIGRATING.md).
func TestSchemaVersionMax_IsFramingContract(t *testing.T) {
	if SchemaVersionMax != 6 {
		t.Fatalf("SchemaVersionMax = %d, want 6 (syslog framing contract)", SchemaVersionMax)
	}
	if SchemaVersionMin != 1 {
		t.Fatalf("SchemaVersionMin = %d, want 1 (raising it is a transition release, not this one)", SchemaVersionMin)
	}
}

// TestRegister_V6FallsBackToV5AgainstV5Server pins the Phase 1 deploy order:
// the server (0.11.296) ships before the collector (1.3.50), but a 1.3.50
// collector that reaches an older server advertising `1-5` must not fail —
// v6 adds nothing the collector gates on, so v5 is a complete, correct
// fallback. The register call advertises 6, takes the 426, re-registers as 5
// and records 5 as the negotiated version.
func TestRegister_V6FallsBackToV5AgainstV5Server(t *testing.T) {
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

		// A pre-0.11.296 server: accepts 1-5 and rejects anything above with
		// 426 + the supported range.
		if body.SchemaVersion > 5 {
			w.Header().Set("X-Probe-Schema-Version-Supported", "1-5")
			w.WriteHeader(http.StatusUpgradeRequired)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"probe_id":7,"probe_name":"p","approved":true,"schema_version":5}`))
	}))
	defer srv.Close()

	c := &Client{Config: Config{RegistrationKey: "k", ServerURL: srv.URL}, httpClient: srv.Client()}
	if err := c.Register(); err != nil {
		t.Fatalf("Register must fall back to v5 and succeed, got: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(advertised) != 2 || advertised[0] != 6 || advertised[1] != 5 {
		t.Errorf("advertised versions = %v, want [6 5] (v6 first, then one v5 retry)", advertised)
	}
	if got := c.negotiatedSchema.Load(); got != 5 {
		t.Errorf("negotiated schema = %d, want 5", got)
	}
}
