package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The collector advertises its relay wire-format version (SchemaVersionMax) on
// register so the server can detect a probe↔server mismatch instead of
// silently mis-parsing the relay traffic. These tests pin the collector half
// of that handshake (the server half lives in xphox2/Firewall-Monitoring):
//
//  1. Register() sends `schema_version: SchemaVersionMax` in the request body
//     and accepts the server's echoed version on success.
//  2. A 426 (Upgrade Required) — the server is too old for this probe's
//     version — yields an actionable error naming the supported range from
//     the X-Probe-Schema-Version-Supported header.

func TestRegister_AdvertisesSchemaVersion(t *testing.T) {
	var gotVersion int
	var sawField bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("server: bad request body: %v", err)
		}
		if v, ok := req["schema_version"]; ok {
			sawField = true
			if f, ok := v.(float64); ok {
				gotVersion = int(f)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        true,
			"approved":       true,
			"probe_id":       7,
			"probe_name":     "test-probe",
			"schema_version": SchemaVersionMax,
		})
	}))
	defer server.Close()

	c := NewClient(Config{ServerURL: server.URL, RegistrationKey: "k"})
	if err := c.Register(); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	if !sawField {
		t.Fatal("collector did not send a schema_version field on register")
	}
	if gotVersion != SchemaVersionMax {
		t.Errorf("advertised schema_version=%d, want SchemaVersionMax=%d", gotVersion, SchemaVersionMax)
	}
}

func TestRegister_ServerRejectsVersion_Returns426Error(t *testing.T) {
	const supported = "1-1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Probe-Schema-Version-Supported", supported)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUpgradeRequired)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Probe schema_version %d not supported (server supports %s); see MIGRATING.md", SchemaVersionMax, supported),
		})
	}))
	defer server.Close()

	c := NewClient(Config{ServerURL: server.URL, RegistrationKey: "k"})
	err := c.Register()
	if err == nil {
		t.Fatal("Register() should fail on a 426 response")
	}
	msg := err.Error()
	// The error must name the supported range so the operator can correlate
	// it, and must not be the generic "HTTP status 426" fallback.
	if !strings.Contains(msg, supported) {
		t.Errorf("error %q should name the supported range %q", msg, supported)
	}
	if !strings.Contains(msg, "schema_version") {
		t.Errorf("error %q should mention schema_version", msg)
	}
}
