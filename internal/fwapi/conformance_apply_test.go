package fwapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestRunApply_ConformanceAbort_NoWrite proves the pre-write conformance gate
// aborts a deploy whose rendered step carries a device-invalid value BEFORE any
// write reaches the device, and reports the offending field.
func TestRunApply_ConformanceAbort_NoWrite(t *testing.T) {
	f := newFakeOPNsense(t, "fwm-t9")
	specRaw, _ := json.Marshal(paritySpec("opnsense"))

	// A single addConnection step with a strongSwan-style proposal OPNsense rejects.
	steps := []ApplyStep{{
		Kind: "http_api", Method: "POST", Path: "/api/ipsec/connections/addConnection",
		Body: `{"connection":{"proposals":"aes256gcm16-prfsha384-ecp384"}}`,
	}}
	p := ApplyPayload{
		Vendor: "opnsense", Op: "apply", BaseURL: f.srv.URL, APIToken: "key:secret",
		InsecureTLS: true, Steps: steps, Checksum: checksumSteps(steps),
		ValidationSpec: specRaw,
	}

	rep := RunApply(context.Background(), p)

	if !rep.Aborted {
		t.Fatalf("expected pre-write abort, got %+v", rep)
	}
	if rep.Applied {
		t.Errorf("must not be applied")
	}
	if f.seq != 0 {
		t.Errorf("no write must reach the device; fake saw %d add(s)", f.seq)
	}
	if !strings.Contains(rep.Error, "conformance") || !strings.Contains(rep.Error, "proposals") {
		t.Errorf("error should name the conformance failure + field; got %q", rep.Error)
	}
}

// TestRunApply_NoSpec_SkipsGate confirms an apply with no ValidationSpec proceeds
// (backward compatible with an older server).
func TestRunApply_NoSpec_SkipsGate(t *testing.T) {
	f := newFakeOPNsense(t, "fwm-t9")
	steps := []ApplyStep{{
		Kind: "http_api", Method: "POST", Path: "/api/ipsec/connections/addConnection",
		Body: `{"connection":{"proposals":"aes256gcm16-prfsha384-ecp384"}}`, CaptureAs: "conn",
	}}
	p := ApplyPayload{
		Vendor: "opnsense", Op: "apply", BaseURL: f.srv.URL, APIToken: "key:secret",
		InsecureTLS: true, Steps: steps, Checksum: checksumSteps(steps),
		// no ValidationSpec
	}
	rep := RunApply(context.Background(), p)
	if rep.Aborted {
		t.Errorf("no spec → conformance gate skipped, should not abort pre-write: %+v", rep)
	}
}

// TestRunApply_MalformedSpec_Aborts proves the conformance gate fails CLOSED: a
// ValidationSpec that is present but unparseable aborts the apply before any
// write, instead of silently disabling the gate (which would be
// indistinguishable from "older server shipped no spec").
func TestRunApply_MalformedSpec_Aborts(t *testing.T) {
	f := newFakeOPNsense(t, "fwm-t9")
	steps := []ApplyStep{{
		Kind: "http_api", Method: "POST", Path: "/api/ipsec/connections/addConnection",
		Body: `{"connection":{"proposals":"aes256gcm16-sha384-ecp384"}}`, CaptureAs: "conn",
	}}
	p := ApplyPayload{
		Vendor: "opnsense", Op: "apply", BaseURL: f.srv.URL, APIToken: "key:secret",
		InsecureTLS: true, Steps: steps, Checksum: checksumSteps(steps),
		ValidationSpec: []byte(`{"objects": [`), // truncated / invalid JSON
	}

	rep := RunApply(context.Background(), p)

	if !rep.Aborted {
		t.Fatalf("malformed spec must abort pre-write (fail closed), got %+v", rep)
	}
	if rep.Applied {
		t.Errorf("must not be applied")
	}
	if f.seq != 0 {
		t.Errorf("no write must reach the device; fake saw %d add(s)", f.seq)
	}
	if !strings.Contains(rep.Error, "malformed validation_spec") {
		t.Errorf("error should name the malformed spec; got %q", rep.Error)
	}
}
