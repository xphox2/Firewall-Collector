package snmp

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"firewall-collector/internal/relay"
)

func withCapturedLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

func TestTrapReceiver_CommunityMismatch_Drops(t *testing.T) {
	const want = "public"
	tr := NewTrapReceiver("127.0.0.1", 0, want)

	if got := tr.allowCommunity("private"); got {
		t.Errorf("allowCommunity(%q) = true, want false (expected %q)", "private", want)
	}
	if got := tr.allowCommunity(""); got {
		t.Errorf("allowCommunity(\"\") = true, want false — empty packet community must be rejected, not silently accepted")
	}
	if got := tr.allowCommunity(want); !got {
		t.Errorf("allowCommunity(%q) = false, want true", want)
	}
}

func TestTrapReceiver_CommunityMismatch_LogsDrop(t *testing.T) {
	tr := NewTrapReceiver("127.0.0.1", 0, "public")

	out := withCapturedLog(t, func() {
		if tr.allowCommunity("private") {
			t.Fatal("expected drop")
		}
	})
	if !strings.Contains(out, "community mismatch") {
		t.Errorf("expected a 'community mismatch' log line, got: %q", out)
	}
	if !strings.Contains(out, "public") || !strings.Contains(out, "private") {
		t.Errorf("expected the log to mention both expected and got community, got: %q", out)
	}
}

func TestTrapReceiver_Start_EmptyCommunity_RefusesError(t *testing.T) {
	tr := NewTrapReceiver("127.0.0.1", 1162, "")

	err := tr.Start(func(*relay.TrapEvent) {})
	if err == nil {
		t.Fatal("Start() with empty community returned nil error; want an error that explains the spoofing hazard")
	}
	if !strings.Contains(err.Error(), "PROBE_SNMP_TRAP_COMMUNITY") {
		t.Errorf("error should name the env var, got: %v", err)
	}
}
