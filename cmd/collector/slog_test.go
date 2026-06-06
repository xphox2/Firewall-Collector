package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// withEnv sets the given env var for the duration of the test (using
// t.Setenv, which restores the original value at cleanup) and returns a
// function the test can call to inspect the current value.
func withEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

// TestLogSetup_DefaultsToInfoText verifies that with no env vars set, the
// default slog level is info and the handler is text-based.
func TestLogSetup_DefaultsToInfoText(t *testing.T) {
	t.Setenv("PROBE_LOG_LEVEL", "")
	t.Setenv("PROBE_LOG_FORMAT", "")

	var buf bytes.Buffer
	setupLoggerWith(&buf)

	if got := slog.Default().Enabled(context.TODO(), slog.LevelInfo); !got {
		t.Error("default level should enable Info")
	}
	if got := slog.Default().Enabled(context.TODO(), slog.LevelDebug); got {
		t.Error("default level should NOT enable Debug")
	}

	slog.Info("hello", slog.String("k", "v"))
	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected text format with level=INFO, got: %q", out)
	}
	if !strings.Contains(out, "msg=hello") {
		t.Errorf("expected msg=hello in text output, got: %q", out)
	}
	if !strings.Contains(out, "k=v") {
		t.Errorf("expected key k=v in text output, got: %q", out)
	}
}

// TestLogSetup_JsonFormat_ProducesValidJSON verifies that PROBE_LOG_FORMAT=json
// produces output that is parseable as a JSON object containing the standard
// slog fields.
func TestLogSetup_JsonFormat_ProducesValidJSON(t *testing.T) {
	withEnv(t, "PROBE_LOG_LEVEL", "info")
	withEnv(t, "PROBE_LOG_FORMAT", "json")

	var buf bytes.Buffer
	setupLoggerWith(&buf)

	slog.Info("json-test", slog.String("device_id", "42"), slog.Int("count", 3))
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("expected at least one log line, got empty buffer")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\nline: %s", err, line)
	}
	if got := parsed["msg"]; got != "json-test" {
		t.Errorf("msg = %v, want %q", got, "json-test")
	}
	if got := parsed["level"]; got != "INFO" {
		t.Errorf("level = %v, want INFO", got)
	}
	if got := parsed["device_id"]; got != "42" {
		t.Errorf("device_id = %v, want \"42\"", got)
	}
	if got, ok := parsed["count"].(float64); !ok || got != 3 {
		t.Errorf("count = %v (type %T), want 3 (number)", parsed["count"], parsed["count"])
	}
	if _, ok := parsed["time"]; !ok {
		t.Error("time field should be present in JSON output")
	}
}

// TestLogSetup_DebugLevel_IncludesDebugLines verifies that PROBE_LOG_LEVEL=debug
// allows debug-level log lines to be emitted.
func TestLogSetup_DebugLevel_IncludesDebugLines(t *testing.T) {
	withEnv(t, "PROBE_LOG_LEVEL", "debug")
	withEnv(t, "PROBE_LOG_FORMAT", "text")

	var buf bytes.Buffer
	setupLoggerWith(&buf)

	slog.Debug("debug-payload", slog.String("src", "test"))
	out := buf.String()
	if !strings.Contains(out, "level=DEBUG") {
		t.Errorf("debug line should be emitted, got: %q", out)
	}
	if !strings.Contains(out, "msg=debug-payload") {
		t.Errorf("debug message text missing, got: %q", out)
	}
	if !strings.Contains(out, "src=test") {
		t.Errorf("debug structured field missing, got: %q", out)
	}
}

// TestLogSetup_UnknownLevelFallsBackToInfo verifies that a typo in the level
// env var does not crash; we fall back to info and emit a warning to stderr.
func TestLogSetup_UnknownLevelFallsBackToInfo(t *testing.T) {
	withEnv(t, "PROBE_LOG_LEVEL", "nonsense")
	withEnv(t, "PROBE_LOG_FORMAT", "text")

	// Capture stderr for the unknown-level warning. The warning is printed
	// via fmt.Fprintf to os.Stderr in setupLoggerWith.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = origStderr }()

	var buf bytes.Buffer
	setupLoggerWith(&buf)
	_ = w.Close()

	var stderrBuf bytes.Buffer
	_, _ = stderrBuf.ReadFrom(r)
	stderrOut := stderrBuf.String()
	if !strings.Contains(stderrOut, "PROBE_LOG_LEVEL") {
		t.Errorf("expected stderr warning mentioning PROBE_LOG_LEVEL, got: %q", stderrOut)
	}

	if got := slog.Default().Enabled(context.TODO(), slog.LevelInfo); !got {
		t.Error("fallback level should enable Info")
	}
	if got := slog.Default().Enabled(context.TODO(), slog.LevelDebug); got {
		t.Error("fallback level should NOT enable Debug")
	}
}

// TestLogSetup_AllLevels verifies every documented level value is accepted.
func TestLogSetup_AllLevels(t *testing.T) {
	cases := []struct {
		level string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
	}
	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			withEnv(t, "PROBE_LOG_LEVEL", tc.level)
			var buf bytes.Buffer
			setupLoggerWith(&buf)
			if got := slog.Default().Enabled(context.TODO(), tc.want); !got {
				t.Errorf("level=%q: expected %v to be enabled", tc.level, tc.want)
			}
		})
	}
}
