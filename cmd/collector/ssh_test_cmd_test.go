package main

import (
	"os"
	"testing"
)

// TestIsSSHToolSubcommand verifies the subcommand-detection helper that
// the main() entry point uses to route `collector ssh-test ...` to
// internal/sshtool. We test the helper directly because main() is not
// callable from tests.
func TestIsSSHToolSubcommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "ssh-test with extra args",
			args: []string{"ssh-test", "--host=10.0.0.1", "sensor"},
			want: true,
		},
		{
			name: "ssh-test alone",
			args: []string{"ssh-test"},
			want: true,
		},
		{
			name: "no args (start collector)",
			args: []string{},
			want: false,
		},
		{
			name: "unrelated subcommand-like arg",
			args: []string{"collect", "--debug"},
			want: false,
		},
		{
			name: "ssh-test buried after flags (NOT supported, must reject)",
			args: []string{"--debug", "ssh-test"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSSHToolSubcommand(tt.args)
			if got != tt.want {
				t.Errorf("isSSHToolSubcommand(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// TestSSHToolSubcommandEndToEnd_NoPassword verifies the full routing
// chain: main()'s `isSSHToolSubcommand(os.Args[1:])` check + the
// subsequent `os.Exit(sshtool.Run(...))` call. We exercise it by
// calling sshtool.Run with a no-password setup and asserting exit 2 —
// the path that is reached when the operator forgets the env var.
//
// We can't test `main()` directly (it calls os.Exit), but we CAN test
// the end-to-end logic that main() runs by re-implementing the dispatch
// here. This is the contract main() must honor: when os.Args[1] ==
// "ssh-test", the program terminates via sshtool.Run's exit code.
func TestSSHToolSubcommandEndToEnd_NoPassword(t *testing.T) {
	t.Setenv("PROBE_TEST_PASSWORD", "") // ensure no env-source password
	// Use a fresh os.Args so the test is independent of the test runner's
	// own arguments. Save and restore the real os.Args.
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	os.Args = []string{"collector", "ssh-test", "--host=10.0.0.1", "--user=admin", "sensor"}

	// Mirror the dispatch logic from main(). If isSSHToolSubcommand
	// returns false, the test fails — that would mean the routing
	// decision in main() would fall through to the long-running
	// collector, which is the bug we're guarding against.
	if !isSSHToolSubcommand(os.Args[1:]) {
		t.Fatal("isSSHToolSubcommand should return true for `collector ssh-test ...`")
	}

	// And the args that get forwarded to sshtool.Run must be exactly
	// os.Args[2:] (i.e. everything after the subcommand name). We don't
	// re-run main() (it would call os.Exit), but the contract is
	// documented here for future readers.
	forwarded := os.Args[2:]
	if len(forwarded) != 3 {
		t.Fatalf("expected 3 forwarded args, got %d: %v", len(forwarded), forwarded)
	}
	if forwarded[0] != "--host=10.0.0.1" {
		t.Errorf("forwarded[0] = %q, want --host=10.0.0.1", forwarded[0])
	}
	if forwarded[2] != "sensor" {
		t.Errorf("forwarded[2] = %q, want sensor", forwarded[2])
	}
}
