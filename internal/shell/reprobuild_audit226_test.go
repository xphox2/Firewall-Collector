package shell

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestReproducibleBuildFlags_AUDIT226 pins that the Dockerfile builds the
// collector binary with -trimpath and -buildvcs=false (parity with the
// server's AUDIT-102). Without them the same source yields different bytes
// per build host (embedded build paths, VCS stamping), so an operator
// cannot verify a binary running on a customer management LAN by
// rebuild-and-compare against the tagged source.
func TestReproducibleBuildFlags_AUDIT226(t *testing.T) {
	const path = "../../Dockerfile"
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("Dockerfile not found at %s (tests must run from the package root); err: %v", path, err)
	}
	defer f.Close()

	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "go build") || !strings.Contains(line, "-o firewall-collector") {
			continue
		}
		found = true
		for _, flag := range []string{"-trimpath", "-buildvcs=false"} {
			if !strings.Contains(line, flag) {
				t.Errorf("Dockerfile build line lacks %s — the shipped binary is no longer reproducible across build hosts (AUDIT-226): %s", flag, strings.TrimSpace(line))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading Dockerfile: %v", err)
	}
	if !found {
		t.Fatal("no `go build ... -o firewall-collector` line found in the Dockerfile — update this guard alongside the build change (AUDIT-226).")
	}
}
