// Package shell holds source-level guardrail tests over non-Go artifacts
// (workflows, Dockerfile) — the same convention as the server repo's
// internal/shell package.
package shell

import (
	"os"
	"strings"
	"testing"
)

// TestCIWorkflow_PinnedToolsAndPermissions_AUDIT178 pins that the CI
// workflow installs its gate tools at pinned versions and declares a
// least-privilege token. The pre-fix workflow installed staticcheck@latest
// and govulncheck@latest, so a new tool release (or a vulnerability-DB
// update) could red CI out from under an unrelated PR — which already
// happened once (see CHANGELOG 1.3.34). It also had no permissions: block,
// inheriting the repo-default GITHUB_TOKEN write scope neither job needs.
func TestCIWorkflow_PinnedToolsAndPermissions_AUDIT178(t *testing.T) {
	const path = "../../.github/workflows/docker.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("workflow not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "go install") && strings.Contains(line, "@latest") {
			t.Errorf("docker.yml installs a tool @latest again (%q) — pin gate tools (staticcheck, govulncheck, gosec) to exact versions so a new release can't red CI under an unrelated PR (AUDIT-178).", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(body, "\npermissions:") {
		t.Error("docker.yml has no top-level permissions: block — jobs inherit the repo-default GITHUB_TOKEN write scope neither job needs (AUDIT-178); declare `permissions: contents: read`.")
	}
	// AUDIT-224: the gosec gate must exist and stay pinned.
	if !strings.Contains(body, "gosec/v2/cmd/gosec@v") {
		t.Error("docker.yml no longer installs a pinned gosec — the collector parses the most hostile input in the system and must keep its security-scan gate (AUDIT-224).")
	}
	if !strings.Contains(body, "run: gosec") {
		t.Error("docker.yml no longer runs gosec — the security-scan gate is gone (AUDIT-224).")
	}
}
