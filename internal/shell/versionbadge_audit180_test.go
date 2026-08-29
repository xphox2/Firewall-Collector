package shell

import (
	"os"
	"regexp"
	"testing"
)

// TestReadmeVersionBadgeMatchesConst_AUDIT180 pins that the README's version
// badge shows exactly the string of `const version` in cmd/collector/main.go.
// The badge had drifted to "1.3.4" against a "1.3.41" binary (AUDIT-180); a
// version badge that lies about the running build is worse than no badge,
// because operators quote it in support and security reports (SECURITY.md
// tells them to). This guard fails the build the next time a release bumps the
// const without bumping the badge.
func TestReadmeVersionBadgeMatchesConst_AUDIT180(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Skipf("README.md not found (tests must run from the package root); err: %v", err)
	}
	mainGo, err := os.ReadFile("../../cmd/collector/main.go")
	if err != nil {
		t.Skipf("cmd/collector/main.go not found (tests must run from the package root); err: %v", err)
	}

	// Robust to the shields.io badge layout: badge/version-<X.Y.Z>-<color>.
	badgeRe := regexp.MustCompile(`badge/version-([0-9]+\.[0-9]+\.[0-9]+)-`)
	bm := badgeRe.FindSubmatch(readme)
	if bm == nil {
		t.Fatal("no `badge/version-X.Y.Z-` version badge found in README.md — the AUDIT-180 guard cannot verify a badge it cannot find; keep the shields.io version badge.")
	}

	constRe := regexp.MustCompile(`const version = "([0-9]+\.[0-9]+\.[0-9]+)"`)
	cm := constRe.FindSubmatch(mainGo)
	if cm == nil {
		t.Fatal("no `const version = \"X.Y.Z\"` found in cmd/collector/main.go — the AUDIT-180 guard reads the badge against this const.")
	}

	if got, want := string(bm[1]), string(cm[1]); got != want {
		t.Errorf("README version badge (%s) does not match cmd/collector/main.go const version (%s) — bump the badge alongside the version const (AUDIT-180).", got, want)
	}
}
