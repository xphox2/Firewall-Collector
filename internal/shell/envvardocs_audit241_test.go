package shell

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docUndocumentedEnvAllowlist lists PROBE_* keys referenced in
// internal/config/config.go that are deliberately NOT documented in
// docs/ENV-VARS.md. It is empty by default: every wired variable must be
// documented. Add a key here ONLY with a comment explaining why it is
// intentionally undocumented (e.g. a deprecated alias kept for one release).
var docUndocumentedEnvAllowlist = map[string]bool{}

// TestEnvVarsDocumented_AUDIT241 pins that every PROBE_* environment variable
// wired in internal/config/config.go appears in docs/ENV-VARS.md. The doc
// calls itself the "authoritative reference", yet PROBE_NETFLOW_SAMPLING_OVERRIDES
// was wired and consumed while absent from it (AUDIT-241) — an operator hitting
// the MikroTik ROS6 sampling bug could not find the escape hatch. This is the
// collector's highest-value doc guard: a new getEnv/parseSamplingOverrides key
// that ships undocumented reds the build.
func TestEnvVarsDocumented_AUDIT241(t *testing.T) {
	const cfgPath = "../../internal/config/config.go"
	const docPath = "../../docs/ENV-VARS.md"

	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Skipf("%s not found (tests must run from the package root); err: %v", cfgPath, err)
	}
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Skipf("%s not found (tests must run from the package root); err: %v", docPath, err)
	}
	docBody := string(doc)

	// Every PROBE_* string literal in config.go is an env-var key: they reach
	// os.Getenv only through the getEnv/parseInt/parseSamplingOverrides helpers,
	// all of which take the key as a string literal.
	keyRe := regexp.MustCompile(`"(PROBE_[A-Z0-9_]+)"`)
	seen := map[string]bool{}
	var keys []string
	for _, m := range keyRe.FindAllStringSubmatch(string(cfg), -1) {
		k := m[1]
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	if len(keys) == 0 {
		t.Fatal("no PROBE_* keys found in internal/config/config.go — the AUDIT-241 guard extracts keys by string literal; a refactor away from literal keys must update this guard.")
	}

	for _, k := range keys {
		if docUndocumentedEnvAllowlist[k] {
			continue
		}
		// Word-boundary match so PROBE_NETFLOW_PORT does not satisfy
		// PROBE_NETFLOW_PORT_EXTRA etc. The doc uses `PROBE_X` in table cells,
		// so require the key followed by a non-identifier char (backtick,
		// space, end of line).
		if !containsEnvKey(docBody, k) {
			t.Errorf("env var %s is wired in %s but not documented in %s — document it (or, if deliberately undocumented, add it to docUndocumentedEnvAllowlist with a reason) (AUDIT-241).", k, "internal/config/config.go", "docs/ENV-VARS.md")
		}
	}
}

// containsEnvKey reports whether body mentions key as a whole token (not as a
// prefix of a longer PROBE_* identifier).
func containsEnvKey(body, key string) bool {
	idx := 0
	for {
		i := strings.Index(body[idx:], key)
		if i < 0 {
			return false
		}
		end := idx + i + len(key)
		if end >= len(body) || !isEnvKeyChar(body[end]) {
			return true
		}
		idx += i + len(key)
	}
}

func isEnvKeyChar(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
