package guardrails

import (
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file is the public-repo hygiene guard. The repository is public, so
// it must never carry internal working material (task notes, audit reports,
// tool settings) or identifying data (real public IP addresses, home
// directories). The guard scans every tracked file, repo-wide:
//
//	(a) no tracked path matches an internal-material glob;
//	(b) every IPv4/IPv6 literal is private, special-purpose, a documentation
//	    or benchmarking address, or on the reviewed allowlist below;
//	(c) no /Users/<name> or /home/<name> path.
//
// Test data uses RFC 5737 (192.0.2/24, 198.51.100/24, 203.0.113/24) and
// RFC 3849 (2001:db8::/32) for external hosts, RFC 2544 (198.18.0.0/15) for
// "our own" public space, RFC 1918 for LANs, and example.* names.

// trackedFile is one tracked, scannable text file.
type trackedFile struct {
	path string // repo-relative, forward slashes
	data []byte
}

// repoRoot returns the repository's top-level directory. It skips the test
// when git or the work tree is unavailable (e.g. a source tarball), because
// a scan that silently saw no files would pass while checking nothing.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git work tree (or git unavailable): %v", err)
	}
	return strings.TrimSpace(string(out))
}

// trackedPaths lists every tracked path relative to the repo root. It runs
// `git ls-files --full-name` FROM the root: run from the package dir, the
// listing would cover only this directory.
func trackedPaths(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "-z", "--full-name")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) < 20 {
		t.Fatalf("git ls-files returned only %d paths from %s — the guard would be scanning almost nothing", len(paths), root)
	}
	return paths
}

// skippedByName lists vendored or binary files that are never scanned: the
// same set the scrub tooling skips. Anything else containing a NUL byte is
// treated as binary too.
func skippedByName(p string) bool {
	base := path.Base(p)
	switch {
	case strings.HasPrefix(p, "vendor/"), strings.Contains(p, "/vendor/"):
		return true
	case strings.HasSuffix(base, ".min.js"), base == "package-lock.json", base == "go.sum":
		return true
	case strings.HasSuffix(base, ".mmdb"), strings.HasSuffix(base, ".woff2"),
		strings.HasSuffix(base, ".png"), strings.HasSuffix(base, ".ico"):
		return true
	}
	return false
}

// trackedTextFiles reads every tracked, non-binary, non-vendored file.
func trackedTextFiles(t *testing.T) []trackedFile {
	t.Helper()
	root := repoRoot(t)
	var files []trackedFile
	for _, p := range trackedPaths(t, root) {
		if skippedByName(p) {
			continue
		}
		data, err := os.ReadFile(root + "/" + p)
		if err != nil {
			// A tracked file deleted in the work tree is not scannable.
			continue
		}
		if bytes.IndexByte(data, 0) >= 0 {
			continue
		}
		files = append(files, trackedFile{path: p, data: data})
	}
	return files
}

// ---------------------------------------------------------------------------
// (a) internal-material paths

// forbiddenPath reports why a tracked path is internal material, or "".
// The same globs are in .gitignore; `scripts/` is forbidden only as a tracked
// path (not ignored) so a future public script is a deliberate decision.
func forbiddenPath(p string) string {
	base := path.Base(p)
	switch {
	case strings.HasPrefix(p, "tasks/"):
		return "internal task notes (tasks/)"
	case strings.HasPrefix(p, "scripts/"):
		return "internal one-off scripts (scripts/)"
	case strings.HasPrefix(p, ".claude/"), strings.Contains(p, "/.claude/"):
		return "local tool settings (.claude/)"
	case p == "docs/AUDIT.md", strings.HasPrefix(p, "docs/audit-20"), strings.HasPrefix(p, "docs/audit-archive/"):
		return "internal audit report"
	case base == "CLAUDE.md", base == "AGENTS.md":
		return "tool working instructions"
	case strings.HasPrefix(base, "session-ses_") && strings.HasSuffix(base, ".md"):
		return "tool session transcript"
	}
	return ""
}

func TestPublicHygiene_NoInternalPaths(t *testing.T) {
	root := repoRoot(t)
	for _, p := range trackedPaths(t, root) {
		if why := forbiddenPath(p); why != "" {
			t.Errorf("%s is tracked but is %s — internal material never belongs in the public repo; remove it from the index (git rm --cached) and keep it outside the repo", p, why)
		}
	}
}

func TestPublicHygiene_ForbiddenPathRules(t *testing.T) {
	bad := []string{"tasks/x", "tasks/lessons.md", "scripts/a.py", ".claude/settings.local.json",
		"docs/AUDIT.md", "docs/audit-2026-01-01.md", "docs/audit-archive/x.md", "CLAUDE.md",
		"sub/AGENTS.md", "session-ses_1.md"}
	good := []string{"docs/FEATURES.md", "internal/tasks.go", "test/guardrails/x_test.go",
		"docs/audit-log-feature.md", "README.md"}
	for _, p := range bad {
		if forbiddenPath(p) == "" {
			t.Errorf("forbiddenPath(%q) = allowed, want forbidden", p)
		}
	}
	for _, p := range good {
		if why := forbiddenPath(p); why != "" {
			t.Errorf("forbiddenPath(%q) = %q, want allowed", p, why)
		}
	}
}

// ---------------------------------------------------------------------------
// (b) IP literals

// allowedV4 are the ranges any IPv4 literal may fall in.
var allowedV4 = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network"; unspecified
		"10.0.0.0/8",      // RFC 1918
		"100.64.0.0/10",   // CGNAT (RFC 6598)
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local
		"172.16.0.0/12",   // RFC 1918
		"192.0.2.0/24",    // TEST-NET-1 (RFC 5737)
		"192.168.0.0/16",  // RFC 1918
		"198.18.0.0/15",   // benchmarking (RFC 2544): "our own" public space in tests
		"198.51.100.0/24", // TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",  // TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved: netmasks and broadcast (255.255.255.x)
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

// ipv4Allowlist is the reviewed list of public IPv4 literals that may appear
// anywhere. Each entry carries its reason. Keep it small: a new entry needs a
// reason a reviewer can check without knowing any private infrastructure.
var ipv4Allowlist = map[string]string{
	"1.1.1.1": "well-known public resolver (Cloudflare), used as a generic reachability example",
	"1.2.3.4": "conventional placeholder address",
	"2.2.2.2": "conventional placeholder address (distinct-target fixtures)",
	"3.3.3.3": "conventional placeholder address (distinct-target fixtures)",
	"8.8.8.8": "well-known public resolver (Google), used as a generic reachability example",
}

// ipv4FileAllowlist is the reviewed per-file allowlist: "path|ip" -> reason.
var ipv4FileAllowlist = map[string]string{
	"internal/netflow/ipfix.go|3.4.2.2": "RFC 7011 section number (§3.4.2.2), not an address",
}

// ipv6Allowlist is the reviewed list of global-unicast IPv6 literals allowed
// outside 2001:db8::/32.
var ipv6Allowlist = map[string]string{
	"2606:4700:4700::1111": "well-known public resolver (Cloudflare)",
}

func v4Allowed(a netip.Addr) bool {
	for _, p := range allowedV4 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseV4 parses dotted-decimal parts as an IPv4 address; ok is false when a
// part is not an octet, i.e. the run is not an address at all.
func parseV4(parts []string) (netip.Addr, bool) {
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, p := range parts {
		if len(p) > 3 {
			return netip.Addr{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// dottedRun matches a maximal dotted-number run, including an optional
// leading and trailing dot so both can be classified.
var dottedRun = regexp.MustCompile(`\.?[0-9]+(?:\.[0-9]+)*\.?`)

// ipFinding is one disallowed literal.
type ipFinding struct {
	line int
	lit  string
}

// scanIPv4 returns every disallowed IPv4 literal in data.
//
//   - A run that starts with "." is an OID fragment and is skipped.
//   - A trailing sentence period is stripped; the run is still checked.
//   - 4 parts: an address.
//   - 5 parts (IP.index or ifIndex.IP): flagged only if neither 4-part window
//     is allowed and at least one window is a public address.
//   - 3 parts followed by ".%d", ".' ||" or ".x": an address template; its
//     /24 must be allowed.
//   - 6+ parts: OIDs, skipped.
func scanIPv4(p string, data []byte) []ipFinding {
	var out []ipFinding
	s := string(data)
	for _, loc := range dottedRun.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]
		// Maximal: the regexp is greedy, but a match can start right after a
		// digit only if the previous match ended there; guard anyway.
		if start > 0 && s[start-1] >= '0' && s[start-1] <= '9' {
			continue
		}
		run := s[start:end]
		if strings.HasPrefix(run, ".") {
			continue // OID fragment
		}
		trailingDot := strings.HasSuffix(run, ".")
		run = strings.TrimSuffix(run, ".")
		parts := strings.Split(run, ".")
		lineNo := strings.Count(s[:start], "\n") + 1
		flag := func(lit string) { out = append(out, ipFinding{line: lineNo, lit: lit}) }
		public := func(a netip.Addr) bool {
			if v4Allowed(a) {
				return false
			}
			lit := a.String()
			if _, ok := ipv4Allowlist[lit]; ok {
				return false
			}
			if _, ok := ipv4FileAllowlist[p+"|"+lit]; ok {
				return false
			}
			return true
		}
		switch len(parts) {
		case 3:
			if !trailingDot {
				continue
			}
			rest := s[end:]
			if !(strings.HasPrefix(rest, "%d") || strings.HasPrefix(rest, "' ||") ||
				(strings.HasPrefix(rest, "x") && (len(rest) == 1 || !isWordByte(rest[1])))) {
				continue
			}
			a, ok := parseV4(append(parts, "0"))
			if ok && public(a) {
				flag(run + ".")
			}
		case 4:
			if a, ok := parseV4(parts); ok && public(a) {
				flag(run)
			}
		case 5:
			first, ok1 := parseV4(parts[:4])
			last, ok2 := parseV4(parts[1:])
			if (ok1 && !public(first)) || (ok2 && !public(last)) {
				continue
			}
			if ok1 || ok2 {
				flag(run)
			}
		}
	}
	return out
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// v6Candidate matches runs of hex digits, colons and dots containing at least
// two colons; only candidates that parse as IPv6 count.
var v6Candidate = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)

var (
	v6Global = netip.MustParsePrefix("2000::/3")
	v6Doc    = netip.MustParsePrefix("2001:db8::/32")
)

// scanIPv6 returns every global-unicast IPv6 literal outside 2001:db8::/32
// that is not allowlisted.
func scanIPv6(data []byte) []ipFinding {
	var out []ipFinding
	s := string(data)
	for _, loc := range v6Candidate.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]
		if start > 0 && isWordByte(s[start-1]) || end < len(s) && isWordByte(s[end]) {
			continue
		}
		cand := strings.TrimSuffix(s[start:end], ".")
		a, err := netip.ParseAddr(cand)
		if err != nil || !a.Is6() || a.Is4In6() {
			continue
		}
		if !v6Global.Contains(a) || v6Doc.Contains(a) {
			continue
		}
		if _, ok := ipv6Allowlist[a.String()]; ok {
			continue
		}
		out = append(out, ipFinding{line: strings.Count(s[:start], "\n") + 1, lit: cand})
	}
	return out
}

func TestPublicHygiene_NoPublicIPLiterals(t *testing.T) {
	for _, f := range trackedTextFiles(t) {
		for _, h := range scanIPv4(f.path, f.data) {
			t.Errorf("%s:%d: public IPv4 literal %q — use RFC 5737 (external hosts), 198.18.0.0/15 (own public space) or RFC 1918 (LANs), or add a reviewed allowlist entry with a reason", f.path, h.line, h.lit)
		}
		for _, h := range scanIPv6(f.data) {
			t.Errorf("%s:%d: global IPv6 literal %q — use 2001:db8::/32 (RFC 3849), or add a reviewed allowlist entry with a reason", f.path, h.line, h.lit)
		}
	}
}

// ip builds a dotted literal at run time so this file carries no literal the
// guard would flag.
func ip(parts ...string) string { return strings.Join(parts, ".") }

func TestPublicHygiene_IPv4Rules(t *testing.T) {
	pub := ip("9", "9", "9", "9") // a public address, not allowlisted
	cases := []struct {
		name string
		text string
		want int
	}{
		{"public 4-part", "x " + pub + " y", 1},
		{"public 4-part, sentence period", "see " + pub + ".", 1},
		{"private", "x 192.168.1.10 y", 0},
		{"documentation", "x 203.0.113.9 y", 0},
		{"benchmarking", "x 198.19.9.1 y", 0},
		{"netmask", "mask 255.255.255.252", 0},
		{"not octets", "x 999.1.1.1 y", 0},
		{"OID fragment", "oid .1.3.6.1.4.1." + pub, 0},
		{"version-like 3 parts", "v7.4.12 ok", 0},
		{"5-part IP.index, first window private", "192.168.1.5.3", 0},
		{"5-part ifIndex.IP, last window private", "5.192.168.1.1", 0},
		{"5-part both windows public", pub + ".9", 1},
		{"long OID", "1.3.6.1.2.1.4.20.1.2", 0},
		{"template %d, public", `"` + ip("9", "9", "9") + `.%d"`, 1},
		{"template %d, benchmarking", `"198.19.9.%d"`, 0},
		{"template SQL, public", "'" + ip("9", "9", "9") + ".' || g", 1},
		{"template .x, public", ip("9", "9", "9") + ".x", 1},
		{"template .x, private", "10.1.2.x", 0},
		{"3 parts no template", ip("9", "9", "9") + " ok", 0},
		{"allowlisted", "dns 8.8.8.8", 0},
	}
	for _, c := range cases {
		if got := len(scanIPv4("x.go", []byte(c.text))); got != c.want {
			t.Errorf("%s: scanIPv4(%q) = %d findings, want %d", c.name, c.text, got, c.want)
		}
	}
}

func TestPublicHygiene_IPv6Rules(t *testing.T) {
	pub := strings.Join([]string{"2a00", "1450", "4001", "", "1"}, ":")
	cases := []struct {
		text string
		want int
	}{
		{"addr " + pub + " x", 1},
		{"addr 2001:db8::1 x", 0},
		{"addr fe80::1 x", 0},
		{"addr fd00::1 x", 0},
		{"allow 2606:4700:4700::1111", 0},
		{"ports 2055:2055", 0},
		{"time 21:39:14", 0},
		{"mac aa:bb:cc:dd:ee:ff", 0},
	}
	for _, c := range cases {
		if got := len(scanIPv6([]byte(c.text))); got != c.want {
			t.Errorf("scanIPv6(%q) = %d findings, want %d", c.text, got, c.want)
		}
	}
}

func TestPublicHygiene_AllowlistsHaveReasons(t *testing.T) {
	for _, m := range []map[string]string{ipv4Allowlist, ipv4FileAllowlist, ipv6Allowlist} {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.TrimSpace(m[k]) == "" {
				t.Errorf("allowlist entry %q has no reason", k)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// (c) home-directory paths

var homePath = regexp.MustCompile(`/(?:Users|home)/([A-Za-z0-9._-]+)`)

// homePathAllowlist is the reviewed list of generic home-directory names.
var homePathAllowlist = map[string]string{}

func scanHomePaths(data []byte) []ipFinding {
	var out []ipFinding
	s := string(data)
	for _, m := range homePath.FindAllStringSubmatchIndex(s, -1) {
		name := s[m[2]:m[3]]
		if _, ok := homePathAllowlist[name]; ok {
			continue
		}
		out = append(out, ipFinding{line: strings.Count(s[:m[0]], "\n") + 1, lit: s[m[0]:m[1]]})
	}
	return out
}

func TestPublicHygiene_NoHomePaths(t *testing.T) {
	for _, f := range trackedTextFiles(t) {
		for _, h := range scanHomePaths(f.data) {
			t.Errorf("%s:%d: home-directory path %q — use a neutral path such as /srv/firewall-collector/...", f.path, h.line, h.lit)
		}
	}
}

func TestPublicHygiene_HomePathRules(t *testing.T) {
	if n := len(scanHomePaths([]byte("cd /" + "Users/x/proj"))); n != 1 {
		t.Errorf("/Users/<name> not flagged (%d findings)", n)
	}
	if n := len(scanHomePaths([]byte("cd /" + "home/someone/proj"))); n != 1 {
		t.Errorf("/home/<name> not flagged (%d findings)", n)
	}
	if n := len(scanHomePaths([]byte("cd /srv/firewall-collector"))); n != 0 {
		t.Errorf("neutral path flagged (%d findings)", n)
	}
}
