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
//	(c) no /Users/<name>, /home/<name> or C:\Users\<name> path.
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
	case base == "CLAUDE.md", base == "AGENTS.md", base == "lessons.md":
		return "tool working instructions / local working notes"
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
		"sub/AGENTS.md", "lessons.md", "docs/lessons.md", "session-ses_1.md"}
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
	"internal/netflow/ipfix.go|" + ip("3", "4", "2", "2"): "RFC 7011 section number in a comment, not an address",
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

// v4AllowedNarrow reports whether a is in an allowed range narrower than a
// first-octet block (0/8, 10/8, 127/8, 224/4, 240/4). The 5-part rule uses it:
// a window inside a first-octet block says nothing about the other four
// parts, so "10." or "224." in front of a public address must not excuse it.
func v4AllowedNarrow(a netip.Addr) bool {
	for _, p := range allowedV4 {
		if p.Bits() > 8 && p.Contains(a) {
			return true
		}
	}
	return false
}

// templateSuffixes are what may follow "a.b.c." to complete an address at run
// time: SQL, Go and JS string concatenation (with or without spaces) and
// shell/JS/Python interpolation. Printf verbs, the "*" wildcard and
// single-letter placeholders are matched by templateTail.
var templateSuffixes = []string{"' ||", "'||", "' +", "'+", `" +`, `"+`, "${", "{"}

// templateTail matches a printf verb ("%d", "%03d", "%[1]d", "%v", ...), a
// "*" wildcard (not "**", Markdown bold closing after a version number), or
// a single-letter placeholder ("x", "X", "N") not followed by a word byte.
var templateTail = regexp.MustCompile(`^(?:%[-+# 0]*(?:\[[0-9]+\])?[0-9]*(?:\.[0-9]+)?[A-Za-z]|\*(?:[^*]|$)|[xXN](?:[^0-9A-Za-z_]|$))`)

// isTemplateTail reports whether rest (the text right after "a.b.c.") turns
// the prefix into an address template.
func isTemplateTail(rest string) bool {
	if templateTail.MatchString(rest) {
		return true
	}
	for _, suf := range templateSuffixes {
		if strings.HasPrefix(rest, suf) {
			return true
		}
	}
	return false
}

// mib2Prefix is the mib-2 subtree (1.3.6.1.2.1); enterprisesPrefix is the
// private-enterprise arc (1.3.6.1.4.1), whose OIDs are never scanned.
var (
	mib2Prefix        = []string{"1", "3", "6", "1", "2", "1"}
	enterprisesPrefix = []string{"1", "3", "6", "1", "4", "1"}
)

// mib2AddrTables are the mib-2 tables whose row index holds raw addresses
// (no InetAddressType/length pair), keyed by the two parts after mib-2, with
// the part positions (from the start of the OID) where an address begins:
//
//	ipAddrTable       1.3.6.1.2.1.4.20.1.C.<ip>
//	ipRouteTable      1.3.6.1.2.1.4.21.1.C.<ip>
//	ipNetToMediaTable 1.3.6.1.2.1.4.22.1.C.<ifIndex>.<ip>
//	ipCidrRouteTable  1.3.6.1.2.1.4.24.4.1.C.<dest>.<mask>.<tos>.<nexthop>
//	tcpConnTable      1.3.6.1.2.1.6.13.1.C.<ip>.<port>.<ip>.<port>
//	udpTable          1.3.6.1.2.1.7.5.1.C.<ip>.<port>
//
// Other mib-2 OIDs (bridge, host resources, ...) carry only column and index
// numbers, which are not addresses.
var mib2AddrTables = map[string][]int{
	"4.20": {10},
	"4.21": {10},
	"4.22": {11},
	"4.24": {11, 15, 20},
	"6.13": {10, 15},
	"7.5":  {10},
}

// hasPrefixParts reports whether parts starts with prefix.
func hasPrefixParts(parts, prefix []string) bool {
	if len(parts) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if parts[i] != p {
			return false
		}
	}
	return true
}

// scanIPv4 returns every disallowed IPv4 literal in data.
//
//   - A leading "." is dropped. The run is an OID fragment, skipped below 6
//     parts, unless the dot follows a word byte (host.a.b.c.d, x_.a.b.c.d) or
//     another dot (an ellipsis, ...a.b.c.d): then the dot is a separator.
//   - A trailing sentence period is stripped; the run is still checked.
//   - 6+ parts (OIDs, with or without the leading dot; checked first):
//     enterprise OIDs (1.3.6.1.4.1...) are skipped. Flagged when "1.4" sits at
//     the start or 6 parts from the end (an IP-MIB address index
//     "1.4.a.b.c.d": InetAddressType ipv4, length 4, bare, after an ifIndex
//     or ending a full OID) and the last 4 parts are a public address; or,
//     for a mib-2 OID (1.3.6.1.2.1...) of 8+ parts in a table indexed by raw
//     addresses (mib2AddrTables), when an address in the index is public.
//   - 4 parts: an address.
//   - 5 parts (IP.index or ifIndex.IP): flagged when a window is a public
//     address, unless the other window is allowed by a range narrower than a
//     first-octet block (or by an allowlist).
//   - 3 parts followed by a template tail (a printf verb such as ".%d",
//     ".%03d" or ".%[1]d"; a concatenation ".' ||", ".'||", ".' +", ".'+",
//     `." +`, `."+`; an interpolation ".${", ".{"; a wildcard ".*"; or a
//     placeholder ".x", ".X", ".N"): an address template; its /24 must be
//     allowed.
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
		oidFragment := false
		if strings.HasPrefix(run, ".") {
			if start == 0 || !isWordByte(s[start-1]) && s[start-1] != '.' {
				oidFragment = true
			}
			run = run[1:] // host.a.b.c.d or ...a.b.c.d: the dot is a separator
			if run == "" {
				continue
			}
		}
		trailingDot := strings.HasSuffix(run, ".")
		run = strings.TrimSuffix(run, ".")
		parts := strings.Split(run, ".")
		lineNo := strings.Count(s[:start], "\n") + 1
		flag := func(lit string) { out = append(out, ipFinding{line: lineNo, lit: lit}) }
		listed := func(a netip.Addr) bool {
			lit := a.String()
			if _, ok := ipv4Allowlist[lit]; ok {
				return true
			}
			_, ok := ipv4FileAllowlist[p+"|"+lit]
			return ok
		}
		public := func(a netip.Addr) bool { return !v4Allowed(a) && !listed(a) }
		excuses := func(a netip.Addr, ok bool) bool { return ok && (v4AllowedNarrow(a) || listed(a)) }
		n := len(parts)
		if n >= 6 {
			if hasPrefixParts(parts, enterprisesPrefix) {
				continue // enterprise OID
			}
			ipMIB := func(i int) bool { return i >= 0 && parts[i] == "1" && parts[i+1] == "4" }
			if ipMIB(0) || ipMIB(n-6) {
				if a, ok := parseV4(parts[n-4:]); ok && public(a) {
					flag(run)
					continue
				}
			}
			if n >= 8 && hasPrefixParts(parts, mib2Prefix) {
				for _, at := range mib2AddrTables[parts[6]+"."+parts[7]] {
					if at+4 > n {
						break
					}
					if a, ok := parseV4(parts[at : at+4]); ok && public(a) {
						flag(run)
						break
					}
				}
			}
			continue
		}
		if oidFragment {
			continue
		}
		switch n {
		case 3:
			if !trailingDot || !isTemplateTail(s[end:]) {
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
			if (ok1 && public(first) && !excuses(last, ok2)) || (ok2 && public(last) && !excuses(first, ok1)) {
				flag(run)
			}
		}
	}
	return out
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// dashedRun matches four dash-separated 1-3 digit groups: an address written
// the way reverse-DNS names spell it.
var dashedRun = regexp.MustCompile(`[0-9]{1,3}(?:-[0-9]{1,3}){3}`)

// scanDashedIPv4 returns public addresses written with dashes instead of
// dots, the form reverse-DNS names use (A-B-C-D.rev.example.net, and after a
// word such as cpe-A-B-C-D.example.net when a domain follows). A run that is
// part of a longer token (a timestamp 2026-10-03T19-42-15, SVG path data
// "s-3-2-3-9h18", a version) is not one. Zero-padded groups are accepted.
func scanDashedIPv4(p string, data []byte) []ipFinding {
	var out []ipFinding
	s := string(data)
	isLetter := func(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	for _, loc := range dashedRun.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]
		next, after := byte(0), byte(0)
		if end < len(s) {
			next = s[end]
		}
		if end+1 < len(s) {
			after = s[end+1]
		}
		domainFollows := next == '.' && isLetter(after)
		if start > 0 && (isWordByte(s[start-1]) || s[start-1] == '.' || s[start-1] == '-' && !domainFollows) {
			continue
		}
		if isWordByte(next) || next == '-' || next == '.' && isDigit(after) {
			continue
		}
		a, ok := parseV4(strings.Split(s[start:end], "-"))
		if !ok || v4Allowed(a) || ipv4Allowlist[a.String()] != "" || ipv4FileAllowlist[p+"|"+a.String()] != "" {
			continue
		}
		out = append(out, ipFinding{line: strings.Count(s[:start], "\n") + 1, lit: s[start:end]})
	}
	return out
}

// v6Candidate matches runs of hex digits, colons and dots containing at least
// two colons; only candidates that parse as IPv6 count.
var v6Candidate = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)

var (
	v6Global = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20}), 3) // global unicast (the /3 starting at 2000)
	v6Doc    = netip.MustParsePrefix("2001:db8::/32")
)

// scanIPv6 returns every global-unicast IPv6 literal outside 2001:db8::/32
// that is not allowlisted. A candidate may follow a letter or a colon
// ("addr:2a00:..."): a single leading or trailing ":" is a separator and is
// dropped ("::" is kept, it is part of the address).
func scanIPv6(data []byte) []ipFinding {
	var out []ipFinding
	s := string(data)
	for _, loc := range v6Candidate.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]
		if end < len(s) && isWordByte(s[end]) {
			continue
		}
		cand := strings.TrimSuffix(s[start:end], ".")
		if strings.HasPrefix(cand, ":") && !strings.HasPrefix(cand, "::") {
			cand = cand[1:]
		}
		if strings.HasSuffix(cand, ":") && !strings.HasSuffix(cand, "::") {
			cand = cand[:len(cand)-1]
		}
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
		for _, h := range scanDashedIPv4(f.path, f.data) {
			t.Errorf("%s:%d: public IPv4 literal in dashed (reverse-DNS) form %q — use a reserved range, or add a reviewed allowlist entry with a reason", f.path, h.line, h.lit)
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
		// 5 parts: a first-octet block (0/8, 10/8, 127/8, 224/4, 240/4) in
		// one window must not excuse a public address in the other.
		{"5-part 10/8 in front of public", "10." + pub, 1},
		{"5-part 127/8 in front of public", "127." + pub, 1},
		{"5-part 224/4 in front of public", "224." + pub, 1},
		{"5-part 240/4 in front of public", "240." + pub, 1},
		{"5-part 0/8 in front of public", "0." + pub, 1},
		{"5-part public then 10/8 window", ip("9", "10", "9", "9", "9"), 1},
		{"5-part both windows first-octet blocks", "10.10.0.0.1", 0},
		{"5-part narrow window still excuses", "192.168.1.1.9", 0},
		// 6+ parts: an IP-MIB "1.4.a.b.c.d" index carries an address.
		{"IP-MIB index, public", "1.4." + pub, 1},
		{"IP-MIB index, public, more parts", ip("1", "4", "7", pub), 1},
		{"enterprise OID is not an IP-MIB index", "1.3.6.1.4.1.9.9.109", 0},
		{"IP-MIB index, private", "1.4.192.168.1.1", 0},
		{"IP-MIB index, allowlisted", "1.4.8.8.8.8", 0},
		// A dot after a letter is a separator, not an OID fragment.
		{"host.a.b.c.d, public", "host." + pub, 1},
		{"host_.a.b.c.d, public", "x_." + pub, 1},
		{"host.a.b.c.d, private", "host.10.0.0.1", 0},
		{"OID fragment after space", "oid ." + pub, 0},
		{"OID name, long numeric tail", "ifDescr.1.3.6.1.2.1", 0},
		// More template suffixes.
		{`template " +, public`, `"` + ip("9", "9", "9") + `." + n`, 1},
		{"template ${, public", ip("9", "9", "9") + ".${n}", 1},
		{"template %v, public", ip("9", "9", "9") + ".%v", 1},
		{"template %s, public", ip("9", "9", "9") + ".%s", 1},
		{"template %v, private", "10.1.2.%v", 0},
		// More evasion forms.
		{`template "+ (gofmt), public`, `"` + ip("9", "9", "9") + `."+strconv.Itoa(i)`, 1},
		{"template JS ' +, public", "'" + ip("9", "9", "9") + ".' + i", 1},
		{"template JS '+, public", "'" + ip("9", "9", "9") + ".'+i", 1},
		{"template SQL '||, public", "'" + ip("9", "9", "9") + ".'||g", 1},
		{"template %03d, public", ip("9", "9", "9") + ".%03d", 1},
		{"template %[1]d, public", ip("9", "9", "9") + ".%[1]d", 1},
		{"template .*, public", ip("9", "9", "9") + ".*", 1},
		{"template .X, public", ip("9", "9", "9") + ".X", 1},
		{"template .N, public", ip("9", "9", "9") + ".N", 1},
		{"template .{i}, public", ip("9", "9", "9") + ".{i}", 1},
		{"template .%03d, private", "10.1.2.%03d", 0},
		{"template .*, benchmarking", "198.19.9.*", 0},
		{"version at the end of Markdown bold", "**Released " + ip("9", "9", "9") + ".**", 0},
		{"3 parts then a word", ip("9", "9", "9") + ".Next", 0},
		{"ellipsis, public", "see ..." + pub, 1},
		{"ellipsis, private", "see ...10.0.0.1", 0},
		// SNMP OIDs carrying addresses.
		{"ifIndex.1.4.ip, public", ip("7", "1", "4", pub), 1},
		{"full IP-MIB OID, no leading dot, public", ip("1", "3", "6", "1", "2", "1", "4", "34", "1", "3", "1", "4", pub), 1},
		{"full IP-MIB OID, leading dot, public", "oid ." + ip("1", "3", "6", "1", "2", "1", "4", "34", "1", "3", "1", "4", pub), 1},
		{"full IP-MIB OID, private", "oid .1.3.6.1.2.1.4.34.1.3.1.4.192.168.1.1", 0},
		{"ipAddrTable, public", "oid ." + ip("1", "3", "6", "1", "2", "1", "4", "20", "1", "2", pub), 1},
		{"ipAddrTable, private", "oid .1.3.6.1.2.1.4.20.1.2.10.0.0.1", 0},
		{"ipRouteTable, public", "oid ." + ip("1", "3", "6", "1", "2", "1", "4", "21", "1", "7", pub), 1},
		{"ipRouteTable, private", "oid .1.3.6.1.2.1.4.21.1.7.192.168.1.0", 0},
		{"ipNetToMedia, public", "oid ." + ip("1", "3", "6", "1", "2", "1", "4", "22", "1", "2", "5", pub), 1},
		{"ipNetToMedia, private", "oid .1.3.6.1.2.1.4.22.1.2.5.172.16.1.1", 0},
		{"ipCidrRoute, public dest", "oid ." + ip("1", "3", "6", "1", "2", "1", "4", "24", "4", "1", "16", pub, "255", "255", "255", "0", "0", "192", "168", "1", "1"), 1},
		{"ipCidrRoute, public next hop", "oid ." + ip("1", "3", "6", "1", "2", "1", "4", "24", "4", "1", "16", "192", "168", "1", "0", "255", "255", "255", "0", "0", pub), 1},
		{"ipCidrRoute, private", "oid .1.3.6.1.2.1.4.24.4.1.16.192.168.1.0.255.255.255.0.0.192.168.1.1", 0},
		{"tcpConnTable, public remote", "oid ." + ip("1", "3", "6", "1", "2", "1", "6", "13", "1", "1", "192", "168", "1", "5", "22", pub, "5000"), 1},
		{"tcpConnTable, private", "oid .1.3.6.1.2.1.6.13.1.1.192.168.1.5.22.10.0.0.9.5000", 0},
		{"udpTable, public", "oid ." + ip("1", "3", "6", "1", "2", "1", "7", "5", "1", "1", pub, "161"), 1},
		{"udpTable, private", "oid .1.3.6.1.2.1.7.5.1.1.10.0.0.1.161", 0},
		{"ipNetToMedia, ifIndex 10 before a public address", "oid ." + ip("1", "3", "6", "1", "2", "1", "4", "22", "1", "2", "10", pub), 1},
		{"mib-2 table OID, column only", "oid .1.3.6.1.2.1.4.20.1.2", 0},
		{"mib-2 bridge OID, column numbers only", "oid .1.3.6.1.2.1.17.7.1.4.5.1.1", 0},
		{"enterprise OID with 1.4 before an address", "oid ." + ip("1", "3", "6", "1", "4", "1", "9", "1", "4", pub), 0},
		// Zero-padded octets are the same address.
		{"zero-padded public", "peer " + ip("009", "9", "009", "9"), 1},
		{"zero-padded private", "peer " + ip("010", "000", "000", "001"), 0},
	}
	for _, c := range cases {
		if got := len(scanIPv4("x.go", []byte(c.text))); got != c.want {
			t.Errorf("%s: scanIPv4(%q) = %d findings, want %d", c.name, c.text, got, c.want)
		}
	}
	dashed := strings.ReplaceAll(pub, ".", "-")
	for _, c := range []struct {
		text string
		want int
	}{
		{"peer " + dashed, 1},
		{"peer " + dashed + ".", 1},
		{"rdns " + dashed + ".rev.example.net", 1},
		{"rdns cpe-" + dashed + ".example.net", 1},
		{"rdns " + strings.ReplaceAll(ip("009", "9", "009", "9"), ".", "-"), 1},
		{"host ip-10-0-0-1 and 203-0-113-7.example.com", 0},
		{"placeholder 1-2-3-4", 0},
		{"stamp 2026-10-03-14-30 and 10-03-14-30-00 and T19-42-15-24h", 0},
		{"build 1.2-3-4-5-6 and v" + dashed, 0},
		{"range " + dashed + ".5 and " + dashed + "-7", 0},
		{`<path d="M6 8c0 7-3 9-3 9h18s-3-2-3-9"/> and "11-8 11-8-11-8-11-8z"`, 0},
		{"host ip-" + dashed, 0}, // a word before the dash: only an address with a domain after it counts
	} {
		if got := len(scanDashedIPv4("x.go", []byte(c.text))); got != c.want {
			t.Errorf("scanDashedIPv4(%q) = %d findings, want %d", c.text, got, c.want)
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
		// After a letter or a colon.
		{"addr:" + pub + " x", 1},
		{"addr" + pub + " x", 1},
		{"ip=" + pub + ": up", 1},
		{"addr:2001:db8::1 x", 0},
		{"at time:21:39:14", 0},
		{"loopback ::1", 0},
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

var (
	homePath = regexp.MustCompile(`/(?:Users|home)/([A-Za-z0-9._-]+)`)
	// winHomePath matches C:\Users\<name> with single or escaped
	// backslashes (a Go or JSON string), any drive letter, any case.
	winHomePath = regexp.MustCompile(`(?i)\b[a-z]:\\+(?:users|documents and settings)\\+([a-z0-9._-]+)`)
)

// homePathAllowlist is the reviewed list of generic home-directory names.
var homePathAllowlist = map[string]string{}

func scanHomePaths(data []byte) []ipFinding {
	var out []ipFinding
	s := string(data)
	for _, re := range []*regexp.Regexp{homePath, winHomePath} {
		for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
			name := s[m[2]:m[3]]
			if _, ok := homePathAllowlist[name]; ok {
				continue
			}
			out = append(out, ipFinding{line: strings.Count(s[:m[0]], "\n") + 1, lit: s[m[0]:m[1]]})
		}
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
	for _, text := range []string{
		`cd C:` + `\Users\someone\proj`,
		`"C:` + `\\Users\\someone\\proj"`,
		`d:` + `\users\someone`,
		`C:` + `\Documents and Settings\someone`,
	} {
		if n := len(scanHomePaths([]byte(text))); n != 1 {
			t.Errorf("Windows home path %q: %d findings, want 1", text, n)
		}
	}
	if n := len(scanHomePaths([]byte(`C:\Program Files\x`))); n != 0 {
		t.Errorf("neutral Windows path flagged (%d findings)", n)
	}
}
