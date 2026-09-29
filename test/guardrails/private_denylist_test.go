package guardrails

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestPrivateDenylist scans every tracked text file for tokens on a private
// denylist (hostnames, domains, serials, usernames, addresses) that must
// never appear in the public repo. The list itself is sensitive — short
// tokens hashed in public could be brute-forced — so it lives outside the
// repository and the test runs only locally:
//
//	FWMON_DENYLIST=/path/to/denylist.txt \
//	FWMON_DENYLIST_KEEP=/path/to/denylist-keep.txt \
//	go test -count=1 -run PrivateDenylist ./test/guardrails/
//
// It is skipped when FWMON_DENYLIST is unset, which is always the case in CI.
//
// File format (both files): one entry per line; blank lines and lines
// starting with "#" are ignored. Matching is case-insensitive.
//
//   - A token made only of digits and dots (an address or prefix) matches
//     with no digit on either side, so "10.1.2" matches inside "10.1.2.3" but
//     not inside "10.1.23".
//   - Any other token matches as a substring of the raw text, and also
//     against runs of adjacent alphanumeric sub-tokens joined by "-", "_",
//     "." or nothing — so "abc-fw-01" also catches "ABC_FW_01" and "abcfw01".
//   - Keep-list entries are exempt: every occurrence of a keep-list entry is
//     blanked out before matching (e.g. a public account name that contains
//     a denylisted word).
func TestPrivateDenylist(t *testing.T) {
	listPath := os.Getenv("FWMON_DENYLIST")
	if listPath == "" {
		t.Skip("FWMON_DENYLIST not set — the private denylist check runs only locally")
	}
	deny, err := readTokenFile(listPath)
	if err != nil {
		t.Fatalf("read FWMON_DENYLIST: %v", err)
	}
	if len(deny) == 0 {
		t.Fatalf("FWMON_DENYLIST %s holds no tokens", listPath)
	}
	var keep []string
	if kp := os.Getenv("FWMON_DENYLIST_KEEP"); kp != "" {
		if keep, err = readTokenFile(kp); err != nil {
			t.Fatalf("read FWMON_DENYLIST_KEEP: %v", err)
		}
	}
	m := newDenyMatcher(deny, keep)
	// Every keep-list entry must itself pass: an entry that still matches
	// would exempt nothing.
	for i, k := range keep {
		if hits := m.scan(k); len(hits) != 0 {
			t.Errorf("keep-list entry #%d still matches denylist entry #%d", i+1, hits[0].entry)
		}
	}
	for _, f := range trackedTextFiles(t) {
		for _, h := range m.scan(string(f.data)) {
			// Report the line and the entry index, never the token itself:
			// test output can end up in logs.
			t.Errorf("%s:%d: matches private denylist entry #%d", f.path, h.line, h.entry)
		}
	}
}

func readTokenFile(p string) ([]string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

type denyEntry struct {
	index     int    // 1-based position among the tokens (for reporting)
	lower     string // lower-cased raw token
	canonical string // lower-cased, joiners removed ("" when not alphanumeric-joinable)
	numeric   bool   // digits and dots only
}

type denyMatcher struct {
	entries []denyEntry
	keep    []string
}

type denyHit struct {
	line  int
	entry int
}

var (
	numericToken = regexp.MustCompile(`^[0-9.]+$`)
	joinable     = regexp.MustCompile(`^[0-9a-z._-]+$`)
	// subTokenRun matches alphanumeric sub-tokens joined by single joiners.
	subTokenRun = regexp.MustCompile(`[0-9a-z]+(?:[-_.][0-9a-z]+)*`)
	subToken    = regexp.MustCompile(`[0-9a-z]+`)
)

func newDenyMatcher(deny, keep []string) *denyMatcher {
	m := &denyMatcher{}
	for i, d := range deny {
		l := strings.ToLower(d)
		e := denyEntry{index: i + 1, lower: l, numeric: numericToken.MatchString(l)}
		if !e.numeric && joinable.MatchString(l) {
			e.canonical = strings.NewReplacer("-", "", "_", "", ".", "").Replace(l)
		}
		m.entries = append(m.entries, e)
	}
	for _, k := range keep {
		m.keep = append(m.keep, strings.ToLower(k))
	}
	return m
}

// blankKeep replaces every keep-list occurrence with spaces of equal length
// (so byte offsets and line numbers are unchanged).
func (m *denyMatcher) blankKeep(lower string) string {
	for _, k := range m.keep {
		if k == "" {
			continue
		}
		lower = strings.ReplaceAll(lower, k, strings.Repeat(" ", len(k)))
	}
	return lower
}

func (m *denyMatcher) scan(text string) []denyHit {
	lower := m.blankKeep(strings.ToLower(text))
	lineAt := func(off int) int { return strings.Count(lower[:off], "\n") + 1 }
	var hits []denyHit
	seen := map[[2]int]bool{}
	add := func(off, entry int) {
		k := [2]int{lineAt(off), entry}
		if !seen[k] {
			seen[k] = true
			hits = append(hits, denyHit{line: k[0], entry: entry})
		}
	}
	for _, e := range m.entries {
		for from := 0; ; {
			i := strings.Index(lower[from:], e.lower)
			if i < 0 {
				break
			}
			at := from + i
			from = at + 1
			if e.numeric {
				end := at + len(e.lower)
				if at > 0 && isDigit(lower[at-1]) || end < len(lower) && isDigit(lower[end]) {
					continue
				}
			}
			add(at, e.index)
		}
	}
	// Compound runs: every contiguous span of sub-tokens (one or more),
	// joined with nothing, compared to each entry's canonical form.
	for _, run := range subTokenRun.FindAllStringIndex(lower, -1) {
		seg := lower[run[0]:run[1]]
		parts := subToken.FindAllString(seg, -1)
		for _, e := range m.entries {
			if e.canonical == "" {
				continue
			}
			for i := range parts {
				joined := ""
				for j := i; j < len(parts) && len(joined) < len(e.canonical); j++ {
					joined += parts[j]
				}
				if joined == e.canonical {
					add(run[0], e.index)
					break
				}
			}
		}
	}
	return hits
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// TestPrivateDenylist_MatcherRules pins the matcher with synthetic tokens.
func TestPrivateDenylist_MatcherRules(t *testing.T) {
	m := newDenyMatcher([]string{"acme-fw-01", "198.18.7", "widgetco", "aa:bb:cc"}, []string{"widgetco-public"})
	cases := []struct {
		text string
		want int
	}{
		{"host ACME-FW-01 up", 1},
		{"host acme_fw_01 up", 1},
		{"host acmefw01 up", 1},
		{"host Acme.Fw.01 up", 1},
		{"host acme-fw-02 up", 0},
		{"peer 198.18.7.4", 1},
		{"peer 1198.18.7.4", 0},
		{"peer 198.18.71.4", 0},
		{"see WidgetCo docs", 1},
		{"see widgetco-public docs", 0},
		{"mac AA:BB:CC:01:02:03", 1},
		{"nothing here", 0},
	}
	for _, c := range cases {
		if got := len(m.scan(c.text)); got != c.want {
			t.Errorf("scan(%q) = %d hits, want %d", c.text, got, c.want)
		}
	}
}
