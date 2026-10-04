package guardrails

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestVendorDefaultGuard keeps "no vendor means FortiGate" from coming back.
//
// Until 1.3.48 an empty device vendor was silently FortiGate in five places
// (the SNMP resolver, DefaultVendor, the SSH client factory, isFortiGateVendor
// and two poll/diagnostic sites in main.go) and each one drifted on its own.
// Since 1.3.49 an empty or unknown vendor is "generic" everywhere, matching
// the server (0.11.290, whose test/guardrails/vendor_default_guard_test.go
// this mirrors). This test walks every tracked non-test Go file and fails on
// a line that assigns, defaults to, or falls back to "fortigate" for a vendor.
// A vendor COMPARISON (`vendor == "fortigate"`, `case "fortigate":`) is
// dispatch, not a default, and is not matched.
//
// Exceptions go in vendorDefaultAllow keyed by file and the exact trimmed
// line, each with a reason; an entry no line uses any more fails the test so
// the list cannot outlive the code it excuses.
var vendorDefaultPatterns = []*regexp.Regexp{
	// vendor := "fortigate" / vendor = "fortigate" / device.Vendor = "fortigate"
	regexp.MustCompile(`(?i)vendor\s*:?=\s*"fortigate"`),
	// gorm:"default:fortigate"
	regexp.MustCompile(`default:fortigate`),
	// case "fortigate", "": / case "", "fortigate": — "" sharing the FortiGate arm
	regexp.MustCompile(`case\s+"fortigate"\s*,\s*""`),
	regexp.MustCompile(`case\s+""\s*,\s*"fortigate"`),
	// cmp.Or(vendor, "fortigate") — the stdlib way to spell a default
	regexp.MustCompile(`cmp\.Or\([^)]*"fortigate"`),
	// GetVendorProfile("fortigate") as a fallback (the registry lookup by a
	// literal; the FortiGate profile's own file registers, never looks up)
	regexp.MustCompile(`GetVendorProfile\("fortigate"\)`),
	// vendor == "" || vendor == "fortigate" — "" sharing the FortiGate branch
	regexp.MustCompile(`==\s*""\s*\|\|[^|]*==\s*"fortigate"`),
	// flag.String("vendor", "fortigate", …) — a CLI default
	regexp.MustCompile(`flag\.String\("vendor",\s*"fortigate"`),
}

// vendorDefaultAllow: file → exact trimmed line → reason.
var vendorDefaultAllow = map[string]map[string]string{}

// vendorDefaultFile reports whether a tracked path is one the guard scans:
// non-test Go.
func vendorDefaultFile(f string) bool {
	return strings.HasSuffix(f, ".go") && !strings.HasSuffix(f, "_test.go")
}

func TestVendorDefaultGuard(t *testing.T) {
	root := repoRoot(t)
	used := map[string]map[string]bool{}
	scanned := 0
	for _, f := range trackedPaths(t, root) {
		if !vendorDefaultFile(f) {
			continue
		}
		scanned++
		for _, hit := range vendorDefaultHits(t, filepath.Join(root, f)) {
			if reason := vendorDefaultAllow[f][hit.line]; reason != "" {
				if used[f] == nil {
					used[f] = map[string]bool{}
				}
				used[f][hit.line] = true
				continue
			}
			t.Errorf("%s:%d: %q defaults a vendor to FortiGate — an empty or unknown vendor is \"generic\" (snmp.resolveVendor); use that, or add the exact line to vendorDefaultAllow in vendor_default_guard_test.go with a reason", f, hit.n, hit.line)
		}
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d Go files — the guard would be checking almost nothing", scanned)
	}
	// The allowlist must stay as small as the tree needs.
	allowed := make([]string, 0, len(vendorDefaultAllow))
	for f := range vendorDefaultAllow {
		allowed = append(allowed, f)
	}
	sort.Strings(allowed)
	for _, f := range allowed {
		for line, reason := range vendorDefaultAllow[f] {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("vendorDefaultAllow[%q][%q] has no reason", f, line)
			}
			if !used[f][line] {
				t.Errorf("vendorDefaultAllow[%q][%q] matches no line any more — remove it", f, line)
			}
		}
	}
}

type vendorDefaultHit struct {
	n    int
	line string
}

// vendorDefaultHits returns the trimmed lines of path that match any
// vendorDefaultPatterns entry, with their 1-based line numbers. A tracked
// file deleted in the work tree is not scannable and yields nothing.
func vendorDefaultHits(t *testing.T, path string) []vendorDefaultHit {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open %s: %v", path, err)
	}
	defer fh.Close()
	var hits []vendorDefaultHit
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		for _, re := range vendorDefaultPatterns {
			if re.MatchString(line) {
				hits = append(hits, vendorDefaultHit{n, strings.TrimSpace(line)})
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return hits
}

// TestVendorDefaultGuard_Patterns pins what the guard does and does not
// match, so a future pattern edit cannot silently widen it onto dispatch
// arms or narrow it off the shapes it exists for.
func TestVendorDefaultGuard_Patterns(t *testing.T) {
	for _, tc := range []struct {
		line string
		hit  bool
	}{
		{`vendor := "fortigate"`, true},
		{`vendor = "fortigate" // comment`, true},
		{`device.Vendor = "fortigate"`, true},
		{`Vendor string ` + "`" + `json:"vendor" gorm:"default:fortigate"` + "`", true},
		{`case "fortigate", "":`, true},
		{`case "", "fortigate":`, true},
		{`vendor := cmp.Or(dev.Vendor, "fortigate")`, true},
		{`profile = GetVendorProfile("fortigate")`, true},
		{`if vendor == "" || vendor == "fortigate" {`, true},
		{`return vendor == "" || vendor == "fortigate"`, true},
		{`vendor := flag.String("vendor", "fortigate", "device vendor")`, true},
		{`vendor == "fortigate"`, false},
		{`return vendor == "fortigate"`, false},
		{`return vendor == "fortigate" || vendor == "opnsense"`, false},
		{`case "fortigate":`, false},
		{`Vendor: "fortigate",`, false},
		{`vendor := "generic"`, false},
		{`vendor = "generic"`, false},
		{`RegisterVendor(&FortiGateProfile{})`, false},
		{`func (f *FortiGateProfile) Name() string { return "fortigate" }`, false},
	} {
		got := false
		for _, re := range vendorDefaultPatterns {
			if re.MatchString(tc.line) {
				got = true
				break
			}
		}
		if got != tc.hit {
			t.Errorf("%q: matched=%v, want %v", tc.line, got, tc.hit)
		}
	}
}
