package guardrails

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The public repo must not name hosts or mailboxes from anyone's real
// environment. TestPublicHygiene_NoPrivateHostnamesOrEmails scans every
// tracked text file for host names and e-mail addresses and allows only:
//
//   - documentation names: example.com / example.net / example.org and
//     their subdomains, and the reserved .example, .test, .invalid and
//     .localhost top-level domains (RFC 2606 / RFC 6761);
//   - the public vendor, documentation and module-path sites listed in
//     hostAllowlist, each with a reason — including the project's own
//     public contact domain (SECURITY.md, CODE_OF_CONDUCT.md).
//
// Names under a site-local suffix (.local, .lan, .internal, .home.arpa, …)
// and reverse-DNS names (in-addr.arpa, ip6.arpa) are never allowed, whatever
// the allowlist says: they always describe a real network. A reverse name
// that spells out a public address is reported as that address.
//
// Test data uses example.com or an .example name instead.

// hostAllowlist lists public domains the tree may reference, with the
// reason. A name is allowed when it equals an entry or is a subdomain of one.
// Keep the list tight: the guard fails on an entry nothing in the tree
// references any more.
var hostAllowlist = map[string]string{
	"xphox.net":                    "the project's public contact domain (SECURITY.md, CODE_OF_CONDUCT.md)",
	"github.com":                   "project host, Go module paths, Actions",
	"golang.org":                   "Go module paths (golang.org/x, google.golang.org)",
	"go.dev":                       "Go documentation (pkg.go.dev)",
	"go.etcd.io":                   "Go module path",
	"honnef.co":                    "staticcheck module path",
	"go.uber.org":                  "Go module path",
	"www.apache.org":               "license text",
	"www.iana.org":                 "port and protocol number registries",
	"shields.io":                   "README badges",
	"www.contributor-covenant.org": "CODE_OF_CONDUCT.md source",
	"semver.org":                   "CHANGELOG convention",
}

// privateTLDs are site-local suffixes that always name a real network.
// .arpa is handled separately (home.arpa, in-addr.arpa, ip6.arpa).
var privateTLDs = map[string]bool{
	"local": true, "lan": true, "internal": true, "intranet": true, "corp": true,
	"home": true, "localdomain": true, "private": true,
}

// reservedTLDs never resolve (RFC 2606 / RFC 6761) and are fine.
var reservedTLDs = map[string]bool{"example": true, "test": true, "invalid": true, "localhost": true}

// hostTLDs are the top-level domains a dotted name is taken as a host name
// under. Two-letter codes that are also English words or common field names
// (id, in, is, it, me, no, at, by, us, …) are left out: a.b.id is a property
// chain far more often than a host, and a real name under such a domain is
// still caught by the private denylist check.
var hostTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "dev": true, "edu": true, "gov": true,
	"mil": true, "info": true, "biz": true, "co": true, "ai": true, "cloud": true, "tech": true,
	"tv": true, "arpa": true,
	"ch": true, "de": true, "fr": true, "nl": true, "uk": true, "ca": true, "au": true, "nz": true,
	"eu": true, "dk": true, "fi": true, "se": true, "es": true, "pl": true, "pt": true, "ru": true,
	"cn": true, "jp": true, "kr": true, "br": true, "mx": true, "za": true, "ie": true, "cz": true,
	"sk": true, "hu": true, "ro": true, "gr": true, "tr": true, "il": true, "ar": true, "cl": true,
	"sg": true, "hk": true, "tw": true, "th": true, "ph": true, "vn": true, "ua": true, "lt": true,
	"lv": true, "ee": true, "lu": true, "li": true,
}

var (
	dottedName = regexp.MustCompile(`[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+`)
	emailAddr  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
)

// hostFinding is one disallowed name.
type hostFinding struct {
	line int
	name string
	why  string
}

// hostAllowed reports whether name (lower case) is a documentation name or
// on the allowlist, and which allowlist entry matched ("" for none).
func hostAllowed(name string) (bool, string) {
	tld := name[strings.LastIndexByte(name, '.')+1:]
	if reservedTLDs[tld] {
		return true, ""
	}
	for _, d := range []string{"example.com", "example.net", "example.org"} {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true, ""
		}
	}
	for d := range hostAllowlist {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true, d
		}
	}
	return false, ""
}

// identifierLabel reports whether label looks like a Go / JS identifier
// rather than a DNS label: an upper-case letter followed by lower case
// (Name, DetectedAt, OPNsense). Host names are written in lower case, or in
// upper case throughout.
func identifierLabel(label string) bool {
	for i := 0; i+1 < len(label); i++ {
		if label[i] >= 'A' && label[i] <= 'Z' && label[i+1] >= 'a' && label[i+1] <= 'z' {
			return true
		}
	}
	return false
}

// reverseName checks an in-addr.arpa name: the four labels before the suffix
// are the address octets in reverse order.
func reverseName(name string) (netip.Addr, bool) {
	labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
	if len(labels) < 4 {
		return netip.Addr{}, false
	}
	labels = labels[len(labels)-4:]
	return parseV4([]string{labels[3], labels[2], labels[1], labels[0]})
}

// classifyHost reports why name is not allowed ("" when it is), and the
// allowlist entry that allowed it.
func classifyHost(name string) (why, allowedBy string) {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return "", ""
	}
	tld := name[i+1:]
	switch {
	case name == "localhost.localdomain":
		return "", "" // the conventional loopback name
	case name == "in-addr.arpa", name == "ip6.arpa", name == "home.arpa":
		return "", "" // the bare suffix, named in prose
	case privateTLDs[tld], strings.HasSuffix(name, ".home.arpa"):
		return "site-local host name", ""
	case strings.HasSuffix(name, ".in-addr.arpa"):
		if a, ok := reverseName(name); !ok || !v4Allowed(a) && ipv4Allowlist[a.String()] == "" {
			return "reverse-DNS name of a public IPv4 address", ""
		}
		return "", ""
	case strings.HasSuffix(name, ".ip6.arpa"), tld == "arpa":
		return "reverse-DNS / .arpa name", ""
	case !hostTLDs[tld]:
		return "", "" // not a host name
	}
	if ok, by := hostAllowed(name); ok {
		return "", by
	}
	return "host name outside the documentation domains and the allowlist", ""
}

// hostContext reports whether text[s:e] sits where only a host name would:
// after "//" or "=", before "/" or ":<port>", or quoted on both sides.
func hostContext(text string, s, e int) bool {
	before, after := byte(0), byte(0)
	if s > 0 {
		before = text[s-1]
	}
	if e < len(text) {
		after = text[e]
	}
	isQuote := func(b byte) bool { return b == '"' || b == '\'' || b == '`' }
	switch {
	case s >= 2 && text[s-2:s] == "//", before == '=':
		return true
	case after == '/', after == ':' && e+1 < len(text) && text[e+1] >= '0' && text[e+1] <= '9':
		return true
	case isQuote(before) && isQuote(after):
		return true
	}
	return false
}

// scanHosts returns the disallowed host names and e-mail addresses in text.
// used collects the allowlist entries that excused a name.
func scanHosts(text string, used map[string]bool) []hostFinding {
	var out []hostFinding
	note := func(by string) {
		if by != "" && used != nil {
			used[by] = true
		}
	}
	for _, loc := range emailAddr.FindAllStringIndex(text, -1) {
		m := text[loc[0]:loc[1]]
		if loc[0] > 0 && isWordByte(text[loc[0]-1]) || loc[1] < len(text) && (isWordByte(text[loc[1]]) || text[loc[1]] == '-') {
			continue
		}
		domain := strings.ToLower(m[strings.IndexByte(m, '@')+1:])
		tld := domain[strings.LastIndexByte(domain, '.')+1:]
		if len(tld) < 2 || strings.Trim(tld, "abcdefghijklmnopqrstuvwxyz") != "" {
			continue // user@1.2.3, pkg@1.0.0: not a mailbox
		}
		line := strings.Count(text[:loc[0]], "\n") + 1
		if why, by := classifyHost(domain); why != "" {
			if strings.HasPrefix(why, "host name ") {
				why = "e-mail address " + strings.TrimPrefix(why, "host name ")
			} else {
				why = "e-mail address at a " + why
			}
			out = append(out, hostFinding{line, m, why})
		} else if ok, by2 := hostAllowed(domain); ok {
			note(by2)
		} else {
			note(by)
			out = append(out, hostFinding{line, m, "e-mail address outside the documentation domains and the allowlist"})
		}
	}
	for _, loc := range dottedName.FindAllStringIndex(text, -1) {
		if loc[0] > 0 && (text[loc[0]-1] == '@' || text[loc[0]-1] == '.') {
			continue // an e-mail domain (checked above) or the tail of a longer run
		}
		if loc[1] < len(text) && (text[loc[1]] == '_' || text[loc[1]] == '-') {
			continue
		}
		m := text[loc[0]:loc[1]]
		labels := strings.Split(m, ".")
		skip := false
		for _, label := range labels {
			if identifierLabel(label) {
				skip = true
				break
			}
		}
		// A two-label run with a one- or two-letter head (r.local, x.net,
		// it.ch) is a property access, unless it sits in a URL, is quoted
		// on both sides, or follows "=" (HOST=fw.lan).
		if len(labels) == 2 && len(labels[0]) < 3 && !hostContext(text, loc[0], loc[1]) {
			skip = true
		}
		if skip {
			continue
		}
		name := strings.ToLower(m)
		why, by := classifyHost(name)
		note(by)
		if why != "" {
			out = append(out, hostFinding{strings.Count(text[:loc[0]], "\n") + 1, m, why})
		}
	}
	return out
}

func TestPublicHygiene_NoPrivateHostnamesOrEmails(t *testing.T) {
	used := map[string]bool{}
	for _, f := range trackedTextFiles(t) {
		for _, h := range scanHosts(string(f.data), used) {
			t.Errorf("%s:%d: %s %q — use example.com / an .example name, or (for a public vendor or documentation site) add it to hostAllowlist in public_hostnames_test.go with a reason", f.path, h.line, h.why, h.name)
		}
	}
	// The allowlist must stay as small as the tree needs.
	keys := make([]string, 0, len(hostAllowlist))
	for k := range hostAllowlist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.TrimSpace(hostAllowlist[k]) == "" {
			t.Errorf("hostAllowlist[%q] has no reason", k)
		}
		if why, _ := classifyHost(k); why != "" {
			t.Errorf("hostAllowlist[%q]: %s — such a name can never be allowed", k, why)
		}
		if !used[k] {
			t.Errorf("hostAllowlist[%q] is no longer referenced by any tracked file — remove it", k)
		}
	}
}

// fqdn joins labels so this file holds no literal name the guard would flag.
func fqdn(labels ...string) string { return strings.Join(labels, ".") }

func TestPublicHygiene_HostRules(t *testing.T) {
	lan := fqdn("fw01", "lan")
	local := fqdn("nas", "home", "local")
	internal := fqdn("db", "corp", "internal")
	homeArpa := fqdn("router", "home", "arpa")
	corp := fqdn("mail", "acme", "com")
	rev := fqdn("9", "9", "9", "9", "in-addr", "arpa")
	for _, tc := range []struct {
		text string
		bad  int
	}{
		{"host fw.example.com and api.example.net and example.org", 0},
		{"host fw.lab.example and db.test and x.invalid and app.localhost", 0},
		{"import \"github.com/x/y\" and golang.org/x/crypto and pkg.go.dev/x", 0},
		{"peer " + lan, 1},
		{"peer " + local, 1},
		{"peer " + internal, 1},
		{"peer " + homeArpa, 1},
		{"peer " + corp, 1},
		{"peer " + corp + ".", 1},
		{"url https://" + corp + "/path", 1},
		{"peer " + strings.ToUpper(corp), 1},
		{"peer " + rev, 1},
		{"peer " + fqdn("1", "105", "168", "192", "in-addr", "arpa"), 0},
		{"peer " + fqdn("1", "0", "0", "db8", "0", "1", "0", "0", "2", "ip6", "arpa"), 1},
		// Code, not names.
		{"ts := det.DetectedAt.Local()", 0},
		{"node := &opnNode{name: t.Name.Local}", 0},
		{"\"OPNsense.Swanctl.locals.local\": {\"round\"}", 0},
		{"var d = tms(b.it.at) - tms(a.it.at)", 0},
		{"state.user.id and row.no and opts.me", 0},
		{"chart.umd.min.js and tailwind.css and main.go", 0},
		{"version 1.3.47 and v1.2.3", 0},
		{"if r." + "local != d." + "local { return s.info + x.net }", 0},
		{"entry localhost.localdomain", 0},
		// A short head is a host in a URL, a quoted value or an assignment.
		{"url https://e." + "lan/x", 1},
		{"host \"" + fqdn("fw", "lan") + "\"", 1},
		{"HOST=" + fqdn("fw", "lan"), 1},
		{"peer " + fqdn("fw", "lan") + ":443", 1},
		{"peer " + fqdn("fw", "lan"), 0},
		// E-mail addresses.
		{"mail ops@example.com and noc@example.test", 0},
		{"mail ops@" + corp, 1},
		{"mail ops@" + lan, 1},
		{"git+ssh://git@github.com/x/y", 0},
		{"npm install pkg@1.2.3 and user@1.2.3.4", 0},
		// A longer run or a word before the name is not a separate name.
		{"my_" + corp, 1},
		{"x" + corp, 1}, // xmail.acme.com: still a host under acme.com
	} {
		if got := len(scanHosts(tc.text, nil)); got != tc.bad {
			t.Errorf("scanHosts(%q) = %d hits, want %d: %+v", tc.text, got, tc.bad, scanHosts(tc.text, nil))
		}
	}
	used := map[string]bool{}
	scanHosts("see https://github.com/x and docs.github.com/y", used)
	if !used["github.com"] {
		t.Error("allowlist usage not recorded")
	}
}
