package fwapi

// Conformance enforcement, collector side (IPSec apply Phase 2). The server ships
// its per-vendor conformance spec (rules as DATA + proposal token sets) in the
// apply payload's validation_spec; this file re-validates every rendered step's
// field VALUES against it BEFORE the first write and aborts with the full findings
// list — defense-in-depth for the server's pre-dispatch guard, and it kills the
// first-step failure masking (all bad fields reported at once, nothing written).
//
// The rule DATA is authored once server-side and shipped; only the evaluator LOGIC
// (this file + the proposal grammar) is duplicated here, pinned to the server by
// the shared ParityCases list (conformance_parity_test.go), exactly as
// checksumSteps is pinned across the two repos.

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// serRule / conformanceSpec mirror the server's conformance.SerRule / Spec JSON.
type serRule struct {
	Kind       string   `json:"kind"`
	Enum       []string `json:"enum,omitempty"`
	Min        int      `json:"min,omitempty"`
	Max        int      `json:"max,omitempty"`
	AllowEmpty bool     `json:"allow_empty,omitempty"`
	Required   bool     `json:"required,omitempty"`
}

type conformanceSpec struct {
	Vendor    string                        `json:"vendor"`
	Grammar   string                        `json:"grammar"`
	Objects   map[string]map[string]serRule `json:"objects"`
	TokenSets map[string][]string           `json:"token_sets"`
}

type conformanceFinding struct {
	Path   string
	Field  string
	Value  string
	Reason string
}

func (f conformanceFinding) String() string {
	return f.Path + ": field " + f.Field + "=" + f.Value + " — " + f.Reason
}

// validateStepsAgainstSpec returns every step field value the spec rejects.
func validateStepsAgainstSpec(spec *conformanceSpec, steps []ApplyStep) []conformanceFinding {
	if spec == nil || len(spec.Objects) == 0 {
		return nil
	}
	ts := map[string]map[string]bool{}
	for name, vals := range spec.TokenSets {
		ts[name] = toSet(vals)
	}
	var out []conformanceFinding
	for _, s := range steps {
		if s.Body == "" {
			continue
		}
		obj := matchObject(spec, s.Path)
		if obj == nil {
			continue
		}
		fields, ok := unwrapBody(s.Body)
		if !ok {
			out = append(out, conformanceFinding{Path: s.Path, Reason: "body is not a JSON object"})
			continue
		}
		for name, rule := range obj {
			raw, present := fields[name]
			if !present {
				if rule.Required {
					out = append(out, conformanceFinding{Path: s.Path, Field: name, Reason: "required field missing"})
				}
				continue
			}
			if f, bad := checkSpecValue(spec, ts, s.Path, name, asScalarString(raw), rule); bad {
				out = append(out, f)
			}
		}
	}
	return out
}

func matchObject(spec *conformanceSpec, path string) map[string]serRule {
	var best string
	var bestObj map[string]serRule
	for key, obj := range spec.Objects {
		if strings.Contains(path, key) && len(key) > len(best) {
			best, bestObj = key, obj
		}
	}
	return bestObj
}

func checkSpecValue(spec *conformanceSpec, ts map[string]map[string]bool, path, name, val string, rule serRule) (conformanceFinding, bool) {
	mk := func(reason string) (conformanceFinding, bool) {
		return conformanceFinding{Path: path, Field: name, Value: val, Reason: reason}, true
	}
	switch rule.Kind {
	case "enum":
		if !inSlice(rule.Enum, val) {
			return mk("not in allowed set " + strings.Join(rule.Enum, "|"))
		}
	case "space_enum":
		for _, tok := range strings.Fields(val) {
			if !inSlice(rule.Enum, tok) {
				return mk("token " + tok + " not in allowed set " + strings.Join(rule.Enum, "|"))
			}
		}
	case "enable_disable":
		if val != "enable" && val != "disable" {
			return mk(`must be "enable" or "disable"`)
		}
	case "bool01":
		if val != "0" && val != "1" {
			return mk(`must be "0" or "1"`)
		}
	case "int_range":
		n, err := strconv.Atoi(val)
		if err != nil {
			return mk("not an integer")
		}
		if n < rule.Min || n > rule.Max {
			return mk("outside range")
		}
	case "address":
		if val == "" {
			if !rule.AllowEmpty {
				return mk("empty not allowed")
			}
			return conformanceFinding{}, false
		}
		for _, part := range strings.Split(val, ",") {
			if !validAddr(strings.TrimSpace(part)) {
				return mk(`not a valid IP/CIDR/hostname (e.g. "%any" is rejected)`)
			}
		}
	case "ip_mask":
		// FortiGate "IP MASK" pair: exactly two space-separated dotted-quad
		// tokens (address + contiguous netmask), e.g. "169.254.1.1
		// 255.255.255.255". Empty / single-token / malformed values are device
		// rejections (the fwm-t4 HTTP 500 class).
		if !validIPMaskPair(val) {
			return mk(`must be "<ipv4> <dotted-netmask>" (two tokens, contiguous mask)`)
		}
	case "proposal_ike":
		if ok, why := evalIKEProposal(spec.Grammar, ts, val); !ok {
			return mk("invalid IKE proposal: " + why)
		}
	case "proposal_esp":
		if ok, why := evalESPProposal(spec.Grammar, ts, val); !ok {
			return mk("invalid ESP proposal: " + why)
		}
	}
	return conformanceFinding{}, false
}

// ---- proposal grammar (mirrors server conformance/{opnsense,fortigate}.go) ----

func isAEADToken(enc string) bool {
	return strings.Contains(enc, "gcm") || enc == "chacha20poly1305"
}

func evalIKEProposal(grammar string, ts map[string]map[string]bool, s string) (bool, string) {
	parts := strings.Split(s, "-")
	switch grammar {
	case "opnsense":
		if len(parts) != 3 {
			return false, "expected 3-part enc-<hash>-dh"
		}
		if !ts["enc"][parts[0]] {
			return false, "unknown cipher " + parts[0]
		}
		if !ts["hash"][parts[1]] {
			return false, "middle term must be a bare hash, got " + parts[1]
		}
		if !ts["dh"][parts[2]] {
			return false, "unknown DH group " + parts[2]
		}
		return true, ""
	case "fortigate":
		if len(parts) != 2 {
			return false, "expected 2-part enc-<prf|hash>"
		}
		if !ts["enc"][parts[0]] {
			return false, "unknown cipher " + parts[0]
		}
		if isAEADToken(parts[0]) {
			if !ts["prf"][parts[1]] {
				return false, "AEAD IKE proposal needs a prf term, got " + parts[1]
			}
			return true, ""
		}
		if !ts["hash"][parts[1]] {
			return false, "CBC IKE proposal needs a hash term, got " + parts[1]
		}
		return true, ""
	}
	return true, "" // unknown grammar → don't manufacture a failure
}

func evalESPProposal(grammar string, ts map[string]map[string]bool, s string) (bool, string) {
	parts := strings.Split(s, "-")
	if len(parts) == 0 || !ts["enc"][parts[0]] {
		return false, "unknown cipher"
	}
	switch grammar {
	case "opnsense":
		if isAEADToken(parts[0]) {
			switch len(parts) {
			case 1:
				if ts["bare_esp"][s] {
					return true, ""
				}
				return false, "bare " + s + " is not a device-accepted no-PFS proposal"
			case 2:
				if !ts["dh"][parts[1]] {
					return false, "unknown DH group " + parts[1]
				}
				return true, ""
			default:
				return false, "AEAD ESP proposal is enc[-dh]"
			}
		}
		switch len(parts) {
		case 2:
			if ts["bare_esp"][s] {
				return true, ""
			}
			return false, "bare " + s + " is not a device-accepted no-PFS proposal"
		case 3:
			if !ts["hash"][parts[1]] {
				return false, "unknown hash " + parts[1]
			}
			if !ts["dh"][parts[2]] {
				return false, "unknown DH group " + parts[2]
			}
			return true, ""
		default:
			return false, "CBC ESP proposal is enc-hash[-dh]"
		}
	case "fortigate":
		if isAEADToken(parts[0]) {
			if len(parts) != 1 {
				return false, "AEAD ESP proposal is a single cipher token"
			}
			return true, ""
		}
		if len(parts) != 2 || !ts["hash"][parts[1]] {
			return false, "CBC ESP proposal is enc-hash"
		}
		return true, ""
	}
	return true, ""
}

// ---- shared helpers (kept local to avoid coupling to apply.go internals) ----

func unwrapBody(body string) (map[string]any, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &top); err != nil {
		return nil, false
	}
	if len(top) == 1 {
		for _, raw := range top {
			var inner map[string]any
			if json.Unmarshal(raw, &inner) == nil {
				return inner, true
			}
		}
	}
	var flat map[string]any
	if err := json.Unmarshal([]byte(body), &flat); err != nil {
		return nil, false
	}
	return flat, true
}

func asScalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "1"
		}
		return "0"
	case nil:
		return ""
	default:
		return ""
	}
}

func validAddr(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return isHostnameToken(s)
}

// validIPMaskPair validates FortiOS's "<ipv4> <dotted-netmask>" two-token form
// (system/interface ip / remote-ip): both tokens dotted-quad IPv4, the mask
// contiguous (net.IPMask.Size reports bits=32 only for contiguous masks).
func validIPMaskPair(val string) bool {
	parts := strings.Fields(val)
	if len(parts) != 2 {
		return false
	}
	if net.ParseIP(parts[0]).To4() == nil {
		return false
	}
	m := net.ParseIP(parts[1]).To4()
	if m == nil {
		return false
	}
	_, bits := net.IPMask(m).Size()
	return bits == 32
}

func isHostnameToken(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, "%*/ ") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return false
			}
		}
	}
	return true
}

func toSet(vs []string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

func inSlice(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
