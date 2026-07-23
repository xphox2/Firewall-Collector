package fwapi

import "testing"

// parityCase / parityCases MUST stay byte-identical with the server copy
// (Firewall-Mon internal/ipsec/conformance/serialize_test.go ParityCases). The
// server (func) evaluator and this collector (data) evaluator must both agree
// with `valid`, pinning the reimplemented proposal grammar across the two repos —
// the same cross-repo pin mechanism as TestChecksumSteps_ParityWith*.
type parityCase struct {
	vendor string
	path   string
	field  string
	value  string
	valid  bool
}

var parityCases = []parityCase{
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256gcm16-sha384-ecp384", true},
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256gcm16-prfsha384-ecp384", false},
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256-sha256-modp2048", true},
	{"opnsense", "/api/ipsec/connections/addConnection", "proposals", "aes256gcm16-sha384", false},
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256gcm16-ecp384", true},
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256gcm16", true},
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes128gcm16", false},
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256-sha256", true},
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256-sha384", false},
	{"opnsense", "/api/ipsec/connections/addChild", "esp_proposals", "aes256-sha256-ecp384", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256gcm-prfsha384", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256gcm16-sha384", false},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256-sha256", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase1-interface", "proposal", "aes256gcm-sha384", false},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase2-interface", "proposal", "aes256gcm", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase2-interface", "proposal", "aes256-sha256", true},
	{"fortigate", "/api/v2/cmdb/vpn.ipsec/phase2-interface", "proposal", "aes256gcm-sha384", false},
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "169.254.1.1 255.255.255.255", true},
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", " 255.255.255.255", false},
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "169.254.1.1", false},
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "169.254.1.1 255.255.0.0.0", false},
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "ip", "", false},
	{"fortigate", "/api/v2/cmdb/system/interface/fwm-t7", "remote-ip", "169.254.1.2 255.255.255.252", true},
}

// parityTokenSets mirror the server's conformance token sets (opnsense.go /
// fortigate.go). Runtime uses the SHIPPED sets; the test needs representative
// copies to exercise the grammar against the shared ground truth.
func paritySpec(vendor string) *conformanceSpec {
	switch vendor {
	case "opnsense":
		return &conformanceSpec{
			Vendor: "opnsense", Grammar: "opnsense",
			Objects: map[string]map[string]serRule{
				"connections/addConnection": {"proposals": {Kind: "proposal_ike"}},
				"connections/addChild":      {"esp_proposals": {Kind: "proposal_esp"}},
			},
			TokenSets: map[string][]string{
				"enc":      {"aes128", "aes192", "aes256", "aes128gcm16", "aes192gcm16", "aes256gcm16", "chacha20poly1305"},
				"hash":     {"sha256", "sha384", "sha512", "aesxcbc"},
				"dh":       {"modp2048", "modp3072", "modp4096", "modp6144", "modp8192", "ecp224", "ecp256", "ecp384", "ecp521", "ecp224bp", "ecp256bp", "ecp384bp", "ecp512bp", "x25519", "x448"},
				"bare_esp": {"aes256gcm16", "chacha20poly1305", "aes256-sha1", "aes256-sha256"},
			},
		}
	case "fortigate":
		return &conformanceSpec{
			Vendor: "fortigate", Grammar: "fortigate",
			Objects: map[string]map[string]serRule{
				"vpn.ipsec/phase1-interface": {"proposal": {Kind: "proposal_ike"}},
				"vpn.ipsec/phase2-interface": {"proposal": {Kind: "proposal_esp"}},
				"system/interface":           {"ip": {Kind: "ip_mask"}, "remote-ip": {Kind: "ip_mask"}},
			},
			TokenSets: map[string][]string{
				"enc":  {"des", "3des", "aes128", "aes192", "aes256", "aes128gcm", "aes192gcm", "aes256gcm", "aria128", "aria192", "aria256", "seed", "chacha20poly1305"},
				"hash": {"md5", "sha1", "sha256", "sha384", "sha512"},
				"prf":  {"prfsha1", "prfsha256", "prfsha384", "prfsha512"},
				"dh":   {"1", "2", "5", "14", "15", "16", "17", "18", "19", "20", "21", "27", "28", "29", "30", "31", "32"},
			},
		}
	}
	return nil
}

func TestConformance_ParityCases_CollectorSide(t *testing.T) {
	for _, c := range parityCases {
		spec := paritySpec(c.vendor)
		body := `{"` + c.field + `":"` + c.value + `"}`
		if c.vendor == "opnsense" {
			key := "connection"
			if c.field == "esp_proposals" {
				key = "child"
			}
			body = `{"` + key + `":` + body + `}`
		}
		steps := []ApplyStep{{Kind: "http_api", Method: "POST", Path: c.path, Body: body}}
		f := validateStepsAgainstSpec(spec, steps)
		got := true
		for _, x := range f {
			if x.Field == c.field {
				got = false
			}
		}
		if got != c.valid {
			t.Errorf("%s %s=%q: collector evaluator valid=%v, want %v (findings: %v)", c.vendor, c.field, c.value, got, c.valid, f)
		}
	}
}
