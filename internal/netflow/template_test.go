package netflow

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tKey builds a templateKey for tests.
func tKey(exporter string, sourceID uint32, templateID uint16) templateKey {
	return templateKey{exporterKey{exporter, sourceID}, templateID}
}

// stdFields is a minimal plausible v9 template body: IPv4 src/dst + counters.
func stdFields() []templateField {
	return []templateField{
		{Type: ieSourceIPv4Address, Length: 4},
		{Type: ieDestinationIPv4Address, Length: 4},
		{Type: ieOctetDeltaCount, Length: 4},
		{Type: iePacketDeltaCount, Length: 4},
	}
}

// TestTemplateCache_PutGet verifies the basic round-trip: a stored template
// comes back with its fields, derived minRecLen, and flags intact.
func TestTemplateCache_PutGet(t *testing.T) {
	c := newTemplateCache()
	now := time.Now()
	key := tKey("192.0.2.1", 7, 256)

	if reason := c.put(key, stdFields(), 0, false, now); reason != putOK {
		t.Fatalf("put rejected: %q", reason)
	}
	rec := c.get(key, now)
	if rec == nil {
		t.Fatal("get returned nil for stored template")
	}
	if len(rec.fields) != 4 || rec.minRecLen != 16 || rec.isOptions || rec.scopeCount != 0 {
		t.Errorf("template mangled: fields=%d minRecLen=%d isOptions=%v scopeCount=%d",
			len(rec.fields), rec.minRecLen, rec.isOptions, rec.scopeCount)
	}
	// A different domain of the SAME exporter IP must be a distinct entry
	// (multi-VDOM isolation — the whole point of exporterKey.sourceID).
	if c.get(tKey("192.0.2.1", 8, 256), now) != nil {
		t.Error("template leaked across observation domains of one exporter IP")
	}
}

// TestTemplateCache_TTLSweep drives the injectable clock: an idle template is
// evicted after templateTTL, but one refreshed by get() survives (lastUsed is
// bumped on every use, so an actively-decoding template never expires).
func TestTemplateCache_TTLSweep(t *testing.T) {
	c := newTemplateCache()
	t0 := time.Now()
	idle := tKey("192.0.2.1", 0, 256)
	active := tKey("192.0.2.1", 0, 257)
	c.put(idle, stdFields(), 0, false, t0)
	c.put(active, stdFields(), 0, false, t0)

	// Touch only the active one 20 minutes in.
	if c.get(active, t0.Add(20*time.Minute)) == nil {
		t.Fatal("active template missing before sweep")
	}

	// 40 minutes in: idle has been unused 40 min (> TTL), active 20 min (< TTL).
	if removed := c.sweep(t0.Add(40 * time.Minute)); removed != 1 {
		t.Fatalf("sweep removed %d templates, want 1", removed)
	}
	if c.get(idle, t0.Add(40*time.Minute)) != nil {
		t.Error("idle template survived the TTL sweep")
	}
	if c.get(active, t0.Add(40*time.Minute)) == nil {
		t.Error("refreshed template was evicted despite recent use")
	}
	// The per-exporter count must shrink with the eviction so the slot is
	// reusable (otherwise sweeps leak capacity until the cap wedges shut).
	if reason := c.put(tKey("192.0.2.1", 0, 300), stdFields(), 0, false, t0.Add(41*time.Minute)); reason != putOK {
		t.Errorf("put after sweep rejected: %q", reason)
	}
}

// TestTemplateCache_PerExporterCap fills one exporter domain to
// maxTemplatesPerExporter and verifies the next NEW template is rejected with
// the exporter-cap reason — while a different exporter is still accepted.
func TestTemplateCache_PerExporterCap(t *testing.T) {
	c := newTemplateCache()
	now := time.Now()
	for i := 0; i < maxTemplatesPerExporter; i++ {
		key := tKey("192.0.2.1", 0, uint16(256+i))
		if reason := c.put(key, stdFields(), 0, false, now); reason != putOK {
			t.Fatalf("put %d rejected: %q", i, reason)
		}
	}
	if reason := c.put(tKey("192.0.2.1", 0, 9000), stdFields(), 0, false, now); reason != putRejectExporter {
		t.Errorf("over-cap put reason = %q, want %q", reason, putRejectExporter)
	}
	// Redefining an EXISTING template must still work at cap (replace, not add).
	if reason := c.put(tKey("192.0.2.1", 0, 256), stdFields()[:2], 0, false, now); reason != putOK {
		t.Errorf("redefinition at cap rejected: %q", reason)
	}
	// Another exporter is unaffected by this one's cap.
	if reason := c.put(tKey("192.0.2.2", 0, 256), stdFields(), 0, false, now); reason != putOK {
		t.Errorf("second exporter rejected by first exporter's cap: %q", reason)
	}
}

// TestTemplateCache_GlobalCap fills the cache to maxTemplatesTotal across many
// exporters and verifies the next template from a fresh exporter is rejected
// with the global-cap reason.
func TestTemplateCache_GlobalCap(t *testing.T) {
	c := newTemplateCache()
	now := time.Now()
	exporters := maxTemplatesTotal / maxTemplatesPerExporter
	for e := 0; e < exporters; e++ {
		ip := fmt.Sprintf("10.0.%d.%d", e/256, e%256)
		for i := 0; i < maxTemplatesPerExporter; i++ {
			if reason := c.put(tKey(ip, 0, uint16(256+i)), stdFields(), 0, false, now); reason != putOK {
				t.Fatalf("fill put (%s/%d) rejected: %q", ip, i, reason)
			}
		}
	}
	if got := c.len(); got != maxTemplatesTotal {
		t.Fatalf("cache holds %d templates, want %d", got, maxTemplatesTotal)
	}
	if reason := c.put(tKey("192.0.2.99", 0, 256), stdFields(), 0, false, now); reason != putRejectTotal {
		t.Errorf("over-global-cap put reason = %q, want %q", reason, putRejectTotal)
	}
}

// TestTemplateCache_RedefinitionReplaces pins the RFC 7011 §8.4 mandate: a new
// definition for an allocated template ID replaces the old one in place,
// always — subsequent gets must see the NEW layout, or every record would be
// decoded with a stale field list.
func TestTemplateCache_RedefinitionReplaces(t *testing.T) {
	c := newTemplateCache()
	now := time.Now()
	key := tKey("192.0.2.1", 0, 256)

	c.put(key, stdFields(), 0, false, now)
	newFields := []templateField{
		{Type: ieSourceIPv6Address, Length: 16},
		{Type: ieDestinationIPv6Address, Length: 16},
	}
	if reason := c.put(key, newFields, 0, false, now); reason != putOK {
		t.Fatalf("redefinition rejected: %q", reason)
	}
	rec := c.get(key, now)
	if rec == nil || len(rec.fields) != 2 || rec.minRecLen != 32 {
		t.Fatalf("redefinition not applied: %+v", rec)
	}
	if rec.fields[0].Type != ieSourceIPv6Address {
		t.Errorf("stale field list after redefinition: %+v", rec.fields)
	}
}

// TestTemplateCache_RejectZeroMinLen pins the zero-progress guard: a template
// whose records are 0 bytes long would spin the data-set walk forever.
func TestTemplateCache_RejectZeroMinLen(t *testing.T) {
	c := newTemplateCache()
	now := time.Now()
	for _, fields := range [][]templateField{
		nil, // no fields at all (withdrawal-shaped)
		{{Type: ieOctetDeltaCount, Length: 0}, {Type: iePacketDeltaCount, Length: 0}},
	} {
		if reason := c.put(tKey("192.0.2.1", 0, 256), fields, 0, false, now); reason != putRejectZeroLen {
			t.Errorf("zero-min-len put reason = %q, want %q (fields=%v)", reason, putRejectZeroLen, fields)
		}
	}
	if c.get(tKey("192.0.2.1", 0, 256), now) != nil {
		t.Error("rejected zero-length template was stored anyway")
	}
}

// TestTemplateCache_QuarantineAbsurdTemplates pins the sanity validation: a
// single fixed field wider than 64 bytes (the FortiGate length-9-integer bug
// class, nfdump #77) or a total record length over 2048 quarantines the whole
// template — while an IPFIX varlen field (0xFFFF) is exempt from the
// single-field bound.
func TestTemplateCache_QuarantineAbsurdTemplates(t *testing.T) {
	c := newTemplateCache()
	now := time.Now()

	// Absurd single field: 128-byte "counter".
	bad := []templateField{{Type: ieOctetDeltaCount, Length: 128}}
	if reason := c.put(tKey("192.0.2.1", 0, 256), bad, 0, false, now); reason != putRejectFieldLen {
		t.Errorf("absurd field-length put reason = %q, want %q", reason, putRejectFieldLen)
	}

	// Absurd total: 40 individually-legal 60-byte fields = 2400 > 2048.
	long := make([]templateField, 40)
	for i := range long {
		long[i] = templateField{Type: uint16(100 + i), Length: 60}
	}
	if reason := c.put(tKey("192.0.2.1", 0, 257), long, 0, false, now); reason != putRejectRecordLen {
		t.Errorf("absurd record-length put reason = %q, want %q", reason, putRejectRecordLen)
	}

	// varlen sentinel is NOT an absurd width — PAN App-ID strings depend on it.
	varlen := []templateField{
		{Type: 56701, Length: varlenFieldLen, EnterpriseID: penPaloAlto},
		{Type: ieOctetDeltaCount, Length: 4},
	}
	if reason := c.put(tKey("192.0.2.1", 0, 258), varlen, 0, false, now); reason != putOK {
		t.Errorf("varlen template rejected: %q", reason)
	}
	// varlen contributes its 1-byte length prefix to minRecLen.
	if rec := c.get(tKey("192.0.2.1", 0, 258), now); rec == nil || rec.minRecLen != 5 {
		t.Errorf("varlen minRecLen wrong: %+v", rec)
	}
}

// TestSamplerCache_FallbackChain walks the full nfdump-style resolution chain
// in precedence order: operator override > per-sampler-ID > per-domain > 1.
func TestSamplerCache_FallbackChain(t *testing.T) {
	s := newSamplerCache()
	ek := exporterKey{"192.0.2.1", 3}

	// 4. Nothing known → 1 (never hold flows waiting for options).
	if r := s.rateFor(ek, 0, false); r != 1 {
		t.Fatalf("empty-cache rate = %d, want 1", r)
	}

	// 3. Domain rate learned from generic options (IE 305/50/34).
	s.setDomainRate(ek, 64)
	if r := s.rateFor(ek, 0, false); r != 64 {
		t.Fatalf("domain rate = %d, want 64", r)
	}

	// 2. Per-sampler rate outranks the domain rate — but only when the record
	// actually referenced a sampler ID (hasSamplerID); otherwise ID 0 must not
	// accidentally match.
	s.setSamplerRate(ek, 5, 100)
	if r := s.rateFor(ek, 5, true); r != 100 {
		t.Errorf("per-sampler rate = %d, want 100", r)
	}
	if r := s.rateFor(ek, 9, true); r != 64 {
		t.Errorf("unknown sampler ID rate = %d, want domain fallback 64", r)
	}
	if r := s.rateFor(ek, 5, false); r != 64 {
		t.Errorf("no-sampler-ID record rate = %d, want domain fallback 64", r)
	}

	// 1. Operator override outranks everything (covers ALL domains of the IP).
	s.SetSamplingOverride("192.0.2.1", 2000)
	if r := s.rateFor(ek, 5, true); r != 2000 {
		t.Errorf("override rate = %d, want 2000", r)
	}
	if r := s.rateFor(exporterKey{"192.0.2.1", 99}, 0, false); r != 2000 {
		t.Errorf("override missed sibling domain: %d, want 2000", r)
	}

	// Override removal (rate 0) restores the learned chain.
	s.SetSamplingOverride("192.0.2.1", 0)
	if r := s.rateFor(ek, 5, true); r != 100 {
		t.Errorf("post-override-removal rate = %d, want 100", r)
	}
}

// TestCacheSet_PersistRoundTrip pins the disk persistence contract (goflow2
// pattern): templates and LEARNED sampler rates survive a save/load cycle into
// fresh caches, so a collector restart doesn't blind v9/IPFIX decoding for a
// full template-refresh interval. Operator overrides are configuration and
// intentionally do NOT persist.
func TestCacheSet_PersistRoundTrip(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "flows", "templates.json")

	src := &cacheSet{templates: newTemplateCache(), samplers: newSamplerCache()}
	dataKey := tKey("192.0.2.1", 3, 256)
	optKey := tKey("192.0.2.1", 3, 257)
	src.templates.put(dataKey, stdFields(), 0, false, now)
	src.templates.put(optKey, []templateField{
		{Type: ieSamplerID, Length: 2},
		{Type: ieSamplerRandomInterval, Length: 4},
	}, 1, true, now)
	src.samplers.setDomainRate(exporterKey{"192.0.2.1", 3}, 64)
	src.samplers.setSamplerRate(exporterKey{"192.0.2.1", 3}, 5, 100)
	src.samplers.SetSamplingOverride("192.0.2.1", 7) // must NOT persist

	if err := src.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	dst := &cacheSet{templates: newTemplateCache(), samplers: newSamplerCache()}
	if err := dst.LoadFrom(path, now); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	rec := dst.templates.get(dataKey, now)
	if rec == nil || len(rec.fields) != 4 || rec.minRecLen != 16 || rec.isOptions {
		t.Fatalf("data template did not round-trip: %+v", rec)
	}
	opt := dst.templates.get(optKey, now)
	if opt == nil || !opt.isOptions || opt.scopeCount != 1 || opt.minRecLen != 6 {
		t.Fatalf("options template did not round-trip: %+v", opt)
	}
	ek := exporterKey{"192.0.2.1", 3}
	if r := dst.samplers.rateFor(ek, 5, true); r != 100 {
		t.Errorf("per-sampler rate did not round-trip: %d, want 100", r)
	}
	if r := dst.samplers.rateFor(ek, 0, false); r != 64 {
		t.Errorf("domain rate did not round-trip: %d, want 64", r)
	}
	if r := dst.samplers.rateFor(exporterKey{"192.0.2.1", 99}, 0, false); r != 1 {
		t.Errorf("operator override leaked into the persisted cache: %d, want 1", r)
	}
}

// TestCacheSet_LoadFromMissingFile confirms a first start (no cache file yet)
// is not an error, and a corrupt file returns one without panicking.
func TestCacheSet_LoadFromMissingFile(t *testing.T) {
	c := &cacheSet{templates: newTemplateCache(), samplers: newSamplerCache()}
	if err := c.LoadFrom(filepath.Join(t.TempDir(), "nope.json"), time.Now()); err != nil {
		t.Fatalf("missing file must be a clean first start, got %v", err)
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.LoadFrom(bad, time.Now()); err == nil {
		t.Error("corrupt cache file should return an error")
	}
}

// TestCacheSet_LoadRevalidates confirms loaded templates run back through
// put()'s quarantine, so a cache file written by an older/laxer build (or
// hand-edited) can't smuggle absurd templates past registration.
func TestCacheSet_LoadRevalidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "poison.json")
	poison := `{"templates":[{"exporter":"192.0.2.1","source_id":0,"template_id":256,` +
		`"fields":[{"type":1,"length":128}]}],"samplers":null}`
	if err := os.WriteFile(path, []byte(poison), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &cacheSet{templates: newTemplateCache(), samplers: newSamplerCache()}
	if err := c.LoadFrom(path, time.Now()); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if c.templates.get(tKey("192.0.2.1", 0, 256), time.Now()) != nil {
		t.Error("absurd persisted template bypassed the put() quarantine")
	}
}

// TestDecodeBE pins the length-agnostic big-endian decoder used by every
// numeric field read in the v9/IPFIX record parsers (RFC 7011 §6.2
// reduced-size encoding means the same IE arrives at different widths).
func TestDecodeBE(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		ok   bool
	}{
		{nil, 0, false},
		{[]byte{0x7f}, 0x7f, true},
		{[]byte{0x01, 0x02}, 0x0102, true},
		{[]byte{0x01, 0x02, 0x03}, 0x010203, true}, // reduced-size 3-byte encoding
		{[]byte{0xde, 0xad, 0xbe, 0xef}, 0xdeadbeef, true},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0xffffffffffffffff, true},
		{make([]byte, 9), 0, false},
	}
	for _, tc := range cases {
		got, ok := decodeBE(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("decodeBE(%x) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
