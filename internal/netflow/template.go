package netflow

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Template cache limits. TTL follows RFC 7011 §8.4 guidance (collector-side
// expiry over UDP is optional but SHOULD cover ≥3× the observed retransmission
// rate — PAN refreshes every 30 min, FortiGate template-tx-timeout defaults to
// 1800 s, so 30 min is the floor, refreshed on every use). The caps bound a
// hostile or broken exporter: without them a template flood is a
// memory-exhaustion DoS (same rationale as ratelimit.MaxSources).
const (
	templateTTL             = 30 * time.Minute
	maxTemplatesPerExporter = 256
	maxTemplatesTotal       = 8192

	// Template sanity bounds (put quarantine). A single fixed-length numeric
	// field wider than 64 bytes is not a real IE — FortiGate FGT1000D shipped
	// length-9 integers that inflated nfdump counters exactly 69× (nfdump #77);
	// we reject the whole template rather than mis-decode every record cut
	// from it. varlen fields (length 0xFFFF, IPFIX only) are exempt: their
	// declared template length is a sentinel, not a width. minRecLen > 2048
	// means a "record" bigger than any real exporter emits — with a 64 KiB UDP
	// ceiling that template could only ever yield a handful of records and is
	// almost certainly garbage that would desync the data-set walk.
	maxFieldLen  = 64
	maxRecordLen = 2048

	// varlenFieldLen is the IPFIX sentinel template length for a
	// variable-length IE (RFC 7011 §7).
	varlenFieldLen = 0xFFFF

	// Sampler-cache caps — same memory-DoS rationale as the template caps
	// above, at the same scale. Without them a rotating set of spoofed
	// exporter IPs/ODIDs accumulates sampler entries indefinitely ACROSS
	// template-cap generations (templates TTL out and free cap headroom every
	// 30 min; learned rates would not), and every entry is serialized into the
	// persisted cache file, growing it monotonically for the life of the
	// install. Each rate family (per-domain, per-sampler) is capped
	// independently; entries whose domain no longer has any live template are
	// evicted by the maintenance sweep (see cacheSet.sweep). Operator
	// overrides are exempt: they are configuration, bounded by config size.
	maxSamplerDomains    = maxTemplatesTotal
	maxSamplersPerDomain = maxTemplatesPerExporter
)

// exporterKey identifies one observation domain of one exporter: v9 sourceID /
// IPFIX observation-domain ID scoped under the exporter's UDP source IP.
// Multi-VDOM FortiGates, ASA contexts, and NP7 CPU-vs-NP paths all multiplex
// several domains behind one source IP, and template IDs are only unique
// within a domain (RFC 7011 §3.1) — keying on the IP alone would let one
// VDOM's template 256 corrupt another's.
type exporterKey struct {
	exporter string // UDP source IP, net.IP.String() form
	sourceID uint32 // v9 Source ID / IPFIX Observation Domain ID
}

// templateKey identifies one template within an exporter domain.
type templateKey struct {
	exporterKey
	templateID uint16
}

// templateField is one field specifier from a (options) template record.
// EnterpriseID is 0 for IANA IEs; non-zero only for IPFIX enterprise-bit
// fields (v9 has no PEN mechanism). Exported fields so persistence can
// marshal the specifier as-is.
type templateField struct {
	Type         uint16 `json:"type"`
	Length       uint16 `json:"length"`
	EnterpriseID uint32 `json:"enterprise_id,omitempty"`
}

// templateRecord is one cached (options) template: the ordered field list plus
// the derived minimum record length used to bound the data-set walk (records
// stop when remaining < minRecLen — trailing padding must not become phantom
// 0.0.0.0→0.0.0.0 flows).
type templateRecord struct {
	fields     []templateField
	scopeCount int  // leading scope fields (options templates only)
	minRecLen  int  // sum of fixed field lengths; varlen fields count 1 (their length prefix)
	isOptions  bool // options template (v9 set 1 / IPFIX set 3)
	lastUsed   time.Time
}

// minRecordLen derives the minimum wire length of one data record cut from
// fields: fixed lengths sum as-is; a varlen field contributes only its 1-byte
// length prefix (RFC 7011 §7 — the escape byte is the minimum presence).
func minRecordLen(fields []templateField) int {
	n := 0
	for _, f := range fields {
		if f.Length == varlenFieldLen {
			n++
			continue
		}
		n += int(f.Length)
	}
	return n
}

// Distinct put rejection reasons, surfaced to the receiver's parse-event
// counter so operators can tell "your exporter ships absurd templates" from
// "you have too many exporters" at a glance.
const (
	putOK              = ""
	putRejectZeroLen   = "template_zero_min_len" // minRecLen == 0: a data set cut from it would never advance
	putRejectFieldLen  = "template_quarantined"  // absurd single-field length (the nfdump-#77 FortiGate bug class)
	putRejectRecordLen = "template_quarantined"  // absurd total record length
	putRejectExporter  = "template_cap_exporter" // per-exporter cap hit
	putRejectTotal     = "template_cap_total"    // global cap hit
)

// templateCache is the shared v9/IPFIX template store. One instance serves
// both receiver sockets — templates are keyed by exporter+domain, not by which
// port the datagram arrived on (a v9 exporter pointed at the IPFIX port must
// still work; dispatch is content-based). All methods take an explicit now so
// tests can drive the TTL clock.
type templateCache struct {
	mu          sync.Mutex
	templates   map[templateKey]*templateRecord
	perExporter map[exporterKey]int
}

func newTemplateCache() *templateCache {
	return &templateCache{
		templates:   make(map[templateKey]*templateRecord),
		perExporter: make(map[exporterKey]int),
	}
}

// put validates and stores a template. Redefinition of an existing key is an
// atomic in-place replace ALWAYS, regardless of any timeout — RFC 7011 §8.4
// calls this "the normal operation of Template ID reuse over UDP"; refusing
// the replace would decode every subsequent record with the stale layout.
// Returns one of the putReject* reasons ("" = accepted).
func (c *templateCache) put(key templateKey, fields []templateField, scopeCount int, isOptions bool, now time.Time) string {
	minLen := minRecordLen(fields)
	// Zero-progress guard: a data-set loop keyed to a 0-length record would
	// spin forever without advancing its offset.
	if minLen == 0 {
		return putRejectZeroLen
	}
	if minLen > maxRecordLen {
		return putRejectRecordLen
	}
	for _, f := range fields {
		if f.Length != varlenFieldLen && f.Length > maxFieldLen {
			return putRejectFieldLen
		}
	}

	rec := &templateRecord{
		fields:     fields,
		scopeCount: scopeCount,
		minRecLen:  minLen,
		isOptions:  isOptions,
		lastUsed:   now,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.templates[key]; exists {
		c.templates[key] = rec // in-place replace; counters unchanged
		return putOK
	}
	if c.perExporter[key.exporterKey] >= maxTemplatesPerExporter {
		return putRejectExporter
	}
	if len(c.templates) >= maxTemplatesTotal {
		return putRejectTotal
	}
	c.templates[key] = rec
	c.perExporter[key.exporterKey]++
	return putOK
}

// get returns the cached template for key (nil if absent) and refreshes its
// lastUsed so actively-decoding templates never TTL out between refreshes.
func (c *templateCache) get(key templateKey, now time.Time) *templateRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.templates[key]
	if rec != nil {
		rec.lastUsed = now
	}
	return rec
}

// sweep evicts templates idle past the TTL and returns how many were removed.
// Called from the receiver's maintenance ticker.
func (c *templateCache) sweep(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for key, rec := range c.templates {
		if now.Sub(rec.lastUsed) > templateTTL {
			delete(c.templates, key)
			if c.perExporter[key.exporterKey]--; c.perExporter[key.exporterKey] <= 0 {
				delete(c.perExporter, key.exporterKey)
			}
			removed++
		}
	}
	return removed
}

// len reports the number of cached templates (metrics/tests).
func (c *templateCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.templates)
}

// samplerCache resolves the sampling rate for a data record via the
// nfdump-style fallback chain (research §2.3), in strict precedence order:
//
//  1. operator override for the exporter IP (SetSamplingOverride — the escape
//     hatch for MikroTik ROS6's little-endian rate bug, where auto-byte-swap
//     is ambiguous and both goflow2 and Akvorado refuse to guess);
//  2. per-sampler-ID rate learned from options data (FLOW_SAMPLER_ID 48 /
//     selectorId 302 records — Cisco runs per-interface samplers);
//  3. per-domain rate learned from generic options (IE 305 [+306 multiplier],
//     50, or 34 — including IE 34 arriving in DATA records, MikroTik-style);
//  4. 1 — firewalls (PAN-OS, ASA, pre-7.6 FortiGate) are unsampled and mostly
//     never send sampler options; flows are NEVER held waiting for an options
//     template that will never come.
type samplerCache struct {
	mu         sync.Mutex
	overrides  map[string]uint32                 // exporter IP -> operator-pinned rate
	perSampler map[exporterKey]map[uint32]uint32 // samplerID -> rate
	perDomain  map[exporterKey]uint32
}

func newSamplerCache() *samplerCache {
	return &samplerCache{
		overrides:  make(map[string]uint32),
		perSampler: make(map[exporterKey]map[uint32]uint32),
		perDomain:  make(map[exporterKey]uint32),
	}
}

// SetSamplingOverride pins the sampling rate for every domain of exporterIP,
// taking precedence over anything the exporter reports. rate 0 removes the
// override.
func (s *samplerCache) SetSamplingOverride(exporterIP string, rate uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rate == 0 {
		delete(s.overrides, exporterIP)
		return
	}
	s.overrides[exporterIP] = rate
}

// setSamplerRate records a per-sampler-ID rate learned from options data.
// At the caps, NEW domains/sampler IDs are dropped rather than grown
// unbounded (existing entries still update) — the same posture as the
// template cache and seqTracker.
func (s *samplerCache) setSamplerRate(ek exporterKey, samplerID, rate uint32) {
	if rate == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.perSampler[ek]
	if m == nil {
		if len(s.perSampler) >= maxSamplerDomains {
			return
		}
		m = make(map[uint32]uint32)
		s.perSampler[ek] = m
	}
	if _, exists := m[samplerID]; !exists && len(m) >= maxSamplersPerDomain {
		return
	}
	m[samplerID] = rate
}

// setDomainRate records a domain-wide rate learned from generic sampling
// options (or an IE-34-in-data-records sighting). Capped like setSamplerRate:
// a new domain past maxSamplerDomains is dropped, existing ones still update.
func (s *samplerCache) setDomainRate(ek exporterKey, rate uint32) {
	if rate == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.perDomain[ek]; !exists && len(s.perDomain) >= maxSamplerDomains {
		return
	}
	s.perDomain[ek] = rate
}

// sweepOrphans evicts learned rates for every domain NOT in live (the set of
// domains that still hold at least one cached template) and returns how many
// map entries were removed. A domain with no template cannot decode a single
// record, so its learned rates are dead weight — this ties sampler-entry
// lifetime to the template TTL instead of keeping a second clock, and stops
// long-gone exporters from riding in the persisted cache file forever.
// Operator overrides are keyed by IP, are configuration, and are never swept.
func (s *samplerCache) sweepOrphans(live map[exporterKey]bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for ek := range s.perDomain {
		if !live[ek] {
			delete(s.perDomain, ek)
			removed++
		}
	}
	for ek := range s.perSampler {
		if !live[ek] {
			delete(s.perSampler, ek)
			removed++
		}
	}
	return removed
}

// rateFor resolves the effective sampling rate for one data record.
// hasSamplerID says whether the record carried a sampler reference (IE 48/302)
// — without one, step 2 is skipped entirely rather than matched against ID 0.
func (s *samplerCache) rateFor(ek exporterKey, samplerID uint32, hasSamplerID bool) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.overrides[ek.exporter]; ok {
		return r
	}
	if hasSamplerID {
		if r, ok := s.perSampler[ek][samplerID]; ok {
			return r
		}
	}
	if r, ok := s.perDomain[ek]; ok {
		return r
	}
	return 1
}

// --- Disk persistence (goflow2 pattern) ---
//
// Templates arrive only on the exporter's refresh cycle (PAN 30 min, FortiGate
// 1800 s default), so a collector restart without persisted state blinds
// v9/IPFIX decoding for up to 30 minutes per exporter. The receiver calls
// LoadFrom at Start and SaveTo on Stop plus every 5 minutes from its
// maintenance ticker. Learned sampler rates ride along; operator overrides do
// NOT persist — they are configuration, re-applied at startup by the caller.

// persistedTemplate is the JSON form of one cached template.
type persistedTemplate struct {
	Exporter   string          `json:"exporter"`
	SourceID   uint32          `json:"source_id"`
	TemplateID uint16          `json:"template_id"`
	Fields     []templateField `json:"fields"`
	ScopeCount int             `json:"scope_count,omitempty"`
	IsOptions  bool            `json:"is_options,omitempty"`
}

// persistedSamplerDomain is the JSON form of one domain's learned rates.
type persistedSamplerDomain struct {
	Exporter   string            `json:"exporter"`
	SourceID   uint32            `json:"source_id"`
	DomainRate uint32            `json:"domain_rate,omitempty"`
	Samplers   map[uint32]uint32 `json:"samplers,omitempty"`
}

// persistedState is the on-disk cache file.
type persistedState struct {
	Templates []persistedTemplate      `json:"templates"`
	Samplers  []persistedSamplerDomain `json:"samplers"`
}

// cacheSet bundles the template and sampler caches so the receiver persists
// them as one file and one call site.
type cacheSet struct {
	templates *templateCache
	samplers  *samplerCache
}

// sweep expires idle templates, then evicts sampler entries for every domain
// left with no live template. Run before each SaveTo (the maintenance ticker)
// so evicted state never rides into the cache file. Returns (templates,
// sampler entries) removed.
func (c *cacheSet) sweep(now time.Time) (int, int) {
	tRemoved := c.templates.sweep(now)
	c.templates.mu.Lock()
	live := make(map[exporterKey]bool, len(c.templates.perExporter))
	for ek := range c.templates.perExporter {
		live[ek] = true
	}
	c.templates.mu.Unlock()
	return tRemoved, c.samplers.sweepOrphans(live)
}

// SaveTo atomically writes both caches to path (temp file + rename, so a crash
// mid-write can't leave a truncated file that LoadFrom would then reject).
func (c *cacheSet) SaveTo(path string) error {
	var st persistedState

	c.templates.mu.Lock()
	for key, rec := range c.templates.templates {
		st.Templates = append(st.Templates, persistedTemplate{
			Exporter:   key.exporter,
			SourceID:   key.sourceID,
			TemplateID: key.templateID,
			Fields:     rec.fields,
			ScopeCount: rec.scopeCount,
			IsOptions:  rec.isOptions,
		})
	}
	c.templates.mu.Unlock()

	c.samplers.mu.Lock()
	seen := make(map[exporterKey]*persistedSamplerDomain)
	domain := func(ek exporterKey) *persistedSamplerDomain {
		if d := seen[ek]; d != nil {
			return d
		}
		d := &persistedSamplerDomain{Exporter: ek.exporter, SourceID: ek.sourceID}
		seen[ek] = d
		return d
	}
	for ek, rate := range c.samplers.perDomain {
		domain(ek).DomainRate = rate
	}
	for ek, m := range c.samplers.perSampler {
		d := domain(ek)
		d.Samplers = make(map[uint32]uint32, len(m))
		for id, rate := range m {
			d.Samplers[id] = rate
		}
	}
	c.samplers.mu.Unlock()
	for _, d := range seen {
		st.Samplers = append(st.Samplers, *d)
	}

	data, err := json.Marshal(&st)
	if err != nil {
		return fmt.Errorf("marshal flow caches: %w", err)
	}
	tmp := path + ".tmp"
	// AUDIT-224 (gosec G301): 0o750, consistent with the 0o600 cache file
	// written just below — private template-cache state.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write flow cache file: %w", err)
	}
	return os.Rename(tmp, path)
}

// LoadFrom restores both caches from path. A missing file is a clean first
// start, not an error. Loaded templates run back through put() so the sanity
// quarantine re-applies — a cache file poisoned by an older, laxer build (or
// hand-edited) cannot smuggle absurd templates past registration.
func (c *cacheSet) LoadFrom(path string, now time.Time) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read flow cache file: %w", err)
	}
	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse flow cache file: %w", err)
	}
	for _, t := range st.Templates {
		key := templateKey{exporterKey{t.Exporter, t.SourceID}, t.TemplateID}
		c.templates.put(key, t.Fields, t.ScopeCount, t.IsOptions, now)
	}
	for _, d := range st.Samplers {
		ek := exporterKey{d.Exporter, d.SourceID}
		if d.DomainRate > 0 {
			c.samplers.setDomainRate(ek, d.DomainRate)
		}
		for id, rate := range d.Samplers {
			c.samplers.setSamplerRate(ek, id, rate)
		}
	}
	return nil
}
