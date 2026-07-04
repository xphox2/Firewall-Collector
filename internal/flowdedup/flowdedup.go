// Package flowdedup prevents dual-export double counting: a device sending
// BOTH sFlow and NetFlow/IPFIX for the same interfaces would double every
// byte in every server-side aggregate. Cross-protocol record matching is
// infeasible (sampled point samples vs stateful session aggregates), so the
// defense is a per-exporter SOURCE PREFERENCE with automatic failover:
//
//   - Under the default prefer-netflow policy, sFlow FLOW samples from an
//     exporter are suppressed while NetFlow/IPFIX records from that exporter
//     have been seen within the activity window. If NetFlow goes quiet
//     (export reconfigured, broken), sFlow flow samples resume on their own.
//   - prefer-sflow is the mirror image; off disables suppression entirely.
//   - sFlow COUNTER samples are never suppressed — interface counters are
//     different data (the SNMP-fallback bandwidth source), not flow records.
//     Callers simply don't consult the tracker for counter samples.
//
// Vendor context (docs/flow-protocol-research-2026-07-03.md §2.8, server
// repo): dual-export is effectively a FortiGate + VyOS scenario, and Fortinet
// itself recommends NetFlow — enabling sFlow disables NPU offload. Complete
// session-based NetFlow is also strictly higher fidelity than 1-in-N sampled
// sFlow, hence the default direction.
package flowdedup

import (
	"strings"
	"sync"
	"time"
)

// Policy values for PROBE_FLOW_DEDUP.
const (
	PolicyPreferNetFlow = "prefer-netflow"
	PolicyPreferSFlow   = "prefer-sflow"
	PolicyOff           = "off"
)

const (
	// activityWindow is how long a source family counts as "live" for an
	// exporter after its last record. It bounds both directions of the
	// transition: suppression engages on the first record of the preferred
	// family, and failover back happens one window after it goes quiet.
	activityWindow = 5 * time.Minute

	// maxExporters bounds the tracker map (same defense class as the rate
	// limiter's max-sources cap — exporter IPs arrive from the network).
	// Above the cap, unknown exporters are simply not tracked, which fails
	// OPEN (no suppression) — never lose flow data to a bookkeeping limit.
	maxExporters = 4096
)

type exporterState struct {
	lastNetFlow time.Time
	lastSFlow   time.Time
}

// Tracker decides, per exporter, whether a flow sample of one family should
// be suppressed because the preferred family is actively exporting.
type Tracker struct {
	mu     sync.Mutex
	policy string
	byIP   map[string]*exporterState
	// suppressing remembers the last announced suppression state per
	// exporter+family so state CHANGES can be logged once instead of
	// per-packet (the caller supplies the log/metric hook).
	suppressing map[string]bool
	onChange    func(exporter, suppressedFamily string, active bool)
}

// NewTracker builds a tracker for the given policy string (unknown values
// behave as off — fail open). onChange, if non-nil, fires once per
// suppression state CHANGE per (exporter, family) — wire it to a log line +
// metric, never to per-packet work.
func NewTracker(policy string, onChange func(exporter, suppressedFamily string, active bool)) *Tracker {
	p := strings.ToLower(strings.TrimSpace(policy))
	if p != PolicyPreferNetFlow && p != PolicyPreferSFlow {
		p = PolicyOff
	}
	return &Tracker{
		policy:      p,
		byIP:        make(map[string]*exporterState),
		suppressing: make(map[string]bool),
		onChange:    onChange,
	}
}

// Policy returns the normalized policy in effect.
func (t *Tracker) Policy() string { return t.policy }

func (t *Tracker) state(exporter string, now time.Time) *exporterState {
	st, ok := t.byIP[exporter]
	if !ok {
		if len(t.byIP) >= maxExporters {
			// Opportunistic prune of idle exporters before refusing. Uses the
			// caller's clock so tests can inject time and the decision is
			// consistent with the suppression math.
			cutoff := now.Add(-2 * activityWindow)
			for ip, s := range t.byIP {
				if s.lastNetFlow.Before(cutoff) && s.lastSFlow.Before(cutoff) {
					delete(t.byIP, ip)
					delete(t.suppressing, ip+"/sflow")
					delete(t.suppressing, ip+"/netflow")
				}
			}
			if len(t.byIP) >= maxExporters {
				return nil // fail open: untracked exporter, no suppression
			}
		}
		st = &exporterState{}
		t.byIP[exporter] = st
	}
	return st
}

// announce fires the onChange hook when the suppression state flips.
func (t *Tracker) announce(exporter, family string, active bool) {
	key := exporter + "/" + family
	if t.suppressing[key] == active {
		return
	}
	t.suppressing[key] = active
	if t.onChange != nil {
		t.onChange(exporter, family, active)
	}
}

// SuppressSFlowFlow records sFlow flow-sample activity from exporter and
// reports whether that sample should be DROPPED (not relayed). Call it only
// for FLOW samples — counter samples bypass dedup entirely.
func (t *Tracker) SuppressSFlowFlow(exporter string, now time.Time) bool {
	if t.policy == PolicyOff {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(exporter, now)
	if st == nil {
		return false
	}
	st.lastSFlow = now
	suppress := t.policy == PolicyPreferNetFlow && now.Sub(st.lastNetFlow) < activityWindow
	t.announce(exporter, "sflow", suppress)
	return suppress
}

// SuppressNetFlow records NetFlow/IPFIX record activity from exporter and
// reports whether that record should be DROPPED.
func (t *Tracker) SuppressNetFlow(exporter string, now time.Time) bool {
	if t.policy == PolicyOff {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(exporter, now)
	if st == nil {
		return false
	}
	st.lastNetFlow = now
	suppress := t.policy == PolicyPreferSFlow && now.Sub(st.lastSFlow) < activityWindow
	t.announce(exporter, "netflow", suppress)
	return suppress
}
