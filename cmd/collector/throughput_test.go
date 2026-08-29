package main

import (
	"math"
	"testing"
	"time"

	"firewall-collector/internal/relay"
)

// eth builds a Type==6 (ethernetCsmacd) interface sample for throughput tests.
func eth(index int, inBytes, outBytes, highSpeedMbps uint64) relay.InterfaceStats {
	return relay.InterfaceStats{
		Index:     index,
		Type:      ethernetCsmacd,
		InBytes:   inBytes,
		OutBytes:  outBytes,
		HighSpeed: highSpeedMbps,
	}
}

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// TestComputeThroughput covers the pure helper: warm-up, steady-state math,
// per-interface reset clamping, interface churn, the plausibility cap (and
// its ΣHighSpeed==0 escape), non-Ethernet exclusion, and the dt floor.
func TestComputeThroughput(t *testing.T) {
	t0 := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	t60 := t0.Add(60 * time.Second)

	// 60s × 100 kbps = 100_000 bits/s × 60 s / 8 = 750_000 bytes.
	const bytesFor100Kbps = 750_000
	// A delta big enough to blow past a 1 Gbps cap (1_000_000 kbps) over 60s:
	// cap × 1000 bits/kbit / 8 × 60 s = 7.5e9 bytes; use well above that.
	const flapDelta = uint64(1e12)

	cases := []struct {
		name     string
		prev     map[int]ifSample
		ifaces   []relay.InterfaceStats
		now      time.Time
		wantIn   float64
		wantOut  float64
		wantNext []int // ifIndexes expected in the returned sample map
	}{
		{
			name:     "first sample warms up to zero",
			prev:     nil,
			ifaces:   []relay.InterfaceStats{eth(1, 1000, 2000, 1000)},
			now:      t0,
			wantIn:   0,
			wantOut:  0,
			wantNext: []int{1},
		},
		{
			name: "steady delta yields expected kbps both directions",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 1000, outBytes: 2000},
			},
			ifaces: []relay.InterfaceStats{
				eth(1, 1000+bytesFor100Kbps, 2000+2*bytesFor100Kbps, 1000),
			},
			now:      t60,
			wantIn:   100,
			wantOut:  200,
			wantNext: []int{1},
		},
		{
			name: "delta-then-sum across two interfaces",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 0, outBytes: 0},
				2: {ts: t0, inBytes: 0, outBytes: 0},
			},
			ifaces: []relay.InterfaceStats{
				eth(1, bytesFor100Kbps, bytesFor100Kbps, 1000),
				eth(2, bytesFor100Kbps, bytesFor100Kbps, 1000),
			},
			now:      t60,
			wantIn:   200,
			wantOut:  200,
			wantNext: []int{1, 2},
		},
		{
			name: "counter reset clamps only that interface",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 9_000_000, outBytes: 9_000_000}, // resets
				2: {ts: t0, inBytes: 0, outBytes: 0},                 // steady
			},
			ifaces: []relay.InterfaceStats{
				eth(1, 5, 7, 1000), // curr < prev → skipped, no negative/wrap spike
				eth(2, bytesFor100Kbps, bytesFor100Kbps, 1000),
			},
			now:      t60,
			wantIn:   100,
			wantOut:  100,
			wantNext: []int{1, 2},
		},
		{
			name: "appearing interface contributes nothing until next poll",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 0, outBytes: 0},
			},
			ifaces: []relay.InterfaceStats{
				eth(1, bytesFor100Kbps, bytesFor100Kbps, 1000),
				eth(9, 5_000_000_000, 5_000_000_000, 1000), // new — huge counters, no prior
			},
			now:      t60,
			wantIn:   100,
			wantOut:  100,
			wantNext: []int{1, 9},
		},
		{
			name: "disappearing interface causes no spike and leaves the cache",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 0, outBytes: 0},
				9: {ts: t0, inBytes: 5_000_000_000, outBytes: 5_000_000_000}, // gone now
			},
			ifaces: []relay.InterfaceStats{
				eth(1, bytesFor100Kbps, bytesFor100Kbps, 1000),
			},
			now:      t60,
			wantIn:   100,
			wantOut:  100,
			wantNext: []int{1},
		},
		{
			name: "plausibility cap clamps a 32-to-64-bit counter flap to zero",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 1000, outBytes: 2000},
			},
			ifaces: []relay.InterfaceStats{
				// In flaps to the 64-bit source (garbage delta); out stays sane.
				eth(1, 1000+flapDelta, 2000+bytesFor100Kbps, 1000),
			},
			now:      t60,
			wantIn:   0, // > Σ ifHighSpeed×1000 kbps → clamped
			wantOut:  100,
			wantNext: []int{1},
		},
		{
			name: "cap skipped when device reports no ifHighSpeed",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 0, outBytes: 0},
			},
			ifaces: []relay.InterfaceStats{
				eth(1, flapDelta, 0, 0), // HighSpeed 0 → ΣHighSpeed 0 → no cap
			},
			now:      t60,
			wantIn:   float64(flapDelta) * 8 / 60 / 1000,
			wantOut:  0,
			wantNext: []int{1},
		},
		{
			name: "non-Ethernet interface types are ignored",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 0, outBytes: 0},
			},
			ifaces: []relay.InterfaceStats{
				eth(1, bytesFor100Kbps, bytesFor100Kbps, 1000),
				{Index: 20, Type: 131, InBytes: 9e9, OutBytes: 9e9, HighSpeed: 1000}, // tunnel
				{Index: 21, Type: 135, InBytes: 9e9, OutBytes: 9e9},                  // l2vlan
			},
			now:      t60,
			wantIn:   100,
			wantOut:  100,
			wantNext: []int{1},
		},
		{
			name: "dt at or below the floor is skipped",
			prev: map[int]ifSample{
				1: {ts: t0, inBytes: 0, outBytes: 0},
			},
			ifaces: []relay.InterfaceStats{
				eth(1, bytesFor100Kbps, bytesFor100Kbps, 1000),
			},
			now:      t0.Add(3 * time.Second), // overlapping poll
			wantIn:   0,
			wantOut:  0,
			wantNext: []int{1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, out, next := computeThroughput(tc.prev, tc.ifaces, tc.now)
			if !almostEqual(in, tc.wantIn) {
				t.Errorf("inKbps = %v, want %v", in, tc.wantIn)
			}
			if !almostEqual(out, tc.wantOut) {
				t.Errorf("outKbps = %v, want %v", out, tc.wantOut)
			}
			if len(next) != len(tc.wantNext) {
				t.Errorf("next has %d entries, want %d", len(next), len(tc.wantNext))
			}
			for _, idx := range tc.wantNext {
				s, ok := next[idx]
				if !ok {
					t.Errorf("next missing ifIndex %d", idx)
					continue
				}
				if !s.ts.Equal(tc.now) {
					t.Errorf("next[%d].ts = %v, want %v", idx, s.ts, tc.now)
				}
			}
		})
	}
}

// TestUpdateThroughput_WarmUpThenSteady exercises the stateful wrapper: the
// first poll returns 0 (no prior samples), the second returns the computed
// rate, and both populate the lastComputed cache Part B reads.
func TestUpdateThroughput_WarmUpThenSteady(t *testing.T) {
	c := newTestCollector(&fakeSink{}, nil)
	t0 := time.Now()
	t60 := t0.Add(60 * time.Second)

	in, out := c.updateThroughput(7, []relay.InterfaceStats{eth(1, 1000, 2000, 1000)}, t0)
	if in != 0 || out != 0 {
		t.Fatalf("warm-up poll = %v/%v kbps, want 0/0", in, out)
	}

	in, out = c.updateThroughput(7, []relay.InterfaceStats{eth(1, 1000+750_000, 2000+750_000, 1000)}, t60)
	if !almostEqual(in, 100) || !almostEqual(out, 100) {
		t.Fatalf("steady poll = %v/%v kbps, want 100/100", in, out)
	}

	gotIn, gotOut := c.cachedThroughput(7, t60)
	if !almostEqual(gotIn, 100) || !almostEqual(gotOut, 100) {
		t.Fatalf("cachedThroughput = %v/%v, want 100/100", gotIn, gotOut)
	}
}

// TestUpdateThroughput_OutOfOrderPoll: a slow same-device walk completing after a
// newer cycle (its `now` predates the cached sample) must NOT roll the baseline
// back or write a transient 0 — it returns the newer cached value, and the next
// in-order poll still computes correctly.
func TestUpdateThroughput_OutOfOrderPoll(t *testing.T) {
	c := newTestCollector(&fakeSink{}, nil)
	t0 := time.Now()
	t60 := t0.Add(60 * time.Second)
	t30 := t0.Add(30 * time.Second) // out-of-order completion

	c.updateThroughput(7, []relay.InterfaceStats{eth(1, 1000, 2000, 1000)}, t0)
	c.updateThroughput(7, []relay.InterfaceStats{eth(1, 1000+750_000, 2000+750_000, 1000)}, t60)

	in, out := c.updateThroughput(7, []relay.InterfaceStats{eth(1, 9_999_999, 9_999_999, 1000)}, t30)
	if !almostEqual(in, 100) || !almostEqual(out, 100) {
		t.Fatalf("out-of-order poll = %v/%v kbps, want cached 100/100", in, out)
	}

	// Baseline preserved: the next in-order poll computes against the t60 sample.
	t120 := t0.Add(120 * time.Second)
	in, out = c.updateThroughput(7, []relay.InterfaceStats{eth(1, 1000+1_500_000, 2000+1_500_000, 1000)}, t120)
	if !almostEqual(in, 100) || !almostEqual(out, 100) {
		t.Fatalf("post-out-of-order poll = %v/%v kbps, want 100/100", in, out)
	}
}

// TestCachedThroughput_FreshnessGate: a cache entry older than 3× the poll
// interval (default 3 minutes when cfg is absent) must read as 0,0, and an
// unknown device must read as 0,0.
func TestCachedThroughput_FreshnessGate(t *testing.T) {
	c := newTestCollector(&fakeSink{}, nil)
	now := time.Now()
	c.lastComputed = map[uint]throughputSample{
		1: {inKbps: 100, outKbps: 50, ts: now.Add(-1 * time.Minute)},  // fresh
		2: {inKbps: 100, outKbps: 50, ts: now.Add(-10 * time.Minute)}, // stale
	}

	if in, out := c.cachedThroughput(1, now); !almostEqual(in, 100) || !almostEqual(out, 50) {
		t.Errorf("fresh cache = %v/%v, want 100/50", in, out)
	}
	if in, out := c.cachedThroughput(2, now); in != 0 || out != 0 {
		t.Errorf("stale cache = %v/%v, want 0/0", in, out)
	}
	if in, out := c.cachedThroughput(99, now); in != 0 || out != 0 {
		t.Errorf("missing cache = %v/%v, want 0/0", in, out)
	}
}

// TestPruneThroughputCache: devices dropped from the assigned list lose both
// their per-interface samples and their computed-throughput cache entry.
func TestPruneThroughputCache(t *testing.T) {
	c := newTestCollector(&fakeSink{}, nil)
	now := time.Now()
	c.prevIface = map[uint]map[int]ifSample{
		1: {1: {ts: now}},
		2: {1: {ts: now}},
	}
	c.lastComputed = map[uint]throughputSample{
		1: {ts: now},
		2: {ts: now},
	}

	c.pruneThroughputCache([]relay.DeviceInfo{{ID: 1}})

	if _, ok := c.prevIface[1]; !ok {
		t.Error("prevIface[1] pruned but device 1 is still assigned")
	}
	if _, ok := c.prevIface[2]; ok {
		t.Error("prevIface[2] not pruned after device 2 was unassigned")
	}
	if _, ok := c.lastComputed[1]; !ok {
		t.Error("lastComputed[1] pruned but device 1 is still assigned")
	}
	if _, ok := c.lastComputed[2]; ok {
		t.Error("lastComputed[2] not pruned after device 2 was unassigned")
	}
}

// sshPerfOutput is a realistic `diagnose sys performance status` dump whose
// SSH-reported throughput (1234.5/567.8 kbps) must NOT reach the relay row —
// the row's throughput comes from the SNMP cache (single source).
const sshPerfOutput = `CPU states:  5% user   3% system   0% nice  90% idle   0% iowait   1% irq   1% softirq
Memory: 4096000k total, 2048000k used (50.0%), 1024000k free (25.0%), 512000k freeable (12.5%)
Average network usage: 1234.5 / 567.8 kbps in 1 minute
Current sessions: 8542
Uptime: 42 days`

// TestSendPerformanceStatus_UsesCachedSNMPThroughput: with a fresh SNMP cache
// the SSH row carries the cached value, and every other parsed field still
// passes through unchanged.
func TestSendPerformanceStatus_UsesCachedSNMPThroughput(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, nil)
	c.lastComputed = map[uint]throughputSample{
		1: {inKbps: 321.5, outKbps: 42.25, ts: time.Now()},
	}

	c.sendPerformanceStatus(validDevice(), sshPerfOutput)

	if len(sink.systemStatuses) != 1 {
		t.Fatalf("sent %d system statuses, want 1", len(sink.systemStatuses))
	}
	got := sink.systemStatuses[0]
	if !almostEqual(got.NetworkInKbps, 321.5) || !almostEqual(got.NetworkOutKbps, 42.25) {
		t.Errorf("row throughput = %v/%v, want cached 321.5/42.25 (not the SSH 1234.5/567.8)", got.NetworkInKbps, got.NetworkOutKbps)
	}
	// Everything else the row carried before must be untouched.
	if got.DeviceID != 1 {
		t.Errorf("DeviceID = %d, want 1", got.DeviceID)
	}
	if !almostEqual(got.CPUUsage, 10) { // 5 user + 3 system + 1 irq + 1 softirq
		t.Errorf("CPUUsage = %v, want 10", got.CPUUsage)
	}
	if !almostEqual(got.CPUUser, 5) || !almostEqual(got.CPUSystem, 3) || !almostEqual(got.CPUIdle, 90) {
		t.Errorf("CPU breakdown = user %v system %v idle %v, want 5/3/90", got.CPUUser, got.CPUSystem, got.CPUIdle)
	}
	if !almostEqual(got.MemoryUsage, 50.0) {
		t.Errorf("MemoryUsage = %v, want 50.0", got.MemoryUsage)
	}
	if got.MemoryTotal != uint64(4096000)*1024 {
		t.Errorf("MemoryTotal = %d, want %d", got.MemoryTotal, uint64(4096000)*1024)
	}
	if got.MemoryFreeable != uint64(512000)*1024 {
		t.Errorf("MemoryFreeable = %d, want %d", got.MemoryFreeable, uint64(512000)*1024)
	}
	if got.SessionCount != 8542 {
		t.Errorf("SessionCount = %d, want 8542", got.SessionCount)
	}
	if got.Uptime != 42*86400*100 { // AUDIT-220: hundredths
		t.Errorf("Uptime = %d, want %d", got.Uptime, 42*86400*100)
	}
}

// TestSendPerformanceStatus_StaleCacheSendsZero: a stale (or absent) SNMP
// cache must zero the row's throughput rather than fall back to the
// SSH-reported average — an SNMP-broken FortiGate shows no throughput.
func TestSendPerformanceStatus_StaleCacheSendsZero(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, nil)
	c.lastComputed = map[uint]throughputSample{
		1: {inKbps: 321.5, outKbps: 42.25, ts: time.Now().Add(-10 * time.Minute)},
	}

	c.sendPerformanceStatus(validDevice(), sshPerfOutput)

	if len(sink.systemStatuses) != 1 {
		t.Fatalf("sent %d system statuses, want 1", len(sink.systemStatuses))
	}
	got := sink.systemStatuses[0]
	if got.NetworkInKbps != 0 || got.NetworkOutKbps != 0 {
		t.Errorf("stale cache row throughput = %v/%v, want 0/0", got.NetworkInKbps, got.NetworkOutKbps)
	}
	if got.SessionCount != 8542 || !almostEqual(got.CPUUsage, 10) {
		t.Errorf("non-throughput fields must still pass through: sessions=%d cpu=%v", got.SessionCount, got.CPUUsage)
	}
}

// TestSendPerformanceStatus_UsesCachedSNMPVitals: with fresh SNMP vitals cached,
// the SSH row carries the SNMP cpu/mem/disk/sessions (alert coherence) instead
// of the SSH-parsed methodology, while the SSH-exclusive CPU breakdown and
// MemoryFreeable pass through.
func TestSendPerformanceStatus_UsesCachedSNMPVitals(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, nil)
	now := time.Now()
	c.lastComputed = map[uint]throughputSample{1: {inKbps: 321.5, outKbps: 42.25, ts: now}}
	c.lastVitals = map[uint]vitalsSample{
		1: {cpuUsage: 73, memoryUsage: 61, diskUsage: 88, diskTotal: 512, sessions: 1200, ts: now},
	}

	c.sendPerformanceStatus(validDevice(), sshPerfOutput)

	got := sink.systemStatuses[0]
	// Alert scalars come from the SNMP cache, not the SSH parse (10/50/8542).
	if !almostEqual(got.CPUUsage, 73) || !almostEqual(got.MemoryUsage, 61) || !almostEqual(got.DiskUsage, 88) {
		t.Errorf("vitals = cpu %v mem %v disk %v, want SNMP 73/61/88", got.CPUUsage, got.MemoryUsage, got.DiskUsage)
	}
	if got.SessionCount != 1200 || got.DiskTotal != 512 {
		t.Errorf("sessions/diskTotal = %d/%d, want SNMP 1200/512", got.SessionCount, got.DiskTotal)
	}
	// SSH-exclusive fields still pass through.
	if !almostEqual(got.CPUUser, 5) || !almostEqual(got.CPUIdle, 90) || got.MemoryFreeable != uint64(512000)*1024 {
		t.Errorf("SSH-exclusive fields lost: user %v idle %v freeable %d", got.CPUUser, got.CPUIdle, got.MemoryFreeable)
	}
}

// TestCacheVitals_OutOfOrderPoll: a slow overlapping same-device poll (its `now`
// predating the cached sample) must NOT clobber the newer vitals — otherwise the
// SSH row would carry a stale CPU and could false-resolve a genuine CPU_HIGH.
func TestCacheVitals_OutOfOrderPoll(t *testing.T) {
	c := newTestCollector(&fakeSink{}, nil)
	t0 := time.Now()
	t60 := t0.Add(60 * time.Second)

	c.cacheVitals(1, &relay.SystemStatus{CPUUsage: 91}, t60) // newer sample
	c.cacheVitals(1, &relay.SystemStatus{CPUUsage: 40}, t0)  // out-of-order (older now)

	v, ok := c.cachedVitals(1, t60)
	if !ok || !almostEqual(v.cpuUsage, 91) {
		t.Fatalf("out-of-order poll clobbered vitals: cpu=%v ok=%v, want 91", v.cpuUsage, ok)
	}
}

// TestSendPerformanceStatus_StaleVitalsKeepsSSH: a stale/absent vitals cache
// leaves the SSH-parsed cpu/mem/sessions in place (best effort during an SNMP
// outage; the server's no-data guard handles the resulting disk_usage==0).
func TestSendPerformanceStatus_StaleVitalsKeepsSSH(t *testing.T) {
	sink := &fakeSink{}
	c := newTestCollector(sink, nil)
	c.lastVitals = map[uint]vitalsSample{
		1: {cpuUsage: 73, memoryUsage: 61, diskUsage: 88, sessions: 1200, ts: time.Now().Add(-10 * time.Minute)},
	}

	c.sendPerformanceStatus(validDevice(), sshPerfOutput)

	got := sink.systemStatuses[0]
	if !almostEqual(got.CPUUsage, 10) || !almostEqual(got.MemoryUsage, 50) || got.SessionCount != 8542 {
		t.Errorf("stale vitals should keep SSH values: cpu %v mem %v sessions %d", got.CPUUsage, got.MemoryUsage, got.SessionCount)
	}
	if got.DiskUsage != 0 {
		t.Errorf("DiskUsage = %v, want 0 (SSH row has no disk; server no-data guard covers it)", got.DiskUsage)
	}
}
