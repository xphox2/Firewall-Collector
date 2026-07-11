package main

import (
	"time"

	"firewall-collector/internal/relay"
)

// Device-total network throughput derived from SNMP interface counter deltas.
//
// The server's device-detail throughput chart reads
// system_status.network_in_kbps/out_kbps, which historically only the
// FortiGate SSH `diagnose sys performance` path populated. The collector
// already walks per-interface 64-bit HC octet counters every SNMP poll, so we
// derive a device total here for ALL vendors: sum, over physical Ethernet
// interfaces (ifType 6, ethernetCsmacd), of per-interface in/out byte deltas
// between consecutive polls. A transit byte hits the entry NIC's ifIn once and
// the exit NIC's ifOut once, so the sum doesn't double-count; LAGG members are
// counted once and lagg/VLAN/bridge parents (other ifTypes) are excluded.

// ethernetCsmacd is the IANA ifType for physical Ethernet interfaces.
const ethernetCsmacd = 6

// minThroughputDelta is the dt floor: samples closer together than this are
// skipped (runPollCycle doesn't barrier, so same-device polls can overlap and
// produce near-zero dt → wildly amplified rates).
const minThroughputDelta = 5 * time.Second

// ifSample is one interface's cumulative octet counters at a poll instant.
type ifSample struct {
	ts       time.Time
	inBytes  uint64
	outBytes uint64
}

// throughputSample is the device-total computed throughput cached for the SSH
// performance-status row (single throughput source).
type throughputSample struct {
	inKbps  float64
	outKbps float64
	ts      time.Time
}

// vitalsSample caches the latest SNMP-sourced system vitals for a device so the
// SSH `diagnose sys performance` row can carry the SAME alert-relevant values.
// Without this, the SSH row reports CPU/memory via a different methodology (and
// no disk at all), which — now that the server evaluates the newest relayed
// row — can flap a borderline threshold alert. Single, coherent source.
type vitalsSample struct {
	cpuUsage    float64
	memoryUsage float64
	diskUsage   float64
	diskTotal   uint64
	sessions    int
	ts          time.Time
}

// computeThroughput derives device-total in/out kbps from per-interface
// counter deltas. Pure: it never mutates prev; the caller stores the returned
// next map for the following poll.
//
// Per-interface delta-then-sum (NOT sum-then-delta), so interfaces appearing,
// disappearing, or resetting individually cannot fabricate a device-wide
// spike:
//   - only ifType 6 (ethernetCsmacd) interfaces participate;
//   - an interface with no prior sample contributes nothing this poll
//     (first poll after startup or after the interface appears → warm-up 0);
//   - a counter reset (curr < prev) skips that interface only;
//   - dt <= minThroughputDelta skips that interface (overlapping polls);
//   - plausibility cap: if a direction's total exceeds Σ ifHighSpeed (Mbps)
//     ×1000 kbps across the summed interfaces, that direction clamps to 0 —
//     this absorbs the 32↔64-bit counter source flap (GetInterfaceStats
//     silently falls back to 32-bit ifInOctets when HC counters are absent,
//     and a source switch produces a garbage delta). The cap is skipped when
//     ΣHighSpeed == 0 (device doesn't report ifHighSpeed).
func computeThroughput(prev map[int]ifSample, ifaces []relay.InterfaceStats, now time.Time) (inKbps, outKbps float64, next map[int]ifSample) {
	next = make(map[int]ifSample)
	var sumHighSpeedMbps uint64
	for _, iface := range ifaces {
		if iface.Type != ethernetCsmacd {
			continue
		}
		next[iface.Index] = ifSample{ts: now, inBytes: iface.InBytes, outBytes: iface.OutBytes}
		sumHighSpeedMbps += iface.HighSpeed

		p, ok := prev[iface.Index]
		if !ok {
			continue // no prior sample — warm-up for this interface
		}
		dt := now.Sub(p.ts).Seconds()
		if dt <= minThroughputDelta.Seconds() {
			continue // overlapping/too-close polls — rate would be garbage
		}
		if iface.InBytes >= p.inBytes {
			inKbps += float64(iface.InBytes-p.inBytes) * 8 / dt / 1000
		}
		if iface.OutBytes >= p.outBytes {
			outKbps += float64(iface.OutBytes-p.outBytes) * 8 / dt / 1000
		}
	}

	if capKbps := float64(sumHighSpeedMbps) * 1000; capKbps > 0 {
		if inKbps > capKbps {
			inKbps = 0
		}
		if outKbps > capKbps {
			outKbps = 0
		}
	}
	return inKbps, outKbps, next
}

// updateThroughput runs the throughput computation for one device poll,
// stores the per-interface samples for the next poll, and caches the computed
// totals for the SSH performance-status row. Safe for concurrent pollDevice
// goroutines.
func (c *Collector) updateThroughput(deviceID uint, ifaces []relay.InterfaceStats, now time.Time) (inKbps, outKbps float64) {
	c.throughputMu.Lock()
	defer c.throughputMu.Unlock()
	if c.prevIface == nil {
		c.prevIface = make(map[uint]map[int]ifSample)
	}
	if c.lastComputed == nil {
		c.lastComputed = make(map[uint]throughputSample)
	}
	// Guard against an out-of-order overlapping poll: if a slow same-device SNMP
	// walk completes after a newer cycle already recorded a sample, its stale
	// `now` would roll the per-interface baseline back and write a transient 0.
	// Skip it and keep the newer cached value.
	if s, ok := c.lastComputed[deviceID]; ok && !now.After(s.ts) {
		return s.inKbps, s.outKbps
	}
	inKbps, outKbps, next := computeThroughput(c.prevIface[deviceID], ifaces, now)
	c.prevIface[deviceID] = next
	c.lastComputed[deviceID] = throughputSample{inKbps: inKbps, outKbps: outKbps, ts: now}
	return inKbps, outKbps
}

// cachedThroughput returns the most recent SNMP-derived throughput for the
// device if it is fresh (within 3× the SNMP poll interval), else 0,0. The SSH
// performance row relays this cache instead of the coarser SSH-reported
// average so the chart has a single throughput source — a stale cache (SNMP
// broken) yields 0, matching "no throughput data" rather than a frozen value.
// cacheFreshFor is the staleness window for the throughput/vitals caches:
// 3× the SNMP poll interval (default 3 minutes at the 60s default).
func (c *Collector) cacheFreshFor() time.Duration {
	if c.cfg != nil && c.cfg.PollInterval > 0 {
		return 3 * c.cfg.PollInterval
	}
	return 3 * time.Minute
}

func (c *Collector) cachedThroughput(deviceID uint, now time.Time) (inKbps, outKbps float64) {
	freshFor := c.cacheFreshFor()
	c.throughputMu.Lock()
	defer c.throughputMu.Unlock()
	s, ok := c.lastComputed[deviceID]
	if !ok || now.Sub(s.ts) > freshFor {
		return 0, 0
	}
	return s.inKbps, s.outKbps
}

// cacheVitals records the latest SNMP-sourced vitals for a device, for the SSH
// performance row to relay (alert coherence).
func (c *Collector) cacheVitals(deviceID uint, s *relay.SystemStatus, now time.Time) {
	c.throughputMu.Lock()
	defer c.throughputMu.Unlock()
	if c.lastVitals == nil {
		c.lastVitals = make(map[uint]vitalsSample)
	}
	// Out-of-order guard (as in updateThroughput): a slow overlapping same-device
	// poll must not clobber a newer sample with stale vitals — that would make
	// the SSH row carry an older CPU/mem than the newest SNMP row.
	if v, ok := c.lastVitals[deviceID]; ok && !now.After(v.ts) {
		return
	}
	c.lastVitals[deviceID] = vitalsSample{
		cpuUsage:    s.CPUUsage,
		memoryUsage: s.MemoryUsage,
		diskUsage:   s.DiskUsage,
		diskTotal:   s.DiskTotal,
		sessions:    s.SessionCount,
		ts:          now,
	}
}

// cachedVitals returns the most recent SNMP vitals for the device if fresh
// (within 3× the SNMP poll interval), else ok=false. A stale/missing cache
// (SNMP broken) means the SSH row keeps its own parsed values — best effort;
// the server's no-data guard covers a resulting disk_usage==0.
func (c *Collector) cachedVitals(deviceID uint, now time.Time) (vitalsSample, bool) {
	freshFor := c.cacheFreshFor()
	c.throughputMu.Lock()
	defer c.throughputMu.Unlock()
	v, ok := c.lastVitals[deviceID]
	if !ok || now.Sub(v.ts) > freshFor {
		return vitalsSample{}, false
	}
	return v, true
}

// pruneThroughputCache drops cached counter samples and computed throughput
// for devices no longer in the assigned list. Called on every device-list
// refresh so unassigned devices don't leak cache entries.
func (c *Collector) pruneThroughputCache(devices []relay.DeviceInfo) {
	keep := make(map[uint]bool, len(devices))
	for _, d := range devices {
		keep[d.ID] = true
	}
	c.throughputMu.Lock()
	defer c.throughputMu.Unlock()
	for id := range c.prevIface {
		if !keep[id] {
			delete(c.prevIface, id)
		}
	}
	for id := range c.lastComputed {
		if !keep[id] {
			delete(c.lastComputed, id)
		}
	}
	for id := range c.lastVitals {
		if !keep[id] {
			delete(c.lastVitals, id)
		}
	}
}
