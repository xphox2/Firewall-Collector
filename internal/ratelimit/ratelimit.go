// Package ratelimit provides a per-source-IP token-bucket limiter for the
// collector's UDP receivers (sFlow, syslog, SNMP traps). UDP senders can't be
// back-pressured, so the limiter sheds load: a datagram from a source over its
// rate is dropped before it is parsed or queued.
//
// Two tiers guard two different failures:
//   - a per-source bucket, so one noisy or hostile agent can't drown the others;
//   - a single global bucket (aggregate ceiling), so the total datagram rate
//     can't overwhelm the single-goroutine parse loop + spillover queue.
//
// The per-source map is bounded (MaxSources) — otherwise a spoofed-source flood
// would grow it without limit and turn the DoS defense into a memory-exhaustion
// DoS. When the map is full, idle buckets (fully refilled → the sender went
// quiet) are evicted to make room; if none can be evicted, the new source is
// admitted under the global bucket only. Active legitimate senders keep low
// token counts and survive; one-hit spoofed sources refill to full and are
// reclaimed.
//
// A nil *Limiter allows everything (so callers don't branch on "limiting off").
package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

// UDPReadBufferBytes is the kernel receive-buffer size the UDP receivers request
// (SetReadBuffer) so short legitimate bursts aren't dropped by the socket before
// the read loop drains them. Complementary to app-level rate limiting.
const UDPReadBufferBytes = 8 << 20 // 8 MiB

// Config tunes a Limiter. Zero fields fall back to sensible defaults (see New).
type Config struct {
	PerSourceRate  float64 // sustained datagrams/sec allowed per source IP
	PerSourceBurst float64 // per-source bucket capacity (short burst allowance)
	GlobalRate     float64 // sustained datagrams/sec allowed across all sources
	GlobalBurst    float64 // global bucket capacity
	MaxSources     int     // max distinct source IPs tracked (memory bound)
	IdleTTL        time.Duration
}

type bucket struct {
	tokens float64
	last   time.Time
}

// take refills the bucket for the elapsed time (capped at burst) and consumes
// one token if available, returning whether the datagram is allowed.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Limiter is a goroutine-safe two-tier rate limiter. Build with New.
type Limiter struct {
	mu      sync.Mutex
	sources map[string]*bucket
	global  bucket

	rate, burst   float64
	grate, gburst float64
	maxSources    int
	idleTTL       time.Duration

	nowFn func() time.Time // injectable clock for tests

	allowed uint64 // atomic
	dropped uint64 // atomic
}

// New builds a Limiter. Zero/negative config fields use defaults tuned to sit
// well above a normal firewall's sFlow/syslog export rate, so legitimate
// traffic is never dropped under normal operation.
func New(cfg Config) *Limiter {
	if cfg.PerSourceRate <= 0 {
		cfg.PerSourceRate = 500
	}
	if cfg.PerSourceBurst <= 0 {
		cfg.PerSourceBurst = cfg.PerSourceRate * 2
	}
	if cfg.GlobalRate <= 0 {
		cfg.GlobalRate = 20000
	}
	if cfg.GlobalBurst <= 0 {
		cfg.GlobalBurst = cfg.GlobalRate * 2
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = 8192
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 5 * time.Minute
	}
	return &Limiter{
		sources:    make(map[string]*bucket),
		rate:       cfg.PerSourceRate,
		burst:      cfg.PerSourceBurst,
		grate:      cfg.GlobalRate,
		gburst:     cfg.GlobalBurst,
		maxSources: cfg.MaxSources,
		idleTTL:    cfg.IdleTTL,
		nowFn:      time.Now,
	}
}

// Allow reports whether a datagram from source ip may be processed now. A nil
// Limiter always allows (limiting disabled).
func (l *Limiter) Allow(ip string) bool {
	if l == nil {
		return true
	}
	return l.allowAt(ip, l.nowFn())
}

// allowAt is the testable core: it evaluates the per-source and global buckets
// at an explicit time.
func (l *Limiter) allowAt(ip string, now time.Time) bool {
	l.mu.Lock()
	b, ok := l.sources[ip]
	if !ok {
		if len(l.sources) >= l.maxSources && !l.evictOneIdleLocked(now) {
			// Map full and nothing idle to reclaim: admit this (possibly
			// spoofed) source under the global ceiling only, without growing
			// the map.
			allowed := l.global.take(now, l.grate, l.gburst)
			l.mu.Unlock()
			l.record(allowed)
			return allowed
		}
		b = &bucket{tokens: l.burst, last: now}
		l.sources[ip] = b
	}
	// Per-source first (protects other agents), then the global ceiling.
	perOK := b.take(now, l.rate, l.burst)
	if !perOK {
		l.mu.Unlock()
		l.record(false)
		return false
	}
	globalOK := l.global.take(now, l.grate, l.gburst)
	l.mu.Unlock()
	l.record(globalOK)
	return globalOK
}

// evictOneIdleLocked removes one bucket whose sender has gone quiet (fully
// refilled and untouched past IdleTTL), freeing a slot. Bounded scan so the hot
// path stays cheap under a spoof flood. Caller holds l.mu. Returns true if it
// evicted one.
func (l *Limiter) evictOneIdleLocked(now time.Time) bool {
	const scanCap = 256
	scanned := 0
	for ip, b := range l.sources {
		if b.tokens >= l.burst && now.Sub(b.last) > l.idleTTL {
			delete(l.sources, ip)
			return true
		}
		if scanned++; scanned >= scanCap {
			break
		}
	}
	return false
}

func (l *Limiter) record(allowed bool) {
	if allowed {
		atomic.AddUint64(&l.allowed, 1)
	} else {
		atomic.AddUint64(&l.dropped, 1)
	}
}

// Stats returns cumulative allowed/dropped datagram counts and the number of
// source IPs currently tracked. Safe to call concurrently.
func (l *Limiter) Stats() (allowed, dropped uint64, tracked int) {
	if l == nil {
		return 0, 0, 0
	}
	allowed = atomic.LoadUint64(&l.allowed)
	dropped = atomic.LoadUint64(&l.dropped)
	l.mu.Lock()
	tracked = len(l.sources)
	l.mu.Unlock()
	return
}
