package ratelimit

import (
	"testing"
	"time"
)

func TestNilLimiterAllows(t *testing.T) {
	var l *Limiter
	for i := 0; i < 100; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatal("nil limiter must allow everything")
		}
	}
}

func TestPerSourceBucket(t *testing.T) {
	l := New(Config{PerSourceRate: 10, PerSourceBurst: 5, GlobalRate: 1e9, GlobalBurst: 1e9, MaxSources: 100})
	now := time.Unix(1000, 0)
	// Burst of 5 allowed immediately, 6th denied (no refill at t0).
	for i := 0; i < 5; i++ {
		if !l.allowAt("10.0.0.1", now) {
			t.Fatalf("packet %d should be allowed within burst", i+1)
		}
	}
	if l.allowAt("10.0.0.1", now) {
		t.Fatal("6th packet should be dropped (burst exhausted)")
	}
	// A different source has its own bucket — not affected.
	if !l.allowAt("10.0.0.2", now) {
		t.Fatal("independent source should have its own bucket")
	}
	// After 1s at 10/s, ~10 tokens refill (capped at burst 5).
	later := now.Add(time.Second)
	got := 0
	for i := 0; i < 10; i++ {
		if l.allowAt("10.0.0.1", later) {
			got++
		}
	}
	if got != 5 {
		t.Errorf("after 1s refill got %d allowed, want 5 (capped at burst)", got)
	}
}

func TestGlobalCeiling(t *testing.T) {
	// Generous per-source, tight global: the global bucket is the binding limit.
	l := New(Config{PerSourceRate: 1e6, PerSourceBurst: 1e6, GlobalRate: 1, GlobalBurst: 3, MaxSources: 100})
	now := time.Unix(2000, 0)
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.allowAt("10.0.0.99", now) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("global ceiling allowed %d, want 3 (global burst)", allowed)
	}
}

func TestMaxSourcesBoundAndOverflowUsesGlobal(t *testing.T) {
	// Map capped at 2 sources. A 3rd distinct source can't grow the map; it is
	// admitted only under the global bucket (which here is generous), and the
	// map stays bounded.
	l := New(Config{PerSourceRate: 1, PerSourceBurst: 1, GlobalRate: 1e9, GlobalBurst: 1e9, MaxSources: 2, IdleTTL: time.Hour})
	now := time.Unix(3000, 0)
	l.allowAt("10.0.0.1", now)
	l.allowAt("10.0.0.2", now)
	// Third source — map is full and nothing is idle (IdleTTL 1h), so it falls
	// through to the global bucket and does NOT create a 3rd map entry.
	if !l.allowAt("10.0.0.3", now) {
		t.Fatal("overflow source should be allowed under the generous global bucket")
	}
	if _, _, tracked := l.Stats(); tracked != 2 {
		t.Errorf("tracked sources = %d, want 2 (map bounded)", tracked)
	}
}

func TestIdleEviction(t *testing.T) {
	l := New(Config{PerSourceRate: 5, PerSourceBurst: 5, GlobalRate: 1e9, GlobalBurst: 1e9, MaxSources: 1, IdleTTL: 10 * time.Second})
	t0 := time.Unix(4000, 0)
	l.allowAt("10.0.0.1", t0) // fills the single slot; bucket now has 4 tokens (not full)

	// Let 10.0.0.1 idle long enough that its EFFECTIVE tokens (stored + refill
	// it would earn) reach burst. H6 of the 2026-07-01 audit: the stored token
	// count alone NEVER reaches burst (take decrements after capping), so the
	// pre-fix `b.tokens >= burst` predicate made eviction dead code.
	idle := t0.Add(30 * time.Second)
	// A new source at t=idle: map full (cap 1), but 10.0.0.1 is idle+refillable → evicted.
	if !l.allowAt("10.0.0.2", idle) {
		t.Fatal("new source should be admitted after evicting an idle bucket")
	}
	_, _, tracked := l.Stats()
	if tracked != 1 {
		t.Errorf("tracked = %d, want 1 (evict-then-insert keeps the bound)", tracked)
	}

	// The decisive check the pre-fix test lacked: the new source must have its
	// OWN per-source bucket, not a global-only admission. Exhaust its burst —
	// with a per-source bucket the 6th packet in the same instant is dropped
	// (burst 5, one already spent above) even though the global bucket is
	// effectively unlimited. On the pre-fix code (eviction dead, global-only
	// fallback) every packet was allowed and this assertion fails.
	for i := 0; i < 4; i++ {
		if !l.allowAt("10.0.0.2", idle) {
			t.Fatalf("packet %d within burst should be allowed", i+2)
		}
	}
	if l.allowAt("10.0.0.2", idle) {
		t.Fatal("burst-exhausted new source must be dropped per-source — it fell through to the global-only path, meaning eviction never happened")
	}
}

// TestIdleEviction_EffectiveRefillPredicate_H6 pins the exact H6 defect shape:
// a bucket whose sender went quiet mid-burst (stored tokens well below burst)
// must still be evictable once idle past TTL, because the predicate now counts
// the refill the bucket would have earned.
func TestIdleEviction_EffectiveRefillPredicate_H6(t *testing.T) {
	l := New(Config{PerSourceRate: 5, PerSourceBurst: 5, GlobalRate: 1e9, GlobalBurst: 1e9, MaxSources: 1, IdleTTL: 10 * time.Second})
	t0 := time.Unix(5000, 0)
	// Drain the bucket to 0 stored tokens — the worst case for the old
	// stored-tokens predicate.
	for i := 0; i < 5; i++ {
		l.allowAt("10.9.9.9", t0)
	}

	// Idle past TTL and long enough to refill (5 tokens at 5/s = 1s << 30s).
	idle := t0.Add(30 * time.Second)
	if !l.allowAt("172.16.0.1", idle) {
		t.Fatal("fully drained then long-idle bucket must be evictable")
	}
	l.mu.Lock()
	_, oldStillTracked := l.sources["10.9.9.9"]
	_, newTracked := l.sources["172.16.0.1"]
	l.mu.Unlock()
	if oldStillTracked {
		t.Error("idle drained bucket was not evicted")
	}
	if !newTracked {
		t.Error("new source did not get its own per-source bucket")
	}
}

// TestManyFirewallsNoCrossInterference simulates one collector serving dozens of
// firewalls: each is a distinct source IP sending steadily under its per-source
// limit. None should be dropped (each has its own bucket), the global ceiling is
// sized for the fleet, and the tracked-source count matches the fleet size —
// well under the map bound. This is the "dozens of firewalls" guarantee.
func TestManyFirewallsNoCrossInterference(t *testing.T) {
	const firewalls = 40
	// Per-source 100/s burst 200; global 100000 (plenty for the fleet).
	l := New(Config{PerSourceRate: 100, PerSourceBurst: 200, GlobalRate: 100000, GlobalBurst: 100000, MaxSources: 8192})
	now := time.Unix(6000, 0)
	for fw := 0; fw < firewalls; fw++ {
		ip := "10.20." + itoa(fw) + ".1"
		for i := 0; i < 200; i++ { // exactly the burst — all allowed at t0
			if !l.allowAt(ip, now) {
				t.Fatalf("firewall %s packet %d dropped — per-source isolation failed", ip, i)
			}
		}
	}
	_, dropped, tracked := l.Stats()
	if dropped != 0 {
		t.Errorf("dropped %d legitimate datagrams across %d firewalls, want 0", dropped, firewalls)
	}
	if tracked != firewalls {
		t.Errorf("tracked %d sources, want %d (one bucket per firewall)", tracked, firewalls)
	}
	// One firewall exceeding ITS burst must not affect the others.
	noisy := "10.20.0.1"
	if l.allowAt(noisy, now) {
		t.Error("noisy firewall past its burst should be dropped")
	}
	if !l.allowAt("10.20.1.1", now.Add(time.Second)) {
		t.Error("a different firewall must still be allowed after a neighbor floods")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}

func TestStatsCounts(t *testing.T) {
	l := New(Config{PerSourceRate: 1, PerSourceBurst: 1, GlobalRate: 1e9, GlobalBurst: 1e9, MaxSources: 10})
	now := time.Unix(5000, 0)
	l.allowAt("10.0.0.1", now) // allowed
	l.allowAt("10.0.0.1", now) // dropped (per-source burst 1)
	allowed, dropped, _ := l.Stats()
	if allowed != 1 || dropped != 1 {
		t.Errorf("stats = allowed %d / dropped %d, want 1 / 1", allowed, dropped)
	}
}
