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

	// Let 10.0.0.1 fully refill (idle) so it becomes evictable.
	idle := t0.Add(30 * time.Second)
	// A new source at t=idle: map full (cap 1), but 10.0.0.1 is now full+idle → evicted.
	if !l.allowAt("10.0.0.2", idle) {
		t.Fatal("new source should be admitted after evicting an idle bucket")
	}
	_, _, tracked := l.Stats()
	if tracked != 1 {
		t.Errorf("tracked = %d, want 1 (evict-then-insert keeps the bound)", tracked)
	}
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
