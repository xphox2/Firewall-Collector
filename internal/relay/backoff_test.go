package relay

import (
	"testing"
	"time"
)

// TestExpBackoff pins the exact per-attempt delays the data-send retry paths
// used inline before the formula was extracted (1s, 2s, 4s).
func TestExpBackoff(t *testing.T) {
	want := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for attempt, w := range want {
		if got := expBackoff(attempt); got != w {
			t.Errorf("expBackoff(%d) = %v, want %v", attempt, got, w)
		}
	}
}

// TestReregisterBackoff_RangeAndJitter pins the registration backoff: a
// 2^attempt × 10s base plus [0, 5s) of jitter.
func TestReregisterBackoff_RangeAndJitter(t *testing.T) {
	for attempt := 0; attempt < 5; attempt++ {
		base := time.Duration(1<<uint(attempt)) * 10 * time.Second
		// Sample several times since the jitter is random.
		for i := 0; i < 50; i++ {
			got := reregisterBackoff(attempt)
			if got < base || got >= base+5*time.Second {
				t.Fatalf("reregisterBackoff(%d) = %v, want in [%v, %v)", attempt, got, base, base+5*time.Second)
			}
		}
	}
}
