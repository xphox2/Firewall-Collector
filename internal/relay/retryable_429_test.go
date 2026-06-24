package relay

import "testing"

// TestIsRetryableStatus_429IsRetryable is the regression for the 2026-06-23
// CTO-loop 429-asymmetry finding: the server rate-limits probe ingestion with
// HTTP 429, but the collector listed 429 as non-retryable and therefore silently
// DROPPED whole SNMP-metric batches the moment the server pushed back. 429 is
// transient and must be retried (the retry loops pace with expBackoff); genuine
// permanent rejections (4xx auth/validation) must stay non-retryable.
func TestIsRetryableStatus_429IsRetryable(t *testing.T) {
	if !isRetryableStatus(429) {
		t.Error("429 (Too Many Requests) must be retryable — it is server backpressure, not a permanent rejection")
	}

	// Permanent rejections must remain non-retryable.
	for _, code := range []int{400, 401, 403, 404, 405, 409, 410, 422} {
		if isRetryableStatus(code) {
			t.Errorf("status %d must remain non-retryable", code)
		}
	}

	// Transient/server-side and success-adjacent codes must be retryable.
	for _, code := range []int{429, 500, 502, 503, 504, 408} {
		if !isRetryableStatus(code) {
			t.Errorf("status %d must be retryable", code)
		}
	}
}
