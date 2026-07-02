package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSendBatch_PermanentVsTransient pins the 2026-07-02 audit M3 fix: sendBatch
// must distinguish a permanent rejection (drop, don't requeue) from a transient
// failure (requeue). Requeuing a permanently-rejected batch retries the same
// poison payload every sync cycle forever and evicts good telemetry at the byte
// cap.
func TestSendBatch_PermanentVsTransient(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		wantDelivered bool
		wantPermanent bool
	}{
		{"2xx delivered", http.StatusOK, true, false},
		{"400 permanent", http.StatusBadRequest, false, true},
		{"422 permanent", http.StatusUnprocessableEntity, false, true},
		{"409 permanent", http.StatusConflict, false, true},
		{"500 transient", http.StatusInternalServerError, false, false},
		{"429 transient", http.StatusTooManyRequests, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			c := &Client{Config: Config{RegistrationKey: "test"}, httpClient: srv.Client()}
			delivered, permanent := c.sendBatch(srv.URL, "syslog", []map[string]string{{"m": "x"}})
			if delivered != tc.wantDelivered || permanent != tc.wantPermanent {
				t.Errorf("status %d: got (delivered=%v, permanent=%v), want (delivered=%v, permanent=%v)",
					tc.status, delivered, permanent, tc.wantDelivered, tc.wantPermanent)
			}
		})
	}
}
