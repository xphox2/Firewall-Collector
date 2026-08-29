package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestSendMethods_ProbeIDNoRace_AUDIT289 pins the AUDIT-289 fix: six relay
// Send* methods (config revision, process snapshot, both interface-error
// senders, sensor details, license details) built their URL from a bare
// c.probeID read while finishRegister writes it under c.mu during
// re-registration — a data race the -race detector flags. The fix routes the
// reads through GetProbeID() (mutex-guarded, never held across the HTTP
// call). Modeled on TestSendTrap_ConcurrentWrite_NoRace; sized to stay well
// inside the package's CI budget.
func TestSendMethods_ProbeIDNoRace_AUDIT289(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if strings.HasSuffix(r.URL.Path, "/register") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"probe_id":42,"probe_name":"p","approved":true,"schema_version":5}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	c := &Client{
		Config:     Config{ServerURL: srv.URL, RegistrationKey: "k"},
		httpClient: srv.Client(),
	}
	c.probeID = 42
	c.approved.Store(true)

	var wg sync.WaitGroup

	// Writer: re-registrations rewrite probeID under c.mu.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if err := c.Register(); err != nil {
				t.Errorf("Register: %v", err)
				return
			}
		}
	}()

	// Readers: the six senders build their URL from the probe ID.
	const readers = 3
	for g := 0; g < readers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = c.SendConfigRevision(&ConfigRevision{DeviceID: 1, Checksum: "x"})
				_ = c.SendProcessSnapshot(&ProcessSnapshot{DeviceID: 1})
				_ = c.SendInterfaceErrorSnapshot(&InterfaceErrorSnapshot{DeviceID: 1})
				_ = c.SendInterfaceErrorSnapshots([]InterfaceErrorSnapshot{{DeviceID: 1}})
				_ = c.SendSensorDetails([]SensorDetail{{DeviceID: 1}})
				_ = c.SendLicenseDetails([]LicenseDetail{{DeviceID: 1}})
			}
		}()
	}

	wg.Wait()
}
