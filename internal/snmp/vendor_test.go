package snmp

import (
	"sync"
	"testing"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// TestVendorRegistry_RegisterAndGet verifies the basic register-then-lookup
// contract: registering a profile under a name makes GetVendorProfile return
// the same instance.
func TestVendorRegistry_RegisterAndGet(t *testing.T) {
	profile := &stubVendorProfile{name: "test-vendor-a"}
	withCleanVendorRegistry(t, func() {
		RegisterVendor(profile)
		got := GetVendorProfile("test-vendor-a")
		if got != profile {
			t.Fatalf("GetVendorProfile returned different instance: got %p want %p", got, profile)
		}
	})
}

// TestVendorRegistry_NotFoundReturnsNil ensures that asking for an unknown
// vendor returns nil rather than a zero-valued VendorProfile interface.
// Callers depend on this nil-check in snmp.go:resolveVendor to fall back to
// DefaultVendor().
func TestVendorRegistry_NotFoundReturnsNil(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		if got := GetVendorProfile("nonexistent-vendor-xyz"); got != nil {
			t.Errorf("GetVendorProfile(unknown) = %v, want nil", got)
		}
	})
}

// TestVendorRegistry_RegisterOverwrites is a defensive test: re-registering
// the same name should replace the old profile, not error or panic.
func TestVendorRegistry_RegisterOverwrites(t *testing.T) {
	first := &stubVendorProfile{name: "dup", marker: "first"}
	second := &stubVendorProfile{name: "dup", marker: "second"}

	withCleanVendorRegistry(t, func() {
		RegisterVendor(first)
		RegisterVendor(second)
		got := GetVendorProfile("dup")
		if got != second {
			t.Errorf("second Register should overwrite first; got %p want %p", got, second)
		}
	})
}

// TestVendorRegistry_ConcurrentAccess hammers RegisterVendor and
// GetVendorProfile from many goroutines simultaneously. Run with -race to
// catch data races. Without the sync.RWMutex guarding vendorRegistry, this
// test would race on the map itself.
func TestVendorRegistry_ConcurrentAccess(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		const goroutines = 50

		// Register 10 distinct vendors from one set of goroutines.
		concurrentRunner(goroutines, func() {
			for i := 0; i < 10; i++ {
				RegisterVendor(&stubVendorProfile{name: vendorName(i)})
			}
		})

		// Lookup goroutines hammer GetVendorProfile for the same names.
		concurrentRunner(goroutines, func() {
			for i := 0; i < 100; i++ {
				_ = GetVendorProfile(vendorName(i % 10))
			}
		})

		// Verify the final registry is consistent.
		for i := 0; i < 10; i++ {
			if got := GetVendorProfile(vendorName(i)); got == nil {
				t.Errorf("GetVendorProfile(%q) returned nil after concurrent registration", vendorName(i))
			}
		}
	})
}

// TestDefaultVendor_PrefersFortigate verifies that when multiple vendors are
// registered, DefaultVendor returns the FortiGate profile (not just any
// random vendor). This is the documented behavior in vendor.go:DefaultVendor.
func TestDefaultVendor_PrefersFortigate(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		// Register non-fortigate vendors first so the map iteration order
		// (which is non-deterministic) would otherwise pick them.
		RegisterVendor(&stubVendorProfile{name: "paloalto"})
		RegisterVendor(&stubVendorProfile{name: "pfsense"})

		forti := &FortiGateProfile{}
		RegisterVendor(forti)

		got := DefaultVendor()
		if got != forti {
			t.Errorf("DefaultVendor() = %v, want FortiGateProfile (matching 'fortigate' lookup)", got)
		}
	})
}

// TestDefaultVendor_StableOrder_AcrossCalls verifies DefaultVendor returns
// the same profile on every call (the "stable order" property called out in
// the issue). Without this, a single collector process could see different
// parsers applied on different polls if the underlying map iteration order
// ever changed (it can't for a non-modified map, but the issue's regression
// scenario implies relying on this determinism).
func TestDefaultVendor_StableOrder_AcrossCalls(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		// Empty registry → DefaultVendor must return nil rather than panic.
		if got := DefaultVendor(); got != nil {
			t.Errorf("DefaultVendor on empty registry = %v, want nil", got)
		}

		// Register 5 vendors in an order chosen to avoid a HashSeed that
		// would make fortigate the first-iterated entry by luck.
		RegisterVendor(&stubVendorProfile{name: "alpha"})
		RegisterVendor(&stubVendorProfile{name: "bravo"})
		RegisterVendor(&stubVendorProfile{name: "charlie"})
		RegisterVendor(&stubVendorProfile{name: "delta"})
		forti := &FortiGateProfile{}
		RegisterVendor(forti)
		RegisterVendor(&stubVendorProfile{name: "echo"})

		// All 100 calls should return the same FortiGateProfile instance.
		first := DefaultVendor()
		for i := 0; i < 100; i++ {
			got := DefaultVendor()
			if got != first {
				t.Fatalf("call #%d: DefaultVendor() returned different instance: %p vs %p", i, got, first)
			}
		}
	})
}

// TestDefaultVendor_FallbackWhenFortigateMissing verifies the second branch
// of DefaultVendor: if "fortigate" is not registered, it returns *some*
// registered profile (any one) so the collector can still function with
// a non-FortiGate fleet.
func TestDefaultVendor_FallbackWhenFortigateMissing(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		pa := &PaloAltoProfile{}
		RegisterVendor(pa)

		got := DefaultVendor()
		if got != pa {
			t.Errorf("DefaultVendor() with no fortigate = %v, want PaloAltoProfile fallback", got)
		}
	})
}

// TestIsValidPDU verifies the package-private filter that excludes
// "value unavailable" PDU types. Every vendor parser calls this first, so
// getting it wrong would silently drop real data or let bogus values
// through.
func TestIsValidPDU(t *testing.T) {
	tests := []struct {
		name string
		pdu  gosnmp.SnmpPDU
		want bool
	}{
		{"integer-ok", gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 1}, true},
		{"octetstring-ok", gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("x")}, true},
		{"counter32-ok", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint32(1)}, true},
		{"gauge32-ok", gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint(1)}, true},
		{"counter64-ok", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(1)}, true},
		{"oid-ok", gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1"}, true},
		{"nosuchobject-rejected", gosnmp.SnmpPDU{Type: gosnmp.NoSuchObject}, false},
		{"nosuchinstance-rejected", gosnmp.SnmpPDU{Type: gosnmp.NoSuchInstance}, false},
		{"endofmibview-rejected", gosnmp.SnmpPDU{Type: gosnmp.EndOfMibView}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidPDU(tt.pdu); got != tt.want {
				t.Errorf("isValidPDU(%v) = %v, want %v", tt.pdu.Type, got, tt.want)
			}
		})
	}
}

// TestRegisterAndGet_RaceOnly ensures that the lock is held during reads.
// This is implicit in TestVendorRegistry_ConcurrentAccess (which run with
// -race) but duplicated here for visibility if concurrent access is
// disabled. The test relies on the go test -race flag to be meaningful.
func TestRegisterAndGet_RaceOnly(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		profile := &stubVendorProfile{name: "race-target"}
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				RegisterVendor(profile)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_ = GetVendorProfile("race-target")
			}
		}()

		wg.Wait()
		if got := GetVendorProfile("race-target"); got != profile {
			t.Errorf("expected race-target profile after concurrent ops, got %v", got)
		}
	})
}

// --- helpers ---

// stubVendorProfile is a minimal VendorProfile used by registry tests that
// don't need any actual parser behavior. Real vendor profiles register
// themselves in init(), which would pollute the global registry if used
// directly.
type stubVendorProfile struct {
	name     string
	marker   string
	trapOIDs map[string]TrapDef
}

func (s *stubVendorProfile) Name() string         { return s.name }
func (s *stubVendorProfile) SystemOIDs() []string { return nil }
func (s *stubVendorProfile) ParseSystemStatus(_ []gosnmp.SnmpPDU) *relay.SystemStatus {
	return nil
}
func (s *stubVendorProfile) VPNBaseOID() string { return "" }
func (s *stubVendorProfile) ParseVPNStatus(_ []gosnmp.SnmpPDU) []relay.VPNStatus {
	return nil
}
func (s *stubVendorProfile) HWSensorBaseOID() string { return "" }
func (s *stubVendorProfile) ParseHardwareSensors(_ []gosnmp.SnmpPDU) []relay.HardwareSensor {
	return nil
}
func (s *stubVendorProfile) ProcessorBaseOID() string { return "" }
func (s *stubVendorProfile) ParseProcessorStats(_ []gosnmp.SnmpPDU) []relay.ProcessorStats {
	return nil
}
func (s *stubVendorProfile) TrapOIDs() map[string]TrapDef { return s.trapOIDs }

func vendorName(i int) string {
	return "concurrent-vendor-" + string(rune('A'+i))
}
