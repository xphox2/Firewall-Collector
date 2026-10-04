package snmp

import (
	"reflect"
	"sort"
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
// DefaultVendor() (the generic profile).
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

// TestDefaultVendor_PrefersGeneric verifies that when multiple vendors are
// registered, DefaultVendor returns the standards-only generic profile (not
// FortiGate, not just any random vendor). Until 1.3.48 the default was
// FortiGate, so an unclassified device was polled with FortiGate enterprise
// OIDs; since 1.3.49 (server 0.11.290) an empty or unknown vendor is generic
// on both sides.
func TestDefaultVendor_PrefersGeneric(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		// Register other vendors first so the map iteration order (which is
		// non-deterministic) would otherwise pick them.
		RegisterVendor(&stubVendorProfile{name: "paloalto"})
		RegisterVendor(&FortiGateProfile{})
		RegisterVendor(&stubVendorProfile{name: "pfsense"})

		generic := &GenericProfile{}
		RegisterVendor(generic)

		got := DefaultVendor()
		if got != generic {
			t.Errorf("DefaultVendor() = %v, want GenericProfile (matching 'generic' lookup)", got)
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
		// would make generic the first-iterated entry by luck.
		RegisterVendor(&stubVendorProfile{name: "alpha"})
		RegisterVendor(&stubVendorProfile{name: "bravo"})
		RegisterVendor(&stubVendorProfile{name: "charlie"})
		RegisterVendor(&stubVendorProfile{name: "delta"})
		generic := &GenericProfile{}
		RegisterVendor(generic)
		RegisterVendor(&stubVendorProfile{name: "echo"})

		// All 100 calls should return the same GenericProfile instance.
		first := DefaultVendor()
		if first != generic {
			t.Fatalf("DefaultVendor() = %v, want the registered GenericProfile", first)
		}
		for i := 0; i < 100; i++ {
			got := DefaultVendor()
			if got != first {
				t.Fatalf("call #%d: DefaultVendor() returned different instance: %p vs %p", i, got, first)
			}
		}
	})
}

// TestDefaultVendor_FallbackWhenGenericMissing verifies the second branch
// of DefaultVendor: if "generic" is not registered, it returns *some*
// registered profile (any one) so the collector can still function with
// a registry that has no generic profile.
func TestDefaultVendor_FallbackWhenGenericMissing(t *testing.T) {
	withCleanVendorRegistry(t, func() {
		pa := &PaloAltoProfile{}
		RegisterVendor(pa)

		got := DefaultVendor()
		if got != pa {
			t.Errorf("DefaultVendor() with no generic = %v, want PaloAltoProfile fallback", got)
		}
	})
}

// registeredVendorNames is the exact set of profiles the collector ships.
// unifi and meraki (1.3.49) are standards-only profiles built from vendor docs
// and untested on real hardware.
var registeredVendorNames = []string{
	"cisco_asa", "firewalla", "fortigate", "generic", "meraki", "opnsense",
	"paloalto", "pfsense", "sonicwall", "unifi",
}

// TestVendorRegistry_RegisteredNames pins the production registry (the one
// the init() functions fill) to the exact set above, so a profile cannot be
// added, renamed or dropped without the docs (FEATURES.md, ARCHITECTURE.md,
// CUSTOM-VENDOR.md) and the server's validVendors list being updated with it.
// Every name must also round-trip through the resolver as itself: the vendor
// name is what rules and capability profiles key on, so a clone of the
// generic profile must come back under its own name, not as generic.
func TestVendorRegistry_RegisteredNames(t *testing.T) {
	vendorMu.RLock()
	got := make([]string, 0, len(vendorRegistry))
	for name, p := range vendorRegistry {
		got = append(got, name)
		if p.Name() != name {
			t.Errorf("registry key %q holds profile named %q", name, p.Name())
		}
	}
	vendorMu.RUnlock()
	sort.Strings(got)
	if !reflect.DeepEqual(got, registeredVendorNames) {
		t.Fatalf("registered vendor profiles = %v, want exactly %v", got, registeredVendorNames)
	}
	s := &SNMPClient{} // resolveVendor does not touch connection state
	for _, name := range registeredVendorNames {
		if r := s.resolveVendor(name).Name(); r != name {
			t.Errorf("resolveVendor(%q) = %q, want %q", name, r, name)
		}
	}
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

// TestFortiGate_ParseHardwareSensors_DisplayStringValue is a regression for the
// bug where every FortiGate temperature/voltage reading showed 0.0 on the
// device page: fgHwSensorEntValue is a DisplayString (gosnmp delivers it as
// []byte) like "52.500000", but the parser used gosnmp.ToBigInt, which returns
// 0 for a []byte AND for any non-integer numeric string. The value must be
// parsed as a float.
func TestFortiGate_ParseHardwareSensors_DisplayStringValue(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDHWSensorName + ".1", Type: gosnmp.OctetString, Value: []byte("CPU LM75 Temp")},
		{Name: fgOIDHWSensorValue + ".1", Type: gosnmp.OctetString, Value: []byte("52.500000")},
		{Name: fgOIDHWSensorAlarm + ".1", Type: gosnmp.Integer, Value: 0},
		{Name: fgOIDHWSensorName + ".2", Type: gosnmp.OctetString, Value: []byte("PS1 Fan 1")},
		{Name: fgOIDHWSensorValue + ".2", Type: gosnmp.OctetString, Value: []byte("11200")},
		{Name: fgOIDHWSensorAlarm + ".2", Type: gosnmp.Integer, Value: 1},
	}

	byName := map[string]relay.HardwareSensor{}
	for _, s := range f.ParseHardwareSensors(pdus) {
		byName[s.Name] = s
	}
	if len(byName) != 2 {
		t.Fatalf("expected 2 sensors, got %d", len(byName))
	}

	temp, ok := byName["CPU LM75 Temp"]
	if !ok {
		t.Fatal("missing temperature sensor")
	}
	if temp.Value != 52.5 {
		t.Errorf("temperature value = %v, want 52.5 (DisplayString must be parsed as float, not zeroed)", temp.Value)
	}
	if temp.Type != "temperature" || temp.Unit != "°C" {
		t.Errorf("temperature type/unit = %q/%q, want temperature/°C", temp.Type, temp.Unit)
	}
	if temp.Status != "normal" {
		t.Errorf("temperature status = %q, want normal", temp.Status)
	}

	fan, ok := byName["PS1 Fan 1"]
	if !ok {
		t.Fatal("missing fan sensor")
	}
	if fan.Value != 11200 {
		t.Errorf("fan value = %v, want 11200", fan.Value)
	}
	if fan.Status != "alarm" {
		t.Errorf("fan status = %q, want alarm", fan.Status)
	}
}
