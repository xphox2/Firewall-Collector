package snmp

import (
	"sync"

	"github.com/gosnmp/gosnmp"
)

// Test-only PDU builders. Real FortiGate / Palo Alto / etc. responses come
// from the network, so the golden tests below construct SnmpPDU values
// in-memory. The package-private helpers in vendor_*.go expect these
// exact value types (see e.g. vendor_fortigate.go ParseSystemStatus):
//   - OctetString values arrive as []byte
//   - Integer / Gauge32 / Counter32 / Counter64 arrive as integers
//   - ObjectIdentifier values arrive as string
//   - IPAddress values arrive as []byte (4 bytes) or string
//
// All helpers preserve the original test readability so golden data is
// self-documenting in the test files (see the FortiGate test for examples).

// mkStringPDU builds an OctetString PDU with a []byte value — this is the
// type gosnmp produces for sysName, version strings, sensor names, etc.
func mkStringPDU(name, value string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  gosnmp.OctetString,
		Value: []byte(value),
	}
}

// mkOIDPDU builds an ObjectIdentifier PDU (value carried as string).
func mkOIDPDU(name, oid string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  gosnmp.ObjectIdentifier,
		Value: oid,
	}
}

// mkIntPDU builds a signed Integer PDU.
func mkIntPDU(name string, value int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  gosnmp.Integer,
		Value: value,
	}
}

// mkGaugePDU builds a Gauge32 PDU (used for CPU%, current conn cache, etc.).
func mkGaugePDU(name string, value uint) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  gosnmp.Gauge32,
		Value: value,
	}
}

// mkCounter32PDU builds a Counter32 PDU (used for octet counters in some MIBs).
func mkCounter32PDU(name string, value uint32) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  gosnmp.Counter32,
		Value: value,
	}
}

// mkCounter64PDU builds a Counter64 PDU (used for 64-bit octet counters).
func mkCounter64PDU(name string, value uint64) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  gosnmp.Counter64,
		Value: value,
	}
}

// mkIPAddressPDU builds an IPAddress PDU carrying a 4-byte value.
// gosnmp typically delivers IPv4 addresses as []byte of length 4.
func mkIPAddressPDU(name string, ip [4]byte) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  gosnmp.IPAddress,
		Value: ip[:],
	}
}

// mkNoSuchPDU builds a "value unavailable" PDU (NoSuchObject, NoSuchInstance,
// or EndOfMibView). These are filtered by isValidPDU in every vendor parser.
func mkNoSuchPDU(name string, asnType gosnmp.Asn1BER) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  name,
		Type:  asnType,
		Value: nil,
	}
}

// withCleanVendorRegistry swaps the global vendorRegistry for a fresh map
// for the duration of fn, restoring the original on return. This is required
// when a test wants to register a custom VendorProfile without polluting the
// global registry for other tests (which all run in the same process).
//
// The replacement registry uses the same sync.RWMutex as the package-level
// vendorMu so concurrent tests see consistent state.
func withCleanVendorRegistry(t testingT, fn func()) {
	t.Helper()
	vendorMu.Lock()
	saved := vendorRegistry
	vendorRegistry = make(map[string]VendorProfile)
	vendorMu.Unlock()
	defer func() {
		vendorMu.Lock()
		vendorRegistry = saved
		vendorMu.Unlock()
	}()
	fn()
}

// withVendorRegistry saves and restores the global registry. Unlike
// withCleanVendorRegistry, this version does NOT wipe the registry first
// — it just guarantees cleanup of any entries the test added.
func withVendorRegistry(t testingT, fn func()) {
	t.Helper()
	vendorMu.Lock()
	saved := vendorRegistry
	vendorMu.Unlock()
	defer func() {
		vendorMu.Lock()
		vendorRegistry = saved
		vendorMu.Unlock()
	}()
	fn()
}

// testingT is a minimal interface that both *testing.T and *testing.B satisfy.
// Used by helpers that need to be callable from any test or benchmark.
type testingT interface {
	Helper()
	FailNow()
}

// concurrentRunner runs n goroutines that each call fn once, then waits for
// all of them. Used by the concurrent registry test.
func concurrentRunner(n int, fn func()) {
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	wg.Wait()
}
