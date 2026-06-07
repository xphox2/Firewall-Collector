package snmp

import (
	"sync"
)

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
