// Package safego provides panic-recovering wrappers for long-lived goroutines.
//
// A single nil deref or out-of-range panic in any of the collector's long-lived
// goroutines (SNMP poll, SSH poll, syslog/sFlow listener, ping loop, heartbeat,
// data-send, debouncer) kills the entire process. The collector is designed to
// run for weeks or months unattended, so a single bad packet from a misbehaving
// firewall must not take down the probe.
//
// Use safego.Go instead of a bare `go` statement for any goroutine that runs
// for the lifetime of the process. Use safego.AfterFunc instead of time.AfterFunc
// for the same reason.
package safego

import (
	"log"
	"runtime/debug"
	"time"
)

// logf is the function used to record recovered panics. It is a var so tests
// can override it to capture output.
var logf = log.Printf

// Go runs fn in a new goroutine, recovering from any panic so the process
// survives. The name is included in the log message for traceability — pick
// something short and unique, e.g. "snmpPollingLoop", "pingDevice(d=42)",
// "tftp.handleWRQ".
func Go(name string, fn func()) {
	go func() {
		defer recoverPanic(name)
		fn()
	}()
}

// AfterFunc is a drop-in replacement for time.AfterFunc that catches panics
// in the timer callback. Returns the underlying *time.Timer so callers can Stop
// it as usual.
func AfterFunc(d time.Duration, name string, fn func()) *time.Timer {
	return time.AfterFunc(d, func() {
		defer recoverPanic("timer:" + name)
		fn()
	})
}

func recoverPanic(name string) {
	r := recover()
	if r == nil {
		return
	}
	logf("PANIC in %s: %v\n%s", name, r, debug.Stack())
}
