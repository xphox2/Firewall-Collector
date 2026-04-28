package main

import (
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/relay"
	"firewall-collector/internal/syslog"
)

// debounceWindow used in tests. Long enough to make scheduling races visible
// (each event arrives much faster than this), short enough that tests finish
// in sub-second time.
const testDebounce = 80 * time.Millisecond

// waitFor polls fn until it returns true or until timeout fires. Returns the
// final result. Used to wait deterministically for AfterFunc-driven side
// effects without sleeping a fixed amount.
func waitFor(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return fn()
}

func TestScheduleConfigBackupWith_DebouncesSameCfgtid(t *testing.T) {
	c := &Collector{}
	dev := relay.DeviceInfo{ID: 7, Name: "fw-test"}
	var fires int32
	action := func() { atomic.AddInt32(&fires, 1) }

	ev := &syslog.FortiEvent{Cfgtid: "100", Logid: syslog.LogidConfigObjAttr}

	// Five events within ~5ms, all sharing cfgtid=100 — should collapse to ONE fire.
	for i := 0; i < 5; i++ {
		c.scheduleConfigBackupWith(dev, ev, testDebounce, action)
	}

	// Fire shouldn't have happened yet — debounce window hasn't expired.
	time.Sleep(testDebounce / 4)
	if atomic.LoadInt32(&fires) != 0 {
		t.Fatalf("fire happened before debounce: %d", atomic.LoadInt32(&fires))
	}

	// After debounce window + a small slack, exactly one fire.
	if !waitFor(testDebounce*4, func() bool { return atomic.LoadInt32(&fires) == 1 }) {
		t.Fatalf("expected exactly 1 fire, got %d", atomic.LoadInt32(&fires))
	}

	// And no extra fire later.
	time.Sleep(testDebounce)
	if atomic.LoadInt32(&fires) != 1 {
		t.Errorf("debounce window should have fired exactly once; got %d", atomic.LoadInt32(&fires))
	}
}

func TestScheduleConfigBackupWith_LaterEventResetsTimer(t *testing.T) {
	// Each new event for the same key should reset the timer, so the fire
	// happens debounce-time after the LAST event, not the first.
	c := &Collector{}
	dev := relay.DeviceInfo{ID: 7, Name: "fw-test"}
	var fires int32
	action := func() { atomic.AddInt32(&fires, 1) }
	ev := &syslog.FortiEvent{Cfgtid: "100", Logid: syslog.LogidConfigAttr}

	c.scheduleConfigBackupWith(dev, ev, testDebounce, action)
	time.Sleep(testDebounce / 2) // halfway through the window
	c.scheduleConfigBackupWith(dev, ev, testDebounce, action)
	// At this point: original timer was Stop()'d, new timer started. We should
	// NOT have fired yet, and we SHOULD fire roughly testDebounce after the
	// reset (not after the original schedule time).

	// Wait until just past where the FIRST timer would have fired.
	time.Sleep(testDebounce/2 + 5*time.Millisecond)
	if atomic.LoadInt32(&fires) != 0 {
		t.Fatalf("fire happened too early — timer wasn't reset; fires=%d", atomic.LoadInt32(&fires))
	}

	// Wait the rest of the new debounce window plus a little slack.
	if !waitFor(testDebounce*2, func() bool { return atomic.LoadInt32(&fires) == 1 }) {
		t.Fatalf("expected 1 fire after reset window, got %d", atomic.LoadInt32(&fires))
	}
}

func TestScheduleConfigBackupWith_DifferentCfgtidsFireSeparately(t *testing.T) {
	// Two distinct CLI commits (distinct cfgtid) for the same device should
	// each produce their own backup.
	c := &Collector{}
	dev := relay.DeviceInfo{ID: 7, Name: "fw-test"}
	var fires int32
	action := func() { atomic.AddInt32(&fires, 1) }

	c.scheduleConfigBackupWith(dev, &syslog.FortiEvent{Cfgtid: "100"}, testDebounce, action)
	c.scheduleConfigBackupWith(dev, &syslog.FortiEvent{Cfgtid: "200"}, testDebounce, action)

	if !waitFor(testDebounce*4, func() bool { return atomic.LoadInt32(&fires) == 2 }) {
		t.Errorf("expected 2 fires (one per distinct cfgtid), got %d", atomic.LoadInt32(&fires))
	}
}

func TestScheduleConfigBackupWith_DifferentDevicesFireSeparately(t *testing.T) {
	// Same cfgtid value (highly unlikely, but possible across firewalls)
	// targeting different devices must not collapse.
	c := &Collector{}
	var fires int32
	action := func() { atomic.AddInt32(&fires, 1) }

	devA := relay.DeviceInfo{ID: 7, Name: "fw-a"}
	devB := relay.DeviceInfo{ID: 8, Name: "fw-b"}
	ev := &syslog.FortiEvent{Cfgtid: "100"}

	c.scheduleConfigBackupWith(devA, ev, testDebounce, action)
	c.scheduleConfigBackupWith(devB, ev, testDebounce, action)

	if !waitFor(testDebounce*4, func() bool { return atomic.LoadInt32(&fires) == 2 }) {
		t.Errorf("expected 2 fires (one per device), got %d", atomic.LoadInt32(&fires))
	}
}

func TestScheduleConfigBackupWith_EmptyCfgtidStillDebounces(t *testing.T) {
	// Rare but possible: an event with no cfgtid. The debouncer should still
	// collapse repeated events for the same device to one fire (the key
	// degrades to "<deviceID>:_").
	c := &Collector{}
	dev := relay.DeviceInfo{ID: 7, Name: "fw-test"}
	var fires int32
	action := func() { atomic.AddInt32(&fires, 1) }
	ev := &syslog.FortiEvent{Cfgtid: ""} // explicitly empty

	for i := 0; i < 3; i++ {
		c.scheduleConfigBackupWith(dev, ev, testDebounce, action)
	}

	if !waitFor(testDebounce*4, func() bool { return atomic.LoadInt32(&fires) == 1 }) {
		t.Errorf("expected exactly 1 fire even with empty cfgtid, got %d", atomic.LoadInt32(&fires))
	}
}
