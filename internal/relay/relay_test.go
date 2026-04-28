package relay

import (
	"sync"
	"testing"
	"time"
)

// ── Queue overflow ────────────────────────────────────────────────────────────

func newTestClient() *Client {
	c := &Client{}
	c.approved.Store(true)
	c.stopChan = make(chan struct{})
	c.done = make(chan struct{})
	return c
}

// When trapQueue reaches maxQueueSize the oldest entry is dropped to make room.
func TestSendTrap_QueueOverflow_DropsOldest(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(3, 100)

	c := newTestClient()

	for i := range 4 {
		c.SendTrap(&TrapEvent{Message: string(rune('A' + i))})
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.trapQueue) != 3 {
		t.Fatalf("trapQueue len = %d, want 3", len(c.trapQueue))
	}
	// "A" (index 0) should have been dropped; "B","C","D" remain
	if c.trapQueue[0].Message != "B" {
		t.Errorf("trapQueue[0].Message = %q, want %q (oldest not dropped)", c.trapQueue[0].Message, "B")
	}
}

func TestSendPingResult_QueueMaxSize(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient()
	c.SendPingResult(&PingResult{TargetIP: "1.1.1.1"})
	c.SendPingResult(&PingResult{TargetIP: "2.2.2.2"})
	c.SendPingResult(&PingResult{TargetIP: "3.3.3.3"})

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.pingQueue) != 2 {
		t.Fatalf("pingQueue len = %d, want 2", len(c.pingQueue))
	}
	if c.pingQueue[0].TargetIP != "2.2.2.2" {
		t.Errorf("oldest ping not dropped: pingQueue[0].TargetIP = %q, want 2.2.2.2", c.pingQueue[0].TargetIP)
	}
}

func TestSendSyslogMessage_QueueOverflow_DropsOldest(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient()
	c.SendSyslogMessage(&SyslogMessage{Message: "first"})
	c.SendSyslogMessage(&SyslogMessage{Message: "second"})
	c.SendSyslogMessage(&SyslogMessage{Message: "third"})

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.syslogQueue) != 2 {
		t.Fatalf("syslogQueue len = %d, want 2", len(c.syslogQueue))
	}
	if c.syslogQueue[0].Message != "second" {
		t.Errorf("oldest syslog not dropped: got %q, want second", c.syslogQueue[0].Message)
	}
}

func TestSendFlowSample_QueueMaxSize(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient()
	c.SendFlowSample(&FlowSample{SrcAddr: "10.0.0.1"})
	c.SendFlowSample(&FlowSample{SrcAddr: "10.0.0.2"})
	c.SendFlowSample(&FlowSample{SrcAddr: "10.0.0.3"})

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.flowQueue) != 2 {
		t.Fatalf("flowQueue len = %d, want 2", len(c.flowQueue))
	}
	if c.flowQueue[0].SrcAddr != "10.0.0.2" {
		t.Errorf("oldest flow not dropped: got %q", c.flowQueue[0].SrcAddr)
	}
}

// Queue writes are protected by a mutex — concurrent senders must not corrupt the slice.
func TestSendTrap_ConcurrentWrite_NoRace(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(1000, 100)

	c := newTestClient()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c.SendTrap(&TrapEvent{DeviceID: uint(n)})
		}(i)
	}
	wg.Wait()

	c.mu.Lock()
	l := len(c.trapQueue)
	c.mu.Unlock()

	if l == 0 {
		t.Error("all concurrent traps were lost")
	}
}

// ── splitIntoChunks ───────────────────────────────────────────────────────────

func makeTrapSlice(n int) []*TrapEvent {
	s := make([]*TrapEvent, n)
	for i := range s {
		s[i] = &TrapEvent{DeviceID: uint(i)}
	}
	return s
}

func TestSplitIntoChunks_ExactMultiple(t *testing.T) {
	items := makeTrapSlice(6)
	chunks := splitIntoChunks(items, 3)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestSplitIntoChunks_WithRemainder(t *testing.T) {
	items := makeTrapSlice(7)
	chunks := splitIntoChunks(items, 3)
	// 3 + 3 + 1 = 3 chunks
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
}

func TestSplitIntoChunks_SingleItem(t *testing.T) {
	items := makeTrapSlice(1)
	chunks := splitIntoChunks(items, 10)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
}

func TestSplitIntoChunks_ChunkLargerThanInput(t *testing.T) {
	items := makeTrapSlice(3)
	chunks := splitIntoChunks(items, 100)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for input smaller than chunk size, got %d", len(chunks))
	}
}

func TestSplitIntoChunks_ZeroChunkSize_ClampsToOne(t *testing.T) {
	items := makeTrapSlice(3)
	chunks := splitIntoChunks(items, 0)
	// 0 is clamped to 1 → 3 chunks of 1 each
	if len(chunks) != 3 {
		t.Fatalf("chunkSize=0 should clamp to 1, expected 3 chunks, got %d", len(chunks))
	}
}

// ── tryReregister rate limiting ───────────────────────────────────────────────

// tryReregister must return false immediately when called within 60 s of the
// last attempt (rate-limit guard). No sleep occurs in this path.
func TestTryReregister_RateLimitedTo60Seconds(t *testing.T) {
	c := newTestClient()
	c.lastReregisterAttempt = time.Now() // within 60 s
	c.reregisterAttempts = 0

	result := c.tryReregister()
	if result {
		t.Error("tryReregister returned true inside 60-second rate-limit window")
	}
}

// After maxReregisterAttempts failures the client enters a 10-minute cooldown.
// tryReregister must return false without sleeping during that cooldown.
func TestTryReregister_CooldownAfterMaxAttempts(t *testing.T) {
	c := newTestClient()
	c.reregisterAttempts = maxReregisterAttempts // exhausted
	c.lastReregisterAttempt = time.Now()          // cooldown not yet elapsed

	result := c.tryReregister()
	if result {
		t.Error("tryReregister returned true during 10-minute cooldown after max attempts")
	}
}

// ── requeueTraps ──────────────────────────────────────────────────────────────

// requeueTraps prepends failed items to the front of the queue so they are
// retried before newer data.
func TestRequeueTraps_PrependsToFront(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(100, 100)

	c := newTestClient()
	// Pre-populate queue with a newer item
	c.trapQueue = []*TrapEvent{{Message: "newer"}}

	failed := []*TrapEvent{{Message: "failed"}}
	c.requeueTraps(failed)

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.trapQueue) != 2 {
		t.Fatalf("trapQueue len = %d, want 2", len(c.trapQueue))
	}
	if c.trapQueue[0].Message != "failed" {
		t.Errorf("requeueTraps[0] = %q, want failed (should be at front)", c.trapQueue[0].Message)
	}
	if c.trapQueue[1].Message != "newer" {
		t.Errorf("requeueTraps[1] = %q, want newer", c.trapQueue[1].Message)
	}
}

// When queue is full, requeue should not exceed maxQueueSize.
func TestRequeueTraps_RespectsQueueCapacity(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient()
	// Fill queue to capacity
	c.trapQueue = []*TrapEvent{{Message: "a"}, {Message: "b"}}

	// Try to requeue 3 more — none should fit (queue already at cap)
	failed := []*TrapEvent{{Message: "x"}, {Message: "y"}, {Message: "z"}}
	c.requeueTraps(failed)

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.trapQueue) > maxQueueSize {
		t.Errorf("trapQueue len = %d, exceeded maxQueueSize %d", len(c.trapQueue), maxQueueSize)
	}
}
