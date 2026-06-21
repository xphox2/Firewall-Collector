package relay

import (
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"firewall-collector/internal/relay/queue"
)

// ── Test client helper ────────────────────────────────────────────────────────

// newTestClient builds a Client with queues opened in t.TempDir() and
// registers cleanup so the BoltDB files are closed after the test.
// AUDIT-058: queues are no longer in-memory slices; they're persistent
// SpilloverQueue instances.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	dir := t.TempDir()
	open := func(name string) *queue.SpilloverQueue {
		q, err := queue.Open(queue.Config{
			Path:   filepath.Join(dir, name+".bolt"),
			Bucket: name,
			MaxMem: maxQueueSize,
		})
		if err != nil {
			t.Fatalf("open %s queue: %v", name, err)
		}
		t.Cleanup(func() { _ = q.Close() })
		return q
	}
	c := &Client{
		trapQueue:   open("traps"),
		pingQueue:   open("pings"),
		syslogQueue: open("syslog"),
		flowQueue:   open("flows"),
	}
	c.approved.Store(true)
	c.stopChan = make(chan struct{})
	c.done = make(chan struct{})
	return c
}

// ── Queue overflow (AUDIT-058) ───────────────────────────────────────────────

// When trapQueue reaches maxQueueSize the oldest in-memory entry is
// moved to disk; from a caller's perspective the in-memory count stays
// at maxQueueSize and the disk absorbs the overflow. Drained order
// remains strict FIFO: [A-on-disk, B, C, D].
func TestSendTrap_QueueOverflow_DropsOldestFromMem(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(3, 100)

	c := newTestClient(t)

	for i := range 4 {
		c.SendTrap(&TrapEvent{Message: string(rune('A' + i))})
	}

	if got := c.trapQueue.Depth(); got != 3 {
		t.Errorf("in-memory depth = %d, want 3", got)
	}
	disk, err := c.trapQueue.DiskCount()
	if err != nil {
		t.Fatalf("DiskCount: %v", err)
	}
	if disk != 1 {
		t.Errorf("disk count = %d, want 1 (oldest trap moved to disk)", disk)
	}
	// Drained order is FIFO across both tiers: A (oldest, on disk) is
	// first, then B, C, D (in memory). Drain once and check all 4.
	items, err := c.trapQueue.Drain(1000)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(items) != 4 {
		t.Fatalf("drained %d items, want 4 (1 disk + 3 in-mem)", len(items))
	}
	for i, want := range []string{"A", "B", "C", "D"} {
		var got TrapEvent
		if err := json.Unmarshal(items[i], &got); err != nil {
			t.Fatalf("unmarshal[%d]: %v", i, err)
		}
		if got.Message != want {
			t.Errorf("drained[%d] = %q, want %q", i, got.Message, want)
		}
	}
}

func TestSendPingResult_QueueMaxSize(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient(t)
	c.SendPingResult(&PingResult{TargetIP: "1.1.1.1"})
	c.SendPingResult(&PingResult{TargetIP: "2.2.2.2"})
	c.SendPingResult(&PingResult{TargetIP: "3.3.3.3"})

	if got := c.pingQueue.Depth(); got != 2 {
		t.Errorf("in-memory depth = %d, want 2", got)
	}
	items, _ := c.pingQueue.Drain(100)
	if len(items) != 3 {
		t.Fatalf("total drained = %d, want 3 (2 in-mem + 1 on disk)", len(items))
	}
	var p PingResult
	if err := json.Unmarshal(items[0], &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// FIFO: 1.1.1.1 is oldest (on disk), then 2.2.2.2, 3.3.3.3 (in mem).
	if p.TargetIP != "1.1.1.1" {
		t.Errorf("drained[0] = %q, want 1.1.1.1 (FIFO oldest, on disk)", p.TargetIP)
	}
	if err := json.Unmarshal(items[2], &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.TargetIP != "3.3.3.3" {
		t.Errorf("drained[2] = %q, want 3.3.3.3 (newest, in memory)", p.TargetIP)
	}
}

func TestSendSyslogMessage_QueueOverflow_DropsOldest(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient(t)
	c.SendSyslogMessage(&SyslogMessage{Message: "first"})
	c.SendSyslogMessage(&SyslogMessage{Message: "second"})
	c.SendSyslogMessage(&SyslogMessage{Message: "third"})

	if got := c.syslogQueue.Depth(); got != 2 {
		t.Errorf("in-memory depth = %d, want 2", got)
	}
	items, _ := c.syslogQueue.Drain(100)
	if len(items) != 3 {
		t.Fatalf("total drained = %d, want 3 (2 in-mem + 1 on disk)", len(items))
	}
	var s SyslogMessage
	if err := json.Unmarshal(items[0], &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// FIFO: "first" is on disk, then "second", "third" in memory.
	if s.Message != "first" {
		t.Errorf("drained[0] = %q, want %q (FIFO oldest, on disk)", s.Message, "first")
	}
}

func TestSendFlowSample_QueueMaxSize(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient(t)
	c.SendFlowSample(&FlowSample{SrcAddr: "10.0.0.1"})
	c.SendFlowSample(&FlowSample{SrcAddr: "10.0.0.2"})
	c.SendFlowSample(&FlowSample{SrcAddr: "10.0.0.3"})

	if got := c.flowQueue.Depth(); got != 2 {
		t.Errorf("in-memory depth = %d, want 2", got)
	}
	items, _ := c.flowQueue.Drain(100)
	if len(items) != 3 {
		t.Fatalf("total drained = %d, want 3 (2 in-mem + 1 on disk)", len(items))
	}
	var f FlowSample
	if err := json.Unmarshal(items[0], &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// FIFO: 10.0.0.1 is on disk, then 10.0.0.2, 10.0.0.3 in memory.
	if f.SrcAddr != "10.0.0.1" {
		t.Errorf("drained[0] = %q, want 10.0.0.1 (FIFO oldest, on disk)", f.SrcAddr)
	}
}

// Queue writes are protected by the SpilloverQueue's internal mutex —
// concurrent senders must not lose items or corrupt the queue.
func TestSendTrap_ConcurrentWrite_NoRace(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(1000, 100)

	c := newTestClient(t)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c.SendTrap(&TrapEvent{DeviceID: uint(n)})
		}(i)
	}
	wg.Wait()

	disk, _ := c.trapQueue.DiskCount()
	total := c.trapQueue.Depth() + disk
	if total == 0 {
		t.Error("all concurrent traps were lost")
	}
}

// ── chunkSlice ────────────────────────────────────────────────────────────────

func makeTrapSlice(n int) []*TrapEvent {
	s := make([]*TrapEvent, n)
	for i := range s {
		s[i] = &TrapEvent{DeviceID: uint(i)}
	}
	return s
}

func TestChunkSlice_ExactMultiple(t *testing.T) {
	items := makeTrapSlice(6)
	chunks := chunkSlice(items, 3)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestChunkSlice_WithRemainder(t *testing.T) {
	items := makeTrapSlice(7)
	chunks := chunkSlice(items, 3)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
}

func TestChunkSlice_SingleItem(t *testing.T) {
	items := makeTrapSlice(1)
	chunks := chunkSlice(items, 10)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
}

func TestChunkSlice_ChunkLargerThanInput(t *testing.T) {
	items := makeTrapSlice(3)
	chunks := chunkSlice(items, 100)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for input smaller than chunk size, got %d", len(chunks))
	}
}

func TestChunkSlice_ZeroChunkSize_ClampsToOne(t *testing.T) {
	items := makeTrapSlice(3)
	chunks := chunkSlice(items, 0)
	if len(chunks) != 3 {
		t.Fatalf("chunkSize=0 should clamp to 1, expected 3 chunks, got %d", len(chunks))
	}
}

// ── tryReregister rate limiting ───────────────────────────────────────────────

func TestTryReregister_RateLimitedTo60Seconds(t *testing.T) {
	c := newTestClient(t)
	c.lastReregisterAttempt = time.Now()
	c.reregisterAttempts = 0

	if c.tryReregister() {
		t.Error("tryReregister returned true inside 60-second rate-limit window")
	}
}

func TestTryReregister_CooldownAfterMaxAttempts(t *testing.T) {
	c := newTestClient(t)
	c.reregisterAttempts = maxReregisterAttempts
	c.lastReregisterAttempt = time.Now()

	if c.tryReregister() {
		t.Error("tryReregister returned true during 10-minute cooldown after max attempts")
	}
}

// ── requeueTraps (AUDIT-058) ──────────────────────────────────────────────────

// requeueTraps puts failed items back into the queue. The new
// SpilloverQueue model means failed items join the in-memory tier
// (the "newest" tier), so they are sent AFTER the items that
// overflowed to disk. The previous "prepend to front" behavior would
// have retried the failed items first; that priority shift is
// acceptable because the on-disk items have been waiting longer
// anyway.
func TestRequeueTraps_AppendsToQueue(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(100, 100)

	c := newTestClient(t)
	c.SendTrap(&TrapEvent{Message: "newer"})

	failed := []*TrapEvent{{Message: "failed"}}
	requeueItems(c.trapQueue, failed, "traps", "trap events")

	items, err := c.trapQueue.Drain(100)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("total drained = %d, want 2 (newer + failed)", len(items))
	}
	var m0, m1 TrapEvent
	if err := json.Unmarshal(items[0], &m0); err != nil {
		t.Fatalf("unmarshal 0: %v", err)
	}
	if err := json.Unmarshal(items[1], &m1); err != nil {
		t.Fatalf("unmarshal 1: %v", err)
	}
	// Order: "newer" was pushed first, then "failed" via requeue.
	// The SpilloverQueue's in-memory tier appends, so the new
	// "failed" item sits at the end.
	if m0.Message != "newer" || m1.Message != "failed" {
		t.Errorf("order = [%q, %q], want [newer, failed]", m0.Message, m1.Message)
	}
}

// SpilloverQueue Push never exceeds MaxMem (oldest is moved to disk),
// so requeueTraps cannot fail in the way the old in-memory slice did.
// The new "full" failure mode is the on-disk byte cap (covered in the
// queue package's own tests).
func TestRequeueTraps_CapacityHandledBySpillover(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(2, 100)

	c := newTestClient(t)
	// Fill the in-memory tier to cap.
	c.SendTrap(&TrapEvent{Message: "a"})
	c.SendTrap(&TrapEvent{Message: "b"})

	// Requeue 3 more — they will spill to disk rather than fail.
	failed := []*TrapEvent{{Message: "x"}, {Message: "y"}, {Message: "z"}}
	requeueItems(c.trapQueue, failed, "traps", "trap events")

	disk, _ := c.trapQueue.DiskCount()
	if disk != 3 {
		t.Errorf("disk count = %d, want 3 (requeued items spilled)", disk)
	}
}
