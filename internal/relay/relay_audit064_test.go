package relay

import (
	"sync"
	"testing"
	"time"
)

// ── AUDIT-064: per-queue mutex isolation ──────────────────────────────────────

// TestSendTrap_QueueMutex_DoesNotBlockOtherQueues verifies that the four
// queue mutexes (trapMu, pingMu, syslogMu, flowMu) are independent. Pre-AUDIT-064
// every Send* method contended on a single c.mu, so any long hold on one
// queue's critical section blocked the syslog, sFlow, trap, and ping senders
// simultaneously — measurable as cross-core cache-line contention at 1000
// syslog/s + 1000 sFlow/s.
//
// The test holds trapMu for 100ms in a background goroutine and asserts that
// the other three Send* methods can each push 100 events in well under that
// time. Pre-fix, they'd all queue behind the trapMu hold and the loop would
// take ~100ms per Send* call (i.e. 300ms total for ping+syslog+flow).
func TestSendTrap_QueueMutex_DoesNotBlockOtherQueues(t *testing.T) {
	c := newTestClient()

	holdDone := make(chan struct{})
	go func() {
		c.trapMu.Lock()
		time.Sleep(100 * time.Millisecond)
		c.trapMu.Unlock()
		close(holdDone)
	}()
	// Give the goroutine time to actually acquire trapMu before we start
	// timing. 10ms is enough on any reasonable scheduler.
	time.Sleep(10 * time.Millisecond)

	const perQueue = 100
	start := time.Now()
	for i := 0; i < perQueue; i++ {
		c.SendPingResult(&PingResult{DeviceID: uint(i)})
		c.SendSyslogMessage(&SyslogMessage{DeviceID: uint(i)})
		c.SendFlowSample(&FlowSample{DeviceID: uint(i)})
	}
	elapsed := time.Since(start)

	// 50ms is a conservative upper bound: with independent mutexes the loop
	// should complete in well under the 100ms hold. If the queues shared a
	// mutex, the loop would take ~100ms per queue (waiting for trapMu to
	// release), so 300ms+ total.
	if elapsed > 50*time.Millisecond {
		t.Errorf("non-trap queues blocked for %v while trapMu was held (want <50ms); queues share a mutex", elapsed)
	}

	c.pingMu.Lock()
	pingN := len(c.pingQueue)
	c.pingMu.Unlock()
	c.syslogMu.Lock()
	syslogN := len(c.syslogQueue)
	c.syslogMu.Unlock()
	c.flowMu.Lock()
	flowN := len(c.flowQueue)
	c.flowMu.Unlock()

	if pingN != perQueue {
		t.Errorf("pingQueue len = %d, want %d", pingN, perQueue)
	}
	if syslogN != perQueue {
		t.Errorf("syslogQueue len = %d, want %d", syslogN, perQueue)
	}
	if flowN != perQueue {
		t.Errorf("flowQueue len = %d, want %d", flowN, perQueue)
	}

	<-holdDone
}

// TestSendSyslogMessage_QueueMutex_DoesNotBlockOtherQueues is the symmetric
// version of the above: it holds syslogMu (the busiest queue in production)
// and confirms ping/flow/trap can still push. The point is to catch a
// regression where someone collapses two queues back onto a shared mutex.
func TestSendSyslogMessage_QueueMutex_DoesNotBlockOtherQueues(t *testing.T) {
	c := newTestClient()

	holdDone := make(chan struct{})
	go func() {
		c.syslogMu.Lock()
		time.Sleep(100 * time.Millisecond)
		c.syslogMu.Unlock()
		close(holdDone)
	}()
	time.Sleep(10 * time.Millisecond)

	const perQueue = 100
	start := time.Now()
	for i := 0; i < perQueue; i++ {
		c.SendTrap(&TrapEvent{DeviceID: uint(i)})
		c.SendPingResult(&PingResult{DeviceID: uint(i)})
		c.SendFlowSample(&FlowSample{DeviceID: uint(i)})
	}
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("non-syslog queues blocked for %v while syslogMu was held (want <50ms)", elapsed)
	}

	<-holdDone
}

// ── AUDIT-064: parallel syslog + flow workload ───────────────────────────────

// TestSendQueue_ParallelSyslogAndFlow_NoLopsidedThroughput runs the issue's
// literal "1000 syslog/s + 1000 sFlow/s" workload in parallel and checks
// that the two streams reach their full counts in comparable time. If the
// queues shared a mutex, one goroutine would spend most of its time waiting
// and the wall-clock times for the two streams would diverge sharply
// (one ~2x the other, because serialised).
func TestSendQueue_ParallelSyslogAndFlow_NoLopsidedThroughput(t *testing.T) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(100000, 100)

	c := newTestClient()

	const N = 1000

	var wg sync.WaitGroup
	var syslogDur, flowDur time.Duration

	wg.Add(2)
	go func() {
		defer wg.Done()
		start := time.Now()
		for i := 0; i < N; i++ {
			c.SendSyslogMessage(&SyslogMessage{DeviceID: uint(i)})
		}
		syslogDur = time.Since(start)
	}()
	go func() {
		defer wg.Done()
		start := time.Now()
		for i := 0; i < N; i++ {
			c.SendFlowSample(&FlowSample{DeviceID: uint(i)})
		}
		flowDur = time.Since(start)
	}()
	wg.Wait()

	c.syslogMu.Lock()
	syslogN := len(c.syslogQueue)
	c.syslogMu.Unlock()
	c.flowMu.Lock()
	flowN := len(c.flowQueue)
	c.flowMu.Unlock()

	if syslogN != N {
		t.Errorf("syslogQueue len = %d, want %d", syslogN, N)
	}
	if flowN != N {
		t.Errorf("flowQueue len = %d, want %d", flowN, N)
	}

	// If queues share a mutex the two streams serialise and one ends up
	// roughly 2x slower than the other. With per-queue mutexes they run
	// concurrently and their per-goroutine times should be within a small
	// factor. 2.5x is loose enough to tolerate scheduler noise on a busy
	// CI machine while still catching a regression.
	fast, slow := syslogDur, flowDur
	if flowDur < syslogDur {
		fast, slow = flowDur, syslogDur
	}
	if slow > 0 && fast > 0 && slow > fast*5/2 {
		t.Errorf("lopsided throughput — syslog=%v flow=%v, ratio %.2fx (want <2.5x); queues may be sharing a mutex",
			syslogDur, flowDur, float64(slow)/float64(fast))
	}
	t.Logf("parallel syslog+flow: syslog=%v flow=%v ratio=%.2fx", syslogDur, flowDur, float64(slow)/float64(fast))
}

// ── AUDIT-064: benchmarks ─────────────────────────────────────────────────────

// BenchmarkSendTrap is the serial baseline. Compare against
// BenchmarkSendTrap_Parallel — pre-AUDIT-064, the parallel version was no
// faster than the serial one because every push serialised on c.mu.
func BenchmarkSendTrap(b *testing.B) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(b.N+1024, 100)

	c := newTestClient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.SendTrap(&TrapEvent{DeviceID: uint(i)})
	}
	b.StopTimer()
}

// BenchmarkSendTrap_Parallel measures the throughput of SendTrap under
// concurrent load. With per-queue mutexes (AUDIT-064) throughput should
// scale with GOMAXPROCS up to memory-bandwidth limits; pre-fix, every
// goroutine serialised on c.mu so -cpu 8 looked the same as -cpu 1.
//
// Run with:  go test -bench BenchmarkSendTrap -cpu 1,2,4,8 ./internal/relay
func BenchmarkSendTrap_Parallel(b *testing.B) {
	orig := maxQueueSize
	defer func() { maxQueueSize = orig }()
	ConfigureLimits(b.N+1024, 100)

	c := newTestClient()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := uint(0)
		for pb.Next() {
			c.SendTrap(&TrapEvent{DeviceID: i})
			i++
		}
	})
	b.StopTimer()
}
