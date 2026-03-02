package ping

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/relay"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// seqCounter provides unique ICMP sequence numbers across all goroutines.
var seqCounter uint32

type PingCollector struct {
	interval time.Duration
	timeout  time.Duration
	count    int
	handler  func(*relay.PingResult)
	probeID  uint
	devices  []relay.DeviceInfo
	mu       sync.Mutex
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
}

func NewPingCollector(interval, timeout time.Duration, count int) *PingCollector {
	return &PingCollector{
		interval: interval,
		timeout:  timeout,
		count:    count,
		stopCh:   make(chan struct{}),
	}
}

func (p *PingCollector) Start(devices []relay.DeviceInfo, probeID uint, handler func(*relay.PingResult)) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.devices = devices
	p.probeID = probeID
	p.handler = handler
	p.mu.Unlock()

	p.wg.Add(1)
	go p.run()
	log.Printf("[Ping] Collector started (interval: %v, timeout: %v, count: %d)", p.interval, p.timeout, p.count)
}

func (p *PingCollector) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	p.mu.Unlock()

	close(p.stopCh)
	p.wg.Wait()
	log.Println("[Ping] Collector stopped")
}

func (p *PingCollector) UpdateDevices(devices []relay.DeviceInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.devices = devices
}

func (p *PingCollector) run() {
	defer p.wg.Done()

	p.collectAll()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.collectAll()
		case <-p.stopCh:
			return
		}
	}
}

func (p *PingCollector) collectAll() {
	p.mu.Lock()
	devices := make([]relay.DeviceInfo, len(p.devices))
	copy(devices, p.devices)
	probeID := p.probeID
	p.mu.Unlock()

	// Ping devices concurrently with a semaphore to limit parallelism
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, dev := range devices {
		if !dev.Enabled {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d relay.DeviceInfo) {
			defer wg.Done()
			defer func() { <-sem }()
			p.pingDevice(d, probeID)
		}(dev)
	}
	wg.Wait()
}

func (p *PingCollector) pingDevice(dev relay.DeviceInfo, probeID uint) {
	targetIP := dev.IPAddress

	var totalLatency float64
	var successCount int
	var lastTTL int
	var lastErr error

	for i := 0; i < p.count; i++ {
		latency, ttl, err := Ping(targetIP, p.timeout)
		if err != nil {
			lastErr = err
			continue
		}
		totalLatency += latency
		successCount++
		lastTTL = ttl
		time.Sleep(100 * time.Millisecond)
	}

	result := &relay.PingResult{
		Timestamp: time.Now(),
		DeviceID:  dev.ID,
		ProbeID:   probeID,
		TargetIP:  targetIP,
	}

	if successCount > 0 {
		result.Success = true
		result.Latency = totalLatency / float64(successCount)
		result.PacketLoss = float64(p.count-successCount) / float64(p.count) * 100
		result.TTL = lastTTL
	} else {
		result.Success = false
		result.PacketLoss = 100.0
		if lastErr != nil {
			result.ErrorMessage = fmt.Sprintf("All %d pings failed: %v", p.count, lastErr)
		} else {
			result.ErrorMessage = "Request timeout"
		}
	}

	if p.handler != nil {
		p.handler(result)
	}
}

// Ping sends a single ICMP echo request and waits for a matching reply.
// Returns latency in milliseconds, TTL, and any error.
func Ping(host string, timeout time.Duration) (latency float64, ttl int, err error) {
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve %s: %w", host, err)
	}

	// Unique ID and sequence for this request
	id := os.Getpid() & 0xffff
	seq := int(atomic.AddUint32(&seqCounter, 1) & 0xffff)

	// Try privileged raw socket first (gives us real TTL via control messages),
	// fall back to unprivileged UDP ICMP socket.
	conn, isRaw, err := newICMPConn()
	if err != nil {
		return 0, 0, fmt.Errorf("icmp listen: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, 0, fmt.Errorf("set deadline: %w", err)
	}

	// Enable TTL control messages on raw sockets
	var p4 *ipv4.PacketConn
	if isRaw {
		p4 = ipv4.NewPacketConn(conn)
		if cfErr := p4.SetControlMessage(ipv4.FlagTTL, true); cfErr != nil {
			p4 = nil // fall back to no TTL extraction
		}
	}

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: make([]byte, 56),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, 0, fmt.Errorf("marshal icmp: %w", err)
	}

	var dst net.Addr
	if isRaw {
		dst = &net.IPAddr{IP: ip.IP}
	} else {
		dst = &net.UDPAddr{IP: ip.IP}
	}

	start := time.Now()
	if _, err = conn.WriteTo(wb, dst); err != nil {
		return 0, 0, fmt.Errorf("icmp write to %s: %w", host, err)
	}

	// Read loop: keep reading until we get a matching echo reply or timeout
	rb := make([]byte, 1500)
	for {
		var n int
		var readErr error
		replyTTL := 0

		if p4 != nil {
			// Use ipv4.PacketConn for TTL via control messages
			var cm *ipv4.ControlMessage
			n, cm, _, readErr = p4.ReadFrom(rb)
			if cm != nil {
				replyTTL = cm.TTL
			}
		} else {
			n, _, readErr = conn.ReadFrom(rb)
		}

		if readErr != nil {
			return 0, 0, fmt.Errorf("icmp read from %s: %w", host, readErr)
		}

		elapsed := float64(time.Since(start).Nanoseconds()) / 1e6

		// Protocol number for parsing: 1=ICMP (raw), 58=ICMPv6, for udp4 use iana.ProtocolICMP=1
		rm, parseErr := icmp.ParseMessage(1, rb[:n])
		if parseErr != nil {
			continue // unparseable, try next packet
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			echo, ok := rm.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			// Validate this reply matches our request
			if echo.ID != id || echo.Seq != seq {
				continue // stale or someone else's reply
			}
			return elapsed, replyTTL, nil

		case ipv4.ICMPTypeDestinationUnreachable:
			return 0, 0, fmt.Errorf("destination unreachable: %s", host)

		case ipv4.ICMPTypeTimeExceeded:
			return 0, 0, fmt.Errorf("time exceeded (TTL expired): %s", host)

		default:
			continue // ignore other ICMP types
		}
	}
}

// newICMPConn creates an ICMP packet connection.
// Tries raw socket ("ip4:icmp") first for real TTL access via control messages,
// falls back to unprivileged UDP ICMP ("udp4") if raw fails.
// Returns the connection, whether it's a raw socket, and any error.
func newICMPConn() (conn net.PacketConn, isRaw bool, err error) {
	// Try raw socket first — requires CAP_NET_RAW on Linux
	conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		return conn, true, nil
	}

	// Fallback to unprivileged UDP-based ICMP
	conn, err = icmp.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, false, fmt.Errorf("both raw and udp icmp failed: %w", err)
	}
	return conn, false, nil
}
