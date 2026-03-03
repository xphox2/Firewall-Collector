package ping

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/relay"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// seqCounter provides globally unique ICMP sequence numbers across all goroutines.
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
	result := &relay.PingResult{
		Timestamp: time.Now(),
		DeviceID:  dev.ID,
		ProbeID:   probeID,
		TargetIP:  dev.IPAddress,
	}

	ip, err := net.ResolveIPAddr("ip4", dev.IPAddress)
	if err != nil {
		result.PacketLoss = 100
		result.ErrorMessage = fmt.Sprintf("resolve %s: %v", dev.IPAddress, err)
		p.emit(result)
		return
	}

	// One UDP ICMP socket per device, reused across all count pings.
	// The kernel filters replies to this specific socket — no cross-talk.
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		result.PacketLoss = 100
		result.ErrorMessage = fmt.Sprintf("icmp socket: %v", err)
		p.emit(result)
		return
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: ip.IP}

	var totalLatency float64
	var successCount int
	var lastErr error

	for i := 0; i < p.count; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		latency, err := sendEcho(conn, dst, dev.IPAddress, p.timeout)
		if err != nil {
			lastErr = err
			continue
		}
		totalLatency += latency
		successCount++
	}

	if successCount > 0 {
		result.Success = true
		result.Latency = totalLatency / float64(successCount)
		result.PacketLoss = float64(p.count-successCount) / float64(p.count) * 100
		log.Printf("[Ping] %s (%s): latency=%.1fms loss=%.0f%%", dev.Name, dev.IPAddress, result.Latency, result.PacketLoss)
	} else {
		result.PacketLoss = 100
		if lastErr != nil {
			result.ErrorMessage = fmt.Sprintf("All %d pings failed: %v", p.count, lastErr)
		} else {
			result.ErrorMessage = "Request timeout"
		}
		log.Printf("[Ping] %s (%s): FAILED — %s", dev.Name, dev.IPAddress, result.ErrorMessage)
	}

	p.emit(result)
}

func (p *PingCollector) emit(result *relay.PingResult) {
	if p.handler != nil {
		p.handler(result)
	}
}

// sendEcho sends one ICMP echo request on conn and waits for the matching reply.
// Returns latency in milliseconds.
// With udp4 sockets, the kernel filters replies to the correct socket — only
// matching replies arrive, so we only need to check the sequence number.
func sendEcho(conn *icmp.PacketConn, dst *net.UDPAddr, host string, timeout time.Duration) (float64, error) {
	seq := int(atomic.AddUint32(&seqCounter, 1) & 0xffff)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, fmt.Errorf("set deadline: %w", err)
	}

	wb, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0, // kernel overwrites ID for udp4 sockets
			Seq:  seq,
			Data: make([]byte, 56),
		},
	}).Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return 0, fmt.Errorf("send to %s: %w", host, err)
	}

	rb := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			return 0, fmt.Errorf("read from %s: %w", host, err)
		}

		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			echo, ok := rm.Body.(*icmp.Echo)
			if !ok || echo.Seq != seq {
				continue
			}
			return float64(time.Since(start).Nanoseconds()) / 1e6, nil

		case ipv4.ICMPTypeDestinationUnreachable:
			return 0, fmt.Errorf("destination unreachable: %s", host)

		case ipv4.ICMPTypeTimeExceeded:
			return 0, fmt.Errorf("TTL expired: %s", host)

		default:
			continue
		}
	}
}

// Ping sends a single ICMP echo request to host and waits for a reply.
// Returns latency in milliseconds, TTL (always 0 for UDP ICMP), and error.
func Ping(host string, timeout time.Duration) (latency float64, ttl int, err error) {
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve %s: %w", host, err)
	}

	conn, err := icmp.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return 0, 0, fmt.Errorf("icmp listen: %w", err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: ip.IP}

	lat, pingErr := sendEcho(conn, dst, host, timeout)
	return lat, 0, pingErr
}
