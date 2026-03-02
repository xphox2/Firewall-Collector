package ping

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"firewall-collector/internal/relay"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

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

	for _, dev := range devices {
		if !dev.Enabled {
			continue
		}
		p.pingDevice(dev, probeID)
	}
}

func (p *PingCollector) pingDevice(dev relay.DeviceInfo, probeID uint) {
	targetIP := dev.IPAddress

	var totalLatency float64
	var successCount int
	var ttl int
	var lastErr error

	for i := 0; i < p.count; i++ {
		latency, t, err := Ping(targetIP, p.timeout)
		if err != nil {
			lastErr = err
			continue
		}
		totalLatency += latency
		successCount++
		ttl = t
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
		result.TTL = ttl
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

func Ping(host string, timeout time.Duration) (latency float64, ttl int, err error) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return 0, 0, fmt.Errorf("icmp listen: %w", err)
	}
	defer conn.Close()

	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve %s: %w", host, err)
	}
	dst := &net.UDPAddr{IP: ip.IP}

	conn.SetDeadline(time.Now().Add(timeout))

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: make([]byte, 56),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, 0, fmt.Errorf("marshal icmp: %w", err)
	}

	start := time.Now()
	if _, err = conn.WriteTo(wb, dst); err != nil {
		return 0, 0, fmt.Errorf("icmp write to %s: %w", host, err)
	}

	rb := make([]byte, 1500)
	respLen, _, err := conn.ReadFrom(rb)
	if err != nil {
		return 0, 0, fmt.Errorf("icmp read from %s: %w", host, err)
	}

	latency = float64(time.Since(start).Nanoseconds()) / 1e6

	rm, err := icmp.ParseMessage(int(ipv4.ICMPTypeEchoReply), rb[:respLen])
	if err != nil {
		return 0, 0, fmt.Errorf("parse icmp reply: %w", err)
	}

	if rm.Type == ipv4.ICMPTypeDestinationUnreachable {
		return 0, 0, fmt.Errorf("destination unreachable: %s", host)
	}

	return latency, 64, nil
}
