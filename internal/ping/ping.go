package ping

import (
	"context"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"firewall-collector/internal/relay"
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

	// Use system ping command - much more reliable than Go ICMP
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(p.count), "-W", "1", dev.IPAddress)
	output, err := cmd.Output()

	if ctx.Err() == context.DeadlineExceeded {
		result.PacketLoss = 100
		result.ErrorMessage = "Request timeout"
	} else if err != nil {
		result.PacketLoss = 100
		result.ErrorMessage = err.Error()
	} else {
		// Parse output: "64 bytes from x.x.x.x: icmp_seq=0 ttl=255 time=0.243 ms"
		outputStr := string(output)
		if strings.Contains(outputStr, "bytes from") {
			// Extract latency
			re := regexp.MustCompile(`time=(\d+\.?\d*)\s*ms`)
			matches := re.FindStringSubmatch(outputStr)
			if len(matches) > 1 {
				latency, _ := strconv.ParseFloat(matches[1], 64)
				result.Latency = latency
				result.Success = true
				result.PacketLoss = 0
			}
		} else {
			result.PacketLoss = 100
			result.ErrorMessage = "No response"
		}
	}

	log.Printf("[Ping] %s (%s): latency=%.2fms loss=%.0f%%", dev.Name, dev.IPAddress, result.Latency, result.PacketLoss)
	p.emit(result)
}

func (p *PingCollector) emit(result *relay.PingResult) {
	if p.handler != nil {
		p.handler(result)
	}
}
