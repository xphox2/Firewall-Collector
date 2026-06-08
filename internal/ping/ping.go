package ping

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/relay"
	"firewall-collector/internal/safego"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ianaProtocolICMP is the IANA protocol number for ICMPv4, required by
// icmp.ParseMessage to select the v4 parser.
const ianaProtocolICMP = 1

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
	safego.Go("ping:run", p.run)
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
		dev := dev
		safego.Go("ping:device:"+dev.Name, func() {
			defer wg.Done()
			defer func() { <-sem }()
			p.pingDevice(dev, probeID)
		})
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

	count := p.count
	if count < 1 {
		count = 1
	}
	// Split the overall timeout budget across the packets, with a 1s floor per
	// packet so a small configured timeout doesn't starve replies.
	perTimeout := p.timeout / time.Duration(count)
	if perTimeout < time.Second {
		perTimeout = time.Second
	}

	latency, loss, err := pingHost(dev.IPAddress, count, perTimeout)
	switch {
	case err != nil:
		result.PacketLoss = 100
		result.ErrorMessage = err.Error()
	case loss >= 100:
		result.PacketLoss = 100
		result.ErrorMessage = "Request timeout"
	default:
		result.Success = true
		result.Latency = latency
		result.PacketLoss = loss
	}

	log.Printf("[Ping] %s (%s): latency=%.2fms loss=%.0f%%", dev.Name, dev.IPAddress, result.Latency, result.PacketLoss)
	p.emit(result)
}

// pingIDCounter hands out a distinct ICMP echo identifier per pingHost call so
// concurrent pings (which all see every ICMP reply on a shared raw socket view)
// can tell their replies apart.
var pingIDCounter uint32

// pingHost sends `count` ICMP echo requests in-process and returns the average
// latency (ms) of the replies and the packet-loss percentage.
//
// It uses a RAW ICMP socket ("ip4:icmp"), which the collector binary is granted
// via cap_net_raw (Dockerfile `setcap cap_net_raw=+ep`). The previous
// implementation shelled out to the external `ping` binary — but that child
// process does NOT inherit the collector's file capability, and in the rootless
// container ('nobody' user, no net.ipv4.ping_group_range) it cannot open an ICMP
// socket, so every ping reported 100% loss. Doing ICMP in-process uses the
// capability the binary already carries.
func pingHost(host string, count int, perTimeout time.Duration) (latency float64, loss float64, err error) {
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, 100, err
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, 100, err
	}
	defer conn.Close()

	id := int(atomic.AddUint32(&pingIDCounter, 1)) & 0xffff

	var sum float64
	received := 0
	for seq := 0; seq < count; seq++ {
		lat, e := echoOnce(conn, dst, id, seq, perTimeout)
		if e != nil {
			continue // timeout / no matching reply for this packet
		}
		received++
		sum += lat
	}

	if received == 0 {
		return 0, 100, nil
	}
	return sum / float64(received), float64(count-received) / float64(count) * 100, nil
}

func echoOnce(conn *icmp.PacketConn, dst *net.IPAddr, id, seq int, timeout time.Duration) (float64, error) {
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: make([]byte, 56)},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, err
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return 0, err
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return 0, err // includes i/o timeout
		}
		// The raw socket sees every host's ICMP replies; accept only one from
		// the address we actually pinged.
		if pa, ok := peer.(*net.IPAddr); !ok || !pa.IP.Equal(dst.IP) {
			continue
		}
		if matchEchoReply(rb[:n], id, seq) {
			return float64(time.Since(start).Microseconds()) / 1000.0, nil
		}
	}
}

// matchEchoReply reports whether raw is an ICMP echo reply for (id, seq). On
// Linux, raw IPPROTO_ICMP sockets prepend the IPv4 header to received packets,
// so it is stripped when present. The version-nibble guard (high nibble == 4)
// is unambiguous: a bare ICMP message starts with its Type byte (echo-reply 0,
// dest-unreachable 3, time-exceeded 11 — all high nibble 0), never 4.
func matchEchoReply(raw []byte, wantID, wantSeq int) bool {
	msg := raw
	if len(msg) > 0 && msg[0]>>4 == 4 {
		ihl := int(msg[0]&0x0f) * 4
		if ihl >= ipv4.HeaderLen && ihl <= len(msg) {
			msg = msg[ihl:]
		}
	}
	rm, err := icmp.ParseMessage(ianaProtocolICMP, msg)
	if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
		return false
	}
	echo, ok := rm.Body.(*icmp.Echo)
	return ok && echo.ID == wantID && echo.Seq == wantSeq
}

func (p *PingCollector) emit(result *relay.PingResult) {
	if p.handler != nil {
		p.handler(result)
	}
}
