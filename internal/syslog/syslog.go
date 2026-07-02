package syslog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/ratelimit"
	"firewall-collector/internal/relay"
	"firewall-collector/internal/reuseport"
	"firewall-collector/internal/safego"
)

const MaxMessageSize = 64 * 1024

// maxTCPSyslogConns caps concurrent TCP syslog connections (M16 of the
// 2026-07-01 audit). Each connection holds a 64 KiB read buffer plus a
// growable bytes.Buffer and a goroutine, so an unbounded accept loop is a
// memory/FD-exhaustion vector from any host on the monitored LAN.
const maxTCPSyslogConns = 256

// SyslogReceiver handles TCP syslog connections.
type SyslogReceiver struct {
	ListenAddr string
	Port       int
	handler    func(*relay.SyslogMessage)
	listener   net.Listener
	running    atomic.Bool
	stopCh     chan struct{}
	stopOnce   sync.Once
	connWg     sync.WaitGroup

	// M16 of the 2026-07-01 audit: the TCP syslog path had none of the
	// protections the UDP path got in v1.2.x — no per-source rate limit, no
	// connection cap, no accept backoff — so it was a full bypass of the
	// syslog defense on the same port. A hostile host could open thousands of
	// connections or stream garbage at TCP line rate, exhausting the probe or
	// flooding parse-error logs, entirely sidestepping the UDP PPS budget.
	limiter    *ratelimit.Limiter
	onRateDrop func()
	connSem    chan struct{} // bounded concurrent-connection semaphore
}

func NewSyslogReceiver(listenAddr string, port int) *SyslogReceiver {
	return &SyslogReceiver{
		ListenAddr: listenAddr,
		Port:       port,
		stopCh:     make(chan struct{}),
		connSem:    make(chan struct{}, maxTCPSyslogConns),
	}
}

// SetRateLimiter attaches a per-source-IP rate limiter checked per parsed line
// (M16). Nil disables limiting. Set before Start. Mirrors the UDP receiver.
func (s *SyslogReceiver) SetRateLimiter(l *ratelimit.Limiter, onDrop func()) {
	s.limiter = l
	s.onRateDrop = onDrop
}

func (s *SyslogReceiver) Start(handler func(*relay.SyslogMessage)) error {
	if s.running.Load() {
		return errors.New("syslog receiver already running")
	}

	s.handler = handler
	addr := fmt.Sprintf("%s:%d", s.ListenAddr, s.Port)

	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on TCP %s: %w", addr, err)
	}

	s.running.Store(true)
	safego.Go("syslogTcp:accept", s.acceptLoop)

	log.Printf("[Syslog TCP] Listening on %s", addr)
	return nil
}

func (s *SyslogReceiver) Stop() error {
	if !s.running.Load() {
		return nil
	}

	var closeErr error
	s.stopOnce.Do(func() {
		s.running.Store(false)
		close(s.stopCh)
		if s.listener != nil {
			closeErr = s.listener.Close()
		}
	})
	s.connWg.Wait()
	return closeErr
}

func (s *SyslogReceiver) acceptLoop() {
	var backoff time.Duration
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if !s.running.Load() {
				return
			}
			// M16: back off on a persistent accept error (e.g. EMFILE from the
			// very flood we're defending against) instead of spinning a tight
			// error-logging loop. Temporary errors get a short, capped sleep.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			log.Printf("[Syslog TCP] Accept error: %v (backing off %s)", err, backoff)
			select {
			case <-time.After(backoff):
			case <-s.stopCh:
				return
			}
			continue
		}
		backoff = 0

		// M16: bound concurrent connections. Beyond the cap, refuse the newest
		// connection immediately rather than letting an attacker exhaust
		// memory/FDs with thousands of idle-but-open connections.
		select {
		case s.connSem <- struct{}{}:
		default:
			log.Printf("[Syslog TCP] Connection cap (%d) reached — refusing %s", maxTCPSyslogConns, conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		s.connWg.Add(1)
		safego.Go("syslogTcp:handleConn", func() {
			defer s.connWg.Done()
			defer func() { <-s.connSem }()
			s.handleConnection(conn)
		})
	}
}

func (s *SyslogReceiver) handleConnection(conn net.Conn) {
	defer conn.Close()

	// M16: resolve the source IP once for the per-line rate-limit check.
	sourceIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(sourceIP); err == nil {
		sourceIP = host
	}

	buf := make([]byte, MaxMessageSize)
	var messageBuf bytes.Buffer

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			break
		}

		messageBuf.Write(buf[:n])

		// Forward-scan the accumulated buffer with an advancing offset, then
		// compact the unconsumed tail ONCE at the end. The previous code did
		// messageBuf.Reset() + rewrite-the-remaining-tail on every newline, which
		// is O(n²) when a single Read() delivers many lines (2026-06-23 audit, M6).
		data := messageBuf.Bytes()
		start := 0
		for {
			rel := bytes.IndexByte(data[start:], '\n')
			if rel == -1 {
				break
			}
			line := data[start : start+rel]
			start += rel + 1
			if len(line) == 0 {
				continue
			}

			// M16: per-source rate limit BEFORE parse, so a garbage-line flood
			// costs nothing (no parse, no handler, no parse-error log spam) and
			// respects the same PPS budget as the UDP path.
			if !s.limiter.Allow(sourceIP) {
				if s.onRateDrop != nil {
					s.onRateDrop()
				}
				continue
			}

			msg, err := ParseRFC5424(line)
			if err != nil {
				continue // M16: don't log per malformed line — a flood would DoS the log
			}

			if msg != nil && s.handler != nil {
				msg.SourceIP = sourceIP
				s.handler(msg)
			}
		}

		// Keep only the bytes after the last newline for the next Read. A
		// delimiter-less partial line that overflows MaxMessageSize is dropped
		// (same cap as before) so a peer can't grow the buffer without bound.
		if start > 0 {
			remaining := data[start:]
			messageBuf.Reset()
			if len(remaining) < MaxMessageSize {
				messageBuf.Write(remaining)
			}
		} else if messageBuf.Len() >= MaxMessageSize {
			messageBuf.Reset()
		}
	}
}

// UDPSyslogReceiver handles UDP syslog packets.
type UDPSyslogReceiver struct {
	ListenAddr string
	Port       int
	handler    func(*relay.SyslogMessage)
	limiter    *ratelimit.Limiter
	onRateDrop func()
	workers    int
	conns      []*net.UDPConn
	running    atomic.Bool
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

// SetRateLimiter attaches a per-source-IP rate limiter; datagrams from a source
// over its rate are dropped before parsing. Nil disables limiting. Set before Start.
func (u *UDPSyslogReceiver) SetRateLimiter(l *ratelimit.Limiter, onDrop func()) {
	u.limiter = l
	u.onRateDrop = onDrop
}

// SetWorkers sets the number of parallel receive sockets/goroutines (SO_REUSEPORT
// fan-out). n<=1 (default) uses a single socket; n>1 requires SO_REUSEPORT
// (Linux) and is clamped to 1 elsewhere. Set before Start.
func (u *UDPSyslogReceiver) SetWorkers(n int) {
	u.workers = n
}

func NewUDPSyslogReceiver(listenAddr string, port int) *UDPSyslogReceiver {
	return &UDPSyslogReceiver{
		ListenAddr: listenAddr,
		Port:       port,
		stopCh:     make(chan struct{}),
	}
}

func (u *UDPSyslogReceiver) Start(handler func(*relay.SyslogMessage)) error {
	if u.running.Load() {
		return errors.New("UDP syslog receiver already running")
	}

	u.handler = handler
	addr := fmt.Sprintf("%s:%d", u.ListenAddr, u.Port)
	workers := reuseport.Workers(u.workers, "Syslog UDP")

	for i := 0; i < workers; i++ {
		conn, err := reuseport.Listen("udp", addr)
		if err != nil {
			for _, c := range u.conns {
				_ = c.Close()
			}
			u.conns = nil
			return fmt.Errorf("failed to listen on UDP %s (worker %d): %w", addr, i, err)
		}
		_ = conn.SetReadBuffer(ratelimit.UDPReadBufferBytes)
		u.conns = append(u.conns, conn)
	}

	u.running.Store(true)
	for _, conn := range u.conns {
		c := conn
		u.wg.Add(1)
		safego.Go("syslogUdp:read", func() { u.readLoop(c) })
	}

	log.Printf("[Syslog UDP] Listening on %s (%d worker(s))", addr, workers)
	return nil
}

func (u *UDPSyslogReceiver) Stop() error {
	if !u.running.Load() {
		return nil
	}

	var closeErr error
	u.stopOnce.Do(func() {
		u.running.Store(false)
		close(u.stopCh)
		for _, c := range u.conns {
			if c != nil {
				if err := c.Close(); err != nil {
					closeErr = err
				}
			}
		}
	})

	u.wg.Wait()
	return closeErr
}

func (u *UDPSyslogReceiver) readLoop(conn *net.UDPConn) {
	defer u.wg.Done()

	buf := make([]byte, MaxMessageSize)
	for u.running.Load() {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if u.running.Load() {
				log.Printf("[Syslog UDP] Read error: %v", err)
			}
			continue
		}

		// Per-source rate limit: shed datagrams from a flooding source before
		// parsing (nil limiter = disabled).
		if u.limiter != nil && clientAddr != nil && !u.limiter.Allow(clientAddr.IP.String()) {
			if u.onRateDrop != nil {
				u.onRateDrop()
			}
			continue
		}

		data := buf[:n]
		if len(data) == 0 {
			continue
		}

		msg, err := ParseRFC5424(data)
		if err != nil {
			log.Printf("[Syslog UDP] Parse error from %s: %v", clientAddr, err)
			continue
		}

		if msg != nil && u.handler != nil {
			msg.SourceIP = clientAddr.IP.String()
			u.handler(msg)
		}
	}
}

// --- RFC 5424 Parser ---

func ParseRFC5424(data []byte) (*relay.SyslogMessage, error) {
	if len(data) == 0 {
		return nil, nil
	}

	msg := &relay.SyslogMessage{
		Timestamp: time.Now(),
	}

	parts := bytes.SplitN(data, []byte(" "), 11)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid syslog format: too few parts")
	}

	priority, err := parsePriority(parts[0])
	if err != nil {
		return nil, err
	}
	msg.Priority = priority.facility*8 + priority.severity
	msg.Facility = priority.facility
	msg.Severity = priority.severity

	version := 1
	if len(parts) > 1 && len(parts[1]) > 0 {
		if v := bytesToInt(parts[1]); v > 0 {
			version = v
		}
	}

	if len(parts) > 2 {
		ts, err := parseTimestamp(version, string(parts[2]))
		if err != nil {
			msg.Timestamp = time.Now()
		} else {
			msg.Timestamp = ts
		}
	}

	if len(parts) > 3 {
		msg.Hostname = string(parts[3])
	}
	if len(parts) > 4 {
		msg.AppName = string(parts[4])
	}
	if len(parts) > 5 {
		msg.ProcessID = string(parts[5])
	}
	if len(parts) > 6 {
		msg.MessageID = string(parts[6])
	}
	if len(parts) > 7 {
		structuredData := string(parts[7])
		if structuredData != "-" {
			msg.StructuredData = structuredData
			msg.DeviceID = extractDeviceID(msg.Hostname, structuredData)
		}
	}
	if len(parts) > 8 {
		msg.Message = string(bytes.Join(parts[8:], []byte(" ")))
	}

	return msg, nil
}

type priorityResult struct {
	facility int
	severity int
}

func parsePriority(b []byte) (priorityResult, error) {
	if len(b) < 2 || b[0] != '<' {
		return priorityResult{}, fmt.Errorf("invalid priority format")
	}
	// Find closing >
	end := bytes.IndexByte(b, '>')
	if end < 0 {
		end = len(b)
	}
	val := bytesToInt(b[1:end])
	if val > 191 {
		return priorityResult{}, fmt.Errorf("priority value out of range: %d", val)
	}
	return priorityResult{
		facility: val / 8,
		severity: val % 8,
	}, nil
}

func parseTimestamp(version int, ts string) (time.Time, error) {
	ts = strings.TrimSpace(ts)
	if ts == "-" || ts == "" {
		return time.Now(), nil
	}

	formats := []string{
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"Jan  2 15:04:05",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t, nil
		}
	}

	return time.Now(), fmt.Errorf("failed to parse timestamp: %s", ts)
}

func extractDeviceID(hostname, structuredData string) uint {
	if hostname != "" && hostname != "-" {
		hostname = strings.ToLower(hostname)
		if strings.HasPrefix(hostname, "fg") || strings.HasPrefix(hostname, "fgt") {
			parts := strings.FieldsFunc(hostname, func(r rune) bool {
				return r == '-' || r == '_' || r == '.'
			})
			for _, part := range parts {
				if len(part) >= 4 {
					var numStr string
					for _, c := range part {
						if c >= '0' && c <= '9' {
							numStr += string(c)
						}
					}
					if numStr != "" {
						if id := parseDeviceID(numStr); id > 0 {
							return id
						}
					}
				}
			}
		}
	}

	if structuredData != "" && structuredData != "-" {
		var sdData map[string]map[string]string
		if err := json.Unmarshal([]byte(structuredData), &sdData); err == nil {
			for sdID, params := range sdData {
				if strings.Contains(strings.ToLower(sdID), "fortigate") || strings.Contains(strings.ToLower(sdID), "fgt") {
					if id, ok := params["device-id"]; ok {
						if fgID := parseDeviceID(id); fgID > 0 {
							return fgID
						}
					}
				}
			}
		}

		re := regexp.MustCompile(`\[(\d+)\]`)
		matches := re.FindStringSubmatch(structuredData)
		if len(matches) > 1 {
			if id := parseDeviceID(matches[1]); id > 0 {
				return id
			}
		}
	}

	return 0
}

func parseDeviceID(idStr string) uint {
	idStr = strings.TrimPrefix(idStr, "0")
	if idStr == "" {
		return 0
	}
	var id uint
	for _, c := range idStr {
		if c >= '0' && c <= '9' {
			id = id*10 + uint(c-'0')
		}
	}
	return id
}

func bytesToInt(b []byte) int {
	var val int
	for _, c := range b {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
		}
	}
	return val
}
