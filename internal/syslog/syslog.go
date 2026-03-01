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

	"firewall-collector/internal/relay"
)

const MaxMessageSize = 64 * 1024

// SyslogReceiver handles TCP syslog connections.
type SyslogReceiver struct {
	ListenAddr string
	Port       int
	handler    func(*relay.SyslogMessage)
	listener   net.Listener
	running    atomic.Bool
	stopCh     chan struct{}
}

func NewSyslogReceiver(listenAddr string, port int) *SyslogReceiver {
	return &SyslogReceiver{
		ListenAddr: listenAddr,
		Port:       port,
		stopCh:     make(chan struct{}),
	}
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
	go s.acceptLoop()

	log.Printf("[Syslog TCP] Listening on %s", addr)
	return nil
}

func (s *SyslogReceiver) Stop() error {
	if !s.running.Load() {
		return nil
	}

	s.running.Store(false)
	close(s.stopCh)

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SyslogReceiver) acceptLoop() {
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running.Load() {
				log.Printf("[Syslog TCP] Accept error: %v", err)
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SyslogReceiver) handleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, MaxMessageSize)
	var messageBuf bytes.Buffer

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}

		messageBuf.Write(buf[:n])

		for {
			data := messageBuf.Bytes()
			idx := bytes.IndexByte(data, '\n')
			if idx == -1 {
				if messageBuf.Len() >= MaxMessageSize {
					messageBuf.Reset()
				}
				break
			}

			line := data[:idx]
			messageBuf.Reset()
			messageBuf.Write(data[idx+1:])

			if len(line) == 0 {
				continue
			}

			msg, err := ParseRFC5424(line)
			if err != nil {
				log.Printf("[Syslog TCP] Parse error: %v", err)
				continue
			}

			if msg != nil && s.handler != nil {
				msg.SourceIP = conn.RemoteAddr().String()
				if i := strings.LastIndex(msg.SourceIP, ":"); i != -1 {
					msg.SourceIP = msg.SourceIP[:i]
				}
				s.handler(msg)
			}
		}
	}
}

// UDPSyslogReceiver handles UDP syslog packets.
type UDPSyslogReceiver struct {
	ListenAddr string
	Port       int
	handler    func(*relay.SyslogMessage)
	conn       *net.UDPConn
	running    atomic.Bool
	stopCh     chan struct{}
	wg         sync.WaitGroup
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
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	u.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", addr, err)
	}

	u.running.Store(true)
	u.wg.Add(1)
	go u.readLoop()

	log.Printf("[Syslog UDP] Listening on %s", addr)
	return nil
}

func (u *UDPSyslogReceiver) Stop() error {
	if !u.running.Load() {
		return nil
	}

	u.running.Store(false)
	close(u.stopCh)

	if u.conn != nil {
		u.conn.Close()
	}

	u.wg.Wait()
	return nil
}

func (u *UDPSyslogReceiver) readLoop() {
	defer u.wg.Done()

	buf := make([]byte, MaxMessageSize)
	for u.running.Load() {
		u.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if u.running.Load() {
				log.Printf("[Syslog UDP] Read error: %v", err)
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
