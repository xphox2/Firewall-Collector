package tftp

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	opRRQ   uint16 = 1
	opWRQ   uint16 = 2
	opDATA  uint16 = 3
	opACK   uint16 = 4
	opERROR uint16 = 5
	opOACK  uint16 = 6

	blockSize       = 512
	maxPacketSize   = 1024
	defaultTimeout  = 30 * time.Second
	transferTimeout = 5 * time.Minute
	maxRetries      = 5

	// maxTransferSize is the AUDIT-050 hard cap on a single WRQ payload.
	// Real FortiGate configs are well under 500 KB; 2 MB leaves comfortable
	// headroom while bounding the per-transfer memory footprint that an
	// unauthenticated UDP peer can force the collector to allocate.
	maxTransferSize = 2 * 1024 * 1024
)

type Config struct {
	Addr    string
	Timeout time.Duration
}

type WriteHandler func(filename string, data []byte, client net.Addr) error
type ReadHandler func(filename string, client net.Addr) ([]byte, error)

type Server struct {
	cfg          *Config
	conn         *net.UDPConn
	stopCh       chan struct{}
	wg           sync.WaitGroup
	readHandler  ReadHandler
	writeHandler WriteHandler
	mu           sync.Mutex
	running      bool
	// handlerMu guards readHandler, writeHandler, and allowedSourceIPs.
	// SetHandler / SetWriteHandler / SetAllowedSourceIPs take the write
	// lock; handleWRQ / handleRRQ take the read lock around the field
	// access. This is the AUDIT-081 fix — the previous code raced because
	// the test (and any production caller) called SetWriteHandler from one
	// goroutine while handleWRQ was already reading it from the listener
	// goroutine. AUDIT-050 extends the same lock to cover allowedSourceIPs.
	handlerMu sync.RWMutex

	// allowedSourceIPs is the AUDIT-050 per-device source-IP allowlist.
	// nil  = no policy (allow every source IP — backward compatible).
	// non-nil but empty = explicitly deny everyone.
	// non-nil with entries = only the listed IPs may submit WRQs.
	// Keys are normalized via net.ParseIP(...).String().
	allowedSourceIPs map[string]bool

	// minWRQInterval is the AUDIT-050 per-source-IP rate limit. Zero
	// disables the limiter (default — preserves the existing behavior so
	// no caller is broken by upgrading). Production callers should set
	// this to something like 60s.
	minWRQInterval time.Duration
	lastWRQMu      sync.Mutex
	lastWRQTime    map[string]time.Time
}

func NewServer(cfg *Config) *Server {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	return &Server{
		cfg:         cfg,
		stopCh:      make(chan struct{}),
		lastWRQTime: make(map[string]time.Time),
	}
}

func (s *Server) SetHandler(handler ReadHandler) {
	s.handlerMu.Lock()
	s.readHandler = handler
	s.handlerMu.Unlock()
}

func (s *Server) SetWriteHandler(handler WriteHandler) {
	s.handlerMu.Lock()
	s.writeHandler = handler
	s.handlerMu.Unlock()
}

// SetAllowedSourceIPs configures the AUDIT-050 per-source-IP allowlist.
//
//	nil  -> clear the policy; accept WRQs from any source IP.
//	[]   -> non-nil empty list; deny every source IP.
//	[…]  -> only accept WRQs whose source IP appears in the list.
//
// Entries that fail to parse as IPs are silently dropped. Entries are
// normalized through net.ParseIP(...).String() so "127.0.0.001" and
// "::ffff:127.0.0.1" both match a peer reporting "127.0.0.1".
func (s *Server) SetAllowedSourceIPs(ips []string) {
	var set map[string]bool
	if ips != nil {
		set = make(map[string]bool, len(ips))
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			set[parsed.String()] = true
		}
	}
	s.handlerMu.Lock()
	s.allowedSourceIPs = set
	s.handlerMu.Unlock()
}

// SetMinWRQInterval configures the AUDIT-050 per-source-IP rate limit:
// a WRQ from a given source IP is refused if a WRQ from the same IP was
// accepted less than d ago. Zero (the default) disables the limiter so
// existing callers see no behavior change.
func (s *Server) SetMinWRQInterval(d time.Duration) {
	s.lastWRQMu.Lock()
	s.minWRQInterval = d
	s.lastWRQMu.Unlock()
}

// isSourceAllowed checks the AUDIT-050 allowlist. With no policy set
// (allowedSourceIPs == nil), every IP is allowed — preserves backward
// compatibility for callers that never call SetAllowedSourceIPs.
func (s *Server) isSourceAllowed(ip net.IP) bool {
	s.handlerMu.RLock()
	defer s.handlerMu.RUnlock()
	if s.allowedSourceIPs == nil {
		return true
	}
	return s.allowedSourceIPs[ip.String()]
}

// checkAndUpdateRateLimit enforces the AUDIT-050 per-source-IP rate
// limit. Returns true if the WRQ should be allowed (and atomically
// records the new last-seen time); returns false if the WRQ should be
// rejected because the previous one was too recent. With minWRQInterval
// == 0 the limiter is a no-op and always allows.
func (s *Server) checkAndUpdateRateLimit(ip net.IP) bool {
	s.lastWRQMu.Lock()
	defer s.lastWRQMu.Unlock()
	if s.minWRQInterval <= 0 {
		return true
	}
	key := ip.String()
	now := time.Now()
	if last, ok := s.lastWRQTime[key]; ok && now.Sub(last) < s.minWRQInterval {
		return false
	}
	s.lastWRQTime[key] = now
	return true
}

func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	s.conn = conn

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.serve()

	return nil
}

// serve reads only RRQ/WRQ packets on the well-known port. Each accepted
// transfer is handed off to a goroutine that allocates its own ephemeral
// UDP socket (the server TID), per RFC 1350.
func (s *Server) serve() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TFTP] PANIC in serve loop: %v", r)
		}
		s.wg.Done()
	}()

	buf := make([]byte, maxPacketSize)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n < 4 {
			continue
		}

		opcode := uint16(buf[0])<<8 | uint16(buf[1])
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		switch opcode {
		case opRRQ:
			log.Printf("[TFTP] RRQ from %s", clientAddr.String())
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleRRQ(pkt, clientAddr)
			}()
		case opWRQ:
			log.Printf("[TFTP] WRQ from %s", clientAddr.String())
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleWRQ(pkt, clientAddr)
			}()
		default:
			log.Printf("[TFTP] Unexpected opcode %d on listen socket from %s — ignoring", opcode, clientAddr.String())
		}
	}
}

// newSessionConn allocates a fresh ephemeral UDP socket bound to the same
// local IP family as the listener. This becomes the server-side TID for the
// transfer.
func (s *Server) newSessionConn() (*net.UDPConn, error) {
	listenIP := s.conn.LocalAddr().(*net.UDPAddr).IP
	return net.ListenUDP("udp", &net.UDPAddr{IP: listenIP, Port: 0})
}

func (s *Server) handleWRQ(reqPkt []byte, clientAddr *net.UDPAddr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TFTP] PANIC in handleWRQ: %v", r)
		}
	}()

	// AUDIT-050: source-IP allowlist check. Run before any state mutation
	// so a blocked peer cannot consume socket/goroutine resources or
	// poison the rate-limit map.
	if !s.isSourceAllowed(clientAddr.IP) {
		log.Printf("[TFTP] WRQ from %s: source IP not in allowlist — refusing", clientAddr.String())
		s.sendErrorOn(s.conn, clientAddr, 2, "Access denied")
		return
	}

	// AUDIT-050: per-source-IP rate limit. Only update the timestamp for
	// peers that pass the allowlist, so blocked peers cannot affect the
	// pacing of allowed peers.
	if !s.checkAndUpdateRateLimit(clientAddr.IP) {
		log.Printf("[TFTP] WRQ from %s: rate-limited (min interval %v) — refusing",
			clientAddr.String(), s.minWRQInterval)
		s.sendErrorOn(s.conn, clientAddr, 0, "Rate limit exceeded")
		return
	}

	s.handlerMu.RLock()
	h := s.writeHandler
	s.handlerMu.RUnlock()
	if h == nil {
		s.sendErrorOn(s.conn, clientAddr, 4, "Write not supported")
		return
	}

	filename, _, _ := parseRequest(reqPkt)
	if filename == "" {
		s.sendErrorOn(s.conn, clientAddr, 1, "Invalid filename")
		return
	}

	sessionConn, err := s.newSessionConn()
	if err != nil {
		log.Printf("[TFTP] WRQ %q: failed to allocate session socket: %v", filename, err)
		s.sendErrorOn(s.conn, clientAddr, 0, "Server resource error")
		return
	}
	defer sessionConn.Close()

	log.Printf("[TFTP] WRQ accepted file=%q client=%s sessionPort=%d",
		filename, clientAddr.String(), sessionConn.LocalAddr().(*net.UDPAddr).Port)

	// ACK 0 from the new session socket — this becomes our TID.
	if err := sendACK(sessionConn, clientAddr, 0); err != nil {
		log.Printf("[TFTP] WRQ %q: failed to send ACK 0: %v", filename, err)
		return
	}

	data, err := s.receiveTransfer(sessionConn, clientAddr)
	if err != nil {
		log.Printf("[TFTP] WRQ %q: receive failed: %v", filename, err)
		s.sendErrorOn(sessionConn, clientAddr, 0, err.Error())
		return
	}

	log.Printf("[TFTP] WRQ %q complete: %d bytes from %s", filename, len(data), clientAddr.String())

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[TFTP] PANIC in writeHandler for %q: %v", filename, r)
			}
		}()
		// Use the handler captured at request-arrival time. Calling
		// s.writeHandler here would re-introduce the race against
		// a concurrent SetWriteHandler (AUDIT-081).
		if err := h(filename, data, clientAddr); err != nil {
			log.Printf("[TFTP] writeHandler %q returned error: %v", filename, err)
		}
	}()
}

func (s *Server) handleRRQ(reqPkt []byte, clientAddr *net.UDPAddr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TFTP] PANIC in handleRRQ: %v", r)
		}
	}()

	s.handlerMu.RLock()
	h := s.readHandler
	s.handlerMu.RUnlock()
	if h == nil {
		s.sendErrorOn(s.conn, clientAddr, 0, "No handler")
		return
	}

	filename, _, _ := parseRequest(reqPkt)
	if filename == "" {
		s.sendErrorOn(s.conn, clientAddr, 1, "File not found")
		return
	}

	data, err := h(filename, clientAddr)
	if err != nil {
		s.sendErrorOn(s.conn, clientAddr, 0, err.Error())
		return
	}

	sessionConn, err := s.newSessionConn()
	if err != nil {
		log.Printf("[TFTP] RRQ %q: failed to allocate session socket: %v", filename, err)
		s.sendErrorOn(s.conn, clientAddr, 0, "Server resource error")
		return
	}
	defer sessionConn.Close()

	if err := s.sendTransfer(sessionConn, clientAddr, data); err != nil {
		log.Printf("[TFTP] RRQ %q: send failed: %v", filename, err)
	}
}

// receiveTransfer reads DATA packets from the client on sessionConn, ACKing
// each one. Terminates when a DATA packet smaller than 516 bytes arrives
// (last block, per RFC 1350) or when the deadline expires.
func (s *Server) receiveTransfer(sessionConn *net.UDPConn, clientAddr *net.UDPAddr) ([]byte, error) {
	buf := make([]byte, maxPacketSize)
	var data []byte
	expectedBlock := uint16(1)
	deadline := time.Now().Add(transferTimeout)

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("transfer timed out after %v", transferTimeout)
		}

		sessionConn.SetReadDeadline(time.Now().Add(s.cfg.Timeout))
		n, addr, err := sessionConn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("read DATA: %w", err)
		}
		if n < 4 {
			continue
		}

		// Lock the session to a single client TID once data is flowing.
		if addr.Port != clientAddr.Port || !addr.IP.Equal(clientAddr.IP) {
			// Stray packet from someone else — reply with ERROR but keep listening.
			s.sendErrorOn(sessionConn, addr, 5, "Unknown TID")
			continue
		}

		opcode := uint16(buf[0])<<8 | uint16(buf[1])
		if opcode == opERROR {
			code := uint16(buf[2])<<8 | uint16(buf[3])
			msg := ""
			if n > 4 {
				if idx := strings.IndexByte(string(buf[4:n]), 0); idx >= 0 {
					msg = string(buf[4 : 4+idx])
				} else {
					msg = string(buf[4:n])
				}
			}
			return nil, fmt.Errorf("client sent ERROR %d: %s", code, msg)
		}
		if opcode != opDATA {
			continue
		}

		block := uint16(buf[2])<<8 | uint16(buf[3])
		payload := buf[4:n]

		if block == expectedBlock {
			// AUDIT-050: reject before the append so we never allocate
			// beyond maxTransferSize. The caller (handleWRQ) translates
			// this error into a TFTP ERROR 0 sent back to the client.
			if len(data)+len(payload) > maxTransferSize {
				return nil, fmt.Errorf("transfer exceeds %d-byte cap (have %d, +%d would overflow)",
					maxTransferSize, len(data), len(payload))
			}
			data = append(data, payload...)
			if err := sendACK(sessionConn, clientAddr, block); err != nil {
				return nil, fmt.Errorf("send ACK %d: %w", block, err)
			}
			if len(payload) < blockSize {
				return data, nil
			}
			expectedBlock++
		} else if block == expectedBlock-1 {
			// Duplicate of the previous block — re-ACK without appending.
			_ = sendACK(sessionConn, clientAddr, block)
		}
		// Out-of-window blocks are dropped silently; client will retransmit.
	}
}

// sendTransfer streams data to the client in 512-byte DATA packets, waiting
// for the matching ACK between each one.
func (s *Server) sendTransfer(sessionConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) error {
	block := uint16(1)
	offset := 0
	deadline := time.Now().Add(transferTimeout)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("transfer timed out after %v", transferTimeout)
		}

		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]

		pkt := make([]byte, 4+len(chunk))
		pkt[0] = 0
		pkt[1] = byte(opDATA)
		pkt[2] = byte(block >> 8)
		pkt[3] = byte(block & 0xff)
		copy(pkt[4:], chunk)

		// Send and wait for matching ACK; retry up to maxRetries.
		acked := false
		for attempt := 0; attempt < maxRetries; attempt++ {
			if _, err := sessionConn.WriteToUDP(pkt, clientAddr); err != nil {
				return fmt.Errorf("write DATA %d: %w", block, err)
			}

			sessionConn.SetReadDeadline(time.Now().Add(s.cfg.Timeout))
			ackBuf := make([]byte, maxPacketSize)
			n, addr, err := sessionConn.ReadFromUDP(ackBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return fmt.Errorf("read ACK %d: %w", block, err)
			}
			if addr.Port != clientAddr.Port || !addr.IP.Equal(clientAddr.IP) {
				s.sendErrorOn(sessionConn, addr, 5, "Unknown TID")
				continue
			}
			if n < 4 {
				continue
			}
			opcode := uint16(ackBuf[0])<<8 | uint16(ackBuf[1])
			ackBlock := uint16(ackBuf[2])<<8 | uint16(ackBuf[3])
			if opcode == opACK && ackBlock == block {
				acked = true
				break
			}
		}
		if !acked {
			return fmt.Errorf("no ACK for block %d after %d retries", block, maxRetries)
		}

		offset = end
		if len(chunk) < blockSize {
			return nil
		}
		block++
	}
}

// parseRequest returns (filename, mode, options) from an RRQ or WRQ packet.
// Options are returned as a flat key,value,key,value list; we don't currently
// negotiate them.
func parseRequest(buf []byte) (string, string, []string) {
	if len(buf) < 4 {
		return "", "", nil
	}
	parts := splitNullTerminated(buf[2:])
	if len(parts) < 2 {
		return "", "", nil
	}
	return parts[0], parts[1], parts[2:]
}

func splitNullTerminated(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

// extractFilename is kept for backwards compatibility with tests.
func extractFilename(buf []byte) string {
	name, _, _ := parseRequest(buf)
	return strings.TrimSpace(name)
}

func sendACK(conn *net.UDPConn, addr *net.UDPAddr, block uint16) error {
	pkt := []byte{0, byte(opACK), byte(block >> 8), byte(block & 0xff)}
	_, err := conn.WriteToUDP(pkt, addr)
	return err
}

func (s *Server) sendErrorOn(conn *net.UDPConn, addr *net.UDPAddr, code uint16, msg string) {
	pkt := make([]byte, 5+len(msg))
	pkt[0] = 0
	pkt[1] = byte(opERROR)
	pkt[2] = byte(code >> 8)
	pkt[3] = byte(code & 0xff)
	copy(pkt[4:], msg)
	conn.WriteToUDP(pkt, addr)
}

func (s *Server) Shutdown() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	close(s.stopCh)
	s.wg.Wait()

	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}
