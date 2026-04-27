package tftp

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Addr    string
	Timeout time.Duration
}

type WriteHandler func(filename string, data []byte, client net.Addr) error

type Server struct {
	cfg          *Config
	conn         *net.UDPConn
	stopCh       chan struct{}
	wg           sync.WaitGroup
	handler      func(filename string, client net.Addr) ([]byte, error)
	writeHandler WriteHandler
	mu           sync.Mutex
	running      bool
}

func NewServer(cfg *Config) *Server {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Server{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

func (s *Server) SetHandler(handler func(filename string, client net.Addr) ([]byte, error)) {
	s.handler = handler
}

func (s *Server) SetWriteHandler(handler WriteHandler) {
	s.writeHandler = handler
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

func (s *Server) serve() {
	defer s.wg.Done()

	buf := make([]byte, 8192)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(s.cfg.Timeout))
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

		msgType := uint16(buf[0])<<8 | uint16(buf[1])

		switch msgType {
		case 1: // RRQ (Read Request) - client wants to download
			go s.handleRRQ(buf[:n], clientAddr)
		case 2: // WRQ (Write Request) - client wants to upload
			go s.handleWRQ(buf[:n], clientAddr)
		default:
			s.sendError(clientAddr, 4, "Not implemented")
		}
	}
}

func (s *Server) handleRRQ(buf []byte, clientAddr *net.UDPAddr) {
	if s.handler == nil {
		s.sendError(clientAddr, 0, "No handler")
		return
	}

	filename := extractFilename(buf)
	if filename == "" {
		s.sendError(clientAddr, 1, "File not found")
		return
	}

	data, err := s.handler(filename, clientAddr)
	if err != nil {
		s.sendError(clientAddr, 0, err.Error())
		return
	}

	s.sendData(clientAddr, data)
}

func (s *Server) handleWRQ(buf []byte, clientAddr *net.UDPAddr) {
	if s.writeHandler == nil {
		s.sendError(clientAddr, 4, "Write not supported")
		return
	}

	filename := extractFilename(buf)
	if filename == "" {
		s.sendError(clientAddr, 1, "Invalid filename")
		return
	}

	s.sendACK(clientAddr, 0)

	data, err := s.receiveData(clientAddr)
	if err != nil {
		s.sendError(clientAddr, 0, err.Error())
		return
	}

	s.writeHandler(filename, data, clientAddr)
}

func extractFilename(buf []byte) string {
	if len(buf) < 2 {
		return ""
	}
	filename := string(buf[2:])
	if idx := strings.Index(filename, "\x00"); idx != -1 {
		filename = filename[:idx]
	}
	return strings.TrimSpace(filename)
}

func (s *Server) sendACK(clientAddr *net.UDPAddr, blockNum uint16) {
	pkt := []byte{0, 4, byte(blockNum >> 8), byte(blockNum & 0xff)}
	s.conn.WriteToUDP(pkt, clientAddr)
}

func (s *Server) receiveData(clientAddr *net.UDPAddr) ([]byte, error) {
	buf := make([]byte, 8192)
	var data []byte

	for {
		s.conn.SetReadDeadline(time.Now().Add(s.cfg.Timeout))
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}

		if n < 4 {
			continue
		}

		msgType := uint16(buf[0])<<8 | uint16(buf[1])
		if msgType != 3 { // DATA
			continue
		}

		blockNum := uint16(buf[2])<<8 | uint16(buf[3])
		data = append(data, buf[4:n]...)

		s.sendACK(clientAddr, blockNum)

		if n < 516 { // Last packet if less than 512 bytes + header
			break
		}
	}

	return data, nil
}

func (s *Server) sendData(clientAddr *net.UDPAddr, data []byte) {
	blkNum := uint16(1)

	for len(data) > 0 {
		pktLen := 512
		if len(data) < 512 {
			pktLen = len(data)
		}

		pkt := make([]byte, 4+pktLen)
		pkt[0] = 0
		pkt[1] = 3 // DATA
		pkt[2] = byte(blkNum >> 8)
		pkt[3] = byte(blkNum & 0xff)
		copy(pkt[4:], data[:pktLen])

		_, err := s.conn.WriteToUDP(pkt, clientAddr)
		if err != nil {
			return
		}

		data = data[pktLen:]
		blkNum++
		if blkNum == 0 {
			blkNum = 1
		}

		// Wait for ACK
		ackBuf := make([]byte, 4)
		s.conn.SetReadDeadline(time.Now().Add(s.cfg.Timeout))
		for {
			_, _, err := s.conn.ReadFromUDP(ackBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			break
		}
	}
}

func (s *Server) sendError(clientAddr *net.UDPAddr, code uint16, msg string) {
	pkt := make([]byte, 5+len(msg))
	pkt[0] = 0
	pkt[1] = 5 // ERROR
	pkt[2] = byte(code >> 8)
	pkt[3] = byte(code & 0xff)
	copy(pkt[4:], msg)
	s.conn.WriteToUDP(pkt, clientAddr)
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
