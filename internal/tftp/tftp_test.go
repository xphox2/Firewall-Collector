package tftp

import (
	"net"
	"testing"
	"time"
)

func TestExtractFilename(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected string
	}{
		{"simple filename", []byte{0, 1, 't', 'e', 's', 't', '.', 't', 'x', 't', 0}, "test.txt"},
		{"with mode", []byte{0, 1, 'c', 'o', 'n', 'f', 'i', 'g', 0, 'o', 'c', 't', 'e', 't', 0}, "config"},
		{"empty", []byte{0, 1, 0}, ""},
		{"short buffer", []byte{0, 1}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractFilename(tt.buf)
			if result != tt.expected {
				t.Errorf("extractFilename() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSendAndReceiveACK(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	server := &Server{
		conn:   conn,
		stopCh: make(chan struct{}),
	}

	clientAddr := conn.LocalAddr().(*net.UDPAddr)

	server.sendACK(clientAddr, 1)

	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP failed: %v", err)
	}

	if n != 4 {
		t.Errorf("expected 4 bytes, got %d", n)
	}

	if buf[0] != 0 || buf[1] != 4 {
		t.Errorf("expected opcode 4 (ACK), got %d", buf[1])
	}

	if buf[2] != 0 || buf[3] != 1 {
		t.Errorf("expected block 1, got %d", (int(buf[2])<<8)|int(buf[3]))
	}
}

func TestServerShutdown(t *testing.T) {
	server := NewServer(&Config{
		Addr:    "127.0.0.1:0",
		Timeout: 1 * time.Second,
	})

	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe failed: %v", err)
	}

	if err := server.Shutdown(); err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestWriteHandlerNotSet(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 8192)
	buf[0] = 0
	buf[1] = 2 // WRQ
	copy(buf[2:], []byte("test\x00octet\x00"))

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: conn.LocalAddr().(*net.UDPAddr).Port}

	_, err = conn.WriteToUDP(buf[:len("test\x00octet\x00")+10], clientAddr)
	if err != nil {
		t.Fatalf("WriteToUDP failed: %v", err)
	}
}
