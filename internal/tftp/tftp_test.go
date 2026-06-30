package tftp

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTFTPServerRRQ(t *testing.T) {
	server := NewServer(&Config{
		Addr:    "127.0.0.1:0",
		Timeout: 2 * time.Second,
	})

	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe failed: %v", err)
	}
	defer server.Shutdown()

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)
	t.Logf("TFTP server listening on %s", serverAddr.String())

	expectedData := []byte("test config content\nwith multiple lines\nand $pecial ch@rs")
	requestedFilename := ""

	server.SetHandler(func(fname string, addr net.Addr) ([]byte, error) {
		requestedFilename = fname
		t.Logf("Handler received RRQ for file: %s from %s", fname, addr.String())
		return expectedData, nil
	})

	// Use ListenUDP (unconnected) so we can receive from the server's
	// ephemeral TID port, which differs from the listen port.
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.WriteToUDP(buildRRQ("testfile"), serverAddr); err != nil {
		t.Fatalf("write RRQ: %v", err)
	}

	// Server allocates a fresh ephemeral port for the response. Read DATA blocks
	// from whatever port the server replies on, ACKing each, then verify payload.
	var dataReceived []byte
	buf := make([]byte, 1024)
	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))

	for {
		n, serverTID, err := clientConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read DATA: %v", err)
		}
		if n < 4 || buf[0] != 0 || buf[1] != byte(opDATA) {
			t.Fatalf("expected DATA, got opcode %d", uint16(buf[0])<<8|uint16(buf[1]))
		}
		block := uint16(buf[2])<<8 | uint16(buf[3])
		dataReceived = append(dataReceived, buf[4:n]...)

		ack := []byte{0, byte(opACK), buf[2], buf[3]}
		clientConn.WriteToUDP(ack, serverTID)
		t.Logf("Client: ACKed block %d (%d bytes)", block, n-4)

		if n-4 < blockSize {
			break
		}
	}

	if requestedFilename != "testfile" {
		t.Errorf("requestedFilename = %q, want %q", requestedFilename, "testfile")
	}
	if !bytes.Equal(dataReceived, expectedData) {
		t.Errorf("dataReceived = %q, want %q", dataReceived, expectedData)
	}
}

// TestTFTPServerWRQ exercises the multi-packet write path that was broken
// by the previous single-socket implementation: DATA packets must reach the
// per-transfer goroutine, not the main listen loop.
func TestTFTPServerWRQ(t *testing.T) {
	server := NewServer(&Config{
		Addr:    "127.0.0.1:0",
		Timeout: 2 * time.Second,
	})

	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe failed: %v", err)
	}
	defer server.Shutdown()

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)
	t.Logf("TFTP server listening on %s", serverAddr.String())

	// Build a payload spanning multiple 512-byte blocks plus a partial final
	// block (terminator). 1500 bytes -> blocks of 512, 512, 476.
	payload := make([]byte, 1500)
	for i := range payload {
		payload[i] = byte('a' + (i % 26))
	}

	var (
		mu         sync.Mutex
		gotName    string
		gotData    []byte
		handlerHit = make(chan struct{})
	)
	server.SetWriteHandler(func(fname string, data []byte, addr net.Addr) error {
		mu.Lock()
		gotName = fname
		gotData = data
		mu.Unlock()
		close(handlerHit)
		return nil
	})

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.WriteToUDP(buildWRQ("fgt_42_config"), serverAddr); err != nil {
		t.Fatalf("write WRQ: %v", err)
	}

	// Read ACK 0 — server should reply from a NEW ephemeral TID, not 69.
	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	ackBuf := make([]byte, 16)
	n, serverTID, err := clientConn.ReadFromUDP(ackBuf)
	if err != nil {
		t.Fatalf("read ACK 0: %v", err)
	}
	if n < 4 || ackBuf[0] != 0 || ackBuf[1] != byte(opACK) {
		t.Fatalf("expected ACK 0, got opcode %d", uint16(ackBuf[0])<<8|uint16(ackBuf[1]))
	}
	if serverTID.Port == serverAddr.Port {
		t.Fatalf("server TID port %d must differ from listen port %d (ephemeral TID required by RFC 1350)",
			serverTID.Port, serverAddr.Port)
	}
	t.Logf("Server TID: %s (listen was %s)", serverTID.String(), serverAddr.String())

	// Send DATA blocks to the server's TID; expect ACKs back.
	block := uint16(1)
	offset := 0
	for {
		end := offset + blockSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[offset:end]
		pkt := make([]byte, 4+len(chunk))
		pkt[1] = byte(opDATA)
		pkt[2] = byte(block >> 8)
		pkt[3] = byte(block & 0xff)
		copy(pkt[4:], chunk)
		if _, err := clientConn.WriteToUDP(pkt, serverTID); err != nil {
			t.Fatalf("write DATA %d: %v", block, err)
		}

		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := clientConn.ReadFromUDP(ackBuf)
		if err != nil {
			t.Fatalf("read ACK %d: %v", block, err)
		}
		if n < 4 || ackBuf[1] != byte(opACK) {
			t.Fatalf("expected ACK %d, got opcode %d", block, uint16(ackBuf[0])<<8|uint16(ackBuf[1]))
		}
		ackBlock := uint16(ackBuf[2])<<8 | uint16(ackBuf[3])
		if ackBlock != block {
			t.Fatalf("expected ACK block %d, got %d", block, ackBlock)
		}

		offset = end
		if len(chunk) < blockSize {
			break
		}
		block++
	}

	select {
	case <-handlerHit:
	case <-time.After(2 * time.Second):
		t.Fatal("write handler not invoked")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotName != "fgt_42_config" {
		t.Errorf("filename = %q, want %q", gotName, "fgt_42_config")
	}
	if !bytes.Equal(gotData, payload) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(gotData), len(payload))
	}
}

func TestTFTPExtractFilename(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected string
	}{
		{"simple filename with mode", buildRRQ("test.txt"), "test.txt"},
		{"fgt config format", buildWRQ("fgt_123_config"), "fgt_123_config"},
		{"too short", []byte{0, 1}, ""},
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

func TestTFTPServerShutdown(t *testing.T) {
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

func buildRRQ(filename string) []byte {
	return buildRequest(opRRQ, filename)
}

func buildWRQ(filename string) []byte {
	return buildRequest(opWRQ, filename)
}

func buildRequest(opcode uint16, filename string) []byte {
	mode := "octet"
	pkt := make([]byte, 0, 2+len(filename)+1+len(mode)+1)
	pkt = append(pkt, byte(opcode>>8), byte(opcode&0xff))
	pkt = append(pkt, []byte(filename)...)
	pkt = append(pkt, 0)
	pkt = append(pkt, []byte(mode)...)
	pkt = append(pkt, 0)
	return pkt
}
