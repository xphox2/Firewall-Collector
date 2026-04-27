package tftp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTFTPServerRRQ(t *testing.T) {
	server := NewServer(&Config{
		Addr:    "127.0.0.1:0",
		Timeout: 5 * time.Second,
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

	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer clientConn.Close()

	rrq := buildRRQ("testfile")
	if _, err := clientConn.Write(rrq); err != nil {
		t.Fatalf("WriteToUDP failed: %v", err)
	}
	t.Logf("Client: Sent RRQ for file: testfile")

	buf := make([]byte, 1024)
	var dataReceived []byte
	timeout := time.After(3 * time.Second)

	for {
		select {
		case <-timeout:
			if len(dataReceived) > 0 {
				t.Logf("Client: Received %d bytes total", len(dataReceived))
			}
			goto verify
		default:
		}

		clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := clientConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				goto verify
			}
			break
		}

		if n >= 4 && buf[0] == 0 && buf[1] == 3 {
			dataReceived = append(dataReceived, buf[4:n]...)
			t.Logf("Client: Received DATA block %d (%d bytes)", int(buf[2])<<8|int(buf[3]), n-4)

			ack := []byte{0, 4, buf[2], buf[3]}
			clientConn.Write(ack)

			if n-4 < 512 {
				break
			}
		}
	}

verify:
	if requestedFilename != "testfile" {
		t.Errorf("requestedFilename = %q, want %q", requestedFilename, "testfile")
	}

	if !bytes.Equal(dataReceived, expectedData) {
		t.Errorf("dataReceived = %q, want %q", dataReceived, expectedData)
	}

	t.Logf("RRQ Test PASSED - Server correctly served file")
}

func TestTFTPExtractFilename(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected string
	}{
		{"simple filename", []byte{0, 1, 't', 'e', 's', 't', '.', 't', 'x', 't', 0}, "test.txt"},
		{"fgt config format", []byte{0, 2, 'f', 'g', 't', '_', '1', '2', '3', '_', 'c', 'o', 'n', 'f', 'i', 'g', 0}, "fgt_123_config"},
		{"empty string", []byte{0, 1, 0}, ""},
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

	t.Logf("Shutdown Test PASSED")
}

func buildRRQ(filename string) []byte {
	packet := make([]byte, 2+len(filename)+1+6+1)
	packet[0] = 0
	packet[1] = 1
	copy(packet[2:], filename)
	packet[2+len(filename)] = 0
	copy(packet[2+len(filename)+1:], []byte("octet"))
	packet[2+len(filename)+1+6] = 0
	return packet
}
