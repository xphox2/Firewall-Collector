package tftp

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// Regression v1.2.63: single-socket implementation created a race between the
// main serve() loop and per-transfer goroutines — both called ReadFromUDP on
// the same port-69 socket. DATA packets from the client could be consumed by
// the main loop (which returned ERROR "Not implemented"), killing the transfer.
// The fix: each WRQ allocates a fresh ephemeral UDP socket (server TID per
// RFC 1350); the main loop never sees DATA packets for ongoing transfers.
func TestRegression_TFTP_ConcurrentTransfers_NoRaceCondition(t *testing.T) {
	server := NewServer(&Config{
		Addr:    "127.0.0.1:0",
		Timeout: 3 * time.Second,
	})

	if err := server.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer server.Shutdown()

	serverAddr := server.conn.LocalAddr().(*net.UDPAddr)

	var (
		mu      sync.Mutex
		results = map[string][]byte{}
	)
	server.SetWriteHandler(func(fname string, data []byte, addr net.Addr) error {
		mu.Lock()
		results[fname] = data
		mu.Unlock()
		return nil
	})

	// Run 3 concurrent WRQ uploads with distinct filenames and payloads.
	// Each payload spans multiple 512-byte blocks so the race would manifest.
	const numTransfers = 3
	payloads := make([][]byte, numTransfers)
	for i := range payloads {
		payloads[i] = make([]byte, 1100) // 3 blocks: 512 + 512 + 76
		for j := range payloads[i] {
			payloads[i][j] = byte(i*7 + j%251)
		}
	}

	var wg sync.WaitGroup
	for i := range numTransfers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			fname := make([]byte, 12)
			fname[0] = 'f'
			fname[1] = 'g'
			fname[2] = 't'
			fname[3] = '_'
			fname[4] = byte('0' + idx)
			fname[5] = '_'
			fname[6] = 'c'
			fname[7] = 'f'
			fname[8] = 'g'
			name := string(fname[:9])
			if err := runWRQ(t, serverAddr, name, payloads[idx]); err != nil {
				t.Errorf("transfer %d (%s) failed: %v", idx, name, err)
			}
		}(i)
	}
	wg.Wait()

	// Give write handlers a moment to complete
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(results) != numTransfers {
		t.Errorf("got %d completed transfers, want %d (race may have dropped transfers)", len(results), numTransfers)
	}
	for i := range numTransfers {
		fname := "fgt_" + string(rune('0'+i)) + "_cfg"
		if got, ok := results[fname]; ok {
			if !bytes.Equal(got, payloads[i]) {
				t.Errorf("transfer %d payload corrupted: got %d bytes want %d", i, len(got), len(payloads[i]))
			}
		}
	}
}

// runWRQ performs a complete TFTP write transfer to serverAddr.
func runWRQ(t *testing.T, serverAddr *net.UDPAddr, filename string, data []byte) error {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.WriteToUDP(buildWRQ(filename), serverAddr); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	ackBuf := make([]byte, 16)
	n, serverTID, err := conn.ReadFromUDP(ackBuf)
	if err != nil {
		return err
	}
	if n < 4 || ackBuf[1] != byte(opACK) {
		return fmt.Errorf("expected ACK 0, got opcode %d", uint16(ackBuf[0])<<8|uint16(ackBuf[1]))
	}

	offset := 0
	block := uint16(1)
	for {
		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		pkt := make([]byte, 4+len(chunk))
		pkt[1] = byte(opDATA)
		pkt[2] = byte(block >> 8)
		pkt[3] = byte(block & 0xff)
		copy(pkt[4:], chunk)

		if _, err := conn.WriteToUDP(pkt, serverTID); err != nil {
			return err
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := conn.ReadFromUDP(ackBuf)
		if err != nil {
			return err
		}
		if n < 4 || ackBuf[1] != byte(opACK) {
			return fmt.Errorf("expected ACK %d", block)
		}

		offset = end
		if len(chunk) < blockSize {
			break
		}
		block++
	}
	return nil
}
