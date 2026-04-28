package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: tftp-test <collector-ip> <port> <device-id> <config-file>")
		fmt.Println("Example: tftp-test 192.168.5.25 6969 1 config.txt")
		os.Exit(1)
	}

	collectorIP := os.Args[1]
	port := os.Args[2]
	deviceID := os.Args[3]
	configFile := os.Args[4]

	filename := fmt.Sprintf("fgt_%s_config", deviceID)

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	fmt.Printf("=== TFTP Client Test ===\n")
	fmt.Printf("Collector: %s:%s\n", collectorIP, port)
	fmt.Printf("Filename: %s\n", filename)
	fmt.Printf("Config size: %d bytes\n\n", len(data))

	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", collectorIP, port))
	if err != nil {
		log.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	// Use ListenUDP (unconnected) so we can receive from the server's
	// ephemeral TID port, which differs from the listen port per RFC 1350.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		log.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Sending WRQ to %s...\n", serverAddr)
	if _, err := conn.WriteToUDP(buildWRQ(filename), serverAddr); err != nil {
		log.Fatalf("WRQ write failed: %v", err)
	}
	fmt.Printf("WRQ sent for file: %s\n", filename)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ackBuf := make([]byte, 16)
	n, serverTID, err := conn.ReadFromUDP(ackBuf)
	if err != nil {
		log.Fatalf("Failed to receive initial ACK: %v", err)
	}
	if n < 4 || ackBuf[1] != 4 {
		log.Fatalf("Expected ACK (opcode 4), got %v", ackBuf[:n])
	}
	fmt.Printf("Received ACK for block 0 from %s\n", serverTID)

	dataCopy := data
	blkNum := uint16(1)
	for len(dataCopy) > 0 {
		pktLen := 512
		if len(dataCopy) < 512 {
			pktLen = len(dataCopy)
		}

		pkt := make([]byte, 4+pktLen)
		pkt[0] = 0
		pkt[1] = 3
		pkt[2] = byte(blkNum >> 8)
		pkt[3] = byte(blkNum & 0xff)
		copy(pkt[4:], dataCopy[:pktLen])

		if _, err := conn.WriteToUDP(pkt, serverTID); err != nil {
			log.Fatalf("DATA write failed: %v", err)
		}
		fmt.Printf("Sent DATA block %d (%d bytes) to %s\n", blkNum, pktLen, serverTID)

		dataCopy = dataCopy[pktLen:]

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		ackBuf := make([]byte, 16)
		n, _, err := conn.ReadFromUDP(ackBuf)
		if err != nil {
			log.Fatalf("Failed to receive ACK for block %d: %v", blkNum, err)
		}
		if n >= 4 {
			ackedBlk := int(ackBuf[2])<<8 | int(ackBuf[3])
			fmt.Printf("Received ACK for block %d\n", ackedBlk)
		}
		blkNum++
	}

	fmt.Printf("\n=== TFTP Transfer Complete ===\n")
	fmt.Printf("Sent %d bytes in %d blocks\n", len(data), blkNum-1)
}

func buildWRQ(filename string) []byte {
	packet := make([]byte, 2+len(filename)+1+6+1)
	packet[0] = 0
	packet[1] = 2
	copy(packet[2:], filename)
	packet[2+len(filename)] = 0
	copy(packet[2+len(filename)+1:], []byte("octet"))
	packet[2+len(filename)+1+6] = 0
	return packet
}
