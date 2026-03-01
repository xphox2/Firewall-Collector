package sflow

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"firewall-collector/internal/relay"
)

type SFlowReceiver struct {
	ListenAddr string
	Port       int
	handler    func(*relay.FlowSample)
	conn       *net.UDPConn
	stopChan   chan struct{}
	running    atomic.Bool
}

func NewSFlowReceiver(listenAddr string, port int) *SFlowReceiver {
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}
	if port == 0 {
		port = 6343
	}
	return &SFlowReceiver{
		ListenAddr: listenAddr,
		Port:       port,
		stopChan:   make(chan struct{}),
	}
}

func (r *SFlowReceiver) Start(handler func(*relay.FlowSample)) error {
	if r.running.Load() {
		return errors.New("sFlow receiver already running")
	}

	r.handler = handler

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", r.ListenAddr, r.Port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	r.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s:%d: %w", r.ListenAddr, r.Port, err)
	}

	r.running.Store(true)
	go r.readLoop()

	log.Printf("[sFlow] Listening on %s:%d", r.ListenAddr, r.Port)
	return nil
}

func (r *SFlowReceiver) Stop() error {
	if !r.running.Load() {
		return nil
	}

	r.running.Store(false)
	close(r.stopChan)

	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

func (r *SFlowReceiver) readLoop() {
	buf := make([]byte, 65536)
	for r.running.Load() {
		r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if r.running.Load() {
				log.Printf("[sFlow] Read error: %v", err)
			}
			return
		}

		if n > 0 {
			r.parseSFlowDatagram(buf[:n])
		}
	}
}

func (r *SFlowReceiver) parseSFlowDatagram(data []byte) {
	if len(data) < 24 {
		return
	}

	version := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if version != 5 {
		return
	}

	sequence := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
	agentIP := net.IP(data[8:12])

	if r.handler != nil {
		sample := &relay.FlowSample{
			Timestamp:      time.Now(),
			SamplerAddress: agentIP.String(),
			SequenceNumber: sequence,
		}
		r.handler(sample)
	}
}
