package sflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
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
	stopOnce   sync.Once
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

	var closeErr error
	r.stopOnce.Do(func() {
		r.running.Store(false)
		close(r.stopChan)
		if r.conn != nil {
			closeErr = r.conn.Close()
		}
	})
	return closeErr
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

// readUint32 reads a big-endian uint32 from data at offset, advancing offset.
func readUint32(data []byte, offset *int) (uint32, bool) {
	if *offset+4 > len(data) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(data[*offset:])
	*offset += 4
	return v, true
}

func (r *SFlowReceiver) parseSFlowDatagram(data []byte) {
	if r.handler == nil {
		return
	}

	offset := 0

	// Datagram header: version(4) + address_type(4) + agent_address(4|16) + sub_agent_id(4) + sequence(4) + uptime(4) + num_samples(4)
	version, ok := readUint32(data, &offset)
	if !ok || version != 5 {
		return
	}

	addrType, ok := readUint32(data, &offset)
	if !ok {
		return
	}

	var agentIP net.IP
	switch addrType {
	case 1: // IPv4
		if offset+4 > len(data) {
			return
		}
		agentIP = net.IP(data[offset : offset+4]).To16()
		offset += 4
	case 2: // IPv6
		if offset+16 > len(data) {
			return
		}
		agentIP = net.IP(data[offset : offset+16])
		offset += 16
	default:
		return
	}

	// sub_agent_id, sequence_number, uptime, num_samples
	if _, ok = readUint32(data, &offset); !ok { // sub_agent_id
		return
	}
	dgSequence, ok := readUint32(data, &offset)
	if !ok {
		return
	}
	if _, ok = readUint32(data, &offset); !ok { // uptime
		return
	}
	numSamples, ok := readUint32(data, &offset)
	if !ok {
		return
	}

	agentAddr := agentIP.String()
	now := time.Now()

	for i := uint32(0); i < numSamples && offset < len(data); i++ {
		// Each sample: enterprise_format(4) + sample_length(4) + sample_data
		efTag, ok := readUint32(data, &offset)
		if !ok {
			return
		}
		sampleLen, ok := readUint32(data, &offset)
		if !ok {
			return
		}

		sampleEnd := offset + int(sampleLen)
		if sampleEnd > len(data) {
			return
		}

		enterprise := efTag >> 12
		format := efTag & 0xFFF

		if enterprise == 0 && (format == 1 || format == 3) {
			// Flow sample (format=1) or expanded flow sample (format=3)
			r.parseFlowSample(data, &offset, format, sampleEnd, agentAddr, dgSequence, now)
		}

		// Skip to end of this sample regardless
		offset = sampleEnd
	}
}

func (r *SFlowReceiver) parseFlowSample(data []byte, offset *int, format uint32, sampleEnd int, agentAddr string, dgSequence uint32, now time.Time) {
	// Flow sample header
	seqNum, ok := readUint32(data, offset)
	if !ok {
		return
	}

	if format == 1 {
		// Standard flow sample: source_id(4)
		if _, ok = readUint32(data, offset); !ok {
			return
		}
	} else {
		// Expanded flow sample (format=3): source_id_type(4) + source_id_index(4)
		if _, ok = readUint32(data, offset); !ok {
			return
		}
		if _, ok = readUint32(data, offset); !ok {
			return
		}
	}

	samplingRate, ok := readUint32(data, offset)
	if !ok {
		return
	}
	if _, ok = readUint32(data, offset); !ok { // sample_pool
		return
	}
	if _, ok = readUint32(data, offset); !ok { // drops
		return
	}

	var inputIfIndex, outputIfIndex uint32
	if format == 1 {
		// Standard: input(4) + output(4) - top 2 bits are format
		v, ok := readUint32(data, offset)
		if !ok {
			return
		}
		inputIfIndex = v & 0x3FFFFFFF

		v, ok = readUint32(data, offset)
		if !ok {
			return
		}
		outputIfIndex = v & 0x3FFFFFFF
	} else {
		// Expanded: input_type(4) + input_index(4) + output_type(4) + output_index(4)
		if _, ok = readUint32(data, offset); !ok { // input_type
			return
		}
		inputIfIndex, ok = readUint32(data, offset)
		if !ok {
			return
		}
		if _, ok = readUint32(data, offset); !ok { // output_type
			return
		}
		outputIfIndex, ok = readUint32(data, offset)
		if !ok {
			return
		}
	}

	numRecords, ok := readUint32(data, offset)
	if !ok {
		return
	}

	sample := &relay.FlowSample{
		Timestamp:      now,
		SamplerAddress: agentAddr,
		SequenceNumber: dgSequence,
		SamplingRate:   samplingRate,
		InputIfIndex:   inputIfIndex,
		OutputIfIndex:  outputIfIndex,
	}

	// Parse flow records looking for raw packet header
	for j := uint32(0); j < numRecords && *offset < sampleEnd; j++ {
		recEF, ok := readUint32(data, offset)
		if !ok {
			return
		}
		recLen, ok := readUint32(data, offset)
		if !ok {
			return
		}
		recEnd := *offset + int(recLen)
		if recEnd > sampleEnd {
			return
		}

		recEnterprise := recEF >> 12
		recFormat := recEF & 0xFFF

		if recEnterprise == 0 && recFormat == 1 {
			// Raw packet header record
			parseRawPacketHeader(data, offset, recEnd, sample)
		}

		*offset = recEnd
	}

	// Only emit if we extracted meaningful flow data
	if sample.SrcAddr != "" || sample.DstAddr != "" || seqNum > 0 {
		// Estimate bytes/packets from sampling
		if sample.Bytes > 0 && samplingRate > 1 {
			sample.Bytes *= uint64(samplingRate)
			sample.Packets = uint64(samplingRate)
		} else if sample.Bytes > 0 {
			sample.Packets = 1
		}
		r.handler(sample)
	}
}

func parseRawPacketHeader(data []byte, offset *int, recEnd int, sample *relay.FlowSample) {
	// Raw packet header: protocol(4) + frame_length(4) + stripped(4) + header_length(4) + header_bytes
	headerProto, ok := readUint32(data, offset)
	if !ok {
		return
	}
	frameLength, ok := readUint32(data, offset)
	if !ok {
		return
	}
	if _, ok = readUint32(data, offset); !ok { // stripped
		return
	}
	headerLen, ok := readUint32(data, offset)
	if !ok {
		return
	}

	if *offset+int(headerLen) > recEnd {
		return
	}

	hdr := data[*offset : *offset+int(headerLen)]
	sample.Bytes = uint64(frameLength)

	if headerProto == 1 {
		// Ethernet
		parseEthernet(hdr, sample)
	}
}

func parseEthernet(hdr []byte, sample *relay.FlowSample) {
	// Ethernet: dst(6) + src(6) + ethertype(2) = 14 bytes minimum
	if len(hdr) < 14 {
		return
	}

	etherType := binary.BigEndian.Uint16(hdr[12:14])
	ipOffset := 14

	// Handle 802.1Q VLAN tags
	for etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100 {
		if ipOffset+4 > len(hdr) {
			return
		}
		etherType = binary.BigEndian.Uint16(hdr[ipOffset+2:])
		ipOffset += 4
	}

	switch etherType {
	case 0x0800: // IPv4
		parseIPv4(hdr[ipOffset:], sample)
	case 0x86DD: // IPv6
		parseIPv6(hdr[ipOffset:], sample)
	}
}

func parseIPv4(data []byte, sample *relay.FlowSample) {
	// IPv4 minimum header: 20 bytes
	if len(data) < 20 {
		return
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl {
		return
	}

	sample.Protocol = data[9]
	sample.SrcAddr = net.IP(data[12:16]).String()
	sample.DstAddr = net.IP(data[16:20]).String()

	parseTransport(data[ihl:], sample)
}

func parseIPv6(data []byte, sample *relay.FlowSample) {
	// IPv6 fixed header: 40 bytes
	if len(data) < 40 {
		return
	}

	sample.Protocol = data[6] // Next Header
	sample.SrcAddr = net.IP(data[8:24]).String()
	sample.DstAddr = net.IP(data[24:40]).String()

	parseTransport(data[40:], sample)
}

func parseTransport(data []byte, sample *relay.FlowSample) {
	switch sample.Protocol {
	case 6: // TCP
		if len(data) < 14 {
			return
		}
		sample.SrcPort = binary.BigEndian.Uint16(data[0:2])
		sample.DstPort = binary.BigEndian.Uint16(data[2:4])
		sample.TCPFlags = data[13]
	case 17: // UDP
		if len(data) < 4 {
			return
		}
		sample.SrcPort = binary.BigEndian.Uint16(data[0:2])
		sample.DstPort = binary.BigEndian.Uint16(data[2:4])
	}
}
