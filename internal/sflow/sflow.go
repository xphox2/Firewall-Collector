package sflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/ratelimit"
	"firewall-collector/internal/relay"
	"firewall-collector/internal/reuseport"
	"firewall-collector/internal/safego"
)

type SFlowReceiver struct {
	ListenAddr     string
	Port           int
	handler        func(*relay.FlowSample)
	counterHandler func(*relay.InterfaceCounterSample)
	limiter        *ratelimit.Limiter
	onRateDrop     func()
	workers        int
	connsMu        sync.Mutex // guards conns entries, which readLoop swaps on respawn
	conns          []*net.UDPConn
	wg             sync.WaitGroup
	stopChan       chan struct{}
	stopOnce       sync.Once
	running        atomic.Bool
}

// SetWorkers sets the number of parallel receive sockets/goroutines (SO_REUSEPORT
// fan-out). n<=1 (the default) uses a single socket. n>1 requires SO_REUSEPORT
// (Linux); on other platforms it is clamped to 1. Set before Start.
func (r *SFlowReceiver) SetWorkers(n int) {
	r.workers = n
}

// SetRateLimiter attaches a per-source-IP UDP rate limiter. Datagrams from a
// source over its rate are dropped (onDrop called, if set) before parsing. A nil
// limiter disables limiting. Set before Start.
func (r *SFlowReceiver) SetRateLimiter(l *ratelimit.Limiter, onDrop func()) {
	r.limiter = l
	r.onRateDrop = onDrop
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

	addr := fmt.Sprintf("%s:%d", r.ListenAddr, r.Port)
	workers := reuseport.Workers(r.workers, "sFlow")

	for i := 0; i < workers; i++ {
		conn, err := reuseport.Listen("udp", addr)
		if err != nil {
			for _, c := range r.conns { // roll back any sockets already opened
				_ = c.Close()
			}
			r.conns = nil
			return fmt.Errorf("failed to listen on UDP %s (worker %d): %w", addr, i, err)
		}
		// Enlarge the kernel receive buffer so short legitimate bursts aren't
		// dropped by the socket before the read loop can drain them. Best-effort.
		_ = conn.SetReadBuffer(ratelimit.UDPReadBufferBytes)
		r.conns = append(r.conns, conn)
	}

	r.running.Store(true)
	for i := range r.conns {
		idx := i
		r.wg.Add(1)
		safego.Go("sflow:read", func() { r.readLoop(idx) })
	}

	log.Printf("[sFlow] Listening on %s (%d worker(s))", addr, workers)
	return nil
}

// SetCounterHandler registers the callback for sFlow counter samples (interface
// counters). It must be set before Start when counter samples are wanted; a nil
// handler (the default) makes the parser skip counters_sample records entirely.
func (r *SFlowReceiver) SetCounterHandler(h func(*relay.InterfaceCounterSample)) {
	r.counterHandler = h
}

func (r *SFlowReceiver) Stop() error {
	if !r.running.Load() {
		return nil
	}

	var closeErr error
	r.stopOnce.Do(func() {
		r.running.Store(false)
		close(r.stopChan)
		r.connsMu.Lock()
		conns := r.conns
		r.connsMu.Unlock()
		for _, c := range conns {
			if c != nil {
				if err := c.Close(); err != nil {
					closeErr = err
				}
			}
		}
	})
	r.wg.Wait() // let the read loops exit before returning
	return closeErr
}

// sFlow socket respawn backoff bounds. A persistent read error kills a socket;
// rather than returning (which leaves the dead SO_REUSEPORT fd bound so the
// kernel keeps hashing datagrams to it — audit L11), the worker closes it and
// reopens a fresh listener after a growing backoff.
const (
	sflowRespawnBackoff = 200 * time.Millisecond
	sflowRespawnMax     = 30 * time.Second
)

// readLoop supervises worker idx's socket: it serves datagrams until a
// persistent (non-timeout) read error, then closes the dead socket so the
// kernel rebalances the SO_REUSEPORT group to the live workers, and reopens a
// replacement after a backoff so this worker's share of agents isn't
// blackholed until a process restart.
func (r *SFlowReceiver) readLoop(idx int) {
	defer r.wg.Done()
	addr := fmt.Sprintf("%s:%d", r.ListenAddr, r.Port)
	backoff := sflowRespawnBackoff
	for r.running.Load() {
		r.connsMu.Lock()
		conn := r.conns[idx]
		r.connsMu.Unlock()

		if conn != nil {
			err := r.serveConn(conn)
			if !r.running.Load() {
				return // clean stop
			}
			log.Printf("[sFlow] worker %d read error: %v; respawning socket", idx, err)
			// Close the dead socket so the kernel drops it from the reuseport hash.
			_ = conn.Close()
			r.connsMu.Lock()
			r.conns[idx] = nil
			r.connsMu.Unlock()
		}

		select {
		case <-time.After(backoff):
		case <-r.stopChan:
			return
		}
		newConn, err := reuseport.Listen("udp", addr)
		if err != nil {
			log.Printf("[sFlow] worker %d respawn listen failed: %v", idx, err)
			backoff = minDuration(backoff*2, sflowRespawnMax)
			continue
		}
		_ = newConn.SetReadBuffer(ratelimit.UDPReadBufferBytes)
		r.connsMu.Lock()
		r.conns[idx] = newConn
		r.connsMu.Unlock()
		backoff = sflowRespawnBackoff // healthy reopen resets the backoff
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// serveConn reads and dispatches datagrams on conn until running flips false or
// a non-timeout read error occurs (returned so readLoop can respawn the socket).
func (r *SFlowReceiver) serveConn(conn *net.UDPConn) error {
	buf := make([]byte, 65536)
	for r.running.Load() {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		// Per-source rate limit: shed datagrams from a flooding source before
		// parsing/queueing (nil limiter = disabled).
		if r.limiter != nil && remoteAddr != nil && !r.limiter.Allow(remoteAddr.IP.String()) {
			if r.onRateDrop != nil {
				r.onRateDrop()
			}
			continue
		}

		if n > 0 {
			r.parseSFlowDatagram(buf[:n])
		}
	}
	return nil
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

// readUint64 reads an XDR unsigned hyper (8 bytes, big-endian). sFlow counter
// records use it for ifSpeed / ifInOctets / ifOutOctets.
func readUint64(data []byte, offset *int) (uint64, bool) {
	if *offset+8 > len(data) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(data[*offset:])
	*offset += 8
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
		} else if enterprise == 0 && (format == 2 || format == 4) {
			// Counters sample (format=2) or expanded (format=4)
			r.parseCountersSample(data, &offset, format, sampleEnd, agentAddr, now)
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
	// drops (sFlow v5 §3.1.1): the number of packets the agent had
	// to drop between this sample and the previous one because it
	// could not keep up. Captured into the emitted FlowSample so
	// the server can alert on agent-side congestion. This was
	// previously read and discarded (see audit 2026-06-22).
	drops, ok := readUint32(data, offset)
	if !ok {
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
		Drops:          uint64(drops),
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

		// Parse each record from a slice bounded to its OWN declared length. A
		// record's readUint32/readUint64 helpers bound against len(their data), so
		// handing them a rec limited to [*offset:recEnd] makes it impossible for a
		// lying recLen to let a sub-parser read past recEnd into the following
		// record's bytes and fold them into SrcAS/next-hop telemetry (audit L9).
		rec := data[*offset:recEnd]
		recOff := 0
		if recEnterprise == 0 && recFormat == 1 {
			// Raw packet header record
			parseRawPacketHeader(rec, &recOff, len(rec), sample)
		} else if recEnterprise == 0 && recFormat == 1003 {
			// Extended gateway (BGP) record — AS path / next hop.
			parseExtendedGateway(rec, &recOff, len(rec), sample)
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

// parseExtendedGateway decodes the sFlow extended_gateway record (RFC 3176 data
// format 1003): the BGP next-hop address, the source AS, and the destination AS
// path. It fills sample.NextHop, sample.SrcAS, sample.DstAS (the origin AS — the
// last hop of the path) and sample.ASPath (space-separated). Every read is
// bounded by recEnd and the array counts are capped, so a malformed or hostile
// record can't drive an unbounded loop (this parser is fuzzed). On any short
// read it returns with whatever it parsed so far; the caller resets offset to
// recEnd regardless.
//
// Record layout: next_hop(address) + as(4) + src_as(4) + src_peer_as(4) +
// dst_as_path<segments> + communities<> + localpref(4). Each path segment is
// type(4) + as_count(4) + as[as_count](4 each). We ignore communities/localpref.
func parseExtendedGateway(data []byte, offset *int, recEnd int, sample *relay.FlowSample) {
	// next_hop address: type(4) + 4|16 bytes
	addrType, ok := readUint32(data, offset)
	if !ok {
		return
	}
	switch addrType {
	case 1: // IPv4
		if *offset+4 > recEnd {
			return
		}
		sample.NextHop = net.IP(data[*offset : *offset+4]).String()
		*offset += 4
	case 2: // IPv6
		if *offset+16 > recEnd {
			return
		}
		sample.NextHop = net.IP(data[*offset : *offset+16]).String()
		*offset += 16
	default:
		return
	}

	if _, ok = readUint32(data, offset); !ok { // as (this gateway's AS) — unused
		return
	}
	srcAS, ok := readUint32(data, offset)
	if !ok {
		return
	}
	sample.SrcAS = srcAS
	if _, ok = readUint32(data, offset); !ok { // src_peer_as — unused
		return
	}

	const maxSegments = 64
	const maxASPerSeg = 256
	segCount, ok := readUint32(data, offset)
	if !ok {
		return
	}
	if segCount > maxSegments {
		segCount = maxSegments
	}
	asPath := make([]uint32, 0, 16)
	for s := uint32(0); s < segCount && *offset < recEnd; s++ {
		if _, ok = readUint32(data, offset); !ok { // segment type (1=set, 2=sequence)
			return
		}
		asCount, ok := readUint32(data, offset)
		if !ok {
			return
		}
		if asCount > maxASPerSeg {
			asCount = maxASPerSeg
		}
		for a := uint32(0); a < asCount && *offset < recEnd; a++ {
			v, ok := readUint32(data, offset)
			if !ok {
				return
			}
			asPath = append(asPath, v)
		}
	}
	if len(asPath) > 0 {
		sample.DstAS = asPath[len(asPath)-1] // origin AS of the destination
		parts := make([]string, len(asPath))
		for i, v := range asPath {
			parts[i] = strconv.FormatUint(uint64(v), 10)
		}
		sample.ASPath = strings.Join(parts, " ")
	}
}

// parseCountersSample decodes an sFlow counters_sample (format 2) or
// counters_sample_expanded (format 4) and, for each generic interface-counters
// record (if_counters, data format 1), emits an InterfaceCounterSample via the
// counter handler. Header: sequence_number(4) + source_id + num_records(4). In
// format 2 source_id is one word ((type<<24)|index); in format 4 it is two
// words (type, index). All reads are bounded; num_records is capped.
func (r *SFlowReceiver) parseCountersSample(data []byte, offset *int, format uint32, sampleEnd int, agentAddr string, now time.Time) {
	if r.counterHandler == nil {
		return
	}
	if _, ok := readUint32(data, offset); !ok { // sequence_number
		return
	}
	var ifIndex uint32
	if format == 2 {
		srcID, ok := readUint32(data, offset)
		if !ok {
			return
		}
		ifIndex = srcID & 0x00FFFFFF // low 24 bits = index, high 8 = type
	} else { // format 4 (expanded)
		if _, ok := readUint32(data, offset); !ok { // source_id_type
			return
		}
		idx, ok := readUint32(data, offset)
		if !ok {
			return
		}
		ifIndex = idx
	}
	numRecords, ok := readUint32(data, offset)
	if !ok {
		return
	}
	const maxRecords = 256
	if numRecords > maxRecords {
		numRecords = maxRecords
	}
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
			// generic interface counters (if_counters). Parse from a record-local
			// slice so a lying recLen can't bleed adjacent-record bytes into the
			// 64-bit octet counters (fake multi-exabyte spikes) — audit L9.
			rec := data[*offset:recEnd]
			recOff := 0
			parseIfCounters(rec, &recOff, ifIndex, agentAddr, now, r.counterHandler)
		}
		*offset = recEnd
	}
}

// parseIfCounters decodes the generic interface counters record (sFlow if_counters,
// counter data format 1) into an InterfaceCounterSample and hands it to emit. The
// record's own ifIndex is preferred; fallbackIfIndex (from the sample source_id)
// is used only if the record reports 0. Every read is length-checked, so a short
// or hostile record returns cleanly without emitting.
//
// Layout: ifIndex(4) ifType(4) ifSpeed(8) ifDirection(4) ifStatus(4)
// ifInOctets(8) ifInUcastPkts(4) ifInMulticastPkts(4) ifInBroadcastPkts(4)
// ifInDiscards(4) ifInErrors(4) ifInUnknownProtos(4)
// ifOutOctets(8) ifOutUcastPkts(4) ifOutMulticastPkts(4) ifOutBroadcastPkts(4)
// ifOutDiscards(4) ifOutErrors(4) ifPromiscuousMode(4).
func parseIfCounters(data []byte, offset *int, fallbackIfIndex uint32, agentAddr string, now time.Time, emit func(*relay.InterfaceCounterSample)) {
	cs := &relay.InterfaceCounterSample{Timestamp: now, SamplerAddress: agentAddr}

	ifIndex, ok := readUint32(data, offset)
	if !ok {
		return
	}
	cs.IfIndex = ifIndex
	if cs.IfIndex == 0 {
		cs.IfIndex = fallbackIfIndex
	}
	if cs.IfType, ok = readUint32(data, offset); !ok {
		return
	}
	if cs.IfSpeed, ok = readUint64(data, offset); !ok {
		return
	}
	if cs.IfDirection, ok = readUint32(data, offset); !ok {
		return
	}
	if cs.IfStatus, ok = readUint32(data, offset); !ok {
		return
	}
	if cs.InOctets, ok = readUint64(data, offset); !ok {
		return
	}
	for i := 0; i < 3; i++ { // ifIn{Ucast,Multicast,Broadcast}Pkts
		if _, ok = readUint32(data, offset); !ok {
			return
		}
	}
	inDiscards, ok := readUint32(data, offset)
	if !ok {
		return
	}
	cs.InDiscards = uint64(inDiscards)
	inErrors, ok := readUint32(data, offset)
	if !ok {
		return
	}
	cs.InErrors = uint64(inErrors)
	if _, ok = readUint32(data, offset); !ok { // ifInUnknownProtos
		return
	}
	if cs.OutOctets, ok = readUint64(data, offset); !ok {
		return
	}
	for i := 0; i < 3; i++ { // ifOut{Ucast,Multicast,Broadcast}Pkts
		if _, ok = readUint32(data, offset); !ok {
			return
		}
	}
	outDiscards, ok := readUint32(data, offset)
	if !ok {
		return
	}
	cs.OutDiscards = uint64(outDiscards)
	outErrors, ok := readUint32(data, offset)
	if !ok {
		return
	}
	cs.OutErrors = uint64(outErrors)
	// ifPromiscuousMode trailing field intentionally not read — unused.

	emit(cs)
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

	// 6in4: an IPv4 packet whose protocol is 41 carries a full IPv6 packet.
	// Decode the inner IPv6 so the flow reflects the real conversation
	// (inner src/dst, upper-layer protocol, ports) instead of just "IPv6".
	// parseIPv6 overwrites SrcAddr/DstAddr/Protocol/ports; if the inner header
	// is truncated in the sampled bytes it returns early, leaving the outer
	// IPv4 tunnel endpoints and protocol 41 as a graceful fallback.
	if sample.Protocol == 41 {
		parseIPv6(data[ihl:], sample)
		return
	}

	parseTransport(data[ihl:], sample)
}

// isIPv6ExtHeader reports whether an IPv6 "Next Header" value is an extension
// header (which chains to a further header) rather than an upper-layer protocol.
// ESP (50) is deliberately excluded: its payload is encrypted, so the chain
// cannot be walked past it. No-Next-Header (59) is also terminal.
func isIPv6ExtHeader(nh uint8) bool {
	switch nh {
	case 0, // Hop-by-Hop Options
		43,  // Routing
		44,  // Fragment
		51,  // Authentication Header
		60,  // Destination Options
		135: // Mobility
		return true
	}
	return false
}

func parseIPv6(data []byte, sample *relay.FlowSample) {
	// IPv6 fixed header: 40 bytes
	if len(data) < 40 {
		return
	}

	sample.SrcAddr = net.IP(data[8:24]).String()
	sample.DstAddr = net.IP(data[24:40]).String()

	// Walk the extension-header chain to the real upper-layer protocol. Without
	// this, any IPv6 packet carrying an extension header (Hop-by-Hop Options is
	// extremely common — MLD/multicast, Router Alert, jumbograms — and has Next
	// Header = 0) would be recorded as protocol 0 (HOPOPT) with no L4 ports,
	// dumping all such traffic into the bogus "HOPOPT"/port-0 bucket. Sampled
	// headers are truncated, so every read is bounds-checked; the iteration cap
	// guards against malformed or looping chains.
	nextHeader := data[6]
	offset := 40
	for i := 0; i < 8 && isIPv6ExtHeader(nextHeader); i++ {
		if offset+2 > len(data) {
			break // can't read this ext header — keep nextHeader as best effort
		}
		var extLen int
		switch nextHeader {
		case 44: // Fragment header is always 8 bytes
			extLen = 8
		case 51: // Authentication Header: (length + 2) 4-byte units
			extLen = (int(data[offset+1]) + 2) * 4
		default: // Hop-by-Hop(0), Routing(43), Dest-Opts(60), Mobility(135)
			extLen = (int(data[offset+1]) + 1) * 8
		}
		nextHeader = data[offset]
		offset += extLen
	}

	sample.Protocol = nextHeader
	if offset <= len(data) {
		parseTransport(data[offset:], sample)
	}
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
