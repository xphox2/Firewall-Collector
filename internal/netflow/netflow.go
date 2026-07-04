package netflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"firewall-collector/internal/ratelimit"
	"firewall-collector/internal/relay"
	"firewall-collector/internal/reuseport"
	"firewall-collector/internal/safego"
)

// Parse-event labels reported through the SetParseEventCallback hook. They are
// strings (not typed constants on the wire) so the observability layer can use
// them directly as a counter label.
const (
	eventMalformed      = "malformed"       // datagram/record structure disagrees with itself
	eventUnknownVersion = "unknown_version" // first 2 bytes are not 5/9/10

	// v9/IPFIX record-decoding events (record.go).
	eventDataNoTemplate       = "data_before_template"   // data set arrived before its template — normal after restart
	eventTotalCountersSkipped = "total_counters_skipped" // record carried only IE 85/86 running totals (never summed as deltas)
	eventReverseOnlyDropped   = "reverse_only_dropped"   // record carried only reverse-direction counters, no forward flow
	eventTemplateWithdrawal   = "template_withdrawal"    // IPFIX withdrawal record — parsed then ignored (RFC 7011 §8.1)

	// Sequence-loss tracker events (seq.go).
	eventSeqGap    = "seq_gap"    // export datagrams lost between the exporter and us (one event per gap)
	eventSeqResync = "seq_resync" // exporter rebooted/renumbered — expectation reset, no loss counted
)

// NetFlow socket respawn backoff bounds — same supervision discipline as the
// sFlow receiver (audit L11): a dead SO_REUSEPORT fd left bound keeps getting
// its share of the kernel's datagram hash, blackholing those exporters until
// process restart, so the worker closes and reopens instead of returning.
const (
	netflowRespawnBackoff = 200 * time.Millisecond
	netflowRespawnMax     = 30 * time.Second

	// cachePersistInterval is how often the maintenance ticker saves the
	// template/sampler caches and sweeps expired templates. 5 minutes bounds
	// the worst-case re-learning window after a crash to well under one
	// exporter template-refresh cycle.
	cachePersistInterval = 5 * time.Minute
)

// NetFlowReceiver listens for NetFlow v5/v9 and IPFIX datagrams on up to two
// UDP ports (the conventional 2055 for NetFlow, 4739 for IPFIX) and emits
// normalized relay.FlowSample records. Dispatch is content-based on the
// datagram's version word — a v9 exporter pointed at the IPFIX port (or vice
// versa) still decodes — so both sockets share ONE rate limiter, allowlist,
// template/sampler cache, and sequence tracker. All three protocols decode:
// v5 (v5.go), v9 (v9.go), IPFIX (ipfix.go), with record semantics shared in
// record.go.
type NetFlowReceiver struct {
	ListenAddr  string
	NetFlowPort int // 0 disables the NetFlow socket
	IPFIXPort   int // 0 disables the IPFIX socket

	handler       func(*relay.FlowSample)
	limiter       *ratelimit.Limiter
	onRateDrop    func()
	onSrcDrop     func()
	allowedMu     sync.RWMutex
	allowedSrcIPs map[string]bool // nil = allow any (back-compat); non-nil empty = deny all
	onParseEvent  func(event string)

	// caches is the shared v9/IPFIX template + sampler state, persisted to
	// persistPath (if set) at Start/Stop and every cachePersistInterval so a
	// restart doesn't blind decoding for a full template-refresh cycle.
	caches      *cacheSet
	persistPath string

	// seq is the per-(exporter, domain, version) sequence-loss tracker
	// (seq.go). In-memory only: sequence expectations are worthless across a
	// restart (the gap during downtime is real but unquantifiable), so it is
	// deliberately NOT persisted with the caches.
	seq *seqTracker

	workers  int
	connsMu  sync.Mutex // guards conns entries, which readLoop swaps on respawn
	conns    []*net.UDPConn
	addrs    []string // per-socket listen address, parallel to conns (respawn target)
	wg       sync.WaitGroup
	stopChan chan struct{}
	stopOnce sync.Once
	running  atomic.Bool
}

// New builds a NetFlowReceiver listening on listenAddr (default 0.0.0.0) with
// the given NetFlow and IPFIX UDP ports. A port of 0 disables that socket;
// Start fails if both are disabled.
func New(listenAddr string, netflowPort, ipfixPort int) *NetFlowReceiver {
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}
	return &NetFlowReceiver{
		ListenAddr:  listenAddr,
		NetFlowPort: netflowPort,
		IPFIXPort:   ipfixPort,
		caches:      &cacheSet{templates: newTemplateCache(), samplers: newSamplerCache()},
		seq:         newSeqTracker(),
		stopChan:    make(chan struct{}),
	}
}

// SetWorkers sets the number of parallel receive sockets/goroutines PER
// ENABLED PORT (SO_REUSEPORT fan-out). n<=1 (the default) uses a single socket
// per port. n>1 requires SO_REUSEPORT (Linux); on other platforms it is
// clamped to 1. Set before Start.
func (r *NetFlowReceiver) SetWorkers(n int) {
	r.workers = n
}

// SetRateLimiter attaches a per-source-IP UDP rate limiter shared by both
// sockets. Datagrams from a source over its rate are dropped (onDrop called,
// if set) before parsing. A nil limiter disables limiting. Set before Start.
func (r *NetFlowReceiver) SetRateLimiter(l *ratelimit.Limiter, onDrop func()) {
	r.limiter = l
	r.onRateDrop = onDrop
}

// SetAllowedSourceIPs restricts which UDP source IPs the receiver accepts
// datagrams from — the same policy as the sFlow/TFTP receivers: NetFlow
// attributes flows to the UDP source address, so any host that can reach the
// port could forge flow records for a monitored firewall and poison the
// analytics/threat pipeline unless the fleet list is enforced here.
//
//	nil -> accept any source (back-compat).
//	[]  -> non-nil empty; deny every source.
//	[…] -> accept only listed IPs. Entries normalized via net.ParseIP.String().
func (r *NetFlowReceiver) SetAllowedSourceIPs(ips []string, onDrop func()) {
	var set map[string]bool
	if ips != nil {
		set = make(map[string]bool, len(ips))
		for _, ip := range ips {
			if parsed := net.ParseIP(ip); parsed != nil {
				set[parsed.String()] = true
			}
		}
	}
	r.allowedMu.Lock()
	r.allowedSrcIPs = set
	r.onSrcDrop = onDrop
	r.allowedMu.Unlock()
}

// SetParseEventCallback registers the hook invoked with a parse-event label
// (eventMalformed, eventV9Pending, …) each time the parser hits a notable
// condition. Wired to the observability counters by the caller. Set before
// Start; a nil callback (the default) discards events.
func (r *NetFlowReceiver) SetParseEventCallback(fn func(event string)) {
	r.onParseEvent = fn
}

// SetTemplatePersistPath sets the file the template/sampler caches are
// persisted to (LoadFrom at Start; SaveTo on Stop and every 5 minutes).
// Empty (the default) disables persistence. Set before Start.
func (r *NetFlowReceiver) SetTemplatePersistPath(path string) {
	r.persistPath = path
}

// SetSamplingOverride pins the sampling rate for an exporter IP, overriding
// anything the exporter reports (research §2.3 step 1 — the MikroTik-ROS6
// escape hatch). rate 0 removes the override. Safe to call while running.
func (r *NetFlowReceiver) SetSamplingOverride(exporterIP string, rate uint32) {
	r.caches.samplers.SetSamplingOverride(exporterIP, rate)
}

// isSourceAllowed reports whether a datagram from ip should be processed. With
// no policy set (nil), every source is allowed.
func (r *NetFlowReceiver) isSourceAllowed(ip net.IP) bool {
	r.allowedMu.RLock()
	defer r.allowedMu.RUnlock()
	if r.allowedSrcIPs == nil {
		return true
	}
	return ip != nil && r.allowedSrcIPs[ip.String()]
}

// emitParseEvent forwards a parse-event label to the registered callback.
func (r *NetFlowReceiver) emitParseEvent(event string) {
	if r.onParseEvent != nil {
		r.onParseEvent(event)
	}
}

// Start binds workers× sockets for each enabled port and begins serving.
// Binding is all-or-nothing: any listen failure rolls back every socket
// already opened so a half-bound receiver can't silently serve one port.
func (r *NetFlowReceiver) Start(handler func(*relay.FlowSample)) error {
	if r.running.Load() {
		return errors.New("NetFlow receiver already running")
	}
	if r.NetFlowPort == 0 && r.IPFIXPort == 0 {
		return errors.New("NetFlow receiver: both ports disabled")
	}

	r.handler = handler

	if r.persistPath != "" {
		if err := r.caches.LoadFrom(r.persistPath, time.Now()); err != nil {
			// Non-fatal: a corrupt cache file just means re-learning templates
			// from the wire, which is the same as a first start.
			log.Printf("[NetFlow] template cache load failed (starting cold): %v", err)
		}
	}

	var portAddrs []string
	if r.NetFlowPort != 0 {
		portAddrs = append(portAddrs, fmt.Sprintf("%s:%d", r.ListenAddr, r.NetFlowPort))
	}
	if r.IPFIXPort != 0 {
		portAddrs = append(portAddrs, fmt.Sprintf("%s:%d", r.ListenAddr, r.IPFIXPort))
	}
	workers := reuseport.Workers(r.workers, "NetFlow")

	for _, addr := range portAddrs {
		for i := 0; i < workers; i++ {
			conn, err := reuseport.Listen("udp", addr)
			if err != nil {
				for _, c := range r.conns { // roll back any sockets already opened
					_ = c.Close()
				}
				r.conns, r.addrs = nil, nil
				return fmt.Errorf("failed to listen on UDP %s (worker %d): %w", addr, i, err)
			}
			// Enlarge the kernel receive buffer so short legitimate bursts aren't
			// dropped by the socket before the read loop can drain them. Silent
			// kernel drops are the #1 "flow totals don't match interface
			// counters" cause. Best-effort.
			_ = conn.SetReadBuffer(ratelimit.UDPReadBufferBytes)
			r.conns = append(r.conns, conn)
			r.addrs = append(r.addrs, addr)
		}
	}

	r.running.Store(true)
	for i := range r.conns {
		idx := i
		r.wg.Add(1)
		safego.Go("netflow:read", func() { r.readLoop(idx) })
	}
	r.wg.Add(1)
	safego.Go("netflow:maintenance", r.maintenanceLoop)

	log.Printf("[NetFlow] Listening on %v (%d worker(s) per port)", portAddrs, workers)
	return nil
}

// Stop closes every socket, waits for the read loops to exit, and persists the
// template/sampler caches so a restart resumes decoding immediately.
func (r *NetFlowReceiver) Stop() error {
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
	r.wg.Wait() // let the read/maintenance loops exit before returning

	if r.persistPath != "" {
		if err := r.caches.SaveTo(r.persistPath); err != nil {
			log.Printf("[NetFlow] template cache save failed: %v", err)
		}
	}
	return closeErr
}

// maintenanceLoop sweeps expired templates and persists the caches every
// cachePersistInterval until Stop.
func (r *NetFlowReceiver) maintenanceLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(cachePersistInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.caches.templates.sweep(time.Now())
			if r.persistPath != "" {
				if err := r.caches.SaveTo(r.persistPath); err != nil {
					log.Printf("[NetFlow] periodic template cache save failed: %v", err)
				}
			}
		case <-r.stopChan:
			return
		}
	}
}

// readLoop supervises worker idx's socket: it serves datagrams until a
// persistent (non-timeout) read error, then closes the dead socket so the
// kernel rebalances the SO_REUSEPORT group to the live workers, and reopens a
// replacement after a backoff so this worker's share of exporters isn't
// blackholed until a process restart.
func (r *NetFlowReceiver) readLoop(idx int) {
	defer r.wg.Done()
	addr := r.addrs[idx]
	backoff := netflowRespawnBackoff
	for r.running.Load() {
		r.connsMu.Lock()
		conn := r.conns[idx]
		r.connsMu.Unlock()

		if conn != nil {
			err := r.serveConn(conn)
			if !r.running.Load() {
				return // clean stop
			}
			log.Printf("[NetFlow] worker %d (%s) read error: %v; respawning socket", idx, addr, err)
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
			log.Printf("[NetFlow] worker %d respawn listen failed: %v", idx, err)
			backoff = minDuration(backoff*2, netflowRespawnMax)
			continue
		}
		_ = newConn.SetReadBuffer(ratelimit.UDPReadBufferBytes)
		r.connsMu.Lock()
		r.conns[idx] = newConn
		r.connsMu.Unlock()
		backoff = netflowRespawnBackoff // healthy reopen resets the backoff
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
func (r *NetFlowReceiver) serveConn(conn *net.UDPConn) error {
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
		if n > 0 && remoteAddr != nil {
			r.handleDatagram(buf[:n], remoteAddr.IP)
		}
	}
	return nil
}

// handleDatagram applies the source-IP allowlist and rate limit BEFORE any
// parsing (a spoofed or flooding source must cost zero parse work), then
// dispatches to the version parser. Split from serveConn so the gate order is
// unit-testable without a live socket.
func (r *NetFlowReceiver) handleDatagram(data []byte, srcIP net.IP) {
	if !r.isSourceAllowed(srcIP) {
		r.allowedMu.RLock()
		onDrop := r.onSrcDrop
		r.allowedMu.RUnlock()
		if onDrop != nil {
			onDrop()
		}
		return
	}
	if r.limiter != nil && !r.limiter.Allow(srcIP.String()) {
		if r.onRateDrop != nil {
			r.onRateDrop()
		}
		return
	}
	r.parseDatagram(data, srcIP.String(), time.Now())
}

// parseDatagram dispatches on the datagram's version word (the first 2 bytes
// in every flow protocol: v5=5, v9=9, IPFIX=10). Dispatch is content-based,
// NOT port-based — exporters routinely get pointed at "the flow port" and a
// v9 sender on the IPFIX socket must still decode. SamplerAddress is always
// the UDP source IP (v5/v9/IPFIX carry no in-band agent address the way
// sFlow does).
func (r *NetFlowReceiver) parseDatagram(data []byte, exporterIP string, now time.Time) {
	if r.handler == nil {
		return
	}
	if len(data) < 2 {
		r.emitParseEvent(eventMalformed)
		return
	}
	switch binary.BigEndian.Uint16(data[0:2]) {
	case 5:
		r.parseV5(data, exporterIP, now)
	case 9:
		r.parseV9(data, exporterIP, now)
	case 10:
		r.parseIPFIX(data, exporterIP, now)
	default:
		r.emitParseEvent(eventUnknownVersion)
	}
}
