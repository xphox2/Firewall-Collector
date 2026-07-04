package netflow

import (
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"firewall-collector/internal/ratelimit"
	"firewall-collector/internal/relay"
)

// TestParseDatagram_VersionDispatch pins the content-based dispatch on the
// first 2 bytes: 5/9/10 → the real parsers (proven here by each parser's own
// truncated-header malformed event), anything else → unknown_version.
// Port-based dispatch would break the "v9 exporter pointed at the IPFIX port"
// case, so the version word decides.
func TestParseDatagram_VersionDispatch(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"v9-truncated-header", u16be(nil, 9), eventMalformed},
		{"ipfix-truncated-header", u16be(nil, 10), eventMalformed},
		{"unknown", u16be(nil, 7), eventUnknownVersion},
		// 0x0000: sFlow's version word is 4 bytes (00 00 00 05), so its first
		// two bytes read as version 0 — an sFlow exporter mispointed at this
		// port must land in unknown_version, not crash a parser.
		{"sflow-mispointed", []byte{0x00, 0x00, 0x00, 0x05}, eventUnknownVersion},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, getSamples, getEvents := newTestReceiver()
			r.parseDatagram(tc.data, "192.0.2.1", time.Now())
			if got := getSamples(); len(got) != 0 {
				t.Fatalf("expected 0 samples, got %d", len(got))
			}
			if ev := getEvents(); len(ev) != 1 || ev[0] != tc.want {
				t.Errorf("events = %v, want [%q]", ev, tc.want)
			}
		})
	}
}

// TestParseDatagram_TooShort: a datagram shorter than the version word is
// malformed, not a panic.
func TestParseDatagram_TooShort(t *testing.T) {
	r, getSamples, getEvents := newTestReceiver()
	r.parseDatagram([]byte{0x05}, "192.0.2.1", time.Now())
	if got := getSamples(); len(got) != 0 {
		t.Fatalf("expected 0 samples, got %d", len(got))
	}
	if ev := getEvents(); len(ev) != 1 || ev[0] != eventMalformed {
		t.Errorf("events = %v, want [%q]", ev, eventMalformed)
	}
}

// TestParseDatagram_NilHandler: the nil-handler guard must hold (Start wires
// the handler; direct parse calls before that must be no-ops).
func TestParseDatagram_NilHandler(t *testing.T) {
	r := New("127.0.0.1", 2055, 4739)
	dg := buildV5(hdrAt(time.Now(), 100000), v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1})
	r.parseDatagram(dg, "192.0.2.1", time.Now()) // must not panic
}

// validV5Datagram builds a well-formed single-record v5 datagram for the
// gate/lifecycle tests.
func validV5Datagram(now time.Time) []byte {
	return buildV5(hdrAt(now, 100000), v5Record{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2},
		packets: 1, octets: 64, first: 90000, last: 95000, proto: 17,
	})
}

// TestHandleDatagram_Allowlist pins the SetAllowedSourceIPs semantics (same
// contract as the sFlow/TFTP receivers): nil = any source, non-nil empty =
// deny all, populated = only listed IPs — and the drop happens BEFORE parsing
// (no sample, no parse event, onDrop fired).
func TestHandleDatagram_Allowlist(t *testing.T) {
	now := time.Now()
	dg := validV5Datagram(now)

	// nil policy: any source allowed (back-compat default).
	r, getSamples, _ := newTestReceiver()
	r.handleDatagram(dg, net.ParseIP("198.51.100.7"))
	if got := getSamples(); len(got) != 1 {
		t.Fatalf("nil policy: expected 1 sample, got %d", len(got))
	}

	// Non-nil empty: deny every source.
	var srcDrops atomic.Int64
	r2, getSamples2, getEvents2 := newTestReceiver()
	r2.SetAllowedSourceIPs([]string{}, func() { srcDrops.Add(1) })
	r2.handleDatagram(dg, net.ParseIP("198.51.100.7"))
	if got := getSamples2(); len(got) != 0 {
		t.Fatalf("deny-all: expected 0 samples, got %d", len(got))
	}
	if ev := getEvents2(); len(ev) != 0 {
		t.Fatalf("deny-all: dropped datagram reached the parser: events=%v", ev)
	}
	if srcDrops.Load() != 1 {
		t.Errorf("deny-all: onDrop fired %d times, want 1", srcDrops.Load())
	}

	// Populated list: only the listed IP passes.
	r2.SetAllowedSourceIPs([]string{"192.0.2.1"}, func() { srcDrops.Add(1) })
	r2.handleDatagram(dg, net.ParseIP("192.0.2.1"))
	r2.handleDatagram(dg, net.ParseIP("192.0.2.2"))
	if got := getSamples2(); len(got) != 1 {
		t.Fatalf("allowlist: expected 1 sample (allowed IP only), got %d", len(got))
	}
	if got := getSamples2(); got[0].SamplerAddress != "192.0.2.1" {
		t.Errorf("allowlist: sample attributed to %q, want 192.0.2.1", got[0].SamplerAddress)
	}
	if srcDrops.Load() != 2 {
		t.Errorf("allowlist: onDrop fired %d times total, want 2", srcDrops.Load())
	}
}

// TestHandleDatagram_RateLimit verifies the per-source rate limit sheds
// datagrams before parsing and fires the drop callback. Burst 1 means the
// first datagram passes and an immediate second is dropped.
func TestHandleDatagram_RateLimit(t *testing.T) {
	now := time.Now()
	dg := validV5Datagram(now)

	var rateDrops atomic.Int64
	r, getSamples, _ := newTestReceiver()
	r.SetRateLimiter(ratelimit.New(ratelimit.Config{PerSourceRate: 1, PerSourceBurst: 1}), func() { rateDrops.Add(1) })

	r.handleDatagram(dg, net.ParseIP("192.0.2.1"))
	r.handleDatagram(dg, net.ParseIP("192.0.2.1"))

	if got := getSamples(); len(got) != 1 {
		t.Fatalf("expected exactly 1 sample (second datagram rate-dropped), got %d", len(got))
	}
	if rateDrops.Load() != 1 {
		t.Errorf("onDrop fired %d times, want 1", rateDrops.Load())
	}
}

// freeUDPPort reserves an ephemeral UDP port and releases it for the receiver
// to bind. Racy in principle, fine in practice for a local test.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

// sendUDP fires one datagram at 127.0.0.1:port.
func sendUDP(t *testing.T, port int, data []byte) {
	t.Helper()
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// TestStartStop_DualPortLifecycle is the end-to-end lifecycle test: both
// sockets bind, a v5 datagram on the NetFlow port decodes into a sample, an
// IPFIX template+data message on the IPFIX port decodes into a FlowSource=3
// sample (content dispatch on the shared path), the template caches persist
// on Stop, and a second Stop is a no-op.
func TestStartStop_DualPortLifecycle(t *testing.T) {
	nfPort := freeUDPPort(t)
	ipfixPort := freeUDPPort(t)
	if nfPort == ipfixPort {
		t.Skip("ephemeral port collision")
	}
	persist := filepath.Join(t.TempDir(), "templates.json")

	var (
		mu      sync.Mutex
		samples []*relay.FlowSample
	)
	r := New("127.0.0.1", nfPort, ipfixPort)
	r.SetTemplatePersistPath(persist)
	if err := r.Start(func(s *relay.FlowSample) {
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	// A second Start while running must refuse.
	if err := r.Start(func(*relay.FlowSample) {}); err == nil {
		t.Error("second Start while running should error")
	}

	sendUDP(t, nfPort, validV5Datagram(time.Now()))
	sendUDP(t, ipfixPort, validIPFIXMessage(time.Now()))

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		gotV5, gotIPFIX := false, false
		for _, s := range samples {
			switch s.FlowSource {
			case relay.FlowSourceNetFlowV5:
				gotV5 = true
			case relay.FlowSourceIPFIX:
				gotIPFIX = true
			}
		}
		mu.Unlock()
		if gotV5 && gotIPFIX {
			break
		}
		if time.Now().After(deadline) {
			mu.Lock()
			n := len(samples)
			mu.Unlock()
			t.Fatalf("timeout: samples=%d (want one v5 + one IPFIX)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	if samples[0].SamplerAddress != "127.0.0.1" {
		t.Errorf("SamplerAddress = %q, want the UDP source 127.0.0.1", samples[0].SamplerAddress)
	}
	mu.Unlock()

	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop should be a no-op, got %v", err)
	}

	// Stop persisted the (empty) caches: the file must exist and load cleanly.
	fresh := &cacheSet{templates: newTemplateCache(), samplers: newSamplerCache()}
	if err := fresh.LoadFrom(persist, time.Now()); err != nil {
		t.Errorf("cache file not written/loadable after Stop: %v", err)
	}
}

// TestStart_BothPortsDisabled: port 0 disables a socket; disabling both is a
// configuration error Start must refuse rather than "run" with nothing bound.
func TestStart_BothPortsDisabled(t *testing.T) {
	r := New("127.0.0.1", 0, 0)
	if err := r.Start(func(*relay.FlowSample) {}); err == nil {
		t.Fatal("Start with both ports disabled should error")
	}
}

// TestStart_LoadsPersistedTemplates verifies Start restores the template and
// sampler caches from the persist path — the anti-blind-window contract.
func TestStart_LoadsPersistedTemplates(t *testing.T) {
	persist := filepath.Join(t.TempDir(), "templates.json")
	seed := &cacheSet{templates: newTemplateCache(), samplers: newSamplerCache()}
	seed.templates.put(tKey("192.0.2.1", 3, 256), stdFields(), 0, false, time.Now())
	seed.samplers.setDomainRate(exporterKey{"192.0.2.1", 3}, 512)
	if err := seed.SaveTo(persist); err != nil {
		t.Fatalf("seed SaveTo: %v", err)
	}

	r := New("127.0.0.1", freeUDPPort(t), 0)
	r.SetTemplatePersistPath(persist)
	if err := r.Start(func(*relay.FlowSample) {}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	if r.caches.templates.get(tKey("192.0.2.1", 3, 256), time.Now()) == nil {
		t.Error("persisted template not loaded at Start")
	}
	if rate := r.caches.samplers.rateFor(exporterKey{"192.0.2.1", 3}, 0, false); rate != 512 {
		t.Errorf("persisted sampler rate = %d, want 512", rate)
	}
}

// TestStop_NoOpWhenNotRunning mirrors the sFlow receiver contract.
func TestStop_NoOpWhenNotRunning(t *testing.T) {
	r := New("127.0.0.1", 2055, 4739)
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop on unstarted receiver should return nil, got %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop should also be no-op, got %v", err)
	}
}

// FuzzParseNetFlowDatagram is the parser panic-safety fuzz target. Every input
// is fed TWICE: the template engine is stateful (v9/IPFIX datagrams mutate the
// cache), so the second pass exercises the "state already learned" paths that
// a single feed never reaches. Run with:
//
//	go test -run=^$ -fuzz=FuzzParseNetFlowDatagram -fuzztime=30s ./internal/netflow/...
func FuzzParseNetFlowDatagram(f *testing.F) {
	now := time.Now()

	// Seed: valid v5 datagrams (single record, multi-record, sampled).
	f.Add(validV5Datagram(now))
	f.Add(buildV5(hdrAt(now, 100000),
		v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 1, first: 90000, last: 95000},
		v5Record{src: [4]byte{10, 0, 0, 3}, dst: [4]byte{10, 0, 0, 4}, proto: 1, dstPort: 0x0303, octets: 84, first: 90000, last: 95000},
	))
	{
		hdr := hdrAt(now, 100000)
		hdr.sampling = 0xC064
		hdr.count = 30 // lying count
		f.Add(buildV5(hdr, v5Record{src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, octets: 88, packets: 1}))
	}

	// Seed: truncations at interesting boundaries.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x05})                 // version word only
	f.Add(validV5Datagram(now)[:v5HeaderLen]) // header, no records
	f.Add(validV5Datagram(now)[:v5HeaderLen-3])
	f.Add(validV5Datagram(now)[:v5HeaderLen+17]) // mid-record cut

	// Seed: bare v9/IPFIX version words (truncated-header paths).
	f.Add([]byte{0x00, 0x09, 0x00, 0x01})
	f.Add([]byte{0x00, 0x0a, 0x00, 0x10})

	// Seed: valid v9 template + data (the stateful two-pass feed below decodes
	// the data set on the second pass via the template learned on the first).
	f.Add(buildV9(v9HdrAt(now, 100000),
		fset(0, 0, v9Template(256, tf(ieSourceIPv4Address, 4), tf(ieDestinationIPv4Address, 4), tf(ieOctetDeltaCount, 4), tf(iePacketDeltaCount, 4))),
		fset(256, 0, append(append([]byte{10, 0, 0, 1, 10, 0, 0, 2}, u32be(nil, 100)...), u32be(nil, 1)...)),
	))
	// Seed: valid v9 options template + options data (byte-length semantics).
	f.Add(buildV9(v9HdrAt(now, 100000),
		fset(1, 2, v9OptionsTemplate(260, [][]byte{tf(1, 4)}, [][]byte{tf(ieSamplerID, 2), tf(ieSamplerRandomInterval, 4)})),
		fset(260, 2, append(append(u32be(nil, 0), u16be(nil, 5)...), u32be(nil, 100)...)),
	))
	// Seed: valid IPFIX template + data incl. a varlen enterprise field.
	f.Add(validIPFIXMessage(now))
	f.Add(buildIPFIX(uint32(now.Unix()), 1, 3,
		fset(2, 0, ipfixTemplate(257, etf(penPaloAlto, 1001, varlenFieldLen), tf(ieOctetDeltaCount, 4))),
		fset(257, 0, append(append([]byte{3}, []byte("dns")...), u32be(nil, 100)...)),
	))
	// Seed: IPFIX withdrawal records (per-template + withdraw-all).
	f.Add(buildIPFIX(uint32(now.Unix()), 2, 3,
		fset(2, 0, ipfixWithdrawal(256), ipfixWithdrawal(2)),
	))

	// Seed: all-zero buffers.
	f.Add(make([]byte, 24))
	f.Add(make([]byte, 1024))

	r := New("127.0.0.1", 2055, 4739)
	r.handler = func(*relay.FlowSample) {}

	f.Fuzz(func(t *testing.T, data []byte) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("parseDatagram panicked on fuzz input: %v\ndata=%x", rec, data)
				}
			}()
			// Twice: template state learned on the first pass must not break
			// (or be broken by) the second.
			r.parseDatagram(data, "192.0.2.1", now)
			r.parseDatagram(data, "192.0.2.1", now)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("parseDatagram hung on fuzz input of %d bytes\ndata=%x", len(data), data)
		}
	})
}
