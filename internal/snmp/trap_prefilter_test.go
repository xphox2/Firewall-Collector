package snmp

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-collector/internal/ratelimit"
	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

const prefilterCommunity = "prefilter-test-community"

func encodeTrap(t *testing.T, community string, version gosnmp.SnmpVersion) []byte {
	t.Helper()
	pkt := &gosnmp.SnmpPacket{
		Version:   version,
		Community: community,
		PDUType:   gosnmp.SNMPv2Trap,
		RequestID: 1,
		Variables: []gosnmp.SnmpPDU{
			{Name: sysUpTimeOID, Type: gosnmp.TimeTicks, Value: uint32(100)},
			{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
		},
	}
	b, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatalf("marshal trap: %v", err)
	}
	return b
}

func TestHeaderCommunity(t *testing.T) {
	msg := encodeTrap(t, prefilterCommunity, gosnmp.Version2c)
	if got, ok := headerCommunity(msg); !ok || got != prefilterCommunity {
		t.Fatalf("headerCommunity = %q, %v; want %q, true", got, ok, prefilterCommunity)
	}
	_, body, _, ok := berTLV(msg)
	if !ok {
		t.Fatal("berTLV rejected a gosnmp-encoded message")
	}
	long := append([]byte{0x30, 0x82, byte(len(body) >> 8), byte(len(body))}, body...)
	if got, ok := headerCommunity(long); !ok || got != prefilterCommunity {
		t.Errorf("long-form length: got %q, %v", got, ok)
	}
	bad := map[string][]byte{
		"empty":           {},
		"truncated":       msg[:10],
		"length overflow": {0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01},
		"version 3":       {0x30, 0x08, 0x02, 0x01, 0x03, 0x04, 0x03, 'a', 'b', 'c'},
		"community short": {0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x09, 'a', 'b', 'c'},
	}
	for name, b := range bad {
		if c, ok := headerCommunity(b); ok {
			t.Errorf("%s: accepted (community %q)", name, c)
		}
	}
}

// TestHandleDatagram_DropsBeforeDecode: a wrong-community datagram and an
// over-rate one never reach the relay; a valid one does.
func TestHandleDatagram_DropsBeforeDecode(t *testing.T) {
	tr := NewTrapReceiver("127.0.0.1", 0, prefilterCommunity)
	var mu sync.Mutex
	var got int
	tr.handler = func(*relay.TrapEvent) { mu.Lock(); got++; mu.Unlock() }
	drops := 0
	tr.SetRateLimiter(ratelimit.New(ratelimit.Config{PerSourceRate: 0.001, PerSourceBurst: 1, GlobalRate: 1000, GlobalBurst: 1000, MaxSources: 100}), func() { drops++ })
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}

	out := withCapturedLog(t, func() {
		tr.handleDatagram(encodeTrap(t, "wrong-community-zzzz", gosnmp.Version2c), src)
	})
	if !strings.Contains(out, "community mismatch") || strings.Contains(out, "Received trap") {
		t.Errorf("wrong community: want a mismatch drop before decode, log: %q", out)
	}
	src2 := &net.UDPAddr{IP: net.ParseIP("192.0.2.2")}
	tr.handleDatagram(encodeTrap(t, prefilterCommunity, gosnmp.Version2c), src2)
	tr.handleDatagram(encodeTrap(t, prefilterCommunity, gosnmp.Version2c), src2)
	if drops != 1 {
		t.Errorf("rate-limit drops = %d, want 1 (burst 1)", drops)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := got
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if got != 1 {
		t.Errorf("relayed traps = %d, want 1", got)
	}
}

// TestTrapReceiver_EndToEnd drives the real socket: a forged trap is dropped,
// an authenticated INFORM is relayed and acknowledged, and Stop ends the loop.
func TestTrapReceiver_EndToEnd(t *testing.T) {
	tr := NewTrapReceiver("127.0.0.1", 0, prefilterCommunity)
	var mu sync.Mutex
	var traps []*relay.TrapEvent
	if err := tr.Start(func(e *relay.TrapEvent) { mu.Lock(); traps = append(traps, e); mu.Unlock() }); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tr.Stop()
	port := tr.conn.LocalAddr().(*net.UDPAddr).Port

	send := func(community string, inform bool) error {
		g := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Community: community,
			Version: gosnmp.Version2c, Timeout: 2 * time.Second, Retries: 0}
		if err := g.Connect(); err != nil {
			return err
		}
		defer g.Conn.Close()
		_, err := g.SendTrap(gosnmp.SnmpTrap{IsInform: inform, Variables: []gosnmp.SnmpPDU{
			{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
		}})
		return err
	}
	if err := send("forged-community-xxxx", false); err != nil {
		t.Fatalf("send forged: %v", err)
	}
	if err := send(prefilterCommunity, true); err != nil {
		t.Fatalf("INFORM was not acknowledged: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(traps)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if len(traps) != 1 {
		t.Errorf("relayed %d traps, want exactly 1 (the authenticated INFORM)", len(traps))
	}
	mu.Unlock()

	tr.Stop()
	select {
	case <-tr.done:
	case <-time.After(3 * time.Second):
		t.Fatal("read loop did not exit after Stop")
	}
}

// TestTrapReceiver_RelayedTrapSurvivesNextDatagram: the relay goroutine reads
// the decoded packet after the read loop has moved on to the next datagram.
// gosnmp's OctetString values alias the datagram bytes, so the loop must hand
// each datagram its own buffer — else the next read rewrites a trap that is
// still being relayed.
func TestTrapReceiver_RelayedTrapSurvivesNextDatagram(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	beforeRelay = func() { once.Do(func() { <-release }) }
	defer func() { beforeRelay = nil }()

	tr := NewTrapReceiver("127.0.0.1", 0, prefilterCommunity)
	got := make(chan *relay.TrapEvent, 2)
	if err := tr.Start(func(e *relay.TrapEvent) { got <- e }); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tr.Stop()
	addr := tr.conn.LocalAddr().(*net.UDPAddr)

	trapWith := func(community, text string) []byte {
		pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: community, PDUType: gosnmp.SNMPv2Trap, RequestID: 1,
			Variables: []gosnmp.SnmpPDU{
				{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
				{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.OctetString, Value: []byte(text)},
			}}
		b, err := pkt.MarshalMsg()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first := strings.Repeat("A", 32)
	c.Write(trapWith(prefilterCommunity, first))
	time.Sleep(100 * time.Millisecond) // the first relay is now parked in beforeRelay
	// Same length and layout, different bytes: overwrites the read buffer in place.
	c.Write(trapWith("forged-community-xxxxxxx"[:len(prefilterCommunity)], strings.Repeat("B", 32)))
	time.Sleep(100 * time.Millisecond)
	close(release)

	select {
	case e := <-got:
		if strings.Contains(e.Message, "BBBB") || !strings.Contains(e.Message, "AAAA") {
			t.Fatalf("relayed trap was rewritten by the next datagram: %q", e.Message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no trap relayed")
	}
}

// TestFormatVarbindValue_ControlCharsNeutralised: a trap's OctetString
// varbind is sender-controlled; it must not carry CR/LF or escapes into the
// relayed message and the receiver's log lines.
func TestFormatVarbindValue_ControlCharsNeutralised(t *testing.T) {
	got := formatVarbindValue(gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("x\r\n2026/01/01 forged\x1b[31m")})
	if strings.ContainsAny(got, "\r\n\x1b") {
		t.Fatalf("formatVarbindValue = %q, control characters survived", got)
	}
}
