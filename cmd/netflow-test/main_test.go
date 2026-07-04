package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"firewall-collector/internal/netflow"
	"firewall-collector/internal/relay"
)

// freeUDPPort grabs an ephemeral UDP port and releases it for the receiver to
// bind. Racy in theory; fine for a local test.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("probe free port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// TestShapesDecodeAgainstReceiver is the end-to-end guard for this tool: every
// crafted conformance shape is fired over real UDP at a real NetFlowReceiver
// and must decode into exactly the rows the tool's "expect:" output promises.
// If a builder here drifts from the parser's spec reading (or vice versa),
// this fails.
func TestShapesDecodeAgainstReceiver(t *testing.T) {
	port := freeUDPPort(t)
	recv := netflow.New("127.0.0.1", port, 0)

	var mu sync.Mutex
	byShape := map[string][]*relay.FlowSample{}
	current := ""
	recv.SetParseEventCallback(func(event string) {
		if event == "malformed" || event == "unknown_version" {
			t.Errorf("shape %q produced parse event %q", current, event)
		}
	})
	if err := recv.Start(func(s *relay.FlowSample) {
		mu.Lock()
		byShape[current] = append(byShape[current], s)
		mu.Unlock()
	}); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer recv.Stop()

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	const (
		rate      = 100
		byteCount = 88
		count     = 2
	)

	// shape → expected emitted rows and (for the sampled shapes) expected
	// forward bytes after the collector's rate multiplication.
	cases := []struct {
		shape    string
		rows     int
		fwdBytes uint64
	}{
		{"v5", count, byteCount * rate},
		{"v9", count, byteCount}, // unsampled → rate 1
		{"ipfix", count, byteCount},
		{"fortigate", count * 2, byteCount * rate}, // forward + biflow reverse
		{"pan", count, byteCount},
		{"asa", count*2 + 1, byteCount}, // teardown fwd+rev, plus 1 denied
		{"sonicwall", count, byteCount},
		{"mikrotik", count, byteCount * rate}, // IE 34 in-data
	}

	for _, tc := range cases {
		mu.Lock()
		current = tc.shape
		mu.Unlock()
		pkts, _ := buildShape(tc.shape, rate, byteCount, count)
		if len(pkts) == 0 {
			t.Fatalf("no packets built for %s", tc.shape)
		}
		for _, p := range pkts {
			if _, err := conn.Write(p.data); err != nil {
				t.Fatalf("send %s: %v", tc.shape, err)
			}
			time.Sleep(20 * time.Millisecond) // preserve template-before-data ordering
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			mu.Lock()
			n := len(byShape[tc.shape])
			mu.Unlock()
			if n >= tc.rows || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for _, tc := range cases {
		rows := byShape[tc.shape]
		if len(rows) != tc.rows {
			t.Errorf("%s: got %d rows, want %d", tc.shape, len(rows), tc.rows)
			continue
		}
		if rows[0].Bytes != tc.fwdBytes {
			t.Errorf("%s: first row bytes = %d, want %d", tc.shape, rows[0].Bytes, tc.fwdBytes)
		}
	}

	// Shape-specific spot checks promised by the tool's "expect:" text.
	if rows := byShape["pan"]; len(rows) > 0 && rows[0].AppName != "ssl" {
		t.Errorf("pan: app_name = %q, want \"ssl\"", rows[0].AppName)
	}
	if rows := byShape["asa"]; len(rows) == count*2+1 {
		denied := rows[len(rows)-1]
		if denied.FirewallEvent != 3 || denied.Bytes != 0 {
			t.Errorf("asa denied row: firewall_event=%d bytes=%d, want 3/0", denied.FirewallEvent, denied.Bytes)
		}
		if rows[0].Packets != 0 {
			t.Errorf("asa teardown packets = %d, want 0 (ASA sends no packet counters)", rows[0].Packets)
		}
	}
	if rows := byShape["fortigate"]; len(rows) >= 2 {
		fwd, rev := rows[0], rows[1]
		if rev.SrcAddr != fwd.DstAddr || rev.DstAddr != fwd.SrcAddr {
			t.Errorf("fortigate reverse row 5-tuple not mirrored: fwd %s→%s rev %s→%s",
				fwd.SrcAddr, fwd.DstAddr, rev.SrcAddr, rev.DstAddr)
		}
		if want := uint64(byteCount/2) * rate; rev.Bytes != want {
			t.Errorf("fortigate reverse bytes = %d, want %d", rev.Bytes, want)
		}
	}
	if rows := byShape["v5"]; len(rows) > 0 && rows[0].FlowSource != relay.FlowSourceNetFlowV5 {
		t.Errorf("v5 flow_source = %d, want %d", rows[0].FlowSource, relay.FlowSourceNetFlowV5)
	}
	if rows := byShape["ipfix"]; len(rows) > 0 {
		if rows[0].FlowSource != relay.FlowSourceIPFIX {
			t.Errorf("ipfix flow_source = %d, want %d", rows[0].FlowSource, relay.FlowSourceIPFIX)
		}
		if rows[0].FlowEndReason != 1 {
			t.Errorf("ipfix flow_end_reason = %d, want 1", rows[0].FlowEndReason)
		}
	}
}
