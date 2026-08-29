package sflow

import (
	"sync"
	"testing"

	"firewall-collector/internal/relay"
)

// TestSourceIPStampedOnFlowSample_AUDIT186 pins that the real UDP source is
// threaded onto every emitted flow sample. sFlow attributes a sample by the
// in-band agent_address (SamplerAddress), which is NOT the packet's real
// sender; without the source carried alongside, the collector cannot detect an
// allowlisted device forging another device's identity (AUDIT-186). The live
// receive path calls parseSFlowDatagramFromSource with the remote IP; if that
// plumbing is reverted (SourceIP left empty), this test reds.
func TestSourceIPStampedOnFlowSample_AUDIT186(t *testing.T) {
	ethTCP := buildIPv4EthernetTCPHeader([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 0x02)
	rec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	sample := buildFlowSample(42, 100, 512, rec)
	// agent_address (in-band) is 192.168.1.10; the datagram actually arrives
	// from a DIFFERENT UDP source — the exact split the forgery check needs.
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 7, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagramFromSource(dg, "203.0.113.9")

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	if got[0].SamplerAddress != "192.168.1.10" {
		t.Errorf("SamplerAddress = %q, want the in-band agent 192.168.1.10", got[0].SamplerAddress)
	}
	if got[0].SourceIP != "203.0.113.9" {
		t.Errorf("SourceIP = %q, want the UDP source 203.0.113.9 (AUDIT-186 binding evidence)", got[0].SourceIP)
	}
}

// TestSourceIPStampedOnCounterSample_AUDIT186 is the counter-sample analogue:
// interface counter samples are also keyed on agent_address and must carry the
// UDP source for the same binding check.
func TestSourceIPStampedOnCounterSample_AUDIT186(t *testing.T) {
	rec := buildIfCountersRecord(3, 1_000_000_000, 111, 222, 0, 0, 0, 0)
	sample := buildCountersSample(1, (6<<24)|3, rec)
	dg := buildCountersDatagram([4]byte{192, 168, 1, 10}, 5, sample)

	var (
		mu  sync.Mutex
		got []*relay.InterfaceCounterSample
	)
	r := NewSFlowReceiver("127.0.0.1", 0)
	r.handler = func(*relay.FlowSample) {}
	r.SetCounterHandler(func(cs *relay.InterfaceCounterSample) {
		mu.Lock()
		got = append(got, cs)
		mu.Unlock()
	})

	r.parseSFlowDatagramFromSource(dg, "203.0.113.9")

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("expected 1 counter sample, got %d", len(got))
	}
	if got[0].SamplerAddress != "192.168.1.10" {
		t.Errorf("SamplerAddress = %q, want the in-band agent 192.168.1.10", got[0].SamplerAddress)
	}
	if got[0].SourceIP != "203.0.113.9" {
		t.Errorf("SourceIP = %q, want the UDP source 203.0.113.9", got[0].SourceIP)
	}
}

// TestParseSFlowDatagram_UnknownSourceEmpty confirms the back-compat entry point
// leaves SourceIP empty (source unknown) rather than inventing a value — the
// attribution layer treats an empty SourceIP as "unresolvable" and falls back to
// the claim rather than rejecting.
func TestParseSFlowDatagram_UnknownSourceEmpty(t *testing.T) {
	ethTCP := buildIPv4EthernetTCPHeader([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1, 2, 0x02)
	rec := buildRawPacketRecord(ethTCP, uint32(16+len(ethTCP)))
	sample := buildFlowSample(1, 1, 1, rec)
	dg := buildDatagram([4]byte{192, 168, 1, 10}, 1, sample)

	r, get := newTestReceiver()
	r.parseSFlowDatagram(dg)

	got := get()
	if len(got) != 1 {
		t.Fatalf("expected 1 flow sample, got %d", len(got))
	}
	if got[0].SourceIP != "" {
		t.Errorf("SourceIP = %q, want empty for the source-unknown entry point", got[0].SourceIP)
	}
}
