package ping

import (
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func echoReplyBytes(t *testing.T, id, seq int) []byte {
	t.Helper()
	m := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("payload")},
	}
	b, err := m.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// fakeIPv4Header builds a minimal 20-byte IPv4 header (no options) so we can
// exercise the strip path that Linux raw IPPROTO_ICMP sockets trigger.
func fakeIPv4Header(payloadLen int) []byte {
	h := make([]byte, ipv4.HeaderLen)
	h[0] = 0x45 // version 4, IHL 5 (20 bytes)
	total := ipv4.HeaderLen + payloadLen
	h[2] = byte(total >> 8)
	h[3] = byte(total)
	h[9] = 1 // protocol ICMP
	return h
}

// TestMatchEchoReply guards the fix for the collector pinging via a raw
// "ip4:icmp" socket (cap_net_raw) instead of the external `ping` binary, which
// reported 100% loss in the rootless container. The trickiest, platform-
// dependent part is that Linux raw sockets prepend the IPv4 header — this pins
// that stripping plus the id/seq matching.
func TestMatchEchoReply(t *testing.T) {
	reply := echoReplyBytes(t, 0x1234, 7)

	// Bare ICMP echo reply (e.g. macOS IP_STRIPHDR / datagram path).
	if !matchEchoReply(reply, 0x1234, 7) {
		t.Error("bare echo reply should match")
	}
	// IPv4-header-prefixed reply (Linux raw socket path).
	withHdr := append(fakeIPv4Header(len(reply)), reply...)
	if !matchEchoReply(withHdr, 0x1234, 7) {
		t.Error("IPv4-prefixed echo reply should match after header strip")
	}
	// Wrong id / seq must not match (concurrent-ping cross-talk guard).
	if matchEchoReply(reply, 0x9999, 7) {
		t.Error("mismatched id must not match")
	}
	if matchEchoReply(withHdr, 0x1234, 8) {
		t.Error("mismatched seq must not match")
	}
	// Garbage / truncated input must not panic or match.
	if matchEchoReply([]byte{0x45, 0x00}, 0x1234, 7) {
		t.Error("truncated input must not match")
	}
	if matchEchoReply(nil, 0x1234, 7) {
		t.Error("nil input must not match")
	}
}
