package relay

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSourceIP_NotSerialized_AUDIT186 pins the json:"-" tag on the collector-
// internal SourceIP field of FlowSample and InterfaceCounterSample: it carries
// the real UDP source only for source-attribution binding and must NEVER reach
// the server wire (the server has no such field and the contract must stay
// identical). If someone drops the json:"-" tag, this reds.
func TestSourceIP_NotSerialized_AUDIT186(t *testing.T) {
	const sentinel = "203.0.113.222"

	fs, err := json.Marshal(&FlowSample{
		SamplerAddress: "192.0.2.1",
		SourceIP:       sentinel,
		SrcAddr:        "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("marshal FlowSample: %v", err)
	}
	if strings.Contains(string(fs), sentinel) || strings.Contains(string(fs), "source_ip") || strings.Contains(string(fs), "SourceIP") {
		t.Errorf("FlowSample JSON leaked the internal SourceIP: %s", fs)
	}

	cs, err := json.Marshal(&InterfaceCounterSample{
		SamplerAddress: "192.0.2.1",
		SourceIP:       sentinel,
		IfIndex:        3,
	})
	if err != nil {
		t.Fatalf("marshal InterfaceCounterSample: %v", err)
	}
	if strings.Contains(string(cs), sentinel) || strings.Contains(string(cs), "source_ip") || strings.Contains(string(cs), "SourceIP") {
		t.Errorf("InterfaceCounterSample JSON leaked the internal SourceIP: %s", cs)
	}
}
