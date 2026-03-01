package snmp

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

type TrapReceiver struct {
	listenAddr string
	port       int
	community  string
	server     *gosnmp.TrapListener
	handler    func(*relay.TrapEvent)
}

func NewTrapReceiver(listenAddr string, port int, community string) *TrapReceiver {
	return &TrapReceiver{
		listenAddr: listenAddr,
		port:       port,
		community:  community,
		server:     gosnmp.NewTrapListener(),
	}
}

func (t *TrapReceiver) Start(handler func(*relay.TrapEvent)) error {
	t.handler = handler

	t.server.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		if t.community != "" && packet.Community != t.community {
			return
		}
		trap := t.parseTrap(packet, addr)
		if trap != nil && t.handler != nil {
			t.handler(trap)
		}
	}

	listenAddr := fmt.Sprintf("%s:%d", t.listenAddr, t.port)
	log.Printf("[SNMP Trap] Starting listener on %s", listenAddr)

	errCh := make(chan error, 1)
	go func() {
		if err := t.server.Listen(listenAddr); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("trap listener failed: %w", err)
		}
		return nil
	case <-time.After(2 * time.Second):
		return nil
	}
}

func (t *TrapReceiver) Stop() {
	t.server.Close()
	log.Println("[SNMP Trap] Listener stopped")
}

func (t *TrapReceiver) parseTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) *relay.TrapEvent {
	if len(packet.Variables) == 0 {
		return nil
	}

	trap := &relay.TrapEvent{
		Timestamp: time.Now(),
		SourceIP:  addr.IP.String(),
	}

	for _, v := range packet.Variables {
		oid := v.Name
		if strings.HasPrefix(oid, ".1.3.6.1.4.1.12356.101.2.0") {
			trap.TrapOID = oid
			trap.TrapType = getTrapType(oid)
			trap.Severity = getTrapSeverity(oid)
			trap.Message = formatTrapMessage(v, oid)
			break
		}
	}

	if trap.TrapOID == "" {
		return nil
	}

	return trap
}

func getTrapType(oid string) string {
	switch oid {
	case TrapVPNTunnelUp:
		return "VPN_TUNNEL_UP"
	case TrapVPNTunnelDown:
		return "VPN_TUNNEL_DOWN"
	case TrapHASwitch:
		return "HA_SWITCH"
	case TrapHAStateChange:
		return "HA_STATE_CHANGE"
	case TrapHAHBFail:
		return "HA_HEARTBEAT_FAIL"
	case TrapHAMemberDown:
		return "HA_MEMBER_DOWN"
	case TrapHAMemberUp:
		return "HA_MEMBER_UP"
	case TrapIPSSignature:
		return "IPS_SIGNATURE"
	case TrapIPSanomaly:
		return "IPS_ANOMALY"
	case TrapAVVirus:
		return "AV_VIRUS"
	case TrapAVOversize:
		return "AV_OVERSIZE"
	default:
		return "UNKNOWN"
	}
}

func getTrapSeverity(oid string) string {
	switch oid {
	case TrapVPNTunnelDown, TrapHAHBFail, TrapHAMemberDown, TrapIPSSignature,
		TrapIPSanomaly, TrapAVVirus:
		return "critical"
	case TrapHASwitch, TrapHAStateChange:
		return "warning"
	default:
		return "info"
	}
}

func formatTrapMessage(v gosnmp.SnmpPDU, oid string) string {
	var sb strings.Builder
	sb.WriteString(getTrapType(oid))

	switch v.Type {
	case gosnmp.OctetString:
		sb.WriteString(": ")
		if val, ok := v.Value.([]byte); ok {
			sb.WriteString(string(val))
		}
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks:
		sb.WriteString(": ")
		sb.WriteString(fmt.Sprintf("%d", v.Value))
	}

	return sb.String()
}
