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

// Standard SNMPv2c trap varbind OIDs
const (
	snmpTrapOID = ".1.3.6.1.6.3.1.1.4.1.0"
	sysUpTimeOID = ".1.3.6.1.2.1.1.3.0"
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
		log.Printf("[SNMP Trap] Received trap from %s (%d varbinds, version %s, community %q)",
			addr.IP, len(packet.Variables), packet.Version, packet.Community)

		if t.community != "" && packet.Community != t.community {
			log.Printf("[SNMP Trap] Dropped: community mismatch (expected %q)", t.community)
			return
		}
		trap := t.parseTrap(packet, addr)
		if trap != nil && t.handler != nil {
			log.Printf("[SNMP Trap] Accepted: type=%s severity=%s from %s", trap.TrapType, trap.Severity, trap.SourceIP)
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

	// SNMPv2c/v3 traps: the trap OID is the VALUE of the snmpTrapOID.0 varbind,
	// not the name. The first two varbinds are sysUpTime.0 and snmpTrapOID.0.
	// SNMPv1 traps: gosnmp puts the enterprise OID in the SnmpTrap field.
	trapOID := ""

	if packet.Version == gosnmp.Version1 {
		// v1: trap OID is constructed from enterprise + specific-trap
		if packet.SnmpTrap.Enterprise != "" {
			trapOID = fmt.Sprintf("%s.0.%d", packet.SnmpTrap.Enterprise, packet.SnmpTrap.SpecificTrap)
		}
	} else {
		// v2c/v3: look for snmpTrapOID.0 varbind — its value is the trap OID
		for _, v := range packet.Variables {
			if v.Name == snmpTrapOID {
				if oid, ok := v.Value.(string); ok {
					trapOID = oid
				}
				break
			}
		}
	}

	// Check if it's a known FortiGate trap
	if trapOID != "" && strings.HasPrefix(trapOID, ".1.3.6.1.4.1.12356.101.2.0") {
		trap.TrapOID = trapOID
		trap.TrapType = getTrapType(trapOID)
		trap.Severity = getTrapSeverity(trapOID)
	}

	// Also scan varbind names as fallback (some devices put the trap OID as a varbind name)
	if trap.TrapOID == "" {
		for _, v := range packet.Variables {
			if strings.HasPrefix(v.Name, ".1.3.6.1.4.1.12356.101.2.0") {
				trap.TrapOID = v.Name
				trap.TrapType = getTrapType(v.Name)
				trap.Severity = getTrapSeverity(v.Name)
				break
			}
		}
	}

	// If we still have no recognized OID, accept it as a generic trap with the raw OID
	if trap.TrapOID == "" {
		if trapOID != "" {
			trap.TrapOID = trapOID
			trap.TrapType = "GENERIC"
			trap.Severity = "info"
		} else {
			// Completely unrecognized — log and drop
			log.Printf("[SNMP Trap] Unrecognized trap from %s, varbinds:", addr.IP)
			for _, v := range packet.Variables {
				log.Printf("[SNMP Trap]   OID=%s Type=%d", v.Name, v.Type)
			}
			return nil
		}
	}

	// Build message from all varbinds (skip sysUpTime and snmpTrapOID meta-varbinds)
	trap.Message = buildTrapMessage(trap.TrapType, packet.Variables)

	return trap
}

func buildTrapMessage(trapType string, vars []gosnmp.SnmpPDU) string {
	var sb strings.Builder
	sb.WriteString(trapType)

	for _, v := range vars {
		// Skip the standard meta-varbinds
		if v.Name == snmpTrapOID || v.Name == sysUpTimeOID {
			continue
		}
		val := formatVarbindValue(v)
		if val != "" {
			sb.WriteString("; ")
			sb.WriteString(val)
		}
	}

	return sb.String()
}

func formatVarbindValue(v gosnmp.SnmpPDU) string {
	switch v.Type {
	case gosnmp.OctetString:
		if val, ok := v.Value.([]byte); ok && len(val) > 0 {
			return string(val)
		}
	case gosnmp.Integer:
		return fmt.Sprintf("%d", v.Value)
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Counter64:
		return fmt.Sprintf("%d", v.Value)
	case gosnmp.ObjectIdentifier:
		if val, ok := v.Value.(string); ok {
			return val
		}
	case gosnmp.IPAddress:
		if val, ok := v.Value.(string); ok {
			return val
		}
	}
	return ""
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
