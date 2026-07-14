package snmp

// L2 topology collection: ARP caches (IP-MIB), MAC forwarding tables
// (BRIDGE-MIB / Q-BRIDGE-MIB) and LLDP neighbor tables (LLDP-MIB). All walks
// use standard MIBs so every vendor gets them without per-vendor code; only
// CDP (Cisco enterprise MIB) goes through the optional CDPProvider vendor
// interface. The server correlates these snapshots across devices to infer
// port-to-port links, so the data contract matters more than usual:
//
//   - MAC addresses are canonical lowercase colon form ("aa:bb:cc:dd:ee:ff").
//   - Only learned, unicast FDB entries are reported.
//   - An unsupported subtree yields an empty result, not an error — most
//     firewalls implement none or only some of these MIBs and that must not
//     produce per-cycle log spam.
//
// Known v1 simplifications (deliberate, documented, firewall-appropriate):
//   - No community@vlan indexed walks — that is a Catalyst-switch idiom; none
//     of the supported firewall vendors need it.
//   - dot1qTpFdb's fdbId index is treated as the VLAN ID directly, skipping
//     the dot1qVlanCurrentTable fdbId→vlanId indirection (true on effectively
//     all firewall implementations).
//   - lldpRemLocalPortNum is treated as an ifIndex best-effort; LocalPortName
//     (from lldpLocPortTable) is the ground-truth join key for the server.

import (
	"net"
	"strconv"
	"strings"

	"firewall-collector/internal/relay"

	"github.com/gosnmp/gosnmp"
)

// MaxTopologyEntriesPerDevice caps the combined ARP+FDB snapshot sent per
// device per topology cycle. It must stay below the server-side batch cap
// (5000) so a snapshot is never truncated server-side — a partially-ingested
// snapshot would silently draw wrong links under the DELETE+INSERT replace
// semantics.
const MaxTopologyEntriesPerDevice = 4000

// L2 topology OIDs (standard MIBs, vendor-neutral).
var (
	// IP-MIB ipNetToMediaTable (classic ARP cache).
	// Index: ifIndex.a.b.c.d — value: physical address.
	OIDIpNetToMediaPhys = ".1.3.6.1.2.1.4.22.1.2"
	// IP-MIB ipNetToPhysicalTable (RFC 4293 successor; walked when the
	// deprecated table is empty). Index: ifIndex.addrType[.addrLen].addr…
	OIDIpNetToPhysicalPhys = ".1.3.6.1.2.1.4.35.1.4"

	// Q-BRIDGE-MIB dot1qTpFdbTable (VLAN-aware forwarding database).
	// Index: fdbId.6-octet-MAC — value: bridge port number.
	OIDDot1qTpFdbPort   = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	OIDDot1qTpFdbStatus = ".1.3.6.1.2.1.17.7.1.2.2.1.3"
	// BRIDGE-MIB dot1dTpFdbTable (legacy FDB). Index: 6-octet-MAC.
	OIDDot1dTpFdbPort   = ".1.3.6.1.2.1.17.4.3.1.2"
	OIDDot1dTpFdbStatus = ".1.3.6.1.2.1.17.4.3.1.3"
	// BRIDGE-MIB dot1dBasePortTable: bridge port → ifIndex.
	OIDDot1dBasePortIfIndex = ".1.3.6.1.2.1.17.1.4.1.2"

	// LLDP-MIB remote systems table (one row per neighbor).
	// Index: timeMark.localPortNum.remIndex.
	OIDLldpRemTable            = ".1.0.8802.1.1.2.1.4.1.1"
	OIDLldpRemChassisIdSubtype = ".1.0.8802.1.1.2.1.4.1.1.4"
	OIDLldpRemChassisId        = ".1.0.8802.1.1.2.1.4.1.1.5"
	OIDLldpRemPortIdSubtype    = ".1.0.8802.1.1.2.1.4.1.1.6"
	OIDLldpRemPortId           = ".1.0.8802.1.1.2.1.4.1.1.7"
	OIDLldpRemPortDesc         = ".1.0.8802.1.1.2.1.4.1.1.8"
	OIDLldpRemSysName          = ".1.0.8802.1.1.2.1.4.1.1.9"
	OIDLldpRemSysDesc          = ".1.0.8802.1.1.2.1.4.1.1.10"
	// LLDP-MIB local port table: localPortNum → port id/description.
	OIDLldpLocPortTable = ".1.0.8802.1.1.2.1.3.7"
	OIDLldpLocPortId    = ".1.0.8802.1.1.2.1.3.7.1.3"
	OIDLldpLocPortDesc  = ".1.0.8802.1.1.2.1.3.7.1.4"
)

// LLDP chassis-id / port-id subtype macAddress (IEEE 802.1AB).
const lldpSubtypeMACAddress = 3 // port id
const lldpChassisSubtypeMAC = 4 // chassis id

// dot1dTpFdbStatus / dot1qTpFdbStatus value for dynamically learned entries.
const fdbStatusLearned = 3

// formatMACLower renders a 6-byte SNMP physical address in the canonical
// lowercase colon form the whole L2-topology pipeline joins on. (The
// interface-stats formatMAC stays uppercase for existing UI consumers; the
// server normalizes both sides at the boundary.)
func formatMACLower(v interface{}) string {
	var b []byte
	switch val := v.(type) {
	case []byte:
		b = val
	case string:
		b = []byte(val)
	default:
		return ""
	}
	if len(b) != 6 {
		return ""
	}
	return net.HardwareAddr(b).String()
}

// isUnicastMAC rejects multicast/broadcast (I/G bit set) and all-zero MACs —
// FDB tables carry both, neither can identify a peer device.
func isUnicastMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	if hw[0]&1 == 1 {
		return false
	}
	for _, o := range hw {
		if o != 0 {
			return true
		}
	}
	return false
}

// walkQuiet walks a subtree that many firewalls simply do not implement. An
// unsupported OID must come back as an empty result, not an error: v2c/v3
// agents end the walk immediately (empty slice, nil error) but SNMPv1 agents
// answer noSuchName, which gosnmp can surface as an error. Only transport
// failures (timeouts — the device stopped answering mid-walk) propagate.
func (s *SNMPClient) walkQuiet(oid string) ([]gosnmp.SnmpPDU, error) {
	pdus, err := s.client.WalkAll(oid)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "timeout") {
			return nil, err
		}
		return nil, nil
	}
	return pdus, nil
}

// GetARPTable walks the device's ARP cache (ipNetToMediaTable, falling back
// to ipNetToPhysicalTable) into TopologyEntry rows with EntryType "arp".
func (s *SNMPClient) GetARPTable() ([]relay.TopologyEntry, error) {
	pdus, err := s.walkQuiet(OIDIpNetToMediaPhys)
	if err != nil {
		return nil, err
	}
	entries := parseIPNetToMedia(pdus)
	if len(entries) == 0 {
		pdus, err = s.walkQuiet(OIDIpNetToPhysicalPhys)
		if err != nil {
			return nil, err
		}
		entries = parseIPNetToPhysical(pdus)
	}
	return entries, nil
}

func parseIPNetToMedia(pdus []gosnmp.SnmpPDU) []relay.TopologyEntry {
	var out []relay.TopologyEntry
	for _, pdu := range pdus {
		suffix := strings.TrimPrefix(pdu.Name, OIDIpNetToMediaPhys+".")
		if suffix == pdu.Name {
			continue
		}
		// Index is ifIndex.a.b.c.d — NOT the bare 4-octet form
		// ipv4FromTableIndex expects, so parse it explicitly.
		parts := strings.Split(suffix, ".")
		if len(parts) != 5 {
			continue
		}
		ifIndex, err := strconv.Atoi(parts[0])
		if err != nil || ifIndex < 0 {
			continue
		}
		ip := strings.Join(parts[1:5], ".")
		if net.ParseIP(ip).To4() == nil {
			continue
		}
		mac := formatMACLower(pdu.Value)
		if mac == "" || !isUnicastMAC(mac) {
			continue
		}
		out = append(out, relay.TopologyEntry{
			EntryType:  "arp",
			IfIndex:    ifIndex,
			MACAddress: mac,
			IPAddress:  ip,
		})
	}
	return out
}

func parseIPNetToPhysical(pdus []gosnmp.SnmpPDU) []relay.TopologyEntry {
	var out []relay.TopologyEntry
	for _, pdu := range pdus {
		suffix := strings.TrimPrefix(pdu.Name, OIDIpNetToPhysicalPhys+".")
		if suffix == pdu.Name {
			continue
		}
		// Index is ifIndex.addrType[.addrLen].addr… — IPv4 only (addrType 1).
		// Standards-compliant agents include the InetAddress length octet;
		// some omit it, so accept both shapes.
		parts := strings.Split(suffix, ".")
		var ipParts []string
		switch {
		case len(parts) == 7 && parts[1] == "1" && parts[2] == "4":
			ipParts = parts[3:7]
		case len(parts) == 6 && parts[1] == "1":
			ipParts = parts[2:6]
		default:
			continue
		}
		ifIndex, err := strconv.Atoi(parts[0])
		if err != nil || ifIndex < 0 {
			continue
		}
		ip := strings.Join(ipParts, ".")
		if net.ParseIP(ip).To4() == nil {
			continue
		}
		mac := formatMACLower(pdu.Value)
		if mac == "" || !isUnicastMAC(mac) {
			continue
		}
		out = append(out, relay.TopologyEntry{
			EntryType:  "arp",
			IfIndex:    ifIndex,
			MACAddress: mac,
			IPAddress:  ip,
		})
	}
	return out
}

// GetFDBTable walks the device's MAC forwarding database (Q-BRIDGE dot1qTpFdb,
// falling back to legacy BRIDGE-MIB dot1dTpFdb) into TopologyEntry rows with
// EntryType "fdb". Bridge port numbers are resolved to ifIndexes through
// dot1dBasePortTable; entries whose port has no mapping are dropped (an FDB
// row without a resolvable interface can't attribute a link).
func (s *SNMPClient) GetFDBTable() ([]relay.TopologyEntry, error) {
	portPdus, err := s.walkQuiet(OIDDot1dBasePortIfIndex)
	if err != nil {
		return nil, err
	}
	portToIfIndex := make(map[int]int, len(portPdus))
	for _, pdu := range portPdus {
		port := getIndexFromOID(pdu.Name, OIDDot1dBasePortIfIndex)
		if port < 0 {
			continue
		}
		portToIfIndex[port] = int(gosnmp.ToBigInt(pdu.Value).Int64())
	}

	ports, err := s.walkQuiet(OIDDot1qTpFdbPort)
	if err != nil {
		return nil, err
	}
	status, err := s.walkQuiet(OIDDot1qTpFdbStatus)
	if err != nil {
		return nil, err
	}
	entries := parseFDB(ports, status, OIDDot1qTpFdbPort, OIDDot1qTpFdbStatus, true, portToIfIndex)
	if len(entries) == 0 {
		ports, err = s.walkQuiet(OIDDot1dTpFdbPort)
		if err != nil {
			return nil, err
		}
		status, err = s.walkQuiet(OIDDot1dTpFdbStatus)
		if err != nil {
			return nil, err
		}
		entries = parseFDB(ports, status, OIDDot1dTpFdbPort, OIDDot1dTpFdbStatus, false, portToIfIndex)
	}
	return entries, nil
}

// fdbIndexMAC extracts the trailing 6-octet MAC from an FDB row index and the
// leading fdbId when present (dot1q). Returns ok=false on a malformed index.
func fdbIndexMAC(suffix string, hasFdbID bool) (mac string, vlanID int, ok bool) {
	parts := strings.Split(suffix, ".")
	want := 6
	if hasFdbID {
		want = 7
	}
	if len(parts) != want {
		return "", 0, false
	}
	if hasFdbID {
		id, err := strconv.Atoi(parts[0])
		if err != nil {
			return "", 0, false
		}
		vlanID = id
		parts = parts[1:]
	}
	b := make([]byte, 6)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return "", 0, false
		}
		b[i] = byte(n)
	}
	return net.HardwareAddr(b).String(), vlanID, true
}

func parseFDB(ports, status []gosnmp.SnmpPDU, portBase, statusBase string, hasFdbID bool, portToIfIndex map[int]int) []relay.TopologyEntry {
	// Status filter: keep learned entries; a row with no status PDU (some
	// agents implement only the port column) is treated as learned. self(4)
	// rows duplicate ifPhysAddress, which already rides InterfaceStats.
	statusByIndex := make(map[string]int, len(status))
	for _, pdu := range status {
		suffix := strings.TrimPrefix(pdu.Name, statusBase+".")
		if suffix == pdu.Name {
			continue
		}
		statusByIndex[suffix] = int(gosnmp.ToBigInt(pdu.Value).Int64())
	}

	var out []relay.TopologyEntry
	for _, pdu := range ports {
		suffix := strings.TrimPrefix(pdu.Name, portBase+".")
		if suffix == pdu.Name {
			continue
		}
		if st, present := statusByIndex[suffix]; present && st != fdbStatusLearned {
			continue
		}
		mac, vlanID, ok := fdbIndexMAC(suffix, hasFdbID)
		if !ok || !isUnicastMAC(mac) {
			continue
		}
		bridgePort := int(gosnmp.ToBigInt(pdu.Value).Int64())
		if bridgePort <= 0 {
			continue
		}
		ifIndex, mapped := portToIfIndex[bridgePort]
		if !mapped || ifIndex <= 0 {
			continue
		}
		out = append(out, relay.TopologyEntry{
			EntryType:  "fdb",
			IfIndex:    ifIndex,
			MACAddress: mac,
			VlanID:     vlanID,
		})
	}
	return out
}

// GetTopologyNeighbors walks the LLDP remote-systems table (standard on every
// vendor that speaks LLDP) plus, where the vendor profile implements
// CDPProvider, the Cisco CDP neighbor cache.
func (s *SNMPClient) GetTopologyNeighbors(vendor ...string) ([]relay.TopologyNeighbor, error) {
	var out []relay.TopologyNeighbor

	remPdus, err := s.walkQuiet(OIDLldpRemTable)
	if err != nil {
		return nil, err
	}
	if len(remPdus) > 0 {
		locPdus, err := s.walkQuiet(OIDLldpLocPortTable)
		if err != nil {
			return nil, err
		}
		out = append(out, parseLLDPRemTable(remPdus, locPdus)...)
	}

	v := ""
	if len(vendor) > 0 {
		v = vendor[0]
	}
	if cdp, ok := s.resolveVendor(v).(CDPProvider); ok {
		pdus, err := s.walkQuiet(cdp.CDPCacheBaseOID())
		if err != nil {
			return nil, err
		}
		if len(pdus) > 0 {
			out = append(out, cdp.ParseCDPNeighbors(pdus)...)
		}
	}
	return out, nil
}

// printableOrMAC renders an LLDP chassis/port identifier: MAC subtypes get the
// canonical lowercase colon form, everything else is kept as trimmed printable
// text (identifiers are neighbor-controlled bytes; control characters are
// stripped so they can't leak into logs or the UI).
func printableOrMAC(v interface{}, subtype int, macSubtype int) string {
	if subtype == macSubtype {
		if mac := formatMACLower(v); mac != "" {
			return mac
		}
	}
	s := strings.TrimSpace(safeString(v))
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func parseLLDPRemTable(remPdus, locPdus []gosnmp.SnmpPDU) []relay.TopologyNeighbor {
	// Local port names: localPortNum → lldpLocPortDesc (preferred) or
	// lldpLocPortId. This is the server's ground-truth join key when
	// lldpRemLocalPortNum is not a real ifIndex.
	locID := map[int]string{}
	locDesc := map[int]string{}
	for _, pdu := range locPdus {
		if strings.HasPrefix(pdu.Name, OIDLldpLocPortId+".") {
			if n := getIndexFromOID(pdu.Name, OIDLldpLocPortId); n >= 0 {
				locID[n] = printableOrMAC(pdu.Value, 0, -1)
			}
		} else if strings.HasPrefix(pdu.Name, OIDLldpLocPortDesc+".") {
			if n := getIndexFromOID(pdu.Name, OIDLldpLocPortDesc); n >= 0 {
				locDesc[n] = printableOrMAC(pdu.Value, 0, -1)
			}
		}
	}
	localPortName := func(port int) string {
		if s := locDesc[port]; s != "" {
			return s
		}
		return locID[port]
	}

	type lldpRow struct {
		localPort      int
		chassisSubtype int
		chassisRaw     interface{}
		portSubtype    int
		portRaw        interface{}
		portDesc       string
		sysName        string
		sysDesc        string
	}
	rows := map[string]*lldpRow{}
	get := func(name, col string) (*lldpRow, bool) {
		suffix := strings.TrimPrefix(name, col+".")
		if suffix == name {
			return nil, false
		}
		// Index: timeMark.localPortNum.remIndex
		parts := strings.Split(suffix, ".")
		if len(parts) != 3 {
			return nil, false
		}
		row, ok := rows[suffix]
		if !ok {
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, false
			}
			row = &lldpRow{localPort: port}
			rows[suffix] = row
		}
		return row, true
	}

	for _, pdu := range remPdus {
		switch {
		case strings.HasPrefix(pdu.Name, OIDLldpRemChassisIdSubtype+"."):
			if row, ok := get(pdu.Name, OIDLldpRemChassisIdSubtype); ok {
				row.chassisSubtype = int(gosnmp.ToBigInt(pdu.Value).Int64())
			}
		case strings.HasPrefix(pdu.Name, OIDLldpRemChassisId+"."):
			if row, ok := get(pdu.Name, OIDLldpRemChassisId); ok {
				row.chassisRaw = pdu.Value
			}
		case strings.HasPrefix(pdu.Name, OIDLldpRemPortIdSubtype+"."):
			if row, ok := get(pdu.Name, OIDLldpRemPortIdSubtype); ok {
				row.portSubtype = int(gosnmp.ToBigInt(pdu.Value).Int64())
			}
		case strings.HasPrefix(pdu.Name, OIDLldpRemPortId+"."):
			if row, ok := get(pdu.Name, OIDLldpRemPortId); ok {
				row.portRaw = pdu.Value
			}
		case strings.HasPrefix(pdu.Name, OIDLldpRemPortDesc+"."):
			if row, ok := get(pdu.Name, OIDLldpRemPortDesc); ok {
				row.portDesc = printableOrMAC(pdu.Value, 0, -1)
			}
		case strings.HasPrefix(pdu.Name, OIDLldpRemSysName+"."):
			if row, ok := get(pdu.Name, OIDLldpRemSysName); ok {
				row.sysName = printableOrMAC(pdu.Value, 0, -1)
			}
		case strings.HasPrefix(pdu.Name, OIDLldpRemSysDesc+"."):
			if row, ok := get(pdu.Name, OIDLldpRemSysDesc); ok {
				row.sysDesc = printableOrMAC(pdu.Value, 0, -1)
			}
		}
	}

	out := make([]relay.TopologyNeighbor, 0, len(rows))
	for _, row := range rows {
		chassis := printableOrMAC(row.chassisRaw, row.chassisSubtype, lldpChassisSubtypeMAC)
		portID := printableOrMAC(row.portRaw, row.portSubtype, lldpSubtypeMACAddress)
		if chassis == "" && row.sysName == "" {
			continue
		}
		out = append(out, relay.TopologyNeighbor{
			Protocol:        "lldp",
			LocalIfIndex:    row.localPort,
			LocalPortName:   localPortName(row.localPort),
			RemoteChassisID: chassis,
			RemotePortID:    portID,
			RemotePortDesc:  row.portDesc,
			RemoteSysName:   row.sysName,
			RemoteSysDesc:   row.sysDesc,
		})
	}
	return out
}

// CapCombinedTopology merges the ARP and FDB snapshots into the single
// per-device payload, enforcing the combined MaxTopologyEntriesPerDevice cap.
// FDB is truncated first — ARP rows carry IP evidence the server can't get
// anywhere else, while a partial FDB still attributes ports for every MAC it
// kept. Returns the merged slice and how many rows were dropped.
func CapCombinedTopology(arp, fdb []relay.TopologyEntry) ([]relay.TopologyEntry, int) {
	max := MaxTopologyEntriesPerDevice
	if len(arp) >= max {
		return arp[:max], len(arp) - max + len(fdb)
	}
	room := max - len(arp)
	if len(fdb) > room {
		return append(arp, fdb[:room]...), len(fdb) - room
	}
	return append(arp, fdb...), 0
}
