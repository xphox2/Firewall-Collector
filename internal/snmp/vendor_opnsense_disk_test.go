package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// hrStorageType OID values (last element = storage-type index).
const (
	oidTypeRam         = ".1.3.6.1.2.1.25.2.1.2"
	oidTypeFixedDisk   = ".1.3.6.1.2.1.25.2.1.4"
	oidTypeNetworkDisk = ".1.3.6.1.2.1.25.2.1.10"
)

func storagePDU(col string, idx int, typ gosnmp.Asn1BER, val interface{}) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: col + "." + itoa(idx), Type: typ, Value: val}
}

func itoa(i int) string {
	// small local int->string to avoid importing strconv just for the fixture
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

func TestOPNsense_ParseDiskUsage(t *testing.T) {
	p := GetVendorProfile("opnsense").(*OPNsenseProfile)

	pdus := []gosnmp.SnmpPDU{
		// RAM row (index 1) — must be excluded.
		storagePDU(onsOIDStorageType, 1, gosnmp.ObjectIdentifier, oidTypeRam),
		storagePDU(onsOIDStorageDescr, 1, gosnmp.OctetString, "Physical memory"),
		storagePDU(onsOIDStorageUnits, 1, gosnmp.Integer, 4096),
		storagePDU(onsOIDStorageSize, 1, gosnmp.Integer, 2000000),
		storagePDU(onsOIDStorageUsed, 1, gosnmp.Integer, 1000000),
		// Root fixed disk (index 31).
		storagePDU(onsOIDStorageType, 31, gosnmp.ObjectIdentifier, oidTypeFixedDisk),
		storagePDU(onsOIDStorageDescr, 31, gosnmp.OctetString, "/"),
		storagePDU(onsOIDStorageUnits, 31, gosnmp.Integer, 512),
		storagePDU(onsOIDStorageSize, 31, gosnmp.Integer, 59927272),
		storagePDU(onsOIDStorageUsed, 31, gosnmp.Integer, 2452560),
		// Network disk (index 32) — must be excluded.
		storagePDU(onsOIDStorageType, 32, gosnmp.ObjectIdentifier, oidTypeNetworkDisk),
		storagePDU(onsOIDStorageDescr, 32, gosnmp.OctetString, "/mnt/nfs"),
		storagePDU(onsOIDStorageUnits, 32, gosnmp.Integer, 4096),
		storagePDU(onsOIDStorageSize, 32, gosnmp.Integer, 100),
		storagePDU(onsOIDStorageUsed, 32, gosnmp.Integer, 50),
		// Unbound chroot bind-mount (index 40) — fixed disk, but must be excluded
		// as noise (duplicates / usage).
		storagePDU(onsOIDStorageType, 40, gosnmp.ObjectIdentifier, oidTypeFixedDisk),
		storagePDU(onsOIDStorageDescr, 40, gosnmp.OctetString, "/var/unbound/lib"),
		storagePDU(onsOIDStorageUnits, 40, gosnmp.Integer, 512),
		storagePDU(onsOIDStorageSize, 40, gosnmp.Integer, 59927272),
		storagePDU(onsOIDStorageUsed, 40, gosnmp.Integer, 2452560),
	}

	got := p.ParseDiskUsage(pdus)
	if len(got) != 1 {
		t.Fatalf("expected 1 fixed-disk row (RAM + NetworkDisk + /var/unbound bind-mount excluded), got %d: %+v", len(got), got)
	}
	d := got[0]
	if d.Mount != "/" {
		t.Errorf("Mount = %q, want /", d.Mount)
	}
	if d.TotalBytes != 59927272*512 {
		t.Errorf("TotalBytes = %d, want %d", d.TotalBytes, uint64(59927272)*512)
	}
	if d.UsedBytes != 2452560*512 {
		t.Errorf("UsedBytes = %d, want %d", d.UsedBytes, uint64(2452560)*512)
	}
	if d.UsedPercent < 4.0 || d.UsedPercent > 4.2 {
		t.Errorf("UsedPercent = %.2f, want ~4.09", d.UsedPercent)
	}
}

func TestOPNsense_ParseDiskUsage_GuardsAndEmpty(t *testing.T) {
	p := GetVendorProfile("opnsense").(*OPNsenseProfile)

	// size==0 → skipped (no div-by-zero).
	zero := []gosnmp.SnmpPDU{
		storagePDU(onsOIDStorageType, 5, gosnmp.ObjectIdentifier, oidTypeFixedDisk),
		storagePDU(onsOIDStorageDescr, 5, gosnmp.OctetString, "/empty"),
		storagePDU(onsOIDStorageUnits, 5, gosnmp.Integer, 4096),
		storagePDU(onsOIDStorageSize, 5, gosnmp.Integer, 0),
		storagePDU(onsOIDStorageUsed, 5, gosnmp.Integer, 0),
	}
	if got := p.ParseDiskUsage(zero); len(got) != 0 {
		t.Errorf("size==0 row should be skipped, got %+v", got)
	}
	if got := p.ParseDiskUsage(nil); got != nil {
		t.Errorf("nil input → nil, got %+v", got)
	}
}

func TestOPNsense_ParseLoadAverage(t *testing.T) {
	p := GetVendorProfile("opnsense").(*OPNsenseProfile)

	pdus := []gosnmp.SnmpPDU{
		{Name: onsBaseOIDLoad + ".1", Type: gosnmp.OctetString, Value: "0.35"},
		{Name: onsBaseOIDLoad + ".2", Type: gosnmp.OctetString, Value: "0.36"},
		{Name: onsBaseOIDLoad + ".3", Type: gosnmp.OctetString, Value: "0.35"},
	}
	got := p.ParseLoadAverage(pdus)
	if len(got) != 1 {
		t.Fatalf("expected 1 load row, got %d", len(got))
	}
	if got[0].Load1 != 0.35 || got[0].Load5 != 0.36 || got[0].Load15 != 0.35 {
		t.Errorf("load = %+v, want 0.35/0.36/0.35", got[0])
	}
	if p.ParseLoadAverage(nil) != nil {
		t.Errorf("nil input → nil expected")
	}
}
