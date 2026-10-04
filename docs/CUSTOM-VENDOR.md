# Adding a custom SNMP vendor profile (collector side)

> Server-side walkthrough: [xphox2/Firewall-Monitoring/docs/custom-vendor.md](https://github.com/xphox2/Firewall-Monitoring/blob/master/docs/custom-vendor.md).
> The collector and the server each have their own `internal/snmp/vendor.go`
> with the same `VendorProfile` interface — vendors registered on the
> **collector** are used when the collector is polling; vendors registered
> on the **server** are used when the server is polling. The two are
> independent; add the profile to whichever side is doing the poll.

The collector's vendor profile registry lives in
`internal/snmp/vendor.go`. The `VendorProfile` interface is:

```go
type VendorProfile interface {
    Name() string                                       // e.g. "fortigate"

    SystemOIDs() []string
    ParseSystemStatus(pdus []gosnmp.SnmpPDU) *relay.SystemStatus
    VPNBaseOID() string
    ParseVPNStatus(pdus []gosnmp.SnmpPDU) []relay.VPNStatus
    HWSensorBaseOID() string
    ParseHardwareSensors(pdus []gosnmp.SnmpPDU) []relay.HardwareSensor
    ProcessorBaseOID() string
    ParseProcessorStats(pdus []gosnmp.SnmpPDU) []relay.ProcessorStats
    TrapOIDs() map[string]TrapDef
}
```

Features your device doesn't expose are one-line stubs (`""` for a
`*BaseOID()`, `nil` for the matching `Parse*`). Nine **optional**
sub-interfaces are declared separately in the same file and picked up by
type assertion when a profile implements them: `DialupVPNProvider`,
`SSLVPNProvider`, `HAProvider`, `SecurityStatsProvider`, `SDWANProvider`,
`LicenseProvider`, `StorageProvider`, `LoadProvider`, `CDPProvider`.

In-tree registered profiles: `generic` (the default for an empty or
unknown vendor), `fortigate`, `paloalto`, `sonicwall`, `cisco_asa`,
`pfsense`, `opnsense`, `firewalla`, `unifi`, `meraki`. They register
themselves in `init()`. (`vendor_linux_vpn.go` / `vendor_bsd_vpn.go` are
shared VPN-parsing helpers, not registered profiles.) A profile for a
device nobody on the project owns — `unifi` and `meraki` today — embeds
`GenericProfile` and says "untested on real hardware; built from vendor
docs" in its type comment until a fixture from a real device exists.

To add a new profile:

1. Create `internal/snmp/vendor_<name>.go` implementing `VendorProfile`.
2. In `init()`, call `RegisterVendor(myVendor{})`.
3. Add the name to the `validVendors` list in
   `internal/api/handlers/handlers.go` (server side, if the server also
   polls this vendor).
4. Add a row to the [FEATURES.md](FEATURES.md#vendor-profiles) table.
5. Add the name to `registeredVendorNames` in
   `internal/snmp/vendor_test.go` (`TestVendorRegistry_RegisteredNames`
   pins the exact registry) and add parser tests for your profile.
6. Update the `test/guardrails/vendor_default_guard_test.go` allowlist only
   if your profile genuinely needs to spell a FortiGate default — it never
   should; an empty or unknown vendor is `generic`.

See the existing `vendor_fortigate.go` for a complete reference
implementation that satisfies six of the nine optional sub-interfaces
(all but `StorageProvider`, `LoadProvider` and `CDPProvider`).
