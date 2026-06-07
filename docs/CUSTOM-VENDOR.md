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
    Name() string                                          // e.g. "fortigate"

    // Optional sub-interfaces (any combination of these may be implemented):
    DialupVPNProvider  // GetVPNStatus
    SSLVPNProvider     // GetVPNStatus (SSL)
    HAProvider         // GetHAStatus
    SecurityStatsProvider // GetSecurityStats
    SDWANProvider      // GetSDWANHealth
    LicenseProvider    // GetLicenseInfo
}
```

In-tree vendors: `fortigate` (default), `paloalto`, `sonicwall`,
`pfsense`, `opnsense`, `firewalla`, `linux_vpn`, `bsd_vpn`. They
register themselves in `init()`.

To add a new profile:

1. Create `internal/snmp/vendor_<name>.go` implementing `VendorProfile`.
2. In `init()`, call `RegisterVendor(myVendor{})`.
3. Add the name to the `validVendors` list in
   `internal/api/handlers/handlers.go` (server side, if the server also
   polls this vendor).
4. Add a row to the [FEATURES.md](FEATURES.md#vendor-profiles) table.
5. Add tests in `internal/snmp/vendor_test.go` (the existing
   `TestVendorProfile_*` tests pin the registry size and the
   `VendorProfile` interface satisfaction).

See the existing `vendor_fortigate.go` for a complete reference
implementation that satisfies all five optional sub-interfaces.
