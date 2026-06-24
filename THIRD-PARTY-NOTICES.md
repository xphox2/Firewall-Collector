# Third-Party Notices

Firewall-Collector is a pure-Go binary; it bundles no browser/JS assets. The
distributed binary statically links the Go modules below. This file lists the
direct dependencies and their licenses; the full transitive set is pinned in
`go.mod` / `go.sum`.

## Go dependencies (`go.mod`)

### Direct dependencies

| Package | Version | License |
|---|---|---|
| [github.com/gosnmp/gosnmp](https://github.com/gosnmp/gosnmp) | v1.43.2 | BSD-2-Clause |
| [github.com/prometheus/client_golang](https://github.com/prometheus/client_golang) | v1.23.2 | Apache-2.0 |
| [go.etcd.io/bbolt](https://github.com/etcd-io/bbolt) | v1.4.3 | MIT |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | v0.52.0 | BSD-3-Clause |

### Indirect dependencies

The above pull in a handful of indirect dependencies; the full list and their
versions are in `go.mod`. License terms for each module are available at
`https://pkg.go.dev/<module-path>?tab=licenses`. Notable transitive dependencies
include `prometheus/client_model` / `prometheus/common` (Apache-2.0),
`golang.org/x/sys` / `golang.org/x/net` (BSD-3-Clause), `google/uuid`
(BSD-3-Clause), `cespare/xxhash` (MIT), and `munnerz/goautoneg` (BSD-3-Clause).

---

## License texts

### MIT License (go.etcd.io/bbolt)

```
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### BSD-2-Clause (github.com/gosnmp/gosnmp)

```
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### BSD-3-Clause (golang.org/x/crypto and the golang.org/x/* modules)

```
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### Apache License 2.0 (github.com/prometheus/client_golang)

`prometheus/client_golang` (and its `prometheus/client_model` / `prometheus/common`
transitive modules) are licensed under the Apache License, Version 2.0. The full
text is at https://www.apache.org/licenses/LICENSE-2.0. Per §4, the upstream
`NOTICE` files are reproduced with the source at
https://github.com/prometheus/client_golang.
