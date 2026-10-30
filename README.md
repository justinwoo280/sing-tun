# sing-tun

Simple transparent proxy library.

For Linux, Windows, macOS and iOS.

## lwIP fork

The [`lwip` branch](https://github.com/justinwoo280/sing-tun/tree/lwip) adds an optional
[sing-lwip](https://github.com/justinwoo280/sing-lwip) backend. It is based on upstream
`dev` at [`5b0a1a7`](https://github.com/SagerNet/sing-tun/commit/5b0a1a7a394ed49d1a1adab3877284b86a8af94e).
The upstream `main` and `dev` branches serve as synchronization references; fork
integration commits live on `lwip`.

### Available stacks

| `NewStack` name | Implementation | Required build tags |
|---|---|---|
| `go` or empty | Native Go userspace stack (default) | None |
| `system` | System TCP/IP integration | None |
| `gvisor` | gVisor userspace stack | `with_gvisor` |
| `mixed` | System TCP and gVisor UDP | `with_gvisor` |
| `lwip` | HEV lwIP through sing-lwip | `with_lwip` plus a binding mode below |

The new Go stack, gVisor and lwIP are independent selectable backends. Enabling
`with_lwip` keeps `go` as the default. Applications also need to expose the
corresponding names in their configuration schema.

This module requires Go 1.25 or newer and retains the module path
`github.com/sagernet/sing-tun`. Applications select the fork using a pinned Go module
replacement. Resolve the branch once, then commit the resulting immutable version
in the application's `go.mod` and `go.sum`:

```sh
version=$(go list -m -f '{{.Version}}' github.com/justinwoo280/sing-tun@lwip)
go mod edit "-replace=github.com/sagernet/sing-tun=github.com/justinwoo280/sing-tun@$version"
go mod tidy
```

The dependency chain is:

```text
application → sing-tun (lwip branch) → sing-lwip → pinned lwIP fork commit
```

### Build and select the backend

Build the application with one of these modes, then select `NewStack("lwip", options)`
(or `"stack": "lwip"` in a compatible sing-box TUN configuration):

| Mode | Build settings |
|---|---|
| CGO, prepared C sources | Prepare a local sing-lwip checkout, then `CGO_ENABLED=1 go build -tags with_lwip ./...` |
| CGO, prebuilt native archive | `CGO_ENABLED=1 go build -tags 'with_lwip with_lwip_prebuilt' ./...` |
| PureGo, runtime shared library | `CGO_ENABLED=0 go build -tags 'with_lwip with_purego' ./...` |

CGO needs a compatible C toolchain. PureGo loads a separately C-built shared library;
set `SING_LWIP_LIBRARY` to the matching library path or place it beside the executable.
For Linux musl prebuilt archives, add `with_musl` and use a musl C toolchain.
See sing-lwip's [platform matrix and loader requirements](https://github.com/justinwoo280/sing-lwip#build-targets)
for supported architectures and mobile/platform exceptions.

The published binding and native library modules are pinned together in `go.mod`.
Prebuilt CGO is the direct static-linking option for module consumers. Source-CGO
development requires a local sing-lwip checkout prepared with
`go run ./cmd/build-lwip sync-lwip` and a local module replacement. The pinned lwIP
sources are downloaded and verified at preparation time; they are not bundled
in the Go module. Plain `go build` does not run source preparation automatically.

`with_lwip` is opt-in and can be combined with `with_gvisor`. The backend supplies TCP
streams and UDP datagrams through the existing handlers, including UDP NAT policies,
DNS interception, packet forwarding, loopback handling and network reset. Linux TUN
offload enables native TCP aggregates; devices without that capability use software
segmentation. Receive GSO eligibility follows accepted TCP connection lifetimes.
Linux output uses vectored I/O with a private header copy, preserving the native
packet for software fallback. The backend uses upstream's asynchronous forwarding
stages, including bounded pending judgements and cancellation on reset/close.
Reassembled UDP datagrams retain per-destination DNS/reject/forwarding policy.
TCP streams expose read-waiter and vectorised-read interfaces with adaptive
two-buffer batching.

### Verification and upstream updates

The [lwIP workflow](.github/workflows/lwip.yml) checks prepared-source CGO, prebuilt CGO
and PureGo with the pinned published dependency, plus default/gVisor builds. Backend
regressions use in-memory packets and cover policy handling, fragmentation, GSO,
checksums, buffer reuse and fallback paths.

To update the integration, fetch upstream `dev`, merge it into `lwip`, review changes
to the TUN/forwarding interfaces, and run the backend checks before publishing a new
immutable version. Include the asynchronous forwarding-stage, TUN framing and
UDP policy regressions when upgrading the upstream interfaces.

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
