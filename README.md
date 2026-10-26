# sing-tun

Simple transparent proxy library.

For Linux, Windows, macOS and iOS.

## lwIP fork

The [`lwip` branch](https://github.com/justinwoo280/sing-tun/tree/lwip) adds an optional
[sing-lwip](https://github.com/justinwoo280/sing-lwip) backend. It is based on upstream
`main` at [`040db71`](https://github.com/SagerNet/sing-tun/commit/040db71fcd33196f1d15708b91eb61e9dc6ab8dd).
The upstream `main` and `dev` branches serve as synchronization references; fork
integration commits live on `lwip`.

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
| CGO, bundled C sources | `CGO_ENABLED=1 go build -tags with_lwip ./...` |
| CGO, prebuilt native archive | `CGO_ENABLED=1 go build -tags 'with_lwip with_lwip_prebuilt' ./...` |
| PureGo, runtime shared library | `CGO_ENABLED=0 go build -tags 'with_lwip with_purego' ./...` |

CGO needs a compatible C toolchain. PureGo loads a separately C-built shared library;
set `SING_LWIP_LIBRARY` to the matching library path or place it beside the executable.
For Linux musl prebuilt archives, add `with_musl` and use a musl C toolchain.
See sing-lwip's [platform matrix and loader requirements](https://github.com/justinwoo280/sing-lwip#build-targets)
for supported architectures and mobile/platform exceptions.

`with_lwip` is opt-in and can be combined with `with_gvisor`. The backend supplies TCP
streams and UDP datagrams through the existing handlers, including UDP NAT policies,
DNS interception, packet forwarding, loopback handling and network reset. Linux TUN
offload enables native TCP aggregates; devices without that capability use software
segmentation. Receive GSO eligibility follows accepted TCP connection lifetimes.

### Verification and upstream updates

The [lwIP workflow](.github/workflows/lwip.yml) checks bundled-source CGO, prebuilt CGO
and PureGo with the pinned published dependency, plus default/gVisor builds. Backend
regressions use in-memory packets and cover policy handling, fragmentation, GSO,
checksums, buffer reuse and fallback paths.

To update the integration, fetch upstream `main`, merge it into `lwip`, review changes
to the TUN/forwarding interfaces, and run the backend checks before publishing a new
immutable version. `dev` currently includes a different default Go stack and broader
forwarding changes, so adopting it is a separate integration step.

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
