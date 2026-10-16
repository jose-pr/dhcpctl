# dhcpctl

[![Version](https://img.shields.io/pypi/v/dhcpctl.svg)](https://pypi.org/project/dhcpctl/)
[![Python versions](https://img.shields.io/pypi/pyversions/dhcpctl.svg)](https://pypi.org/project/dhcpctl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/dhcpctl/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/dhcpctl/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/dhcpctl/test.yml)](https://github.com/jose-pr/dhcpctl/actions/workflows/test.yml)

One interface to DHCP servers: **arm a reservation** for a client on dnsmasq,
ISC Kea, ISC dhcpd or Windows DHCP, then **remove it or keep it** without its
boot options. A server is a URI; its scheme picks the backend and its query
carries both the connection settings and the DHCP options to serve.
Documentation: <https://jose-pr.github.io/dhcpctl/>.

## Features

- **Four servers, one call** — `add`, `remove`, `complete` on dnsmasq (files,
  local or over `sftp://`), Kea (control agent), dhcpd (OMAPI) and Windows DHCP
  (PowerShell cmdlets or netsh, locally, over ssh or WinRM).
- **One option vocabulary** — `router`, `boot-file-name`, `next-server`,
  `option-<n>`, ...; each backend translates them, and backend-native text rides
  through untouched (`raw.<scheme>=`).
- **Conditions** — options served only to clients that match a test (the iPXE
  chainload), as a Windows policy, a dhcpd `if` or group, or a Kea client class;
  a backend that cannot express one refuses rather than arming without it, and
  hands over the server-side recipe when it lacks the rights to create it.
- **Completion that does not reinstall** — keep a finished client's reservation
  and replace only its boot options.
- **Values are data, never source** — dhcpd statements are escaped, Windows
  scripts get their parameters as a JSON payload, netsh arguments stay array
  elements.
- **Nothing required** — each backend's library is an extra, imported only when
  its scheme is used; secrets come from the URI or the caller, and a password
  is masked wherever a server is shown.
- **Pluggable** — a backend is a `DHCPServer` subclass registered for a scheme,
  directly or through the `dhcpctl.backends` entry point.

## Installation

```bash
pip install dhcpctl
```

| Scheme | Server | Install |
| --- | --- | --- |
| `dnsmasq://` | dnsmasq | nothing locally; `dhcpctl[ssh]` for `sftp://` paths |
| `kea://`, `keas://` | ISC Kea control agent | `dhcpctl[kea]` (requests) |
| `dhcpd://` | ISC dhcpd over OMAPI | `dhcpctl[dhcpd]` (pypureomapi) |
| `windhcp://` | Windows DHCP | nothing locally or over ssh; `dhcpctl[winrm]` (pywinrm) |

Python 3.9 or later.

## Usage

```python
import dhcpctl
from ipaddress import ip_address, ip_network

from netimps import MACAddress

server = dhcpctl.connect("kea://kea01:8000/?service=dhcp4&router=10.0.0.1")

reservation = dhcpctl.Reservation(
    target=dhcpctl.Target(
        "web01", mac=MACAddress("aa:bb:cc:dd:ee:ff"), ip=ip_address("10.0.0.10")
    ),
    scope=dhcpctl.Scope("lan", network=ip_network("10.0.0.0/24")),
    # The URI's options, then these; later wins.
    options=server.client_options({"boot-file-name": "undionly.kpxe"}),
    completion=dhcpctl.Completion(keep=True),  # keep the address when done
)

server.add(reservation)       # arm
server.complete(reservation)  # finished: keep the entry, drop its boot options
```

A condition serves different options to clients that match a test:

```python
import dataclasses

conditions = dhcpctl.parse_conditions(
    {"ipxe": {"match": {"user-class": "iPXE"}, "options": {"boot-file-name": "boot.ipxe"}}}
)
server.add(dataclasses.replace(reservation, conditions=conditions))
print(server.condition_recipe(reservation, conditions["ipxe"]))  # what an admin applies
```

A secret is the URI's when it carries one, else the caller's, asked for only
when needed — so it can stay out of a URI that ends up in config or logs:

```python
server = dhcpctl.connect(
    "windhcp://dhcp01/?transport=winrm", secrets={"user": "svc", "password": "..."}
)
```

## Writing a backend

```python
class Recorder(dhcpctl.DHCPServer):
    def add(self, reservation): ...
    def remove(self, reservation): ...

dhcpctl.register_backend("recorder", Recorder)
dhcpctl.connect("recorder://anything")
```

or declare it in your package's metadata:

```toml
[project.entry-points."dhcpctl.backends"]
recorder = "mypkg.dhcp:Recorder"
```

## License

MIT
