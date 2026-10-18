# dhcpctl

[![Version](https://img.shields.io/pypi/v/pydhcpctl.svg)](https://pypi.org/project/pydhcpctl/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydhcpctl.svg)](https://pypi.org/project/pydhcpctl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/dhcpctl/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/dhcpctl/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/dhcpctl/test.yml)](https://github.com/jose-pr/dhcpctl/actions/workflows/test.yml)

One interface to DHCP servers: **arm a reservation** for a client on dnsmasq,
ISC Kea, ISC dhcpd or Windows DHCP, then **remove it or keep it** without its
boot options. A server is a URI: its scheme picks the backend and its query says how to
reach it. The options to serve belong to each reservation.
Documentation: <https://jose-pr.github.io/dhcpctl/>.

## Features

- **Four servers, one call** — `add`, `remove`, `complete` on dnsmasq (files,
  local or over `sftp://`), Kea (control agent), dhcpd (OMAPI) and Windows DHCP
  (PowerShell cmdlets or netsh, locally, over ssh or WinRM).
- **pydhcp's lease** — what a client is served is a [pydhcp](https://github.com/jose-pr/pydhcp)
  `DHCPLease`: its address, its `DHCPOptions` named by pydhcp's registry
  (`router`, `dns`, `option-<n>`) or an alias, each value read by its pydhcp
  codec before any server sees it, and the BOOTP header fields (`next-server`,
  `file`); each backend translates them, and backend-native text in a
  reservation's `extras` rides through untouched.
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
- **Reservations as documents** — `Reservation.to_mapping` / `from_mapping`
  and `to_text` / `from_text` (JSON, YAML, TOML, INI) round-trip a reservation
  through pydhcp's own option form.
- **Pluggable** — a backend is a `DHCPServer` subclass registered for a scheme,
  directly or through the `dhcpctl.backends` entry point.

## Installation

```bash
pip install pydhcpctl
```

The distribution is `pydhcpctl`; the import package is `dhcpctl`.

| Scheme | Server | Install |
| --- | --- | --- |
| `dnsmasq://` | dnsmasq | nothing locally; `pydhcpctl[ssh]` for `sftp://` paths |
| `kea://`, `keas://` | ISC Kea control agent | `pydhcpctl[kea]` (requests) |
| `dhcpd://` | ISC dhcpd over OMAPI | `pydhcpctl[dhcpd]` (pypureomapi) |
| `windhcp://` | Windows DHCP | nothing locally; `pydhcpctl[ssh]` over ssh, `pydhcpctl[winrm]` over WinRM |

`pydhcpctl[formats]` adds YAML, TOML and INI to `Reservation.to_text` /
`from_text` (JSON needs nothing), and `pydhcpctl[cli]` the `dhcpctl` command.

Python 3.9 or later.

## Usage

```python
import dhcpctl
from ipaddress import ip_network

from netimps import MACAddress

server = dhcpctl.connect("kea://kea01:8000/?service=dhcp4")  # how to reach it, nothing else

# Options by name, and the BOOTP header fields beside them (not options).
lease = server.codes.lease(
    {"router": "10.0.0.1", "file": "undionly.kpxe", "next-server": "10.0.0.2"}
)
reservation = dhcpctl.Reservation(
    target=dhcpctl.Target("web01", mac=MACAddress("aa:bb:cc:dd:ee:ff")),
    scope=dhcpctl.Scope("lan", network=ip_network("10.0.0.0/24")),
    lease=lease.replace(ip="10.0.0.10"),
    completion=dhcpctl.Completion(keep=True),  # keep the address when done
)

server.add(reservation)       # arm
server.complete(reservation)  # finished: keep the entry, drop its boot options
```

A condition serves different options to clients that match a test:

```python
import dataclasses

conditions = dhcpctl.parse_conditions(
    {"ipxe": {"match": {"user-class": "iPXE"}, "options": {"file": "boot.ipxe"}}}
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

## Command line

`pip install pydhcpctl[cli]` adds the `dhcpctl` command (also `python -m
dhcpctl`). A reservation is given by flags, or as a document with `--from`
(`.json`, `.yaml`, `.toml`, `.ini`, or `-` for JSON on standard input), which
can also carry conditions and a completion:

```bash
# What arming web01 would send, contacting nothing:
dhcpctl render 'dhcpd://dhcp01/' -n web01 -m aa:bb:cc:dd:ee:ff --ip 10.0.0.10 \
    -o router=10.0.0.1 -o file=undionly.kpxe
dhcpctl add 'kea://kea01/?target=memory' --from web01.json   # arm (or re-arm)
dhcpctl complete 'kea://kea01/?target=memory' --from web01.json --keep
dhcpctl remove 'windhcp://dhcp01/?transport=winrm' -n web01 -m aa:bb:cc:dd:ee:ff
dhcpctl recipe 'windhcp://dhcp01/' --from web01.json         # what an admin sets up once
dhcpctl backends --json
```

`-o name=value` is an option or header field; a comma makes a list
(`dns=10.0.0.53,10.0.0.54`) and `json:` a JSON value (`lease-time=json:600`).
Secrets come from the environment, never a flag: `DHCPCTL_USER`,
`DHCPCTL_PASSWORD`, `DHCPCTL_KEYNAME`, `DHCPCTL_OMAPI_KEY`. Exit status 0 is
done, 1 the server refused or could not be reached, 2 the invocation or the
reservation was wrong.

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

A backend is done when it passes the contract the shipped ones pass, which
talks to no server (it needs pytest, and the backend to implement `render`):

```python
from dhcpctl.testing import BackendContract

class TestRecorder(BackendContract):
    uri = "recorder://anything"
```

## License

MIT
