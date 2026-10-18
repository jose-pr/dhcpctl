# `dhcpctl` — public API header

Header-file-style reference for the `dhcpctl` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is self-contained.
Development documentation lives with the source at
<https://github.com/jose-pr/dhcpctl>.

Every public name is importable from `dhcpctl`; `dhcpctl.exceptions` and
`dhcpctl.backends` (the four backend classes, imported lazily) are public too.
Modules whose name starts with an underscore are private.

`pip install pydhcpctl` (the distribution; the import package is `dhcpctl`) needs `netimps`, `pydhcp`, `pathapi`, `pathapi-uri` and
`hostctl`, whose hosts run every command a backend runs (locally, over ssh,
over WinRM). Each backend's library is an extra, imported only when a URI with
its scheme is first **used** (building a server needs none): `kea`
(requests), `dhcpd` (pypureomapi), `winrm` (`hostctl[winrm]`), `ssh`
(`hostctl[ssh]` and `sftppath[uri]`: windhcp over ssh, and a remote dnsmasq's
`sftp://` paths and reload). A missing one raises `BackendUnavailableError` naming
`pydhcpctl[<extra>]`; `formats` (pydhcp's pktcap) adds YAML, TOML and INI
to `Reservation.to_text`. `dhcpctl.__version__` is the installed distribution's version. Python 3.9+.

## Connecting (`dhcpctl`)

```python
connect(uri: str, *, secrets: Secrets = None, owner: str = "dhcpctl", codes: type[OptionCodes] | Mapping | None = None) -> DHCPServer
```

The backend registered for `uri`'s scheme, built from `uri`. **Does no I/O.**
Raises `UnknownBackendError` (no backend for the scheme), `ConfigError` (no
scheme, or the backend cannot use the URI).

- `secrets`: the caller's secrets, which **override the URI's**, so one URI
  serves several logins: a mapping, or a callable `key -> str | None` asked
  **when the value is needed** (so a value set after `connect` is seen). A
  caller's `None` leaves the URI's userinfo (percent-decoded) in effect, and
  `""` is an empty secret. Keys: kea and windhcp `user` / `password` (the
  URI's user and password; windhcp's password is for WinRM); dhcpd `keyname` /
  `omapi_key` (the URI's user and password; `keyname=` and `keyfile=` outrank
  them).
- `owner`: letters, digits, `-`, `_` (else `ConfigError`). It names what this
  server writes on the DHCP server: dnsmasq region markers
  `# >>> <owner> <tag>`, the temporary file suffix, Windows policy names
  `<owner>-<machex>[-<condition>]`, the netsh reservation comment, recipe
  comment headers, and the `<OWNER>-NO-POLICY-CMDLETS` marker. Entries written
  under one owner are **not** found under another.
- `codes`: the codemap `server.codes.lease(...)` reads names with, an `OptionCodes` or
  a declarations mapping; stacked over the backend's own `OPTION_NAMES`, over
  pydhcp's (`server.codes`).

A URI says **only how to reach the server**: its query takes the backend's own
`SETTINGS` and nothing else (`ConfigError`, "options belong to the
reservation").

```python
register_backend(scheme: str, backend: type[DHCPServer] | str, *, replace: bool = False) -> None
unregister_backend(scheme: str) -> bool
backend_names() -> tuple[str, ...]
get_backend(scheme: str) -> type[DHCPServer]
ENTRY_POINT_GROUP = "dhcpctl.backends"
```

Schemes are case-insensitive. `backend` may be `"module:Class"`, imported on
first use. Registering a different backend for a taken scheme raises
`ValueError` unless `replace=True`. Installed packages register through the
entry-point group (name = scheme); one naming a taken scheme is ignored with a
warning. Shipped: `dnsmasq`, `kea`, `keas`, `dhcpd`, `windhcp`.
`get_backend` raises `UnknownBackendError`.

## The contract (`DHCPServer`)

```python
class DHCPServer:
    SETTINGS: ClassVar[frozenset[str]]       # query keys read as connection settings
    def __init__(self, uri, *, secrets=None, owner="dhcpctl"): ...
    uri: str; scheme: str; owner: str
    redacted_uri: str                        # uri with any password as ***; also str(server)
    settings: dict[str, str]                 # the SETTINGS found in the query
    codes: type[OptionCodes]                 # the caller's, then OPTION_NAMES, then pydhcp's
```

Constructing validates the URI and does no I/O. `str()`, `repr()` and the
library's own messages show `redacted_uri`, never a password; `uri` is kept as
given. `URI_SECRETS` (class attribute) maps the URI's `username`/`password`
parts to secret names. Methods take a `Reservation`:

- **`add(r)`** — arm. Every shipped backend ensures `r.conditions` first, so a
  refusal leaves nothing half-applied. **Re-arming replaces** the entry the
  server holds for this client (by MAC), with its options, on every shipped
  backend: dnsmasq rewrites its entry, dhcpd deletes and creates the host, Kea
  `reservation-update`s, Windows removes and adds the reservation.
- **`remove(r)`** — disarm; removing what is not there succeeds.
- **`keep(r)`** — keep the entry serving `r.completion.apply_to(r.lease)`. Base
  raises `NotImplementedError`; all four shipped backends implement it.
- **`complete(r)`** — `remove(r)` unless `r.completion.keep`; then
  `remove_condition_member(r, c)` for each condition, then `keep(r)`.
- **`ensure_condition(r, condition) -> str`** — the construct's name: use it if
  it exists, create it if possible, else raise **`ConditionMissingError`**
  (`.recipe` = `condition_recipe`); the base raises
  **`ConditionUnsupportedError`**.
- **`condition_recipe(r, condition) -> str`** — what a privileged operator
  applies, as text, never run. Same text the error carries. Base: `""`.
- **`remove_condition_member(r, condition)`** — detach this client from a
  shared construct, never deleting it. Base: no-op.
- **`render(r, action="add") -> str`** — what `add`, `keep`, `complete` or
  `remove` would send, **contacting nothing**: the backend's own text, one
  step after another (dnsmasq: each entry's lines under the path they go to,
  a directory only when the setting ends with `/`, then the reload command;
  Kea: each command's JSON body; dhcpd: each OMAPI call; Windows: each
  PowerShell script, payload included). A step that would read the server is
  answered "nothing there yet" (Kea asks for the scope's subnet id instead of
  reading its config). An unknown action is `ValueError`; a backend without
  a recorder raises `NotImplementedError` -- a subclass makes `_recording(sent)`
  return a context in which what it sends is appended to `sent`.
- **`extras(r, phase="add") -> list`** — backend-native fragments, emitted
  **verbatim** after the modelled options: `r.extras[phase]`. Override it to
  decide per client (`r.context` is the caller's), calling `super()`. `phase`
  not in `PHASES` raises `ValueError`. A URI never carries them. `add`
  writes the `add` phase and `keep` the `remove` phase, on every backend;
  `remove` deletes the entry, and only windhcp also runs the `remove` phase.
- **`secret(key) -> str | None`** — from `secrets`, else the URI's, else None.

## Reservations (`dhcpctl`)

Frozen dataclasses.

```python
Target(name: str, mac: MACAddress | None = None, hostname: str = "")
Scope(name: str = "", network: IPNetwork | None = None, subnet_id: int | None = None, scope_id: str | None = None)
Reservation(target, scope=Scope(), lease=DHCPLease("0.0.0.0", strict=False), conditions={}, completion=Completion(), extras={}, context=None)
Reservation.ip_text -> str
Reservation.require_ip(what: str) -> IPv4Address
Reservation.to_mapping() -> dict[str, Any]
Reservation.from_mapping(data: Mapping[str, Any], *, codes=None) -> Reservation
Reservation.to_text(format: str) -> str
Reservation.from_text(text: str, format: str, *, codes=None) -> Reservation
```

- `Target.name` labels the client on the server (dhcpd host name, Windows
  reservation name, dnsmasq tag) and in messages. `.require_mac(what)` returns
  the MAC or raises **`MissingMACError`**; `NULL_MAC`
  (`"00:00:00:00:00:00"`) counts as none. dnsmasq, Kea, dhcpd and Windows all
  key a reservation by MAC (dnsmasq `remove` does not need it).
- `Scope.network` is the Kea subnet (matched against `config-get` when no
  `subnet_id`) and the Windows scope (its network address, unless `scope_id`).
  `name` keys Kea's per-scope subnet-id cache.
- **`Reservation.lease`** is what the server answers the client with: a
  pydhcp **`DHCPLease`** (re-exported), served as given. Its `ip` is the
  client's address, `0.0.0.0` for a MAC-only reservation (build it with
  `strict=False`); `.ip_text` is `""` then, and `.require_ip(what)` raises
  `ConfigError` -- dhcpd and Windows need an address, dnsmasq and Kea do not.
  Its `options` are the merged options; `siaddr`, `sname` and `file` are the
  BOOTP header fields (the next server, its name, the boot file), which are
  **not** options 66 and 67: a backend writes them as its server spells the
  fields. Build it with `server.codes.lease(mapping)` (this backend's
  spellings too), merge option layers with pydhcp's own `copy(*layers)` /
  `update(*layers)`, and set the rest with `lease.replace(ip=...,
  strict=False)`. `conditions` maps name -> `Condition`. `extras` maps
  phase -> fragments. `context` is carried untouched.
- **`.to_mapping()`** / **`Reservation.from_mapping()`** — the reservation as
  plain data and back, to an equal reservation:

  ```yaml
  target: {name: pc1, mac: "aa:bb:cc:dd:ee:ff", hostname: pc1}
  scope: {name: lab, network: 10.0.0.0/24, subnet-id: 3, scope-id: 10.0.0.0}
  lease: {ip: 10.0.0.5, offered: false, siaddr: 10.0.0.2, file: undionly.kpxe, options: {ROUTER: [10.0.0.1]}}
  conditions: {ipxe: {match: {user-class: iPXE}, lease: {ip: 0.0.0.0, offered: false, file: boot.ipxe, options: {}}}}
  completion: {keep: true, lease: {ip: 0.0.0.0, offered: false, file: local, options: {}}}
  extras: {add: ["..."]}
  ```

  Each `lease` is pydhcp's `DHCPLease.to_mapping` form; `conditions` and
  `completion` are what `Condition.to_mapping` and `Completion.to_mapping`
  write. An unset field and a removing completion are left out, and `context`
  is never written. Reading needs only `target.name`; leases are read by
  `DHCPLease.from_mapping` with `codes` (pydhcp's; pass the codemap the
  options were made with) and `strict=False`, `conditions` and `completion` as
  `parse_conditions` and `parse_completion` read them. An unknown key, an
  `extras` phase not in `PHASES` or not a list, or a field that cannot be read
  is a `ConfigError`.
- **`.to_text(format)`** / **`Reservation.from_text(text, format)`** — the same
  as a `"json"`, `"yaml"`, `"toml"` or `"ini"` document, by pydhcp's
  `pydhcp.packet.structured` with its errors; all but JSON need the
  `formats` extra.

## Options and header fields (`dhcpctl`)

Options are **pydhcp's**: `dhcpctl.DHCPOptions` *is* `pydhcp.options.DHCPOptions`
and `dhcpctl.DHCPOptionCode` is pydhcp's registry, both re-exported. Code names
an option by code: `options[DHCPOptionCode.ROUTER] = "10.0.0.1"` or
`options[3]`; a value is whatever the option's pydhcp codec accepts, and stays a
pydhcp object: `options[code]` is the raw payload, `options.get(code)` the
decoded value, `.to_json()` plain data. **A backend decides** which of those its
server needs. pydhcp's own header (`pydhcp/options/AGENTS.md`) is the
container's contract; `copy()` and `update()` are pydhcp's.

**Names are for configs**, and a **codemap** reads them: an `OptionCodes`
enum (a pydhcp `OptionCodeEnum`) holding pydhcp's member names and whatever a
caller declares, passed to pydhcp as `DHCPOptions(codemap=...)`. So a bag
built with it decodes declared options with their declared type, and pydhcp's
`update(**overrides)` takes its names (`bag.update(GW="10.0.0.9")`). As an
`OptionCodeEnum`, each codemap has its own codecs and unnamed members: it
starts with the codecs `base` (pydhcp's `DHCPOptionCode` by default) has when
it is made, then the declared types, and `codes(224).register_type(String)`
binds a codec in that codemap alone. A codemap also names the lease's header
fields: **`BOOT_FIELDS`** = `{"siaddr": "siaddr", "next-server": "siaddr",
"sname": "sname", "file": "file"}`, plus whatever a backend or caller declares.

```python
option_codes(declared=None, *, base=None) -> type[OptionCodes]
```

`declared` maps a name to an option of the caller's own, or to an alias:

```yaml
site-tag: {code: 224, type: String}   # `type`, a pydhcp codec name or List[...] of one, applies to this codemap only
gw: router                            # an alias of a name...
routers: 3                            # ...or of a code
tag: site-tag                         # ...or of another declared name
boot-file-name: file                  # ...or of a header field
```

The codemap holds `base`'s members (pydhcp's by default) and the declared
names; an alias is an enum alias of its member, so its `label()` is the
canonical name. A code with no member is an unnamed member labelled
`UNKNOWN`, as in pydhcp. Every declaration is checked when the codemap is
made, and a bad one raises `ConfigError` (`options.<name>: ...`): an unknown
key, no `code` or one pydhcp refuses, an unknown type, a header field name,
`option-<n>`, a number or a non-identifier as a name, a pydhcp name meaning
another code or a field, an alias of nothing, or a loop. A name declared as
an option over a base's field alias is an option again. **`PYDHCP_CODES`** is
pydhcp's names alone.

- **`codes.resolve(name) -> member`** — pydhcp's `resolve`: a member name in
  any case, `-` or `_` alike (`bootfile-name`), `option-<n>`, a number or an
  int; pydhcp's `ValueError` (or `TypeError`) otherwise.
  **`codes.field(name) -> str | None`** — the header field a name means
  (`"next-server"` -> `"siaddr"`). **`codes.knows(name)`** asks either
  without raising.
- **`codes.options(mapping, where="") -> DHCPOptions`** — a bag with this
  codemap from a mapping of names to values (a `DHCPOptions` is copied, its
  codemap kept), built with pydhcp's `DHCPOptions.from_mapping`: a value is
  what its codec takes, an enum option takes its member name (`DHCPACK`), and
  octets are `{"hex": "0a0b"}` or, for an opaque option, hex text (`0a:0b`).
  A refused value leaves nothing half-built: `ConfigError` with pydhcp's
  message (`option 3 (ROUTER) cannot hold a str: ...`) and ` (on 'where')`.
- **`codes.lease(mapping, where="") -> DHCPLease`** — what a config mapping
  serves: its header-field names (`next-server`, `file`, a declared alias)
  set `siaddr`/`sname`/`file`, `None` or `""` leaving one unset, and the rest
  are `codes.options`; the lease has no address (`0.0.0.0`, `strict=False`).
  A `DHCPLease` is returned as it is. `ConfigError` for what pydhcp refuses
  (`siaddr: Expected 4 octets in 'tftp'`).
- **`codes.read_lease(data, where="") -> DHCPLease`** — `DHCPLease.from_mapping`
  with this codemap and `strict=False`; `ConfigError` for what it refuses.
- **`codes.over(base) -> type[OptionCodes]`** — this codemap's declarations,
  every layer of them, made over `base`. **`OptionCodes.of(x)`** — `x` itself,
  a declarations mapping as a codemap, or `PYDHCP_CODES` for none.
- A **`DHCPOptionCode` formats as its name** (`f"{code}"` is `ROUTER`): write
  `int(code)` wherever a number belongs.
- **`plain_items(options) -> list[tuple[code, Any]]`** — the bag's own codemap members; a helper for a
  backend that writes text: each value as `to_json()` (a list option a list of
  strings, a number an `int`, an opaque option hex).
- **`UNSPECIFIED`** is pydhcp's `UNSPECIFIED_ADDRESS` (`IPv4Address("0.0.0.0")`),
  an address field with nothing in it.
- `PHASES = ("add", "remove")`.

## Conditions (`dhcpctl`)

- **`Condition(name, match, lease, codes=None)`** — `.name`, `.match`
  (`MATCH_KEYS` key -> value; several keys mean all), `.lease` (what is served
  on a match: a `DHCPLease` with no address, or a config mapping read by
  `codes.lease`: Kea's class fields and option-data, dhcpd's statements in the
  `if`, dnsmasq's `dhcp-option` lines in the recipe), `.option_codes`
  (`{77: "iPXE"}`), `.to_mapping()` (`{match, lease}`, which
  `parse_conditions` reads back).
- **`MATCH_KEYS`** = `{"user-class": 77, "vendor-class": 60}`; **`NAME_CHARS`**
  letters, digits, `-`, `_` (a name reaches PowerShell, dhcpd and Kea).
- **`parse_conditions(declared, where="", codes=None) -> dict[str, Condition]`** — from
  `{name: {match: {...}, options: {...}}}` (a config: `options` as
  `codes.lease` reads it) or `{name: {match: {...}, lease: {...}}}` (a
  document); falsy -> `{}`. Raises `ConfigError` naming `where` for a bad name,
  unknown key, empty or unknown `match`, a condition that serves nothing,
  unknown option.

Per backend:
- **dnsmasq** refuses (`ConditionUnsupportedError`): the tag needs a
  `dhcp-match` line in dnsmasq's main config, which the opts file cannot hold.
  The message and recipe give the `dhcp-match` line and the condition's
  `dhcp-option` lines.
- **Kea**: a client class of this client's own, `<condition>-<mac hex>`,
  tested `pkt4.mac == 0x<mac> and option[<code>].hex == '<value>'` (`.hex`:
  iPXE sends option 77 as a flat string); `class-update` when Kea has it, else
  `class-add` (needs the `class_cmds` hook; without it `ConditionMissingError`
  with the `client-classes` JSON). Kea serves a reservation's values over any
  class's, so a value a condition overrides is not in the reservation but in a
  second class, `<owner>-<mac hex>`, tested `pkt4.mac == 0x<mac> and not
  member('<condition class>')...`; the reservation names no `client-classes`
  (that would put the client in them whatever their tests). Leaving a
  condition and `remove` delete both classes (the second first). A class
  carries the header fields as `next-server`, `server-hostname`,
  `boot-file-name`. A match value with a quote or newline is a `ConfigError`.
  Checked against a real Kea 3.0.4 (`tests/test_kea_real.py`).
- **dhcpd**: `conditions=if` (default) inlines `if exists user-class and option
  user-class = "..." { ... }` on the host; `conditions=group` uses the group
  named after the conditions (joined by `-`), creating it when an OMAPI
  lookup finds none (a refused create is a `ServerError` and nothing is
  armed), and creates the host in it. A host's statements outrank its
  group's, so in group mode each value a condition overrides is the host's
  only in the `else` of that condition's test. The recipe is a durable
  `dhcpd.conf` `group` block, for a server where OMAPI may not create one (an
  OMAPI group, like a host, is kept in dhcpd's leases file across a restart).
- **windhcp**: scope-level policies through the cmdlets (**netsh has no policy
  verb**), creating the user/vendor class first. **A reservation's options
  outrank every policy**, so an option id a condition overrides is left off the
  reservation. `conditions=target` (default): one policy per condition matched
  on the MAC and the test, plus a base policy on the MAC alone with the
  overridden values, processing order set explicitly; completion, keeping or
  removing, removes them. `conditions=shared`: one policy per condition name,
  no MAC, never removed; one that exists is used as it is (nothing about it is
  changed), and on a host without the DhcpServer module the policies are
  trusted to exist; the base value is the operator's to provide. In target
  mode a host without the module raises `ConditionMissingError` with the
  PowerShell recipe. The recipe is built from the policies `add` would apply
  (in target mode the MAC-matched pair and their processing order), every
  value a single-quoted literal with `'` and the typographic single quotes
  doubled.

## Completion (`dhcpctl`)

- **`Completion(keep=False, lease=None, codes=None)`** — falsy unless `keep`.
  `.lease` is a `DHCPLease` or a config mapping read by `codes.lease` (none:
  nothing). `.apply_to(lease) -> DHCPLease` drops **`BOOT_OPTIONS`** (67, 66)
  and puts `.lease`'s options in their place, and replaces `siaddr`, `sname`
  and `file` with `.lease`'s (**replaced, not merged**; unset: the client
  falls through to its disk); the address and every other option stay. Equal
  when `keep` and the leases are; `.to_mapping()` is `{keep: false}`, or
  `{keep: true, lease: {...}}`.
- **`parse_completion(declared, where="", codes=None) -> Completion | None`** — from
  `{keep: bool, options: {...}}` (a config) or `{keep: bool, lease: {...}}`
  (a document); `None` stays `None`. Something to serve without `keep: true`
  is a `ConfigError`.
- Keeping: dnsmasq rewrites the region; Kea rewrites the reservation with
  the kept lease and no classes (`reservation-update`, else `reservation-del`
  and `reservation-add`); dhcpd
  deletes and creates the host again (dhcpd refuses to create one that
  exists; for that moment the client has no reservation); windhcp sets the wanted options and removes
  the rest (already absent is fine). Every backend's keep writes the
  `remove`-phase extras.

## Backends (`dhcpctl.backends`)

- **`DnsmasqBackend`** — `dnsmasq://[user@][host]/?hostsfile=&optsfile=&reload=&pidfile=`.
  Writes `<mac>,set:<tag>[,ip][,hostname]` to `hostsfile` and
  `tag:<tag>,<code>,<value>` lines plus extras to `optsfile`: each line is the
  value of `--dhcp-host` / `--dhcp-option` without the key, as dnsmasq(8)
  reads those files, and an extras line is written the same way. A number,
  flag, number list or octets value is its encoded octets as colon hex (one
  octet as a decimal number: alone, `0a` is text to dnsmasq); addresses and
  text as written. The header
  fields are `option:bootfile-name`, `option:tftp-server` and
  `option:server-ip-address` (dnsmasq fills the file field from the first
  unless the client asks for option 67). A
  path is a **directory** (the setting ends with `/`, or it exists: one
  `<tag>.conf` per client) or a **file** (an owned, marked region). A bare
  path is local without a host and `sftp://[user@]host/path` with one; a path
  may carry its own scheme. A reservation that serves anything (an option, a
  header field, an extras line) with no `optsfile` is a `ConfigError`, before
  anything is written. The tag is the target's name; a name with characters a
  tag cannot hold is reduced and gets an 8-hex digest of itself appended, so
  two names never share a tag. **Reloading**: `reload=` runs a command every
  time, as an argv through a hostctl host (this machine, or the URI's host
  over ssh with the `user`/`password` secrets, which needs the `ssh` extra),
  bounded at 60 s; `reload=signal` SIGHUPs
  `pidfile` (default `/run/dnsmasq/dnsmasq.pid`) locally. With no `reload`, a
  file is a `ConfigError`; a directory needs nothing for a new entry, and
  SIGHUPs `pidfile` locally when an entry dnsmasq may have read is removed or
  changed (keep, remove, re-arming with other values), because
  `--dhcp-hostsdir` only adds; on a remote host that is a `ConfigError`
  asking for `reload=`. A failing, missing or hung (60 s) reload command, or a
  pidfile that cannot be signalled, is a `ServerError`; a platform with no
  SIGHUP is a `ConfigError`. Writes go through a sibling temporary file and a
  rename where the path type allows (both dotfiles, which dnsmasq skips in a
  directory); a local **file** is rewritten under an
  exclusive lock on `.<file>.lock`, so concurrent writers keep each other's
  regions (a remote `sftp://` file is not locked).
- **`KeaBackend`** — `kea://[user[:password]@]host[:8000]/?service=dhcp4&target=`
  (account from the `user`/`password` secrets: no user, no auth),
  `keas://` for https; `service=dhcp4` only (anything else is a
  `ConfigError`). `reservation-add` / `reservation-del` (needs the
  `host_cmds` hook and a writable hosts backend; result 2 is explained).
  `target=` is sent as host_cmds' `operation-target` (`memory`, `database`,
  `all`, `default`; Kea 2.7.4+): `memory` keeps reservations in the running
  configuration, which is how a Kea with no hosts database takes them (it
  otherwise answers "Host database not available", and the error says so).
  Keeping rewrites the reservation with
  `reservation-update`, or, on a Kea without it (result 2), `reservation-del`
  then `reservation-add`; every result is checked. A scope's subnet id is
  found among `subnet4` and every `shared-networks` entry's `subnet4`.
  The header fields are the reservation's `next-server`, `server-hostname`
  and `boot-file-name`, option 12 its `hostname`, the rest `option-data`
  entries **by code** (`{"code": 3, "data": ...}`: Kea's option names are not
  pydhcp's; octets as hex with `"csv-format": false`, a flag as `true`/`false`),
  extras appended to `option-data`. Kea's spellings
  (`OPTION_NAMES`) include `boot-file-name` and `server-hostname` for the
  fields. An existing reservation is replaced (`reservation-update`, or
  delete and add); other refusals and HTTP failures -> `ServerError`. `.command(name, arguments)`
  sends one command.
- **`DHCPDBackend`** — `dhcpd://[keyname[:key]@]host[:7911]/?keyname=&keyfile=&conditions=if|group`.
  An OMAPI host, deleted and created again on each arm (OMAPI cannot rewrite
  a host's statements in place) and deleted with `del_host`
  (not-found on remove is fine). The lease becomes `statements`: its options
  named by dhcpd's own table (every code dhcpd 4.4 defines: `routers`,
  `domain-name-servers`, `bootfile-name`, ...) in that option's syntax, any
  other code `unknown-<n>` with quoted text or its octets; octets for one of
  the codes dhcpd defines with a structure of its own (62, 77-79, 85-87, 98,
  136, 137, 159, 212) are a `ConfigError`; then `filename`, `server-name` and `next-server`
  for the header fields (also the names dhcpd's `OPTION_NAMES` reads): a value whose
  pydhcp codec is text (`String`, `OctetString`, `DomainList`) is quoted with
  `"`/`\` escaped, a `DomainName` written bare, others must look like
  addresses or (signed) numbers, a newline or
  NUL is a `ConfigError`. `keyname` with no key is a `ConfigError`. `.omapi()` opens a
  connection: pypureomapi's, with `create_host(ip, mac, name, statements=,
  group=)` and `group_exists(name)` added. Checked against a real ISC dhcpd
  4.4 (`tests/test_dhcpd_real.py`). **`render_statements(lease, extras=None)`** and
  **`render_condition(condition)`** are importable from
  `dhcpctl.backends._dhcpd` for testing. dhcpd keeps an OMAPI host in its
  leases file, so it survives a restart that keeps that file.
- **`WinDHCPBackend`** — `windhcp://[user@]host/?transport=local|ssh|winrm&method=powershell|netsh&server=&auth=&port=&ssl=&timeout=&conditions=target|shared`.
  `transport` is how a shell is reached, as a hostctl host
  (**`.host_config()`** returns its config): `local` (`LocalConfig`; default
  for an **empty** host; `ConfigError` off Windows), `ssh` (`SSHConfig` with
  the PowerShell shell and a Windows path flavour, so a Windows OpenSSH
  server's `cmd.exe` login shell is allowed for; default for a named host;
  the `user`/`password` secrets, then `~/.ssh/config` and the keys as `ssh`
  finds them) or `winrm` (`WinRMConfig`, `auth` default `ntlm`, `ssl`
  for https, the password secret). hostctl delivers the script whole and
  reports its status; `timeout=` (seconds, default 120) bounds one script. A
  non-zero status is a `ServerError` with its error text, and so are an
  unreachable host, a refused login and an expired timeout; a missing
  transport extra is a `BackendUnavailableError`. A script whose output lacks
  its closing `{"ok": true}` is a `ServerError`.
  `method` is what runs: `powershell` (DhcpServer cmdlets) or `netsh` (invoked
  from PowerShell as `& netsh @a`, one argument per array element, judged by
  `$LASTEXITCODE`, state read back with `netsh ... dump` because netsh reports
  success after dropping a value; its data type comes from the option's pydhcp
  codec: addresses `IPADDRESS`, 32-bit `DWORD`, 16-bit `WORD`, 8-bit and
  boolean `BYTE`, else `STRING`). Option ids are the codes. A Windows
  reservation has no header fields, so `file` is sent as option 67 and `sname`
  as 66 unless the lease sets those options itself; `siaddr` and option 119
  are left off, with a WARNING (Windows has no siaddr per reservation and
  defines no 119 by default). `keep` honours `method=netsh` (`set` / `delete
  reservedoptionvalue`, read back as `add` is), and `add` reads back the
  options it set, not those a policy serves. `server=` is `-ComputerName` / netsh's
  `\\server`. Parameters travel as a JSON payload, never in the script text; an
  option value is always a list. `.run(payload, body)` / `.script_for(...)`
  run or show a script. A non-zero exit is `ServerError`. Extras: a PowerShell
  line, or `{"Args": [...] | "a b c", "Ignore": bool}` — a netsh command, which
  under `method=powershell` becomes a quoted `netsh` call.

## Errors (`dhcpctl.exceptions`, all re-exported)

`DHCPCtlError` is the base of all. `ConfigError(DHCPCtlError, ValueError)`;
`UnknownBackendError(ConfigError)`; `BackendUnavailableError(DHCPCtlError,
ImportError)`; `MissingMACError(DHCPCtlError, LookupError)`;
`ServerError(DHCPCtlError)`;
`ConditionUnsupportedError(DHCPCtlError)`;
`ConditionMissingError(DHCPCtlError)` with `.recipe` (also appended to the
message). A failure reaching a Windows or dnsmasq host (refused, unreachable,
a login refused, a timeout) is a `ServerError`; an OMAPI connection's own
exception from pypureomapi is not wrapped.

## Testing a backend (`dhcpctl.testing`)

- **`BackendContract`** — subclass it in a pytest module and set `uri` (a URI
  building the backend, with no I/O), optionally `secret_uri` (the same with
  `{secret}` where a password goes; None skips that test) and `keyed_by_mac`
  (default True). The inherited tests check, through `render` and so with no
  server: building from the URI; a URI with an option (`router=`) is a
  `ConfigError`; a password is in no `str`/`repr`/`redacted_uri`; arming
  renders text naming the client (its MAC in any spelling, or its name),
  removing and keeping render, completing without keeping renders exactly
  as removing; a client with no MAC is `MissingMACError`; a condition is
  served (`boot.ipxe` in the text, a recipe string) or refused with a
  `ConditionUnsupportedError` naming it; an unknown action or phase is
  `ValueError`. `.server()` and `.reservation(server, **changes)` (`web01`,
  10.0.0.10 in 10.0.0.0/24, Kea subnet 1; `mac=None` drops the MAC) are the
  helpers. Needs pytest; `import dhcpctl` never imports it.
- **`SECRET`** — the text `{secret}` is replaced with.

## Command line

`pip install pydhcpctl[cli]` (duho); `dhcpctl` and `python -m dhcpctl` run
**`dhcpctl.cli.main(argv=None) -> int`**, which without the extra exits with one
line naming it. `import dhcpctl` never imports `dhcpctl.cli`.

- `dhcpctl render URI <reservation> [-a add|keep|complete|remove]` —
  `DHCPServer.render` to standard output.
- `dhcpctl add|complete [--keep]|remove URI <reservation>` — the operation,
  then one line saying what was done.
- `dhcpctl recipe URI --from DOC` — `condition_recipe` per condition.
- `dhcpctl backends [--json]` — scheme, class and `SETTINGS` of each backend.

`<reservation>` is `-n NAME [-m MAC] [--ip IP] [--hostname H] [--network CIDR]
[--subnet-id N] [--scope-id S] [-o name=value]...` (a comma in a value makes a
list, `json:` a JSON value), or `--from DOC` alone (`.json`/`.yaml`/`.toml`/
`.ini` by suffix, `-` for JSON on standard input; conditions and completion
only this way). `--owner` (default `dhcpctl`) is the connection's owner.
Secrets are read from `DHCPCTL_USER`, `DHCPCTL_PASSWORD`, `DHCPCTL_KEYNAME`,
`DHCPCTL_OMAPI_KEY`, never from a flag. Exit: 0 done, 1 a `DHCPCTL` error or
`OSError` (the server refused or is unreachable), 2 a `ConfigError` or a
usage error.

## Environment variables

| Variable | Read by | Effect |
| --- | --- | --- |
| `DHCPCTL_USER`, `DHCPCTL_PASSWORD`, `DHCPCTL_KEYNAME`, `DHCPCTL_OMAPI_KEY` | the `dhcpctl` command | that secret for the server; the library reads none |
| `DHCPCTL_REQUIRE_PEERS` | the test suite | a real-peer test that cannot run fails instead of skipping |

## Logging

Logger `"dhcpctl"`: debug lines for each command, connection and script run,
info when a Kea class is created or a new dnsmasq directory entry needs no reload.
Secrets are never logged.
