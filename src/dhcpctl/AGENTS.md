# `dhcpctl` — public API header

Header-file-style reference for the `dhcpctl` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is self-contained.
Development documentation lives with the source at
<https://github.com/jose-pr/dhcpctl>.

Every public name is importable from `dhcpctl`; `dhcpctl.exceptions` and
`dhcpctl.backends` (the four backend classes, imported lazily) are public too.
Modules whose name starts with an underscore are private.

`pip install dhcpctl` needs `netimps`, `pathapi` and `pathapi-uri`. Each
backend's library is an extra, imported only when a URI with its scheme is
first **used** (building a server needs none): `kea` (requests), `dhcpd`
(pypureomapi), `winrm` (pywinrm), `ssh` (sftppath with paramiko, for dnsmasq
`sftp://` paths). A missing one raises `BackendUnavailableError` naming
`dhcpctl[<extra>]`. `dhcpctl.__version__` is the installed version. Python 3.9+.

## Connecting (`dhcpctl`)

```python
connect(uri: str, *, secrets: Secrets = None, owner: str = "dhcpctl") -> DHCPServer
```

The backend registered for `uri`'s scheme, built from `uri`. **Does no I/O.**
Raises `UnknownBackendError` (no backend for the scheme), `ConfigError` (no
scheme, or the backend cannot use the URI).

- `secrets`: what the URI does not carry. A secret is the **URI's** when its
  userinfo has it (percent-decoded), else the caller's: a mapping, or a
  callable `key -> str | None` asked **when the value is needed** (so a value
  set after `connect` is seen). Keys: kea and windhcp `user` / `password` (the
  URI's user and password; windhcp's password is for WinRM); dhcpd `keyname` /
  `omapi_key` (the URI's user and password; `keyname=` and `keyfile=` outrank
  them).
- `owner`: letters, digits, `-`, `_` (else `ConfigError`). It names what this
  server writes on the DHCP server: dnsmasq region markers
  `# >>> <owner> <tag>`, the temporary file suffix, Windows policy names
  `<owner>-<machex>[-<condition>]`, the netsh reservation comment, recipe
  comment headers, and the `<OWNER>-NO-POLICY-CMDLETS` marker. Entries written
  under one owner are **not** found under another.

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
    options: DHCPOptions                     # every other query key, with raw.* fragments
    options_builder: str | None              # `options_builder=` from the query, stored, never called
```

Constructing validates the URI and does no I/O. `str()`, `repr()` and the
library's own messages show `redacted_uri`, never a password; `uri` is kept as
given. `URI_SECRETS` (class attribute) maps the URI's `username`/`password`
parts to secret names. Methods take a `Reservation`:

- **`add(r)`** — arm. Every shipped backend ensures `r.conditions` first, so a
  refusal leaves nothing half-applied. Re-arming an existing entry is backend
  specific (Kea raises `ReservationExistsError`).
- **`remove(r)`** — disarm; removing what is not there succeeds.
- **`keep(r)`** — keep the entry with `r.completion.apply_to(r.options)`. Base
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
- **`extras(r, phase="add") -> list`** — backend-native fragments, emitted
  **verbatim** after the modelled options: the URI's `raw.<scheme>` (for
  `add`) and `raw.<scheme>.add` / `raw.<scheme>.remove`, then
  `r.extras[phase]`. Override it to decide per client (`r.context` is the
  caller's), calling `super()`. `phase` not in `PHASES` raises `ValueError`.
- **`client_options(*layers, defaults=None) -> DHCPOptions`** — `defaults`,
  then this URI's options (with its raw fragments), then each layer; later wins.
- **`secret(key) -> str | None`** — the URI's, else from `secrets`, else None.

## Reservations (`dhcpctl`)

Frozen dataclasses.

```python
Target(name: str, mac: MACAddress | None = None, ip: IPAddress | None = None, hostname: str = "")
Scope(name: str = "", network: IPNetwork | None = None, subnet_id: int | None = None, scope_id: str | None = None)
Reservation(target, scope=Scope(), options=DHCPOptions(), conditions={}, completion=Completion(), extras={}, context=None)
```

- `Target.name` labels the client on the server (dhcpd host name, Windows
  reservation name, dnsmasq tag) and in messages. `.ip_text` is `""` for no
  address. `.require_mac(what)` returns the MAC or raises **`MissingMACError`**;
  `NULL_MAC` (`"00:00:00:00:00:00"`) counts as none. dnsmasq, Kea, dhcpd and
  Windows all key a reservation by MAC (dnsmasq `remove` does not need it).
- `Scope.network` is the Kea subnet (matched against `config-get` when no
  `subnet_id`) and the Windows scope (its network address, unless `scope_id`).
  `name` keys Kea's per-scope subnet-id cache.
- `Reservation.options` are served as given: build them with
  `server.client_options(...)` to include the URI's. `conditions` maps name ->
  `Condition`. `extras` maps phase -> fragments. `context` is carried
  untouched.

## Options (`dhcpctl`)

- **`GENERIC_OPTIONS`** — names every backend translates: `router`,
  `domain-name-servers`, `domain-name`, `domain-search`, `next-server`,
  `boot-file-name`, `tftp-server-name`, `host-name`, `subnet-mask`,
  `broadcast-address`, `lease-time`, `ntp-servers`, `vendor-class-identifier`.
  `option-<n>` or a bare number is always accepted (**`is_option(name)`**).
- **`APPLY_TIME`** — keys refused in a URI query because they depend on the
  client: `subnet_id`, `scope`, `boot-file-name`, `next-server`,
  `tftp-server-name`, `host-name`; the `ConfigError` says where each belongs.
- A query key is a backend setting, `options_builder`, `raw.<name>[.add|.remove]`,
  or an option; anything else is a `ConfigError` naming both vocabularies. A
  repeated key is a list (a multi-valued option).
- **`DHCPOptions(dict)`** — `.raw` (`dict[str, list]`), `.raw_for(name,
  phase="add")` (unsuffixed first for `add`), `.copy()` keeps `.raw`.
- `RAW_PREFIX = "raw."`, `OPTIONS_BUILDER = "options_builder"`,
  `PHASES = ("add", "remove")`.

## Conditions (`dhcpctl`)

- **`Condition(name, match, options)`** — `.name`, `.match` (`MATCH_KEYS` key ->
  value; several keys mean all), `.options` (`DHCPOptions`), `.option_codes`
  (`{77: "iPXE"}`).
- **`MATCH_KEYS`** = `{"user-class": 77, "vendor-class": 60}`; **`NAME_CHARS`**
  letters, digits, `-`, `_` (a name reaches PowerShell, dhcpd and Kea).
- **`parse_conditions(declared, where="") -> dict[str, Condition]`** — from
  `{name: {match: {...}, options: {...}}}`; falsy -> `{}`. Raises `ConfigError`
  naming `where` for a bad name, unknown key, empty or unknown `match`, empty
  `options`, unknown option.

Per backend:
- **dnsmasq** refuses (`ConditionUnsupportedError`): the tag needs a
  `dhcp-match` line in dnsmasq's main config, which the opts file cannot hold.
  The message and recipe give the `dhcp-match`/`dhcp-option` pair.
- **Kea**: `class-get`, else `class-add` (needs the `class_cmds` hook; without
  it `ConditionMissingError` with the `client-classes` JSON); the reservation
  names its classes in `client-classes`. A match value with a quote or newline
  is a `ConfigError`.
- **dhcpd**: `conditions=if` (default) inlines `if exists user-class and option
  user-class = "..." { ... }` on the host; `conditions=group` creates a group
  named after the conditions (joined by `-`) and moves the host into it. The
  recipe is a durable `dhcpd.conf` `group` block (OMAPI groups vanish on
  restart).
- **windhcp**: scope-level policies through the cmdlets (**netsh has no policy
  verb**), creating the user/vendor class first. **A reservation's options
  outrank every policy**, so an option id a condition overrides is left off the
  reservation. `conditions=target` (default): one policy per condition matched
  on the MAC and the test, plus a base policy on the MAC alone with the
  overridden values, processing order set explicitly; completion removes them.
  `conditions=shared`: one policy per condition name, no MAC, never removed; the
  base value is the operator's to provide. A host without the DhcpServer module
  raises `ConditionMissingError` with the PowerShell recipe.

## Completion (`dhcpctl`)

- **`Completion(keep=False, options=None)`** — falsy unless `keep`.
  `.apply_to(options)` drops **`BOOT_OPTIONS`** (`boot-file-name`,
  `next-server`, `tftp-server-name`) and puts `.options` in their place
  (**replaced, not merged**), keeping `.raw`.
- **`parse_completion(declared, where="") -> Completion | None`** — from
  `{keep: bool, options: {...}}`; `None` stays `None`. `options` without
  `keep: true` is a `ConfigError`.
- Keeping: dnsmasq rewrites the region; Kea re-adds the reservation
  (`reservation-add` upserts) without boot fields or classes; dhcpd supersedes
  the host in one call; windhcp sets the wanted options and removes the rest
  (already absent is fine).

## Backends (`dhcpctl.backends`)

- **`DnsmasqBackend`** — `dnsmasq://[user@][host]/?hostsfile=&optsfile=&reload=&pidfile=`.
  Writes `dhcp-host=<mac>,set:<tag>[,ip][,hostname]` to `hostsfile` and
  `dhcp-boot`/`dhcp-option=tag:<tag>,...` lines plus extras to `optsfile`. A
  path is a **directory** (ends with `/` or exists: one `<tag>.conf` per
  client) or a **file** (an owned, marked region). A bare path is local
  without a host and `sftp://[user@]host/path` with one; a path may carry its
  own scheme. `reload=` runs a command (over `ssh <host>` when the URI has a
  host), `reload=signal` SIGHUPs `pidfile` locally; with no `reload` a
  directory needs nothing (`--dhcp-hostsdir`) and a file raises `ConfigError`.
  A failing reload is `ServerError`. Writes go through a sibling temporary file
  and a rename where the path type allows.
- **`KeaBackend`** — `kea://[user[:password]@]host[:8000]/?service=dhcp4`
  (account from the `user`/`password` secrets: no user, no auth),
  `keas://` for https. `reservation-add` / `reservation-del` (needs the
  `host_cmds` hook and a writable hosts backend; result 2 is explained).
  `next-server`/`boot-file-name`/`host-name` are reservation fields, the rest
  `option-data` (by name, or `code` for `option-<n>`), extras appended to
  `option-data`. Existing reservation -> `ReservationExistsError`; other
  refusals and HTTP failures -> `ServerError`. `.command(name, arguments)`
  sends one command.
- **`DHCPDBackend`** — `dhcpd://[keyname[:key]@]host[:7911]/?keyname=&keyfile=&conditions=if|group`.
  An OMAPI host (`add_host_supersede`, `del_host`; not-found on remove is
  fine). Options become `statements`: text values quoted with `"`/`\`
  escaped, others must look like addresses or numbers, a newline or NUL is a
  `ConfigError`. `keyname` with no key is a `ConfigError`. `.omapi()` opens a
  connection. **`render_statements(options, raw=None)`** and
  **`render_condition(condition)`** are importable from
  `dhcpctl.backends._dhcpd` for testing. OMAPI hosts do not survive a dhcpd
  restart by themselves.
- **`WinDHCPBackend`** — `windhcp://[user@]host/?transport=local|ssh|winrm&method=powershell|netsh&server=&auth=&port=&ssl=&conditions=target|shared`.
  `transport` is how a shell is reached: `local` (default for an **empty** host;
  `ConfigError` off Windows), `ssh` (default for a named host; the system
  client, `powershell -NoProfile -NonInteractive -Command -` on stdin) or
  `winrm` (pywinrm, `auth` default `ntlm`, `ssl` for https, password secret).
  `method` is what runs: `powershell` (DhcpServer cmdlets) or `netsh` (invoked
  from PowerShell as `& netsh @a`, one argument per array element, judged by
  `$LASTEXITCODE`, state read back with `netsh ... dump` because netsh reports
  success after dropping a value). `server=` is `-ComputerName` / netsh's
  `\\server`. Parameters travel as a JSON payload, never in the script text; an
  option value is always a list. `.run(payload, body)` / `.script_for(...)`
  run or show a script. A non-zero exit is `ServerError`. Extras: a PowerShell
  line, or `{"Args": [...] | "a b c", "Ignore": bool}` — a netsh command, which
  under `method=powershell` becomes a quoted `netsh` call.

## Errors (`dhcpctl.exceptions`, all re-exported)

`DHCPCtlError` is the base of all. `ConfigError(DHCPCtlError, ValueError)`;
`UnknownBackendError(ConfigError)`; `BackendUnavailableError(DHCPCtlError,
ImportError)`; `MissingMACError(DHCPCtlError, LookupError)`;
`ServerError(DHCPCtlError)`; `ReservationExistsError(ServerError)`;
`ConditionUnsupportedError(DHCPCtlError)`;
`ConditionMissingError(DHCPCtlError)` with `.recipe` (also appended to the
message). A transport's own exception (a timeout, a refused connection from
pypureomapi or pywinrm) is not wrapped.

## Logging

Logger `"dhcpctl"`: debug lines for each command, connection and script run,
info when a Kea class is created or a dnsmasq directory needs no reload.
Secrets are never logged.
