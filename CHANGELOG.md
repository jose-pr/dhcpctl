# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The command line ends through `duho.run`: Ctrl-C ends with status 130 and a closed
  standard output with status 1, both without a traceback. `--help`, `--version` and a
  usage error still raise `SystemExit`.

## [0.1.0] - 2026-10-19

### Added

- `DHCPServer.render(reservation, action="add")`: what an operation would
  send, contacting nothing, on every shipped backend.
- `dhcpctl.testing.BackendContract`: the suite every shipped backend passes,
  for a third-party backend to run unmodified; it talks to no server.
- The `dhcpctl` command line (`pydhcpctl[cli]`): `render`, `add`,
  `complete`, `remove`, `recipe` and `backends`, a reservation given by flags
  or a document, secrets from `DHCPCTL_*` variables.
- Published as `pydhcpctl`; the import package is `dhcpctl`.
- `connect(uri, *, secrets=None, owner="dhcpctl")`, `register_backend`,
  `unregister_backend`, `backend_names`, `get_backend` and the
  `dhcpctl.backends` entry-point group.
- `DHCPServer`: `add`, `remove`, `keep`, `complete`, `ensure_condition`,
  `condition_recipe`, `remove_condition_member`, `extras`,
  `secret`, `redacted_uri`. A secret is the caller's when it gives one, else
  the URI's user or password, so one URI serves several logins; a password is
  masked in `str`, `repr` and messages.
- `Reservation`, `Target`, `Scope`, `Condition`, `Completion`,
  `parse_conditions`, `parse_completion`. What each serves is a pydhcp
  `DHCPLease` (re-exported): the address (`0.0.0.0` for a MAC-only
  reservation), the options, and the BOOTP header fields `siaddr`, `sname` and
  `file`, which are not options 66 and 67; each backend writes them as its
  server spells the fields. `Reservation.to_mapping` / `from_mapping` and
  `to_text` / `from_text` write and read a reservation as plain data or a
  JSON, YAML, TOML or INI document (all but JSON with the `formats` extra),
  each lease in pydhcp's `DHCPLease.to_mapping` form.
- Options are pydhcp's `DHCPOptions` and `DHCPOptionCode`, re-exported, and
  reach a backend as pydhcp objects for it to write as its server needs.
  A codemap (`option_codes`, an `OptionCodes` enum, pydhcp's
  `OptionCodeEnum`, its names read by pydhcp's `resolve`) reads a config's option names: declared options with a
  code and a pydhcp type of their own, aliases of names or codes, over pydhcp's
  names, values read by pydhcp's `DHCPOptions.from_mapping` (an enum member
  by name, octets as hex); the Kea and dhcpd backends add their own spellings (`OPTION_NAMES`),
  and `connect(uri, codes=...)` the caller's; `codes.lease(mapping)` takes
  the header fields (`next-server`, `file`, an alias) out of a config's options. Declared types belong to the
  codemap, which starts from the codecs its base has when it is made. netsh's
  data types come from the codecs. An unset address is `UNSPECIFIED`
  (pydhcp's `UNSPECIFIED_ADDRESS`, `0.0.0.0`), as in BOOTP.
- The dnsmasq backend writes its hosts and options files as dnsmasq reads
  them: each line the value of `--dhcp-host` / `--dhcp-option` without the
  key (netboot wrote `dhcp-host=` and `dhcp-option=` prefixes, which dnsmasq
  rejects as "bad hex constant", so no reservation took effect), and the boot
  file and next server as `option:bootfile-name` / `option:server-ip-address`
  in place of a `dhcp-boot` line. An extras line for the options file is
  written the same way. Checked against a real dnsmasq and DHCP client
  (`tests/test_dnsmasq_real.py`).
- A dnsmasq directory (`--dhcp-hostsdir`) is SIGHUPed when an entry it may have
  read is removed or changed: dnsmasq only ever adds what such a directory
  holds, so a completed client kept its boot file. A new entry still needs no
  signal. A reservation with options and no `optsfile=` is refused instead of
  arming the client without them; a trailing `/` on a path that does not exist
  yet means a directory; names that reduce to one tag get distinct tags; a
  missing or hung reload command, an unreadable pidfile and a platform without
  SIGHUP are errors instead of a stray exception or SIGTERM. A local hosts or
  options file is rewritten under a lock on `.<file>.lock`, so two runs at once
  no longer drop each other's entries.
- Every option reaches each server in a form it reads. dhcpd: an option it
  defines is written under its name in its own syntax (119 codes, taken from
  dhcpd 4.4 itself); netboot wrote `unknown-<n>` and octets for all but a
  dozen, which dhcpd parses as the option's own type, so it refused the
  host's statements and served none of them (70 of 134 options). Negative
  numbers and domain names are written bare, and octets for an option dhcpd
  defines with a structure of its own are a `ConfigError`. dnsmasq: a flag,
  a number list and octets are written as octets (`True`, `576,1500` and
  `0a0b` were text or refused). Kea: octets go with `csv-format` off, a flag
  as `true`. Windows: a flag is 1 or 0, and a negative number the DWORD it
  stores (it refused `-3600` for option 2). Checked by sending every option of a
  plain codec through a real dhcpd (`dhcpd -t`) and dnsmasq, and one of each
  codec to a real client (`tests/test_dhcpd_real.py`,
  `tests/test_dnsmasq_real.py`).
- Re-arming a client replaces what the server holds for it, on every
  backend: dhcpd and Kea refused, and the Windows cmdlet threw.
- Kea conditions work: a condition is a client class of the client's own,
  tested on its MAC and `option[n].hex` (iPXE's flat option 77 never matched
  `.text`), and what it overrides is served by a second class of the
  client's when it does not match, since Kea serves a reservation's values
  over any class's. The reservation names no `client-classes`, which put the
  client in the class whatever its test said: on a real Kea every client was
  handed the reservation's boot file, iPXE or not. `?target=memory` (host_cmds'
  `operation-target`) arms a Kea with no hosts database. Checked against a
  real Kea 3.0.4 (`tests/test_kea_real.py`).
- Commands run through hostctl hosts: the Windows backend's local, ssh and
  WinRM transports (`hostctl.LocalConfig`, `SSHConfig`, `WinRMConfig`) and a
  dnsmasq `reload=`, locally or over ssh. hostctl delivers a PowerShell script
  whole; netboot piped it into `powershell -Command -`, which runs only the
  first line of a multi-line block and exits 0 even when a cmdlet fails, so
  reservations were reported armed and were not. A script that ends without
  printing its closing `{"ok": true}` is a `ServerError`, as are an
  unreachable host, a refused login and a timeout (`timeout=`, default 120 s).
  ssh is asyncssh, through `hostctl[ssh]`, rather than the system `ssh`
  client; it reads `~/.ssh/config` as `ssh` does, and the `ssh` extra now
  serves windhcp over ssh too. Checked against real Windows PowerShell 5.1
  (`tests/test_windhcp_delivery.py`), and against a live Windows Server 2025
  DHCP server over ssh with both methods: arm, re-arm, keep and remove, the
  policies included (`tests/test_windhcp_live.py`, opt-in).
- The Windows backend removes a target's own policies when it removes the
  target (they kept answering its MAC); leaves an existing shared policy as it
  is, and trusts it on a host without the DhcpServer module; prints, in target
  mode, the MAC-matched policies it would create rather than a scope-wide one,
  with every value quoted against injection (typographic quotes included);
  reads back under `method=netsh` the options it actually set; keeps a
  reservation through netsh when `method=netsh`; and warns about option 119 and
  a next-server it cannot set.
- The Kea backend keeps a reservation and detaches its classes with
  `reservation-update` (or `reservation-del` then `reservation-add` where Kea
  lacks it), checking every result: `reservation-add` on an existing
  reservation was refused, and the detach's answer was ignored. Kea's keep
  writes the `remove`-phase extras, as the other backends' do; a subnet inside
  a `shared-networks` entry is found; `service=` other than `dhcp4` is
  refused.
- The dhcpd backend keeps a host by deleting and creating it again (dhcpd
  refuses to create a host that exists, so keeping and leaving a group failed);
  creates a host in its group in one create, after finding the group by lookup
  or creating it, and arms nothing when the group cannot be made; in group mode
  puts each value a condition overrides in the `else` of its test, since a
  host's statements outrank its group's; writes an option dhcpd has no name
  for as `unknown-<n>` (`dhcp-option-<n>` does not parse); and refuses to arm a
  host that exists rather than failing deep in pypureomapi. Checked against a
  real ISC dhcpd 4.4 and DHCP client (`tests/test_dhcpd_real.py`).
- Backends for dnsmasq, Kea (`kea`/`keas`), ISC dhcpd over OMAPI and Windows
  DHCP (PowerShell or netsh; local, ssh or WinRM), taken from netboot 0.4,
  sending what netboot sent, except that Kea's `option-data` names options by
  code (netboot sent names Kea does not define: `router`, `lease-time`), and a
  Kea client class carries the boot file as its `boot-file-name` field, as a
  reservation does, rather than as option 67.
- Errors under `DHCPCtlError`: `ConfigError`, `UnknownBackendError`,
  `BackendUnavailableError`, `MissingMACError`, `ServerError`,
  `ConditionUnsupportedError`, `ConditionMissingError`.

[Unreleased]: https://github.com/jose-pr/dhcpctl/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jose-pr/dhcpctl/releases/tag/v0.1.0
