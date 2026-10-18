# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

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
  SIGHUP are errors instead of a stray exception or SIGTERM.
- The Windows backend's local and ssh transports deliver the script whole: a
  fixed `-EncodedCommand` bootstrap reads it from standard input and runs it
  as one scriptblock. netboot piped it into `powershell -Command -`, which runs
  only the first line of a multi-line block and exits 0 even when a cmdlet
  fails, so reservations were reported armed and were not. A script that
  ends without printing its closing `{"ok": true}` is now a `ServerError`.
  Checked against real Windows PowerShell 5.1 and pwsh 7
  (`tests/test_windhcp_delivery.py`).
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
  `ReservationExistsError`, `ConditionUnsupportedError`,
  `ConditionMissingError`.
