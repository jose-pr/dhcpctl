# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- `connect(uri, *, secrets=None, owner="dhcpctl")`, `register_backend`,
  `unregister_backend`, `backend_names`, `get_backend` and the
  `dhcpctl.backends` entry-point group.
- `DHCPServer`: `add`, `remove`, `keep`, `complete`, `ensure_condition`,
  `condition_recipe`, `remove_condition_member`, `extras`, `client_options`,
  `secret`, `redacted_uri`. A secret is the URI's user or password when it
  carries one, else the caller's; a password is masked in `str`, `repr` and
  messages.
- `Reservation`, `Target`, `Scope`, `DHCPOptions`, `Condition`, `Completion`,
  `parse_conditions`, `parse_completion`.
- Backends for dnsmasq, Kea (`kea`/`keas`), ISC dhcpd over OMAPI and Windows
  DHCP (PowerShell or netsh; local, ssh or WinRM), taken from netboot 0.4,
  sending what netboot sent.
- Errors under `DHCPCtlError`: `ConfigError`, `UnknownBackendError`,
  `BackendUnavailableError`, `MissingMACError`, `ServerError`,
  `ReservationExistsError`, `ConditionUnsupportedError`,
  `ConditionMissingError`.
