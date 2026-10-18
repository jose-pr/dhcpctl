# Backends

A server is a URI. Its **scheme** picks the backend, and its **query string**
says only how to reach the server: the backend's connection settings below,
nothing else. What to serve belongs to each reservation: a pydhcp `DHCPLease`,
its options named as [pydhcp](https://github.com/jose-pr/pydhcp) names them
(`router`, `dns`, `bootfile-name`, `option-<n>`) or by an alias, beside the
BOOTP header fields `siaddr` (`next-server`), `sname` and `file` (the boot
file), which are not options: each backend writes them as its server spells
the fields.

| Scheme | Server | How it applies a reservation | Install |
| --- | --- | --- | --- |
| `dnsmasq://` | dnsmasq | writes `--dhcp-hostsfile` / `--dhcp-optsfile` entries, local or over `sftp://` | nothing locally; `pydhcpctl[ssh]` for remote paths |
| `kea://`, `keas://` | ISC Kea | `reservation-add` / `reservation-del` via the control agent | `pydhcpctl[kea]` |
| `dhcpd://` | ISC dhcpd | an OMAPI host object | `pydhcpctl[dhcpd]` |
| `windhcp://` | Windows DHCP | its PowerShell cmdlets *or* `netsh`, locally, over ssh or WinRM | nothing locally; `pydhcpctl[ssh]` over ssh, `pydhcpctl[winrm]` for WinRM |

## What is easy to get wrong

- **dnsmasq** re-reads `--dhcp-hostsfile` / `--dhcp-optsfile` only on SIGHUP and
  never re-reads its main config. `--dhcp-hostsdir` / `--dhcp-optsdir` read a
  new file by themselves but only ever add: a removed or changed entry is
  served until SIGHUP. So a directory arms with no `reload=`, and removing or
  keeping a client signals `pidfile=` (or runs `reload=`, which a remote host
  needs); a plain file needs `reload=` every time. Options need `optsfile=`.
- **Kea** needs the `host_cmds` hook loaded *and* a writable hosts backend; a
  file-only Kea loads the hook and still refuses.
- **dhcpd** writes a host added over OMAPI to its leases file, which is what
  keeps it across a restart: a dhcpd started with a fresh leases file has lost
  it.
- **Windows** validates some option values as it stores them: a name server
  that does not answer is refused. It needs an account with DHCP-administrator
  rights and, for `method=powershell`, the `DhcpServer` module where the shell
  runs; `method=netsh` drives `netsh dhcp server ...` instead. `transport=` is
  how the shell is reached (`local`, `ssh`, `winrm`), `method=` what runs
  there, and `server=` the DHCP server it acts on — `transport=local` with
  `server=` is the ordinary RSAT shape. netsh exits 0 after dropping a value it
  dislikes, so the netsh method reads the state back and fails naming what did
  not land.

## Conditions

A condition serves options only to clients that match a test — the iPXE
chainload is the usual one: hand a PXE ROM the iPXE binary, and iPXE itself the
script.

| Backend | Construct | Created here? | Without the rights |
| --- | --- | --- | --- |
| `windhcp://` | a scope policy per client and condition (plus the class it references), and a base policy for the client; or, with `conditions=shared`, one policy per condition | yes, through the cmdlets — netsh has none | `ConditionMissingError` with the PowerShell to run once |
| `dhcpd://` | an inline `if` on the host, or a named group with `conditions=group` | yes | the recipe is a durable `dhcpd.conf` group |
| `kea://` | a client class of the client's own, plus one serving what it overrides when it does not match | with the `class_cmds` hook | `ConditionMissingError` with the `client-classes` JSON |
| `dnsmasq://` | — | no: the tag needs a `dhcp-match` line in dnsmasq's own config | `ConditionUnsupportedError` with the lines to add |

## Extra fragments

A reservation's `extras` (by phase: `add`, or `remove` for teardown), or a
subclass overriding `extras()`, adds text no option models. It is emitted **verbatim**, after the modelled options:

| Backend | A fragment is | Where it lands |
| --- | --- | --- |
| `dhcpd://` | dhcpd config statements | the host object's `statements` |
| `dnsmasq://` | config lines | the options file for the client's tag |
| `kea://` | an `option-data` entry | the reservation's `option-data` |
| `windhcp://` | a PowerShell line, or `{"Args": [...], "Ignore": false}` for netsh | after the reservation and its options |
