# Backends

A server is a URI. Its **scheme** picks the backend; its **query string**
carries that backend's connection settings and, for every other key, the DHCP
options to serve. A key that depends on the client (`boot-file-name`,
`next-server`, `tftp-server-name`, `host-name`, `subnet_id`, `scope`) is refused
in a URI and belongs in the reservation.

| Scheme | Server | How it applies a reservation | Install |
| --- | --- | --- | --- |
| `dnsmasq://` | dnsmasq | writes `dhcp-host` / `dhcp-option` files, local or over `sftp://` | nothing locally; `dhcpctl[ssh]` for remote paths |
| `kea://`, `keas://` | ISC Kea | `reservation-add` / `reservation-del` via the control agent | `dhcpctl[kea]` |
| `dhcpd://` | ISC dhcpd | an OMAPI host object | `dhcpctl[dhcpd]` |
| `windhcp://` | Windows DHCP | its PowerShell cmdlets *or* `netsh`, locally, over ssh or WinRM | nothing locally or over ssh; `dhcpctl[winrm]` for WinRM |

## What is easy to get wrong

- **dnsmasq** re-reads `--dhcp-hostsfile` / `--dhcp-optsfile` only on SIGHUP and
  never re-reads its main config, but `--dhcp-hostsdir` / `--dhcp-optsdir` pick
  up changed files by themselves — which is why a directory needs no `reload=`
  and a plain file does.
- **Kea** needs the `host_cmds` hook loaded *and* a writable hosts backend; a
  file-only Kea loads the hook and still refuses.
- **dhcpd** hosts added over OMAPI do not survive a restart by themselves —
  that is dhcpd's design.
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
| `kea://` | a client class named in the reservation | with the `class_cmds` hook | `ConditionMissingError` with the `client-classes` JSON |
| `dnsmasq://` | — | no: the tag needs a `dhcp-match` line in dnsmasq's own config | `ConditionUnsupportedError` with the lines to add |

## Extra fragments

`raw.<scheme>=` in the query (or `raw.<scheme>.remove=` for teardown), a
reservation's `extras`, or a subclass overriding `extras()` adds text no option
models. It is emitted **verbatim**, after the modelled options:

| Backend | A fragment is | Where it lands |
| --- | --- | --- |
| `dhcpd://` | dhcpd config statements | the host object's `statements` |
| `dnsmasq://` | config lines | the options file for the client's tag |
| `kea://` | an `option-data` entry | the reservation's `option-data` |
| `windhcp://` | a PowerShell line, or `{"Args": [...], "Ignore": false}` for netsh | after the reservation and its options |
