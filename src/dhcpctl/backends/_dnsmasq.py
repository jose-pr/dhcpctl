"""dnsmasq backend: write reservation files, reload only if we must.

dnsmasq re-reads the files given to `--dhcp-hostsfile` / `--dhcp-optsfile` on
SIGHUP, but **not** its main config file. `--dhcp-hostsdir` / `--dhcp-optsdir`
take a directory and read a new or changed file with no signal, but only ever
**add** what they read: a deleted or rewritten file keeps being served until
SIGHUP (dnsmasq(8)). So directory mode arms a new client with no signal, and
signals whenever it takes an entry away.

Paths go through pathapi, so the same code serves a dnsmasq on this host and one
reached over `sftp://`.
"""

from __future__ import annotations

import contextlib as _contextlib
import hashlib as _hashlib
import logging
import os as _os
import shlex as _shlex
import subprocess as _subprocess
from typing import Any, List, Optional, Tuple
from urllib.parse import urlsplit

from hostctl.shell import Exec
from pydhcp.options import I32, U8, U16, U32, Boolean, Bytes, DomainList
from pydhcp.options import List as CodecList
from pydhcp.options import OctetString, String

from .._conditions import MATCH_KEYS, Condition
from .._model import Reservation, Target
from .._options import DHCPLease, DHCPOptions, plain_items
from .._paths import parse_path
from .._server import DEFAULT_OWNER, DHCPServer, Secrets
from ..exceptions import (
    BackendUnavailableError,
    ConditionUnsupportedError,
    ConfigError,
    ServerError,
)

__all__ = ["DnsmasqBackend"]

LOGGER = logging.getLogger("dhcpctl")


class DnsmasqBackend(DHCPServer):
    """`dnsmasq://[host]/?hostsfile=...&optsfile=...&reload=...`

    `hostsfile`/`optsfile` may be a directory (one file per client, preferred)
    or a single file (the owner keeps a marked region inside it). Each may carry
    its own scheme; a bare path is local when the URI has no host, and
    `sftp://<host>/<path>` when it does.
    """

    SETTINGS = frozenset({"hostsfile", "optsfile", "reload", "pidfile"})

    def __init__(
        self,
        uri: str,
        *,
        secrets: Secrets = None,
        owner: str = DEFAULT_OWNER,
        codes: Any = None,
    ) -> None:
        super().__init__(uri, secrets=secrets, owner=owner, codes=codes)
        parts = urlsplit(uri)
        self.host = parts.hostname or ""
        self.user = self.secret("user") or ""

        hostsfile = self.settings.get("hostsfile") or parts.path
        if not hostsfile or hostsfile == "/":
            raise ConfigError(
                "dnsmasq needs hostsfile=<path> (the dnsmasq --dhcp-hostsfile or "
                "--dhcp-hostsdir location)"
            )
        self.hostsfile = self._path(hostsfile)
        optsfile = self.settings.get("optsfile")
        self.optsfile = self._path(optsfile) if optsfile else None
        # Read from the setting as written: a path type may drop the slash.
        self._slashed = {
            "hosts": hostsfile.endswith(("/", "\\")),
            "opts": bool(optsfile) and optsfile.endswith(("/", "\\")),
        }
        self.reload_command = self.settings.get("reload")
        self.pidfile = self.settings.get("pidfile", "/run/dnsmasq/dnsmasq.pid")
        self._reload_warned = False

    def _path(self, value: str) -> Any:
        """A configured path: its own scheme, else local or sftp on our host."""
        if "://" in value:
            _require_sftp(value)
            return parse_path(value)
        if self.host:
            user = f"{self.user}@" if self.user else ""
            remote = f"sftp://{user}{self.host}{value}"
            _require_sftp(remote)
            return parse_path(remote)
        return parse_path(value)

    # -- the DHCPServer contract ------------------------------------------

    def ensure_condition(self, reservation: Reservation, condition: Condition) -> str:
        """dnsmasq cannot express a condition in the files this backend owns.

        The tag half is `dhcp-match=set:<tag>,77,iPXE`, a **main config**
        directive: `--dhcp-optsfile` accepts `dhcp-option` lines only. Writing
        the option half without the match would arm a condition that never fires.
        """
        raise ConditionUnsupportedError(
            f"dnsmasq cannot serve dhcp_when.{condition.name}: the tag needs a "
            f"`dhcp-match` line in dnsmasq's own config, which {self.owner} does "
            f"not write (--dhcp-optsfile takes dhcp-option lines only). Put this "
            f"in dnsmasq.conf, and the option half in the reservation's extras:\n"
            f"  {self.condition_recipe(reservation, condition)}"
        )

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """The `dhcp-match`/`dhcp-option` pair for dnsmasq.conf."""
        lines = [
            f"dhcp-match=set:{condition.name},{int(MATCH_KEYS[key])},{value}"
            for key, value in condition.match.items()
        ]
        lines.extend(
            f"dhcp-option={value}"
            for value in _option_lines(condition.name, condition.lease)
        )
        return "\n  ".join(lines)

    def add(self, reservation: Reservation) -> None:
        # Refuse before writing anything: a half-applied condition is a client
        # that boots the installer again.
        for condition in reservation.conditions.values():
            self.ensure_condition(reservation, condition)
        tag = self._tag(reservation.target)
        options = _option_lines(tag, reservation.lease, self.extras(reservation, "add"))
        self._require_optsfile(options)
        took = self._write("hosts", tag, [_host_line(reservation, tag)])
        if self.optsfile is not None:
            took |= self._write("opts", tag, options)
        self._reload(took)

    def keep(self, reservation: Reservation) -> None:
        """Rewrite this client's region with the completion options."""
        tag = self._tag(reservation.target)
        options = _option_lines(
            tag,
            reservation.completion.apply_to(reservation.lease),
            self.extras(reservation, "remove"),
        )
        self._require_optsfile(options)
        took = self._write("hosts", tag, [_host_line(reservation, tag)])
        if self.optsfile is not None:
            took |= self._write("opts", tag, options)
        self._reload(took)

    def remove(self, reservation: Reservation) -> None:
        tag = self._tag(reservation.target)
        took = self._write("hosts", tag, [])
        if self.optsfile is not None:
            took |= self._write("opts", tag, [])
        self._reload(took)

    def _recording(self, sent: List[str]) -> Any:
        """Each entry as the lines written, under the path it goes to, and the
        reload command. A path is a directory only when it ends with `/`: the
        file system is not asked."""

        def write(which: str, tag: str, lines: List[str]) -> bool:
            base = self.hostsfile if which == "hosts" else self.optsfile
            path = base / f"{tag}.conf" if self._slashed[which] else base
            shown = path.as_posix() if hasattr(path, "as_posix") else str(path)
            where = f"# {which}: {shown}" + (
                "" if self._slashed[which] else f" [{tag}]"
            )
            sent.append("\n".join([where, *lines]) if lines else where + ": removed")
            return False

        def reload(took_away: bool) -> None:
            if self.reload_command and self.reload_command != "signal":
                sent.append(f"# reload: {self.reload_command}")

        return self._replaced(_write=write, _reload=reload)

    def _require_optsfile(self, options: List[str]) -> None:
        """Refuse to arm a client whose options would have nowhere to go."""
        if options and self.optsfile is None:
            raise ConfigError(
                "dnsmasq: this reservation serves options (the boot file among "
                "them), and the URI has no optsfile=<path> to write them to; a "
                "client armed without them boots without them. Add optsfile= "
                "(the --dhcp-optsfile or --dhcp-optsdir location)"
            )

    def _tag(self, target: Target) -> str:
        """A dnsmasq tag for this client: its name, reduced to what a tag may hold.

        A name that had to be reduced gets a digest of itself appended, so two
        names that reduce alike (`web.01`, `web-01`) are two tags.
        """
        name = str(target.name or "")
        cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name)
        cleaned = cleaned.strip("-")
        if cleaned == name and name:
            return name
        digest = _hashlib.sha1(name.encode("utf-8")).hexdigest()[:8]
        return f"{cleaned or self.owner}-{digest}"

    # -- writing ----------------------------------------------------------

    def _directory(self, which: str) -> bool:
        """Is the `hosts` or `opts` path a directory (one file per client)?"""
        base = self.hostsfile if which == "hosts" else self.optsfile
        return self._slashed[which] or _is_directory(base)

    def _write(self, which: str, tag: str, lines: List[str]) -> bool:
        """Put `lines` under `tag` in the `hosts` or `opts` path, or remove that
        tag's entry when empty. True when an entry dnsmasq may have read
        already was removed or changed."""
        base = self.hostsfile if which == "hosts" else self.optsfile
        if self._directory(which):
            return self._write_file(base / f"{tag}.conf", lines)
        return self._write_region(base, tag, lines)

    def _write_file(self, path: Any, lines: List[str]) -> bool:
        try:
            before: Optional[str] = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            before = None
        if not lines:
            try:
                path.unlink()
            except FileNotFoundError:
                pass  # removing twice is quiet: completion may re-run
            return before is not None
        text = "\n".join(lines) + "\n"
        if text == before:
            return False
        self._atomic_write(path, text)
        return before is not None

    def _write_region(self, path: Any, tag: str, lines: List[str]) -> bool:
        """Replace only the owner's marked region, leaving every other line.

        The file is read, edited and replaced whole, so a local one is locked
        for that time: two writers would otherwise each drop the other's
        region. A remote file has no lock to take.
        """
        with _locked(path):
            return self._rewrite_region(path, tag, lines)

    def _rewrite_region(self, path: Any, tag: str, lines: List[str]) -> bool:
        start = f"# >>> {self.owner} {tag}"
        end = f"# <<< {self.owner} {tag}"
        try:
            existing = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            existing = []

        kept, region, skipping = [], [], False
        for line in existing:
            if line.strip() == start:
                skipping = True
                continue
            if line.strip() == end:
                skipping = False
                continue
            (region if skipping else kept).append(line)

        if lines:
            kept += [start, *lines, end]
        self._atomic_write(path, "\n".join(kept) + ("\n" if kept else ""))
        return bool(region) and region != list(lines)

    def _atomic_write(self, path: Any, text: str) -> None:
        """Write via a sibling temporary file where the path type allows a rename.

        A half-written `dhcp-host` line read on an unrelated SIGHUP is a lease
        handed to the wrong machine.
        """
        parent = path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except (FileExistsError, NotImplementedError):
            pass
        # Per process, so two writers never share one; a dotfile, which dnsmasq
        # skips when it reads a --dhcp-hostsdir or --dhcp-optsdir.
        tmp = parent / f".{path.name}.{self.owner}-{_os.getpid()}-tmp"
        try:
            tmp.write_text(text, encoding="utf-8")
            _replace(tmp, path)
        except (NotImplementedError, AttributeError, OSError) as exc:
            LOGGER.debug("atomic write unavailable (%s); writing in place", exc)
            path.write_text(text, encoding="utf-8")

    # -- reloading --------------------------------------------------------

    def _reload(self, took_away: bool) -> None:
        """Make dnsmasq read what was written.

        A file needs `reload=` every time. A directory picks up new files by
        itself but keeps serving a removed or changed one, so `took_away` --
        an entry dnsmasq may have read is gone or different -- needs a SIGHUP:
        `reload=` when given, else the local `pidfile`.
        """
        if not self.reload_command:
            if not self._directory("hosts"):
                raise ConfigError(
                    "dnsmasq: reload=<command> is required when hostsfile is a "
                    "file (dnsmasq re-reads it only on SIGHUP); use a directory "
                    "with --dhcp-hostsdir to need no reload for a new client"
                )
            if not took_away:
                if not self._reload_warned:
                    LOGGER.info(
                        "dnsmasq: a new entry needs no reload; --dhcp-hostsdir/"
                        "--dhcp-optsdir read new files by themselves"
                    )
                    self._reload_warned = True
                return
            if self.host:
                raise ConfigError(
                    "dnsmasq: a running dnsmasq keeps serving a removed or changed "
                    "--dhcp-hostsdir/--dhcp-optsdir entry until SIGHUP; give "
                    "reload=<command> to run on the host over ssh"
                )
            _signal_pidfile(self.pidfile)
            return

        if self.reload_command == "signal":
            if self.host:
                raise ConfigError(
                    "dnsmasq: reload=signal is local only; give a command to run "
                    "over ssh instead"
                )
            _signal_pidfile(self.pidfile)
            return

        argv = _shlex.split(self.reload_command)
        LOGGER.debug("dnsmasq reload on %s: %s", self.host or "this host", argv)
        try:
            with _open_host(self.reload_host()) as host:
                host.run(Exec(*argv), timeout=60)
        except ImportError as exc:
            raise BackendUnavailableError(
                "reloading a remote dnsmasq over ssh requires the 'ssh' extra: "
                "pip install pydhcpctl[ssh]"
            ) from exc
        except _subprocess.CalledProcessError as exc:
            raise ServerError(
                f"dnsmasq: reload command {argv!r} failed ({exc.returncode})"
            ) from exc
        except _subprocess.TimeoutExpired as exc:
            raise ServerError(
                f"dnsmasq: reload command {argv!r} did not finish in 60 seconds"
            ) from exc
        except OSError as exc:
            raise ServerError(
                f"dnsmasq: cannot run reload command {argv!r}: {exc}"
            ) from exc

    def reload_host(self) -> Any:
        """The hostctl config `reload=` runs on: this machine, or the URI's host
        over ssh."""
        import hostctl

        if not self.host:
            return hostctl.LocalConfig()
        return hostctl.SSHConfig(
            self.host,
            username=self.user or None,
            password=self.secret("password") or None,
        )


def _open_host(config: Any) -> Any:
    """An open hostctl host for `config`, closed by `with`."""
    return config.open()


def _require_sftp(uri: str) -> None:
    """Name dhcpctl's own extra before sftppath names its own."""
    if not uri.startswith("sftp://"):
        return
    import importlib.util as _util

    if _util.find_spec("sftppath") is None or (
        _util.find_spec("paramiko") is None and _util.find_spec("asyncssh") is None
    ):
        raise BackendUnavailableError(
            "a remote dnsmasq path (sftp://) requires the 'ssh' extra: "
            "pip install pydhcpctl[ssh]"
        )


def _host_line(reservation: Reservation, tag: str) -> str:
    target = reservation.target
    mac = target.require_mac(
        "dnsmasq keys reservations by MAC; give the target a mac, or key it by one"
    )
    fields = [str(mac), f"set:{tag}"]
    if reservation.ip_text:
        fields.append(reservation.ip_text)
    if target.hostname:
        fields.append(target.hostname)
    # A --dhcp-hostsfile line is the value of --dhcp-host, without the key.
    return ",".join(fields)


def _option_lines(
    tag: str, lease: DHCPLease, extras: Optional[List[Any]] = None
) -> List[str]:
    """What `lease` serves, as --dhcp-optsfile lines: --dhcp-option values.

    dnsmasq(8) takes the header fields in an options file by these names, as
    --dhcp-boot would set them; `bootfile-name` fills the file field unless
    the client asks for option 67.
    """
    lines: List[str] = []
    for name, value in (
        ("bootfile-name", lease.file),
        ("tftp-server", lease.sname),
        ("server-ip-address", "" if lease.siaddr.is_unspecified else lease.siaddr),
    ):
        if value:
            lines.append(f"tag:{tag},option:{name},{value}")
    for code, value in _codes(lease.options):
        lines.append(f"tag:{tag},{code},{value}")
    lines.extend(str(line) for line in (extras or ()))
    return lines


#: Codecs whose value dnsmasq would read as text unless given as octets.
_OCTETS = (Bytes, Boolean, U8, U16, U32, I32)
_TEXT_CODECS = (String, OctetString, DomainList)


def _codes(options: DHCPOptions) -> List[Tuple[str, str]]:
    """Options as (dnsmasq option code, the value as dnsmasq reads it)."""
    return [
        (str(int(code)), _option_value(options, code, value))
        for code, value in plain_items(options)
    ]


def _option_value(options: DHCPOptions, code: Any, value: Any) -> str:
    """A number, flag or octets as their encoded octets; anything else as text.

    dnsmasq reads `True` and `0a0b` as text, and sizes a bare number by its
    value for an option it has no type for; colon-separated hex is the octets
    exactly. One octet is written as a number: alone, `0a` is text to dnsmasq.
    """
    codec = code.get_type()
    if issubclass(codec, CodecList):
        # A list of numbers too: dnsmasq takes `576,1500` for addresses.
        codec = codec.item_type()
    if not issubclass(codec, _OCTETS) or issubclass(codec, _TEXT_CODECS):
        return _value(value)
    raw = bytes(options[int(code)])
    if len(raw) == 1:
        return str(raw[0])
    return ":".join(f"{octet:02x}" for octet in raw)


def _value(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def _is_directory(path: Any) -> bool:
    """An existing directory, or a path that still shows a trailing slash."""
    text = str(path)
    if text.endswith(("/", "\\")):
        return True
    try:
        return path.is_dir()
    except (NotImplementedError, OSError):  # pragma: no cover - exotic path types
        return False


@_contextlib.contextmanager
def _locked(path: Any) -> Any:
    """Hold an exclusive lock on `.<name>.lock` beside `path`, a local file.

    A dotfile, so a `conf-dir` holding the file does not read it as config.
    """
    try:
        name = _os.fspath(path)
    except TypeError:
        yield  # a remote path
        return
    _os.makedirs(_os.path.dirname(name) or ".", exist_ok=True)
    directory, base = _os.path.split(name)
    with open(_os.path.join(directory, f".{base}.lock"), "a+b") as handle:
        if _os.name == "nt":
            import msvcrt

            # LK_LOCK retries for ten seconds, then raises OSError.
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _replace(tmp: Any, path: Any) -> None:
    """Rename `tmp` onto `path`, for whichever path flavour we have."""
    try:
        _os.replace(tmp.__fspath__(), path.__fspath__())
        return
    except (NotImplementedError, AttributeError):
        pass
    rename = getattr(tmp, "replace", None) or getattr(tmp, "rename", None)
    if rename is None:
        raise NotImplementedError("path type cannot rename")
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    rename(path)


def _signal_pidfile(pidfile: str) -> None:
    """SIGHUP the dnsmasq whose pid is in `pidfile` (local only).

    :raises ConfigError: this platform has no SIGHUP.
    :raises ServerError: the pidfile cannot be read, or the process signalled.
    """
    import signal

    hangup = getattr(signal, "SIGHUP", None)
    if hangup is None:
        raise ConfigError(
            "dnsmasq: this platform has no SIGHUP to signal dnsmasq with; give "
            "reload=<command> instead"
        )
    try:
        with open(pidfile, encoding="utf-8") as handle:
            pid = int(handle.read().strip())
        _os.kill(pid, hangup)
    except (OSError, ValueError) as exc:
        raise ServerError(
            f"dnsmasq: cannot SIGHUP the dnsmasq in pidfile {pidfile!r}: {exc}; "
            f"set pidfile= or reload="
        ) from exc
