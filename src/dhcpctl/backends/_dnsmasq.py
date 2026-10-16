"""dnsmasq backend: write reservation files, reload only if we must.

dnsmasq re-reads the files given to `--dhcp-hostsfile` / `--dhcp-optsfile` on
SIGHUP, but **not** its main config file. `--dhcp-hostsdir` / `--dhcp-optsdir`
take a directory and pick up changed or new files with no signal at all, which
is why directory mode is the recommended shape: write a file and be done, with
no shell access and no right to signal anything.

Paths go through pathapi, so the same code serves a dnsmasq on this host and one
reached over `sftp://`.
"""

from __future__ import annotations

import logging
import os as _os
import shlex as _shlex
import subprocess as _subprocess
from typing import Any, List, Optional, Tuple
from urllib.parse import urlsplit

from .._conditions import MATCH_KEYS, Condition
from .._model import Reservation, Target
from .._options import DHCPOptions
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

#: Generic option name -> dnsmasq option number.
_CODES = {
    "router": 3,
    "subnet-mask": 1,
    "broadcast-address": 28,
    "domain-name-servers": 6,
    "domain-name": 15,
    "domain-search": 119,
    "ntp-servers": 42,
    "lease-time": 51,
    "tftp-server-name": 66,
    "boot-file-name": 67,
    "vendor-class-identifier": 60,
}


class DnsmasqBackend(DHCPServer):
    """`dnsmasq://[host]/?hostsfile=...&optsfile=...&reload=...`

    `hostsfile`/`optsfile` may be a directory (one file per client, preferred)
    or a single file (the owner keeps a marked region inside it). Each may carry
    its own scheme; a bare path is local when the URI has no host, and
    `sftp://<host>/<path>` when it does.
    """

    SETTINGS = frozenset({"hostsfile", "optsfile", "reload", "pidfile"})

    def __init__(
        self, uri: str, *, secrets: Secrets = None, owner: str = DEFAULT_OWNER
    ) -> None:
        super().__init__(uri, secrets=secrets, owner=owner)
        parts = urlsplit(uri)
        self.host = parts.hostname or ""
        self.user = parts.username or ""

        hostsfile = self.settings.get("hostsfile") or parts.path
        if not hostsfile or hostsfile == "/":
            raise ConfigError(
                "dnsmasq needs hostsfile=<path> (the dnsmasq --dhcp-hostsfile or "
                "--dhcp-hostsdir location)"
            )
        self.hostsfile = self._path(hostsfile)
        optsfile = self.settings.get("optsfile")
        self.optsfile = self._path(optsfile) if optsfile else None
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
            f"in dnsmasq.conf and use `raw.dnsmasq=` for the option half:\n"
            f"  {self.condition_recipe(reservation, condition)}"
        )

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """The `dhcp-match`/`dhcp-option` pair for dnsmasq.conf."""
        lines = [
            f"dhcp-match=set:{condition.name},{MATCH_KEYS[key]},{value}"
            for key, value in condition.match.items()
        ]
        lines.extend(
            f"dhcp-option=tag:{condition.name},{code},{_value(value)}"
            for code, value in _codes(condition.options)
        )
        return "\n  ".join(lines)

    def add(self, reservation: Reservation) -> None:
        # Refuse before writing anything: a half-applied condition is a client
        # that boots the installer again.
        for condition in reservation.conditions.values():
            self.ensure_condition(reservation, condition)
        target = reservation.target
        tag = self._tag(target)
        self._write(self.hostsfile, tag, [_host_line(target, tag)])
        if self.optsfile is not None:
            self._write(
                self.optsfile,
                tag,
                _option_lines(
                    tag, reservation.options, self.extras(reservation, "add")
                ),
            )
        self._reload()

    def keep(self, reservation: Reservation) -> None:
        """Rewrite this client's region with the completion options."""
        target = reservation.target
        tag = self._tag(target)
        options = reservation.completion.apply_to(reservation.options)
        self._write(self.hostsfile, tag, [_host_line(target, tag)])
        if self.optsfile:
            self._write(
                self.optsfile,
                tag,
                _option_lines(tag, options, self.extras(reservation, "remove")),
            )
        self._reload()

    def remove(self, reservation: Reservation) -> None:
        tag = self._tag(reservation.target)
        self._write(self.hostsfile, tag, [])
        if self.optsfile is not None:
            self._write(self.optsfile, tag, [])
        self._reload()

    def _tag(self, target: Target) -> str:
        """A dnsmasq tag for this client: its name, reduced to what a tag may hold."""
        cleaned = "".join(
            ch if ch.isalnum() or ch in "-_" else "-" for ch in str(target.name or "")
        )
        return cleaned.strip("-") or self.owner

    # -- writing ----------------------------------------------------------

    def _write(self, base: Any, tag: str, lines: List[str]) -> None:
        """Put `lines` under `tag`, or remove that tag's entry when empty."""
        if _is_directory(base):
            self._write_file(base / f"{tag}.conf", lines)
        else:
            self._write_region(base, tag, lines)

    def _write_file(self, path: Any, lines: List[str]) -> None:
        if not lines:
            try:
                path.unlink()
            except FileNotFoundError:
                pass  # removing twice is quiet: completion may re-run
            return
        self._atomic_write(path, "\n".join(lines) + "\n")

    def _write_region(self, path: Any, tag: str, lines: List[str]) -> None:
        """Replace only the owner's marked region, leaving every other line."""
        start = f"# >>> {self.owner} {tag}"
        end = f"# <<< {self.owner} {tag}"
        try:
            existing = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            existing = []

        kept, skipping = [], False
        for line in existing:
            if line.strip() == start:
                skipping = True
                continue
            if line.strip() == end:
                skipping = False
                continue
            if not skipping:
                kept.append(line)

        if lines:
            kept += [start, *lines, end]
        self._atomic_write(path, "\n".join(kept) + ("\n" if kept else ""))

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
        tmp = parent / f"{path.name}.{self.owner}-tmp"
        try:
            tmp.write_text(text, encoding="utf-8")
            _replace(tmp, path)
        except (NotImplementedError, AttributeError, OSError) as exc:
            LOGGER.debug("atomic write unavailable (%s); writing in place", exc)
            path.write_text(text, encoding="utf-8")

    # -- reloading --------------------------------------------------------

    def _reload(self) -> None:
        if not self.reload_command:
            if _is_directory(self.hostsfile):
                if not self._reload_warned:
                    LOGGER.info(
                        "dnsmasq: no reload configured; assuming --dhcp-hostsdir/"
                        "--dhcp-optsdir, which re-read changed files by themselves"
                    )
                    self._reload_warned = True
                return
            raise ConfigError(
                "dnsmasq: reload=<command> is required when hostsfile is a file "
                "(dnsmasq re-reads it only on SIGHUP); use a directory with "
                "--dhcp-hostsdir to need no reload at all"
            )

        if self.reload_command == "signal":
            if self.host:
                raise ConfigError(
                    "dnsmasq: reload=signal is local only; give a command to run "
                    "over ssh instead"
                )
            _signal_pidfile(self.pidfile)
            return

        argv = _shlex.split(self.reload_command)
        if self.host:
            destination = f"{self.user}@{self.host}" if self.user else self.host
            argv = ["ssh", destination, *argv]
        LOGGER.debug("dnsmasq reload: %s", argv)
        try:
            _subprocess.run(argv, check=True, timeout=60)
        except _subprocess.CalledProcessError as exc:
            raise ServerError(
                f"dnsmasq: reload command {argv!r} failed ({exc.returncode})"
            ) from exc


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


def _host_line(target: Target, tag: str) -> str:
    mac = target.require_mac(
        "dnsmasq keys reservations by MAC; give the target a mac, or key it by one"
    )
    fields = [str(mac), f"set:{tag}"]
    if target.ip:
        fields.append(target.ip_text)
    if target.hostname:
        fields.append(target.hostname)
    return "dhcp-host=" + ",".join(fields)


def _option_lines(
    tag: str, options: DHCPOptions, extras: Optional[List[Any]] = None
) -> List[str]:
    """Translate the generic options into dnsmasq's own syntax."""
    lines: List[str] = []
    boot_file = options.get("boot-file-name")
    next_server = options.get("next-server")
    if boot_file or next_server:
        # next-server is not an option in dnsmasq: it is dhcp-boot's third field.
        lines.append(
            f"dhcp-boot=tag:{tag},{_value(boot_file) if boot_file else ''},,"
            f"{_value(next_server) if next_server else ''}".rstrip(",")
        )
    for name, value in options.items():
        if name in ("boot-file-name", "next-server"):
            continue
        code = _CODES.get(name)
        if code is None:
            code = name[len("option-") :] if name.startswith("option-") else name
        lines.append(f"dhcp-option=tag:{tag},{code},{_value(value)}")
    lines.extend(str(line) for line in (extras or ()))
    return lines


def _codes(options: DHCPOptions) -> List[Tuple[str, Any]]:
    """Options as (dnsmasq option code, value), the same mapping a tag line uses."""
    pairs = []
    for name, value in options.items():
        code = _CODES.get(name)
        if code is None:
            code = name[len("option-") :] if name.startswith("option-") else name
        pairs.append((str(code), value))
    return pairs


def _value(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def _is_directory(path: Any) -> bool:
    """Directory mode: an existing directory, or a path written with a slash."""
    text = str(path)
    if text.endswith(("/", "\\")):
        return True
    try:
        return path.is_dir()
    except (NotImplementedError, OSError):  # pragma: no cover - exotic path types
        return False


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
    """SIGHUP the dnsmasq whose pid is in `pidfile` (local only)."""
    import signal

    with open(pidfile, encoding="utf-8") as handle:
        pid = int(handle.read().strip())
    _os.kill(pid, getattr(signal, "SIGHUP", signal.SIGTERM))
