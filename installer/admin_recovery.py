#!/usr/bin/python3 -I
"""Installed as psiphon-3x-ui-admin; authorize locally, then drop privileges.

This standalone launcher uses only the system Python standard library as root.
The panel's recovery module is imported only by a separate, unprivileged Python
process. The installer registers trusted prefix/account settings in admin.json.
The launcher deliberately stays outside the updater's managed-file manifest so
older, saved updater helpers can still roll back their existing manifests.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
ATTEMPT = re.compile(r"[0-9a-f]{32}-[0-9a-f]{32}\Z")
MAX_FILE = 65536


class RecoveryError(Exception):
    """A non-secret failure suitable for a server operator."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        # An operator may accidentally pass a password as an unsupported flag.
        # argparse's usual error includes those arguments, so never echo them.
        self.print_usage(sys.stderr)
        self.exit(
            2,
            "Invalid recovery arguments. Use --help; enter passwords only at the hidden prompt.\n",
        )


@dataclass(frozen=True)
class Host:
    state: Path = Path("/var/lib/psiphon-3x-ui-updater")
    lock_dir: Path = Path("/run/psiphon-3x-ui-updater")
    systemd: Path = Path("/etc/systemd/system")
    owner: int = 0
    anchor: Path | None = None


def protected_directory(path: Path, host: Host, *, sticky_prefix: Path | None = None) -> None:
    """Reject substituted ancestors before privileged reads or lock opens."""
    if not path.is_absolute() or ".." in path.parts:
        raise RecoveryError("The recovery installation path is invalid.")
    if host.anchor is not None and not path.is_relative_to(host.anchor):
        raise RecoveryError("Recovery path escapes its trusted directory.")
    for directory in reversed([path, *path.parents]):
        if host.anchor is not None and directory in host.anchor.parents:
            continue
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != host.owner:
            raise RecoveryError("Recovery requires real, root-owned installation directories.")
        if info.st_mode & 0o022 and not (
            directory == sticky_prefix and info.st_mode & stat.S_ISVTX
        ):
            raise RecoveryError("A recovery directory is writable by another account.")


def read_file(
    path: Path,
    host: Host,
    *,
    sticky_prefix: Path | None = None,
    panel_gid: int | None = None,
) -> bytes:
    protected_directory(path.parent, host, sticky_prefix=sticky_prefix)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        allowed_write = panel_gid is not None and info.st_gid == panel_gid
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != host.owner
            or info.st_nlink != 1
            or info.st_mode & 0o002
            or (info.st_mode & 0o020 and not allowed_write)
            or info.st_size > MAX_FILE
        ):
            raise RecoveryError("A recovery configuration file has unsafe permissions.")
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise RecoveryError("A recovery configuration file is too large.")
    return data


def installation(data: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RecoveryError("Recovery configuration has duplicate fields.")
            result[key] = value
        return result

    try:
        values = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RecoveryError("Recovery configuration is invalid.") from exc
    if not isinstance(values, dict) or set(values) != {"prefix", "user", "group"}:
        raise RecoveryError("Recovery configuration has unexpected fields.")
    for key in ("user", "group"):
        if not isinstance(values[key], str) or not ACCOUNT.fullmatch(values[key]):
            raise RecoveryError("Recovery service account is invalid.")
    raw = values["prefix"]
    if not isinstance(raw, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", raw):
        raise RecoveryError("Recovery installation prefix is invalid.")
    prefix = Path(raw)
    if prefix == Path("/") or any(part in {".", ".."} for part in raw.split("/")):
        raise RecoveryError("Recovery installation prefix is invalid.")
    return {**values, "prefix": prefix}


def database_path(data: bytes, prefix: Path) -> Path:
    """Read one literal setting; panel.env is data, never shell code."""
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise RecoveryError("Panel environment must be UTF-8 text.") from exc
    value = None
    for line in text.splitlines():
        key, separator, item = line.strip().partition("=")
        if not separator or key.strip() != "PSIPHON3XUI_DB_PATH":
            continue
        if value is not None:
            raise RecoveryError("Panel database configuration is duplicated.")
        value = item.strip()
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise RecoveryError("Panel database configuration is invalid.")
            value = value[1:-1]
    expected = prefix / "panel.db"
    if value is not None and value != str(expected):
        raise RecoveryError("Recovery requires panel.db inside the installation prefix.")
    return expected


def active_python(host: Host, prefix: Path) -> Path:
    override = host.systemd / "psiphon-3x-ui.service.d" / "50-panel-update.conf"
    try:
        text = read_file(override, host).decode("utf-8")
    except FileNotFoundError:
        return prefix / "venv" / "bin" / "python"
    except UnicodeError as exc:
        raise RecoveryError("The active panel environment is invalid.") from exc
    starts = [line.strip() for line in text.splitlines() if line.startswith("ExecStart=")]
    if len(starts) != 2 or starts[0] != "ExecStart=":
        raise RecoveryError("The active panel environment needs administrator inspection.")
    head, separator, arguments = starts[1].removeprefix("ExecStart=").partition(" ")
    interpreter = Path(head)
    try:
        relative = interpreter.relative_to(host.state / "venvs")
    except ValueError as exc:
        raise RecoveryError(
            "The active panel interpreter is outside its trusted directory."
        ) from exc
    if (
        not separator
        or arguments != "-I -m panel"
        or len(relative.parts) != 3
        or not ATTEMPT.fullmatch(relative.parts[0])
        or relative.parts[1:] != ("bin", "python")
    ):
        raise RecoveryError("The active panel environment is invalid.")
    return interpreter


def check_python(path: Path, host: Host, prefix: Path) -> None:
    protected_directory(path.parent, host, sticky_prefix=prefix)
    info = path.lstat()
    if info.st_uid != host.owner:
        raise RecoveryError("The panel interpreter must be root-owned.")
    # A normal venv's bin/python is a root-owned symlink to the system Python.
    target = path.resolve(strict=True)
    protected_directory(target.parent, host, sticky_prefix=prefix)
    info = target.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != host.owner
        or info.st_mode & 0o022
        or not os.access(target, os.X_OK)
    ):
        raise RecoveryError("The panel interpreter has unsafe permissions.")


@contextlib.contextmanager
def operation_lock(host: Host):
    import fcntl

    protected_directory(host.lock_dir.parent, host)
    host.lock_dir.mkdir(mode=0o755, exist_ok=True)
    protected_directory(host.lock_dir, host)
    fd = os.open(
        host.lock_dir / "operation.lock",
        os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != host.owner
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise RecoveryError("The installation lock has unsafe permissions.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RecoveryError(
                "An installer or panel update is running. Try again after it finishes."
            ) from exc
        if (host.state / "transaction.json").exists() or (
            host.state / "transaction.json"
        ).is_symlink():
            raise RecoveryError(
                "An interrupted panel update needs recovery before changing credentials."
            )
        yield fd
    finally:
        os.close(fd)


def run_recovery(host: Host, args: list[str]) -> int:
    import grp
    import pwd

    with operation_lock(host) as lock_fd:
        settings = installation(read_file(host.state / "admin.json", host))
        prefix = settings["prefix"]
        uid = pwd.getpwnam(settings["user"]).pw_uid
        gid = grp.getgrnam(settings["group"]).gr_gid
        if uid == 0 or gid == 0:
            raise RecoveryError("Panel recovery must use an unprivileged service account.")
        database = database_path(
            read_file(prefix / "panel.env", host, sticky_prefix=prefix, panel_gid=gid), prefix
        )
        protected_directory(database.parent, host, sticky_prefix=prefix)
        info = database.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RecoveryError("The existing panel database is not a regular file.")
        python = active_python(host, prefix)
        check_python(python, host, prefix)
        # subprocess changes credentials before exec; no panel/dependency code
        # and no caller-supplied environment executes with root privileges.
        # Keep the read-only lock open in the child even if the launcher exits.
        result = subprocess.run(
            [str(python), "-I", "-m", "panel.admin_recovery", "--db", str(database), *args],
            user=uid,
            group=gid,
            extra_groups=[],
            pass_fds=(lock_fd,),
            umask=0o077,
            cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            check=False,
        )
        if result.returncode == 0 and args[0] == "reset-password":
            audit_reset()
        return result.returncode


def audit_reset() -> None:
    # The hash is already committed. Logging must neither expose credentials
    # nor turn that successful reset into an apparent failure.
    with contextlib.suppress(ImportError, OSError):
        import syslog

        invoking = os.environ.get("SUDO_UID", "0")
        if not re.fullmatch(r"[0-9]{1,10}", invoking):
            invoking = "unknown"
        syslog.openlog("psiphon-3x-ui-admin", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(
            syslog.LOG_NOTICE, f"Panel admin credentials reset by invoking uid {invoking}."
        )


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="Recover this server's panel login credentials.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show-username", help="display the current admin username")
    reset = commands.add_parser("reset-password", help="set a password through hidden prompts")
    reset.add_argument("--username", help="also replace the admin username")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.exit(2, "Run this command on the panel's Linux server using sudo.\n")
    forwarded = [args.command]
    if args.command == "reset-password" and args.username is not None:
        forwarded += ["--username", args.username]
    try:
        return run_recovery(Host(), forwarded)
    except RecoveryError as exc:
        print(f"Recovery failed: {exc}", file=sys.stderr)
    except (OSError, KeyError):
        print(
            "Recovery failed: a required installation file or service account is missing or inaccessible. "
            "Install the current panel with its server installer to register recovery.",
            file=sys.stderr,
        )
    except KeyboardInterrupt:
        print("Recovery cancelled.", file=sys.stderr)
        return 130
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
