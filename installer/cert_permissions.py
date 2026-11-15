#!/usr/bin/env python3
"""Grant the panel group read-only access to PEM files in managed TLS trees.

Installed root-owned in /usr/local/libexec, never executed as root from the
service-writable panel installation. No panel.env parsing or shell execution.
Symlinks are not followed: targets inside the tree are handled by walking their
real directory, while targets outside it never have their permissions changed.
Descriptor-relative opens and fchown/fchmod avoid rename/symlink races.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path

_MAX_PEM_BYTES = 1024 * 1024
_PEM_BLOCK = re.compile(
    rb"^-----BEGIN (CERTIFICATE|(?:(?:RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY)-----[ \t]*\r?\n"
    rb"(?:(?:Proc-Type|DEK-Info):[^\r\n]*\r?\n)*"
    rb"[A-Za-z0-9+/= \t\r\n]+"
    rb"^-----END \1-----[ \t]*\r?$",
    re.MULTILINE,
)


def _contains_pem(fd: int) -> bool:
    with os.fdopen(fd, "rb", closefd=False) as stream:
        contents = stream.read(_MAX_PEM_BYTES + 1)
    return len(contents) <= _MAX_PEM_BYTES and _PEM_BLOCK.search(contents) is not None


def _open_directory(path: Path) -> int:
    """Open an absolute directory without following any path-component links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            if component in (".", ".."):
                raise ValueError("managed TLS directories must not contain dot components")
            child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def repair_permissions(directory: Path, group_id: int, *, owner_uid: int = 0) -> int:
    """Repair trusted PEM files only; return the count of changed objects.

    owner_uid is injectable for unprivileged POSIX tests. The installed CLI
    always uses root (0), and the unit's allow-listed paths are root-owned.
    A missing directory is normal on installations that do not use TLS.
    """
    if not directory.is_absolute():
        raise ValueError("managed TLS directories must be absolute")
    try:
        root_fd = _open_directory(directory)
    except FileNotFoundError:
        return 0

    changed = 0

    def apply(fd: int, mode: int) -> None:
        nonlocal changed
        info = os.fstat(fd)
        if info.st_gid != group_id:
            os.fchown(fd, -1, group_id)
            changed += 1
        if stat.S_IMODE(info.st_mode) != mode:
            os.fchmod(fd, mode)
            changed += 1

    def walk(fd: int) -> None:
        info = os.fstat(fd)
        if info.st_uid != owner_uid:
            return
        apply(fd, 0o750)
        with os.scandir(fd) as entries:
            for entry in entries:
                try:
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    if info.st_uid != owner_uid or stat.S_ISLNK(info.st_mode):
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                        child = os.open(entry.name, flags, dir_fd=fd)
                        try:
                            walk(child)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                        child = os.open(entry.name, flags, dir_fd=fd)
                        try:
                            actual = os.fstat(child)
                            if (
                                actual.st_uid != owner_uid
                                or not stat.S_ISREG(actual.st_mode)
                                or actual.st_nlink != 1
                            ):
                                continue
                            if _contains_pem(child):
                                apply(child, 0o640)
                        finally:
                            os.close(child)
                except FileNotFoundError:
                    # An issuer can atomically replace files during this walk.
                    # The next timer tick repairs the replacement inode.
                    continue

    try:
        walk(root_fd)
    finally:
        os.close(root_fd)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", default="psiphon3xui")
    parser.add_argument("--directory", action="append", type=Path)
    args = parser.parse_args(argv)
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("the certificate permission helper must run as root on Linux")
    import grp

    group_id = grp.getgrnam(args.group).gr_gid
    directories = args.directory or [Path("/root/cert")]
    failed = False
    for directory in directories:
        try:
            repair_permissions(directory, group_id)
        except (OSError, ValueError) as exc:
            print(f"TLS permission repair failed for {directory}: {exc}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
