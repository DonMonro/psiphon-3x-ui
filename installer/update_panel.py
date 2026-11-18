#!/usr/bin/env python3
"""Root-owned staged panel updater. Run with /usr/bin/python3 -I from /.

The only panel input is updates/request.json; it contains four scalar identity
fields, never paths or commands. GitHub main is re-resolved by this process.
Download only parses data. Builds happen after explicit install consent, in a
new permanent venv, with a clean environment and no imports from the old venv.

All runtime paths below are fixed except the root-configured installation
prefix/user/group. Changes to the managed file list or transaction schema must
remain compatible with recovery.py: a copy of the PREVIOUS trusted helper,
saved before activation and used by the recovery unit and ExecStopPost. It is
never replaced with unverified candidate code during an activation transaction.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import sqlite3
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

REPOSITORY = "DonMonro/psiphon-3x-ui"
DEFAULT_PREFIX = "/opt/psiphon-3x-ui"
DEFAULT_ACCOUNT = "psiphon3xui"
STATE = Path("/var/lib/psiphon-3x-ui-updater")
LOCK_DIR = Path("/run/psiphon-3x-ui-updater")
LIBEXEC = Path("/usr/local/libexec/psiphon-3x-ui")
SYSTEMD = Path("/etc/systemd/system")
POLKIT = Path("/etc/polkit-1/rules.d")
PANEL_UNIT = "psiphon-3x-ui.service"
OVERRIDE = "psiphon-3x-ui.service.d/50-panel-update.conf"
MAX_REQUEST = 4096
MAX_JSON = 65536
MAX_ENV = 65536
MAX_MANAGED = 1024 * 1024
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_MEMBER = 8 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_DATABASE = 256 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
JOB = re.compile(r"[0-9a-f]{32}\Z")
ATTEMPT = re.compile(r"[0-9a-f]{32}-[0-9a-f]{32}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z")
ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
# Source paths and destination names are an allowlist, NOT archive metadata.
MANAGED = {
    "panel_unit": ("systemd/psiphon-3x-ui.service", "systemd", PANEL_UNIT, 0o644),
    "cert_helper": ("installer/cert_permissions.py", "libexec", "cert_permissions.py", 0o755),
    "cert_unit": (
        "systemd/psiphon-cert-perms.service",
        "systemd",
        "psiphon-cert-perms.service",
        0o644,
    ),
    "cert_timer": (
        "systemd/psiphon-cert-perms.timer",
        "systemd",
        "psiphon-cert-perms.timer",
        0o644,
    ),
    "update_helper": ("installer/update_panel.py", "libexec", "update_panel.py", 0o755),
    "download_unit": (
        "systemd/psiphon-3x-ui-update-download.service",
        "systemd",
        "psiphon-3x-ui-update-download.service",
        0o644,
    ),
    "install_unit": (
        "systemd/psiphon-3x-ui-update-install.service",
        "systemd",
        "psiphon-3x-ui-update-install.service",
        0o644,
    ),
    "recover_unit": (
        "systemd/psiphon-3x-ui-update-recover.service",
        "systemd",
        "psiphon-3x-ui-update-recover.service",
        0o644,
    ),
    "polkit": ("systemd/49-psiphon-3x-ui.rules", "polkit", "49-psiphon-3x-ui.rules", 0o644),
}


class UpdateError(Exception):
    """A deliberately non-secret, operator-readable failure."""


class BusyError(UpdateError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def version_tuple(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise UpdateError("Expected a bounded major.minor.patch version.")
    return tuple(int(piece) for piece in value.split("."))


def identity(value: dict, *, revision_optional: bool = False) -> dict:
    if not isinstance(value, dict):
        raise UpdateError("Invalid update identity.")
    version_tuple(value.get("version"))
    revision = value.get("revision")
    if not (revision_optional and revision is None) and (
        not isinstance(revision, str) or not SHA.fullmatch(revision)
    ):
        raise UpdateError("Invalid source revision.")
    return {"version": value["version"], "revision": revision}


def parse_json(data: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise UpdateError("Duplicate JSON fields are not accepted.")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise UpdateError("Invalid JSON data.") from exc
    if not isinstance(value, dict):
        raise UpdateError("Expected a JSON object.")
    return value


def request_from_bytes(data: bytes, action: str) -> dict:
    if len(data) > MAX_REQUEST:
        raise UpdateError("Update request is too large.")
    value = parse_json(data)
    if set(value) != {"action", "job_id", "revision", "version"}:
        raise UpdateError("Update request has unexpected or missing fields.")
    if action not in {"download", "install"} or value["action"] != action:
        raise UpdateError("Update request does not match the service action.")
    if not isinstance(value["job_id"], str) or not JOB.fullmatch(value["job_id"]):
        raise UpdateError("Invalid update job identity.")
    identity(value)
    return value


def job_identity(value: dict) -> dict:
    result = identity(value)
    job = value.get("job_id")
    if not isinstance(job, str) or not JOB.fullmatch(job):
        raise UpdateError("Invalid staged job identity.")
    return {"job_id": job, **result}


@dataclass(frozen=True)
class Paths:
    prefix: Path = Path(DEFAULT_PREFIX)
    state: Path = STATE
    lock_dir: Path = LOCK_DIR
    libexec: Path = LIBEXEC
    systemd: Path = SYSTEMD
    polkit: Path = POLKIT

    @property
    def inbox(self) -> Path:
        return self.prefix / "updates"

    def destination(self, key: str) -> Path:
        if key == "override":
            return self.systemd / OVERRIDE
        if key not in MANAGED:
            raise UpdateError("Unknown managed destination.")
        _, directory, name, _ = MANAGED[key]
        return getattr(self, directory) / name


class Files:
    """Descriptor-relative, no-follow filesystem boundary.

    anchor/owner are injectable for unprivileged tests, never CLI options.
    Linux is mandatory at the CLI. The portable branch allows behavior tests
    on Windows; it is never used by an installed service.
    """

    def __init__(self, paths: Paths, gid: int, uid: int, *, owner=0, anchor=None):
        self.paths, self.gid, self.uid = paths, gid, uid
        self.owner, self.anchor = owner, anchor

    def _check_directory(self, info, path):
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner:
            raise UpdateError("Updater directory must be a real root-owned directory.")
        writable = info.st_mode & 0o022
        if path == self.paths.inbox:
            if stat.S_IMODE(info.st_mode) != 0o770 or info.st_gid != self.gid:
                raise UpdateError("Update inbox must be root-owned, panel-group mode 0770.")
        elif writable and not info.st_mode & stat.S_ISVTX:
            raise UpdateError("Updater directory is writable by another account.")
        elif writable and path != self.paths.prefix and path != Path("/tmp"):
            raise UpdateError("Unexpected writable updater ancestor.")

    @contextlib.contextmanager
    def directory(self, path: Path):
        if not path.is_absolute() or ".." in path.parts:
            raise UpdateError("Updater directory must be an absolute canonical path.")
        if os.name != "posix":
            # The production entrypoint refuses non-Linux hosts.
            for part in [path, *path.parents]:
                if part.is_symlink():
                    raise UpdateError("Directory symlinks are not accepted.")
            yield None
            return
        start = self.anchor or Path("/")
        try:
            pieces = path.relative_to(start).parts
        except ValueError as exc:
            raise UpdateError("Path is outside the trusted test filesystem.") from exc
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(start, flags)
        current = start
        try:
            self._check_directory(os.fstat(fd), current)
            for piece in pieces:
                child = os.open(piece, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                current = current / piece
                self._check_directory(os.fstat(fd), current)
            yield fd
        finally:
            os.close(fd)

    def mkdir(self, path: Path, mode=0o700):
        with self.directory(path.parent) as parent:
            try:
                if parent is None:
                    path.mkdir(mode=mode)
                else:
                    os.mkdir(path.name, mode, dir_fd=parent)
            except FileExistsError:
                pass
        # Open the new inode without following a substituted entry. A root
        # child cannot be renamed by panel members of the sticky prefix.
        if path == self.paths.inbox:
            with self.directory(path.parent) as parent:
                if parent is not None:
                    fd = os.open(
                        path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
                    )
                    try:
                        if os.fstat(fd).st_uid != self.owner:
                            raise UpdateError("Existing inbox is not root-owned.")
                        os.fchown(fd, self.owner, self.gid)
                        os.fchmod(fd, mode)
                    finally:
                        os.close(fd)
        else:
            with self.directory(path) as fd:
                if fd is not None:
                    os.fchown(fd, self.owner, self.gid)
                    os.fchmod(fd, mode)

    @contextlib.contextmanager
    def opened(self, path: Path, *, limit: int, panel=False, writable=False):
        with self.directory(path.parent) as parent:
            access = os.O_RDWR if writable else os.O_RDONLY
            flags = (
                access
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            if path.is_symlink():
                raise UpdateError("File symlinks are not accepted.")
            fd = os.open(path.name if parent is not None else path, flags, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                    raise UpdateError("Expected a bounded regular file with one link.")
                if os.name == "posix" and (
                    info.st_uid not in ({self.owner, self.uid} if panel else {self.owner})
                    or (info.st_mode & (0o002 if panel else 0o022))
                ):
                    raise UpdateError("File ownership or permissions are unsafe.")
                with os.fdopen(fd, "r+b" if writable else "rb", closefd=False) as stream:
                    yield stream, info
                    after = os.fstat(fd)
                    if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                        info.st_size,
                        info.st_mtime_ns,
                        info.st_ctime_ns,
                    ):
                        raise UpdateError("File changed while it was being read.")
            finally:
                os.close(fd)

    def read(self, path, limit=MAX_JSON, *, panel=False) -> bytes:
        with self.opened(path, limit=limit, panel=panel) as (stream, _):
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise UpdateError("File exceeds its size limit.")
            return data

    def json(self, path, *, optional=False) -> dict | None:
        try:
            return parse_json(self.read(path))
        except FileNotFoundError:
            if optional:
                return None
            raise

    @contextlib.contextmanager
    def writer(self, path: Path, mode=0o600, *, panel_owner=False):
        with self.directory(path.parent) as parent:
            temporary = f".update-{uuid.uuid4().hex}"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            name = temporary if parent is not None else path.parent / temporary
            fd = os.open(name, flags, 0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    yield stream
                    stream.flush()
                    if os.name == "posix":
                        os.fchmod(fd, mode)
                        os.fchown(fd, self.owner, self.gid)
                    os.fsync(fd)
                    if parent is not None:
                        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                        # Do not make the temporary name panel-owned in the
                        # sticky, writable prefix before its atomic rename.
                        if panel_owner:
                            os.fchown(fd, self.uid, self.gid)
                            os.fsync(fd)
                        os.fsync(parent)
                if parent is None:
                    # Windows cannot rename an open temporary file. The
                    # portable branch is only used by isolated behavior tests;
                    # production retains its descriptor-relative atomic rename.
                    os.close(fd)
                    fd = None
                    os.replace(name, path)
            finally:
                if fd is not None:
                    os.close(fd)
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=parent)

    def write(self, path, data, mode=0o600, *, panel_owner=False):
        with self.writer(path, mode, panel_owner=panel_owner) as stream:
            stream.write(data)

    def put_json(self, path, data, mode=0o600):
        self.write(path, (json.dumps(data, sort_keys=True) + "\n").encode(), mode)

    def remove(self, path):
        with self.directory(path.parent) as parent:
            try:
                os.unlink(path.name if parent is not None else path, dir_fd=parent)
                if parent is not None:
                    os.fsync(parent)
            except FileNotFoundError:
                pass

    def copy(self, source, target, limit, *, panel=False):
        with self.opened(source, limit=limit, panel=panel) as (reader, info):
            with self.writer(target) as writer:
                copy_bounded(reader, writer, limit)
            return info


def copy_bounded(reader, writer, limit: int, *, deadline=None, expected=None) -> str:
    digest = hashlib.sha256()
    count = 0
    while True:
        if deadline is not None and time.monotonic() > deadline:
            raise UpdateError("Download exceeded its time limit.")
        block = reader.read(min(65536, limit - count + 1))
        if not block:
            break
        count += len(block)
        if count > limit:
            raise UpdateError("Download or file exceeds its size limit.")
        writer.write(block)
        digest.update(block)
    if expected is not None and count != expected:
        raise UpdateError("File ended before its declared size.")
    return digest.hexdigest()


class DigestSink:
    def write(self, _block):
        pass


def archive_digest(files: Files, path: Path) -> str:
    with files.opened(path, limit=MAX_ARCHIVE) as (reader, _):
        return copy_bounded(reader, DigestSink(), MAX_ARCHIVE)


def validate_url(url: str) -> str:
    """Every redirect is checked BEFORE urllib issues the next request."""
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise UpdateError("Invalid upstream URL.") from exc
    allowed = {
        "api.github.com": rf"/repos/{REPOSITORY}/commits/main",
        "github.com": rf"/{REPOSITORY}/archive/[0-9a-f]{{40}}\.tar\.gz",
        "codeload.github.com": rf"/{REPOSITORY}/(?:legacy\.)?tar\.gz/[0-9a-f]{{40}}",
    }
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(allowed[parsed.hostname], parsed.path)
    ):
        raise UpdateError("Upstream URL or redirect is outside the fixed HTTPS repository.")
    return url


class RepositoryRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Upstream:
    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            RepositoryRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    @contextlib.contextmanager
    def open(self, url):
        validate_url(url)
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "psiphon-3x-ui-updater",
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
            },
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                validate_url(response.geturl())
                if response.status != 200:
                    raise UpdateError("Upstream returned an unexpected HTTP status.")
                yield response
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # URLs/response bodies can contain sensitive material. Never echo them.
            raise UpdateError("Could not fetch the fixed GitHub update source.") from exc

    def main_revision(self) -> str:
        with self.open(f"https://api.github.com/repos/{REPOSITORY}/commits/main") as response:
            raw = response.read(MAX_JSON + 1)
        if len(raw) > MAX_JSON:
            raise UpdateError("Main-channel response exceeds its size limit.")
        value = parse_json(raw).get("sha")
        if not isinstance(value, str) or not SHA.fullmatch(value):
            raise UpdateError("Main channel did not resolve to an immutable revision.")
        return value

    def download(self, revision, writer) -> str:
        with self.open(f"https://codeload.github.com/{REPOSITORY}/tar.gz/{revision}") as response:
            return copy_bounded(response, writer, MAX_ARCHIVE, deadline=time.monotonic() + 180)


class LimitedReader:
    """Bound decompressed data, including tar extension headers and padding."""

    def __init__(self, reader, limit):
        self.reader, self.remaining = reader, limit

    def read(self, size=-1):
        size = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        data = self.reader.read(size)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise UpdateError("Expanded archive exceeds its size limit.")
        return data


def source_version(package: bytes, project: bytes) -> str:
    try:
        package_text, project_text = package.decode("utf-8"), project.decode("utf-8")
    except UnicodeError as exc:
        raise UpdateError("Version declarations are not UTF-8.") from exc
    packages = re.findall(r'^__version__\s*=\s*[\'"]([0-9.]+)[\'"]\s*$', package_text, re.M)
    sections = re.findall(r"^\[project\]\s*\n(.*?)(?=^\[|\Z)", project_text, re.M | re.S)
    projects = (
        re.findall(r'^version\s*=\s*[\'"]([0-9.]+)[\'"]\s*$', sections[0], re.M)
        if len(sections) == 1
        else []
    )
    if len(packages) != 1 or len(projects) != 1 or packages[0] != projects[0]:
        raise UpdateError("Source package and project versions must agree.")
    version_tuple(packages[0])
    return packages[0]


def inspect_archive(path: Path, revision: str, expected_version: str, *, destination=None):
    """Validate every member; optionally extract using our own file writer.

    extractall is deliberately never used. Archive ownership, permissions,
    links, and special file types are never applied to the filesystem.
    """
    root = f"psiphon-3x-ui-{revision}"
    seen, regular, versions = set(), set(), {}
    count = total = 0
    try:
        with path.open("rb") as compressed, gzip.GzipFile(fileobj=compressed) as uncompressed:
            bounded = LimitedReader(uncompressed, MAX_EXPANDED)
            with tarfile.open(fileobj=bounded, mode="r|", ignore_zeros=True) as archive:
                for member in archive:
                    count += 1
                    name = member.name.removesuffix("/") if member.isdir() else member.name
                    pieces = name.split("/")
                    if (
                        count > MAX_MEMBERS
                        or len(name) > 512
                        or len(pieces) > 24
                        or any(piece in ("", ".", "..") for piece in pieces)
                        or any(ord(char) < 32 for char in name)
                        or "\\" in name
                        or ":" in name
                        or pieces[0] != root
                        or PurePosixPath(name).is_absolute()
                        or name in seen
                        or not (member.isdir() or member.isfile())
                        or member.issparse()
                        or member.size < 0
                        or member.size > MAX_MEMBER
                        or (member.isdir() and member.size != 0)
                        or any(key not in {"comment", "mtime"} for key in member.pax_headers)
                    ):
                        raise UpdateError(
                            "Archive contains an unsafe, duplicate, or oversized member."
                        )
                    if any("/".join(pieces[:i]) in regular for i in range(1, len(pieces))):
                        raise UpdateError("Archive contains a file/directory collision.")
                    if member.isfile() and any(item.startswith(name + "/") for item in seen):
                        raise UpdateError("Archive contains a file/directory collision.")
                    if len(pieces) == 1 and not member.isdir():
                        raise UpdateError("Archive root must be a directory.")
                    seen.add(name)
                    if member.isdir():
                        continue
                    regular.add(name)
                    total += member.size
                    if total > MAX_EXPANDED:
                        raise UpdateError("Archive contents exceed their total size limit.")
                    relative = "/".join(pieces[1:])
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise UpdateError("Archive member could not be read.")
                    with stream:
                        version_data = None
                        if relative in {"panel/__init__.py", "pyproject.toml"}:
                            if member.size > MAX_JSON:
                                raise UpdateError("Version file exceeds its size limit.")
                            version_data = stream.read()
                            versions[relative] = version_data
                        if destination is not None:
                            target = destination.joinpath(*pieces[1:])
                            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                            # destination is a NEW private root-owned directory;
                            # all ancestor types have been validated above.
                            with target.open("xb") as output:
                                if version_data is not None:
                                    output.write(version_data)
                                else:
                                    copy_bounded(stream, output, member.size, expected=member.size)
                            target.chmod(0o600)
            # Verify gzip CRC and enforce the decompression limit even for tail padding.
            while bounded.read(65536):
                pass
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise UpdateError("The downloaded source archive is invalid.") from exc
    required = {"panel/__init__.py", "panel/main.py", "pyproject.toml"} | {
        item[0] for item in MANAGED.values()
    }
    if not required.issubset({name.removeprefix(root + "/") for name in regular}):
        raise UpdateError("Source archive is missing required panel or managed files.")
    if (
        source_version(versions.get("panel/__init__.py", b""), versions.get("pyproject.toml", b""))
        != expected_version
    ):
        raise UpdateError("Downloaded source version does not match the requested version.")


def clean_environment(work: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONNOUSERSITE": "1",
    }


def run_command(command, *, environment, timeout=120, capture=False, check=True, label="Command"):
    """No shell, inherited secrets, source cwd, or unbounded build log capture."""
    process = subprocess.Popen(
        command,
        cwd="/",
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except BaseException as exc:
        if os.name == "posix":
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait()
        if isinstance(exc, subprocess.TimeoutExpired):
            raise UpdateError(f"{label} timed out.") from exc
        raise
    if check and process.returncode:
        raise UpdateError(f"{label} failed (exit {process.returncode}).")
    if output is not None and len(output) > MAX_JSON:
        raise UpdateError(f"{label} returned too much data.")
    return process.returncode, output or b""


def local_settings(contents: bytes, prefix: Path) -> dict:
    """Parse only the small subset needed for local health/backup, never source."""
    try:
        text = contents.decode("utf-8")
    except UnicodeError as exc:
        raise UpdateError("Panel environment must be UTF-8 text.") from exc
    names = {
        "PSIPHON3XUI_PORT",
        "PSIPHON3XUI_HOST",
        "PSIPHON3XUI_TLS_CERT",
        "PSIPHON3XUI_TLS_KEY",
        "PSIPHON3XUI_DB_PATH",
    }
    values = {}
    for line in text.splitlines():
        key, separator, value = line.strip().partition("=")
        if not separator or key.strip() not in names:
            continue
        key, value = key.strip(), value.strip()
        if key in values:
            raise UpdateError("Duplicate panel health configuration.")
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise UpdateError("Unsupported quoting in panel health configuration.")
            value = value[1:-1]
        if any(char in value for char in "\x00\r\n\\$`"):
            raise UpdateError("Unsupported panel health configuration.")
        values[key] = value
    port = values.get("PSIPHON3XUI_PORT", "8080")
    if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
        raise UpdateError("Panel health port is invalid.")
    host = values.get("PSIPHON3XUI_HOST", "127.0.0.1")
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise UpdateError(
            "Panel health check requires a loopback-accessible bind address."
        ) from exc
    if not (address.is_loopback or address.is_unspecified):
        raise UpdateError("Panel health check requires a loopback-accessible bind address.")
    cert, key = values.get("PSIPHON3XUI_TLS_CERT", ""), values.get("PSIPHON3XUI_TLS_KEY", "")
    if bool(cert) != bool(key):
        raise UpdateError("Panel TLS configuration is incomplete.")
    if Path(values.get("PSIPHON3XUI_DB_PATH", str(prefix / "panel.db"))) != prefix / "panel.db":
        raise UpdateError("Updater requires panel.db inside the configured installation prefix.")
    return {
        "host": "::1" if address.version == 6 else "127.0.0.1",
        "port": int(port),
        "tls": bool(cert),
    }


def health_once(settings: dict, expected: dict) -> bool:
    connection = None
    try:
        if settings["tls"]:
            # A local IP-only request supports self-signed and domain certificates.
            # No proxy, redirect, certificate path, or credentials are consumed.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(
                settings["host"], settings["port"], timeout=2, context=context
            )
        else:
            connection = http.client.HTTPConnection(settings["host"], settings["port"], timeout=2)
        connection.request("GET", "/api/health", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(MAX_JSON + 1)
        if response.status != 200 or len(body) > MAX_JSON:
            return False
        value = parse_json(body)
        return (
            value.get("status") == "ok"
            and value.get("version") == expected["version"]
            and (expected["revision"] is None or value.get("revision") == expected["revision"])
        )
    except (OSError, ValueError, UpdateError, http.client.HTTPException):
        return False
    finally:
        if connection is not None:
            connection.close()


def process_identity(pid: int) -> dict:
    # Kernel-owned /proc is deliberately separate from managed filesystem IO.
    if os.stat(f"/proc/{pid}").st_uid != 0:
        raise UpdateError("Lock owner is not a root process.")
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {
        "pid": pid,
        "start": fields[19],
        "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def active_install(files: Files, transaction: dict) -> bool:
    try:
        value = files.json(files.paths.state / "active.json")
        if value.get("action") != "install" or value.get("job_id") != transaction.get("job_id"):
            return False
        return value.get("process") == process_identity(value["process"]["pid"])
    except (OSError, UpdateError, KeyError, TypeError, ValueError, IndexError):
        return False


@contextlib.contextmanager
def operation_lock(files: Files, inherited_fd: int | None = None):
    import fcntl

    files.mkdir(files.paths.lock_dir, 0o755)
    path = files.paths.lock_dir / "operation.lock"
    with files.directory(path.parent) as parent:
        fd = os.open(
            path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent
        )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != files.owner
            or info.st_mode & 0o022
        ):
            raise UpdateError("Unsafe operation lock file.")
        if inherited_fd is not None:
            inherited = os.fstat(inherited_fd)
            if (inherited.st_dev, inherited.st_ino) != (info.st_dev, info.st_ino):
                raise UpdateError("Inherited lock descriptor is not the updater lock.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
                raise UpdateError("Inherited operation lock was not held.")
            # Succeeds only if this inherited open-file description owns it.
            fcntl.flock(inherited_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError as exc:
        raise BusyError("Another installer or update is running.") from exc
    finally:
        # Never LOCK_UN an inherited FD: the manual installer still owns it.
        os.close(fd)


class Updater:
    def __init__(
        self,
        paths: Paths,
        files: Files,
        *,
        user=DEFAULT_ACCOUNT,
        group=DEFAULT_ACCOUNT,
        upstream=None,
    ):
        self.paths, self.files = paths, files
        self.user, self.group = user, group
        self.upstream = upstream or Upstream()
        self.system_environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def layout(self):
        self.files.mkdir(self.paths.state, 0o750)
        self.files.mkdir(self.paths.state / "jobs")
        self.files.mkdir(self.paths.state / "transactions")
        self.files.mkdir(self.paths.state / "venvs", 0o750)
        self.files.mkdir(self.paths.inbox, 0o770)

    def status(self, job, phase, message, error=None, **extra):
        self.files.put_json(
            self.paths.state / "status.json",
            {
                **job_identity(job),
                "phase": phase,
                "message": message,
                "error": error,
                "updated_at": utcnow(),
                **extra,
            },
            0o640,
        )

    def installed(self):
        value = self.files.json(self.paths.state / "installed.json")
        if set(value) != {"version", "revision"}:
            raise UpdateError("Installed marker has an unsupported format.")
        return identity(value, revision_optional=True)

    def ready(self):
        value = self.files.json(self.paths.state / "ready.json", optional=True)
        return job_identity(value) if value is not None else None

    def request(self, action):
        return request_from_bytes(
            self.files.read(self.paths.inbox / "request.json", MAX_REQUEST, panel=True), action
        )

    def transaction(self):
        value = self.files.json(self.paths.state / "transaction.json", optional=True)
        if value is None:
            return None
        job_identity(value)
        if (
            value.get("schema") != 1
            or not isinstance(value.get("attempt"), str)
            or not ATTEMPT.fullmatch(value["attempt"])
            or not value["attempt"].startswith(value["job_id"] + "-")
        ):
            raise UpdateError("Recovery transaction has an unsupported format.")
        if value.get("step") not in {
            "prepared",
            "stopping",
            "backed_up",
            "activating",
            "rolling_back",
            "restored",
            "committed",
        }:
            raise UpdateError("Recovery transaction step is invalid.")
        identity(value.get("previous"), revision_optional=True)
        return value

    def save_transaction(self, value, step=None):
        if step is not None:
            value["step"] = step
        self.files.put_json(self.paths.state / "transaction.json", value)

    def systemctl(self, *args, check=True, capture=False):
        return run_command(
            ["/usr/bin/systemctl", *args],
            environment=self.system_environment,
            timeout=90,
            check=check,
            capture=capture,
            label="Panel service operation",
        )

    def ensure_stopped(self):
        self.systemctl("stop", PANEL_UNIT)
        _, state = self.systemctl(
            "show", "--property=ActiveState", "--value", PANEL_UNIT, capture=True
        )
        if state.strip() not in {b"inactive", b"failed"}:
            raise UpdateError("Panel did not stop; no database files were changed.")

    def wait_health(self, settings, expected, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code, _ = self.systemctl("is-active", "--quiet", PANEL_UNIT, check=False)
            if code == 0 and health_once(settings, expected):
                return
            time.sleep(1)
        raise UpdateError("Panel did not report the expected version and revision after restart.")

    def render(self, key: str, content: bytes) -> bytes:
        if key.endswith("helper"):
            return content
        try:
            text = content.decode("utf-8")
        except UnicodeError as exc:
            raise UpdateError("Managed template is not UTF-8.") from exc
        text = text.replace(DEFAULT_PREFIX, str(self.paths.prefix))
        if key == "panel_unit":
            text = re.sub(r"^User=.*$", "User=" + self.user, text, flags=re.M)
            text = re.sub(r"^Group=.*$", "Group=" + self.group, text, flags=re.M)
            if f"User={self.user}" not in text or f"Group={self.group}" not in text:
                raise UpdateError("Panel service template must run as the panel account.")
        elif key == "polkit":
            text = text.replace(DEFAULT_ACCOUNT, self.user)
        else:
            text = text.replace("--user " + DEFAULT_ACCOUNT, "--user " + self.user)
            text = text.replace("--group " + DEFAULT_ACCOUNT, "--group " + self.group)
        return text.encode()

    def download(self, request):
        if self.transaction() is not None:
            raise UpdateError(
                "An interrupted activation requires recovery before another download."
            )
        previous_ready = self.ready()
        if previous_ready == job_identity(request):
            self.verify_stage(request)
            self.status(
                request,
                "ready",
                "Update is downloaded and awaiting explicit installation.",
                candidate_ready=True,
            )
            return
        current = self.installed()
        if version_tuple(request["version"]) < version_tuple(current["version"]):
            raise UpdateError("A lower panel version cannot be staged.")
        if request["revision"] == current["revision"]:
            raise UpdateError("This source revision is already installed.")
        self.status(request, "downloading", "Verifying main and downloading the pinned source.")
        if self.upstream.main_revision() != request["revision"]:
            raise UpdateError("Main has changed; check again before downloading.")
        job_dir = self.paths.state / "jobs" / request["job_id"]
        if job_dir.exists():
            raise UpdateError("This job identity has already been used; check again.")
        self.files.mkdir(job_dir)
        archive = job_dir / "source.tar.gz"
        with self.files.writer(archive) as writer:
            digest = self.upstream.download(request["revision"], writer)
        inspect_archive(archive, request["revision"], request["version"])
        self.files.put_json(
            job_dir / "stage.json",
            {
                **job_identity(request),
                "sha256": digest,
                "repository": REPOSITORY,
                "created_at": utcnow(),
            },
        )
        self.files.put_json(self.paths.state / "ready.json", job_identity(request))
        self.status(
            request,
            "ready",
            "Update is downloaded and awaiting explicit installation.",
            candidate_ready=True,
        )
        if previous_ready is not None:
            # Keep installed venvs and all rollback transactions. Only obsolete
            # download-only material is disposable after the new stage is ready.
            old = self.paths.state / "jobs" / previous_ready["job_id"]
            with contextlib.suppress(OSError):
                shutil.rmtree(old)

    def verify_stage(self, request):
        if self.ready() != job_identity(request):
            raise UpdateError("Install request does not identify the downloaded candidate.")
        job = self.paths.state / "jobs" / request["job_id"]
        metadata = self.files.json(job / "stage.json")
        if (
            job_identity(metadata) != job_identity(request)
            or metadata.get("repository") != REPOSITORY
        ):
            raise UpdateError("Staged source identity does not match the request.")
        if not isinstance(metadata.get("sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", metadata["sha256"]
        ):
            raise UpdateError("Staged source digest is invalid.")
        archive = job / "source.tar.gz"
        if archive_digest(self.files, archive) != metadata["sha256"]:
            raise UpdateError("Staged source digest changed; download again.")
        return archive

    def prepare(self, request, attempt):
        archive = self.verify_stage(request)
        work = self.paths.state / "jobs" / request["job_id"] / attempt
        self.files.mkdir(work)
        for name in ("source", "home", "tmp", "wheels"):
            self.files.mkdir(work / name)
        source = work / "source"
        inspect_archive(archive, request["revision"], request["version"], destination=source)
        self.status(request, "installing", "Verified the downloaded source archive.", progress=10)
        (source / "panel" / "data").mkdir(mode=0o700, parents=True, exist_ok=True)
        self.files.put_json(source / "panel" / "data" / "build.json", identity(request))
        managed = {}
        for key, (relative, _, _, _) in MANAGED.items():
            content = self.files.read(source / relative, MAX_MANAGED)
            if not content:
                raise UpdateError("Managed source file is empty.")
            managed[key] = self.render(key, content)
        if shutil.disk_usage(self.paths.state).free < 512 * 1024 * 1024:
            raise UpdateError("At least 512 MiB of free space is required to prepare an update.")
        venv = self.paths.state / "venvs" / attempt
        if venv.exists():
            raise UpdateError("Candidate virtual environment already exists.")
        environment = clean_environment(work)
        self.status(request, "installing", "Creating the isolated panel environment.", progress=10)
        run_command(
            ["/usr/bin/python3", "-I", "-m", "venv", "--copies", str(venv)],
            environment=environment,
            timeout=180,
            label="Creating candidate environment",
        )
        self.status(request, "installing", "Created the isolated panel environment.", progress=20)
        python = str(venv / "bin" / "python")
        pip = [
            python,
            "-I",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--no-input",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--index-url",
            "https://pypi.org/simple",
        ]
        self.status(request, "installing", "Installing panel build tools.", progress=25)
        run_command(
            [*pip, "build", "setuptools>=68", "wheel"],
            environment=environment,
            timeout=600,
            label="Installing build tools",
        )
        self.status(request, "installing", "Installed the panel build tools.", progress=35)
        self.status(request, "installing", "Building the panel package.", progress=40)
        run_command(
            [
                python,
                "-I",
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(work / "wheels"),
                str(source),
            ],
            environment=environment,
            timeout=600,
            label="Building panel wheel",
        )
        self.status(request, "installing", "Built and verified the panel package.", progress=50)
        wheels = list((work / "wheels").glob("*.whl"))
        if len(wheels) != 1 or not wheels[0].name.startswith(
            f"psiphon_3x_ui_panel-{request['version']}-"
        ):
            raise UpdateError("Build did not produce the expected panel wheel.")
        with zipfile.ZipFile(wheels[0]) as wheel:
            info = wheel.getinfo("panel/data/build.json")
            if info.file_size > MAX_JSON or parse_json(wheel.read(info)) != identity(request):
                raise UpdateError("Built wheel did not preserve source identity.")
        self.status(
            request, "installing", "Installing the new panel and its dependencies.", progress=52
        )
        run_command(
            [*pip, str(wheels[0])],
            environment=environment,
            timeout=600,
            label="Installing candidate dependencies",
        )
        self.status(
            request, "installing", "Installed the new panel and its dependencies.", progress=57
        )
        self.status(request, "installing", "Checking candidate dependencies.", progress=58)
        run_command(
            [python, "-I", "-m", "pip", "--isolated", "check"],
            environment=environment,
            timeout=60,
            label="Checking candidate dependencies",
        )
        self.status(
            request,
            "installing",
            "Dependency checks passed; preparing the panel restart.",
            progress=60,
        )
        # The permanent venv must be readable by the unprivileged service even
        # though the unit launching this helper has UMask=0077.
        for directory, directories, names in os.walk(venv, followlinks=False):
            for item in [
                Path(directory),
                *(Path(directory) / name for name in directories + names),
            ]:
                if item.is_symlink():
                    continue  # venv's lib64 -> lib; never chmod through a link
                info = item.stat()
                if os.name == "posix":
                    if info.st_uid != self.files.owner or not (
                        stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                    ):
                        raise UpdateError("Candidate environment contains an unsafe object.")
                    os.chown(item, self.files.owner, self.files.gid)
                item.chmod(0o750 if item.is_dir() or info.st_mode & 0o111 else 0o640)
        return venv, managed

    def backup_managed(self, backup):
        manifest = {}
        for key in [*MANAGED, "override"]:
            path = self.paths.destination(key)
            try:
                with self.files.opened(path, limit=MAX_MANAGED) as (reader, info):
                    data = reader.read(MAX_MANAGED + 1)
                self.files.write(backup / key, data)
                # Windows only reports its read-only flag, so behavior tests
                # use the declared destination mode. Linux preserves the
                # actual installed permissions for rollback.
                mode = (
                    stat.S_IMODE(info.st_mode)
                    if os.name == "posix"
                    else (0o644 if key == "override" else MANAGED[key][3])
                )
                manifest[key] = {"mode": mode, "sha256": hashlib.sha256(data).hexdigest()}
            except FileNotFoundError:
                manifest[key] = None
        if manifest["panel_unit"] is None or manifest["update_helper"] is None:
            raise UpdateError("The installed panel/updater service files are missing.")
        self.files.put_json(backup / "manifest.json", manifest)
        # Recover executes this last-known-good code, including if the new
        # update_panel.py cannot even parse after a power loss.
        self.files.write(
            self.paths.state / "recovery.py",
            self.files.read(backup / "update_helper", MAX_MANAGED),
            0o600,
        )

    def backup_data(self, backup):
        env = self.files.read(self.paths.prefix / "panel.env", MAX_ENV, panel=True)
        settings = local_settings(env, self.paths.prefix)
        self.files.write(backup / "panel.env", env)
        raw = backup / "sqlite-copy"
        self.files.mkdir(raw)
        self.files.copy(self.paths.prefix / "panel.db", raw / "panel.db", MAX_DATABASE, panel=True)
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                # SQLite's SHM is transient; copying is only needed to reject an
                # unsafe existing inode. The private copy recreates its own SHM.
                target = raw / ("panel.db" + suffix)
                self.files.copy(
                    self.paths.prefix / ("panel.db" + suffix), target, MAX_DATABASE, panel=True
                )
                if suffix == "-shm":
                    self.files.remove(target)
            except FileNotFoundError:
                pass
        deadline = time.monotonic() + 60

        def progress(_status, _remaining, _total):
            if time.monotonic() > deadline:
                raise UpdateError("Consistent database backup timed out.")

        try:
            with (
                contextlib.closing(sqlite3.connect(raw / "panel.db", timeout=5)) as source,
                contextlib.closing(sqlite3.connect(backup / "panel.db", timeout=5)) as target,
            ):
                source.execute("PRAGMA trusted_schema=OFF")
                source.backup(target, pages=256, progress=progress, sleep=0.05)
        except sqlite3.Error as exc:
            raise UpdateError("Could not make a consistent panel database backup.") from exc
        # sqlite3 owns its handle; explicitly sync the completed backup.
        with self.files.opened(backup / "panel.db", limit=MAX_DATABASE, writable=True) as (
            stream,
            _,
        ):
            os.fsync(stream.fileno())
        self.files.put_json(
            backup / "data.json",
            {
                "env_sha256": hashlib.sha256(env).hexdigest(),
                "db_sha256": self.digest_database(backup / "panel.db"),
            },
        )
        return settings

    def digest_database(self, path):
        with self.files.opened(path, limit=MAX_DATABASE) as (stream, _):
            return copy_bounded(stream, DigestSink(), MAX_DATABASE)

    def restore_data(self, backup):
        metadata = self.files.json(backup / "data.json")
        env = self.files.read(backup / "panel.env", MAX_ENV)
        if hashlib.sha256(env).hexdigest() != metadata.get("env_sha256") or self.digest_database(
            backup / "panel.db"
        ) != metadata.get("db_sha256"):
            raise UpdateError("Rollback data backup failed its integrity check.")
        # Remove fixed sidecar names, never follow them. No process is running.
        for suffix in ("-wal", "-shm", "-journal"):
            self.files.remove(self.paths.prefix / ("panel.db" + suffix))
        with (
            self.files.opened(backup / "panel.db", limit=MAX_DATABASE) as (reader, _),
            self.files.writer(self.paths.prefix / "panel.db", 0o660, panel_owner=True) as writer,
        ):
            copy_bounded(reader, writer, MAX_DATABASE)
        self.files.write(self.paths.prefix / "panel.env", env, 0o660)
        return local_settings(env, self.paths.prefix)

    def restore_managed(self, backup):
        manifest = self.files.json(backup / "manifest.json")
        if set(manifest) != {*MANAGED, "override"}:
            raise UpdateError("Rollback managed-file manifest is incomplete.")
        contents = {}
        # Validate ALL backups before restoring any of them.
        for key, item in manifest.items():
            if item is not None:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"mode", "sha256"}
                    or type(item["mode"]) is not int
                    or item["mode"] & ~0o755
                ):
                    raise UpdateError("Rollback file metadata is invalid.")
                data = self.files.read(backup / key, MAX_MANAGED)
                if hashlib.sha256(data).hexdigest() != item["sha256"]:
                    raise UpdateError("Rollback managed-file backup failed its integrity check.")
                contents[key] = data
        for key, item in manifest.items():
            path = self.paths.destination(key)
            if item is None:
                self.files.remove(path)
            else:
                self.files.write(path, contents[key], item["mode"])

    def rollback(self, transaction, *, restart: bool):
        backup = self.paths.state / "transactions" / transaction["attempt"]
        self.save_transaction(transaction, "rolling_back")
        if restart:
            self.ensure_stopped()
        else:
            # Called by the Before=panel boot unit; never synchronously start or
            # stop its dependent panel unit, which would deadlock systemd.
            _, state = self.systemctl(
                "show", "--property=ActiveState", "--value", PANEL_UNIT, capture=True
            )
            if state.strip() not in {b"inactive", b"failed", b"activating"}:
                raise UpdateError("Boot recovery requires the panel to be stopped.")
            _, pid = self.systemctl(
                "show", "--property=MainPID", "--value", PANEL_UNIT, capture=True
            )
            if pid.strip() not in {b"", b"0"}:
                raise UpdateError("Boot recovery found a running panel process.")
        self.restore_managed(backup)
        settings = (
            self.restore_data(backup)
            if transaction.get("data_ready") is True
            else local_settings(
                self.files.read(self.paths.prefix / "panel.env", MAX_ENV, panel=True),
                self.paths.prefix,
            )
        )
        self.files.put_json(self.paths.state / "installed.json", transaction["previous"], 0o640)
        self.save_transaction(transaction, "restored")
        self.systemctl("daemon-reload")
        if restart:
            self.systemctl("start", PANEL_UNIT)
            self.wait_health(settings, transaction["previous"])
        self.status(
            transaction,
            "failed",
            "Update failed; the previous panel was restored and verified."
            if restart
            else "Interrupted update rolled back; systemd will start the previous panel.",
            error=transaction.get("failure", "Update was interrupted."),
            candidate_ready=self.ready() == job_identity(transaction),
            rollback_restored=True,
            rollback_health_verified=restart,
        )
        self.files.remove(self.paths.state / "transaction.json")

    def install(self, request):
        if self.transaction() is not None:
            raise UpdateError(
                "An interrupted activation requires recovery before another installation."
            )
        current = self.installed()
        if version_tuple(request["version"]) < version_tuple(current["version"]):
            raise UpdateError("A lower panel version cannot be installed.")
        self.verify_stage(request)
        # Validate the health/backup configuration while the old panel still runs.
        local_settings(
            self.files.read(self.paths.prefix / "panel.env", MAX_ENV, panel=True), self.paths.prefix
        )
        self.status(
            request,
            "installing",
            "Building a fresh panel environment; the current panel is still running.",
            candidate_ready=True,
            progress=5,
        )
        attempt = request["job_id"] + "-" + uuid.uuid4().hex
        venv, managed = self.prepare(request, attempt)
        backup = self.paths.state / "transactions" / attempt
        self.files.mkdir(backup)
        self.files.mkdir(self.paths.systemd / "psiphon-3x-ui.service.d", 0o755)
        self.backup_managed(backup)
        transaction = {
            **job_identity(request),
            "schema": 1,
            "attempt": attempt,
            "step": "prepared",
            "data_ready": False,
            "previous": current,
        }
        self.save_transaction(transaction)
        try:
            self.status(
                request,
                "installing",
                "Candidate built. Backing up and restarting the companion panel.",
                candidate_ready=True,
                progress=60,
            )
            self.save_transaction(transaction, "stopping")
            self.ensure_stopped()
            settings = self.backup_data(backup)
            transaction["data_ready"] = True
            self.save_transaction(transaction, "backed_up")
            self.status(
                request,
                "installing",
                "Panel data backed up; activating the new panel environment.",
                candidate_ready=True,
                progress=75,
            )
            self.save_transaction(transaction, "activating")
            for key, data in managed.items():
                self.files.write(self.paths.destination(key), data, MANAGED[key][3])
            self.files.write(
                self.paths.destination("override"),
                f"[Service]\nExecStart=\nExecStart={venv}/bin/python -I -m panel\n".encode(),
                0o644,
            )
            self.systemctl("daemon-reload")
            self.systemctl("start", PANEL_UNIT)
            self.status(
                request,
                "installing",
                "New panel started; verifying its health and installed revision.",
                candidate_ready=True,
                progress=90,
            )
            self.wait_health(settings, identity(request))
            # This is the commit point. An interrupted final status write must
            # not roll back a panel that has already passed health verification.
            self.save_transaction(transaction, "committed")
            self.finish_commit(transaction)
        except Exception as exc:
            if transaction["step"] == "committed":
                raise UpdateError(
                    "Update passed health verification; recovery will finish recording the result."
                ) from exc
            transaction["failure"] = safe_failure(exc)
            try:
                self.rollback(transaction, restart=True)
            except Exception as rollback_exc:
                self.status(
                    request,
                    "failed",
                    "Update failed and automatic rollback is incomplete. Root recovery is required.",
                    error=safe_failure(rollback_exc),
                    candidate_ready=True,
                    rollback_restored=False,
                    rollback_health_verified=False,
                )
                raise UpdateError(
                    "Automatic rollback is incomplete; run the recovery service as root."
                ) from rollback_exc
            raise UpdateError(transaction["failure"]) from exc

    def finish_commit(self, transaction):
        self.files.put_json(self.paths.state / "installed.json", identity(transaction), 0o640)
        self.status(
            transaction,
            "succeeded",
            "Panel update installed and health verified.",
            candidate_ready=False,
            progress=100,
        )
        self.files.remove(self.paths.state / "ready.json")
        self.files.remove(self.paths.state / "transaction.json")

    def recover(self, *, restart=False, download_only=False):
        transaction = self.transaction()
        # Download's restricted service can reconcile its own interrupted job,
        # but must never restore panel files or an unrelated install transaction.
        if download_only and transaction is not None:
            return
        if download_only:
            status = self.files.json(self.paths.state / "status.json", optional=True)
            if status is None or status.get("phase") != "downloading":
                return
        if transaction is not None:
            if transaction["step"] == "committed":
                self.finish_commit(transaction)
            else:
                try:
                    self.rollback(transaction, restart=restart)
                except Exception as exc:
                    self.status(
                        transaction,
                        "failed",
                        "Interrupted update could not be fully restored. Panel startup is blocked until root recovery succeeds.",
                        error=safe_failure(exc),
                        candidate_ready=self.ready() == job_identity(transaction),
                        rollback_restored=False,
                        rollback_health_verified=False,
                    )
                    raise UpdateError(
                        "Recovery failed; panel startup must remain blocked."
                    ) from exc
        else:
            status = self.files.json(self.paths.state / "status.json", optional=True)
            if status is not None and status.get("phase") in {"downloading", "installing"}:
                self.status(
                    status,
                    "failed",
                    "The update job was interrupted. Retry the download or installation.",
                    error="The previous updater process ended before completing its work.",
                    candidate_ready=self.ready() == job_identity(status),
                )
        self.files.remove(self.paths.state / "active.json")

    def record(self, metadata_path):
        if self.transaction() is not None:
            raise UpdateError("Recover the interrupted activation before a manual reinstall.")
        metadata = self.files.json(metadata_path)
        if set(metadata) != {"version", "revision"}:
            raise UpdateError("Build metadata has unexpected fields.")
        metadata = identity(metadata, revision_optional=True)
        self.files.put_json(self.paths.state / "installed.json", metadata, 0o640)
        self.files.remove(self.paths.state / "ready.json")
        self.files.remove(self.paths.state / "status.json")
        self.files.remove(self.paths.state / "active.json")

    def setup(self, source, metadata):
        self.layout()
        if self.transaction() is not None:
            raise UpdateError("Recover the interrupted activation before replacing updater files.")
        # Validate the entire input before replacing installed recovery code.
        marker = identity(self.files.json(metadata), revision_optional=True)
        helper = self.files.read(source / "installer/update_panel.py", MAX_MANAGED)
        units = {
            key: self.render(key, self.files.read(source / MANAGED[key][0], MAX_MANAGED))
            for key in ("download_unit", "install_unit", "recover_unit")
        }
        if not helper or any(not content for content in units.values()):
            raise UpdateError("Updater bootstrap files must not be empty.")
        self.files.mkdir(self.paths.libexec.parent, 0o755)
        self.files.mkdir(self.paths.libexec, 0o755)
        self.files.write(self.paths.libexec / "update_panel.py", helper, 0o755)
        self.files.write(self.paths.state / "recovery.py", helper, 0o600)
        for key, content in units.items():
            self.files.write(self.paths.destination(key), content, 0o644)
        self.files.put_json(self.paths.state / "installed.json", marker, 0o640)
        self.record(metadata)


def safe_failure(exc: Exception) -> str:
    if isinstance(exc, UpdateError):
        return str(exc)
    if isinstance(exc, OSError):
        return "A required file, permission, network, or service operation failed. Check the root updater service."
    return "The updater could not complete this operation. Check the root updater service."


def signal_failure(_number, _frame):
    # Give rollback its TimeoutStopSec window; a second TERM must not interrupt it.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise UpdateError("The update service was interrupted or reached its time limit.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("download", "install", "recover", "setup", "record"))
    parser.add_argument("--prefix", default=DEFAULT_PREFIX, type=Path)
    parser.add_argument("--user", default=DEFAULT_ACCOUNT)
    parser.add_argument("--group", default=DEFAULT_ACCOUNT)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--lock-fd", type=int)
    recovery_mode = parser.add_mutually_exclusive_group()
    recovery_mode.add_argument(
        "--after-job",
        action="store_true",
        help="restore and restart after a worker has exited",
    )
    recovery_mode.add_argument(
        "--download-job",
        action="store_true",
        help="record an interrupted download without touching panel activation",
    )
    recovery_mode.add_argument(
        "--boot",
        action="store_true",
        help="restore before panel startup without starting the dependent panel unit",
    )
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("the updater must run as root on Linux")
    if not ACCOUNT.fullmatch(args.user) or not ACCOUNT.fullmatch(args.group):
        parser.error("invalid service account")
    if (
        not args.prefix.is_absolute()
        or not re.fullmatch(r"/[a-zA-Z0-9_./-]+", str(args.prefix))
        or any(part in {".", ".."} for part in args.prefix.parts)
        or args.prefix == Path("/")
    ):
        parser.error("installation prefix must be an absolute simple path")
    if args.lock_fd is not None and args.action not in {"setup", "record", "recover"}:
        parser.error("inherited locks are only accepted for manual installer actions")
    if (args.after_job or args.boot or args.download_job) and args.action != "recover":
        parser.error("recovery modes are only accepted for recovery")
    if args.action in {"setup", "record"} and args.metadata is None:
        parser.error("manual installation requires trusted --metadata")
    if args.action == "setup" and args.source is None:
        parser.error("setup requires a trusted source directory")
    import grp
    import pwd

    uid, gid = pwd.getpwnam(args.user).pw_uid, grp.getgrnam(args.group).gr_gid
    if uid == 0 or gid == 0:
        parser.error("the panel account and group must be unprivileged")
    os.umask(0o077)
    os.chdir("/")
    signal.signal(signal.SIGTERM, signal_failure)
    signal.signal(signal.SIGINT, signal_failure)
    paths = Paths(prefix=args.prefix)
    files = Files(paths, gid, uid)
    updater = Updater(paths, files, user=args.user, group=args.group)
    request = None
    try:
        with operation_lock(files, args.lock_fd):
            updater.layout()
            if args.action == "setup":
                updater.setup(args.source, args.metadata)
            elif args.action == "record":
                updater.record(args.metadata)
            elif args.action == "recover":
                updater.recover(restart=args.after_job, download_only=args.download_job)
            else:
                request = updater.request(args.action)
                files.put_json(
                    paths.state / "active.json",
                    {
                        **job_identity(request),
                        "action": args.action,
                        "process": process_identity(os.getpid()),
                    },
                    0o640,
                )
                try:
                    getattr(updater, args.action)(request)
                except Exception as exc:
                    # Preserve rollback's more specific, durable result.
                    status = files.json(paths.state / "status.json", optional=True)
                    if (
                        status is None
                        or status.get("phase") != "failed"
                        or status.get("job_id") != request["job_id"]
                    ):
                        ready = updater.ready()
                        display = (
                            ready if args.action == "download" and ready is not None else request
                        )
                        updater.status(
                            display,
                            "ready" if display is ready else "failed",
                            "The update could not complete; a downloaded candidate remains available."
                            if ready
                            else "The update could not complete. Check again to retry.",
                            error=safe_failure(exc),
                            candidate_ready=ready is not None,
                        )
                    raise
                finally:
                    files.remove(paths.state / "active.json")
        return 0
    except BusyError as exc:
        if args.action == "recover":
            try:
                transaction = updater.transaction()
                if transaction is None or active_install(files, transaction):
                    return 0
            except (OSError, UpdateError):
                pass
        print(safe_failure(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(safe_failure(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
