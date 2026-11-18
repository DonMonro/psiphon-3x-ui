"""Unprivileged update discovery, durable intent, and root-result reconciliation.

Only the two fixed systemd units may perform work. Discovery never executes
fetched source, GET never contacts GitHub, and a ready job keeps its exact
identity until an explicit action replaces it. The application has one serving
process; its short state lock also arbitrates installation against HTTP/SSE
mutations. Root serializes actual work with the installer's operation lock.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import __version__, get_build_revision
from .config import Settings, get_settings

_log = logging.getLogger(__name__)
REPOSITORY_API = "https://api.github.com/repos/DonMonro/psiphon-3x-ui"
MAIN_URL = f"{REPOSITORY_API}/commits/main"
SOURCE_URL = "https://raw.githubusercontent.com/DonMonro/psiphon-3x-ui"
HELPER_PATH = Path("/usr/local/libexec/psiphon-3x-ui/update_panel.py")
UNIT_DIR = Path("/etc/systemd/system")
SYSTEMCTL = "/usr/bin/systemctl"
UNITS = {
    "download": "psiphon-3x-ui-update-download.service",
    "install": "psiphon-3x-ui-update-install.service",
}
MAX_JSON_BYTES = 32 * 1024
MAX_REMOTE_BYTES = 256 * 1024
CHECK_TIMEOUT_SECONDS = 25
DISPATCH_TIMEOUT_SECONDS = 10
ACK_TIMEOUT_SECONDS = 960
DOWNLOAD_TIMEOUT_SECONDS = 960
INSTALL_TIMEOUT_SECONDS = 3000
POLL_SECONDS = 30
ROOT_UID = 0
PROC_ROOT = Path("/proc")

Revision = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{40}$", max_length=40)]
JobID = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{32}$", max_length=32)]
Version = Annotated[
    str,
    Field(
        strict=True, pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$", max_length=32
    ),
]
Phase = Literal[
    "idle", "checking", "available", "downloading", "ready", "installing", "succeeded", "failed"
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def version_key(version: str) -> tuple[int, ...]:
    """Compare numeric release components, never lexical strings."""
    if (
        not isinstance(version, str)
        or len(version) > 32
        or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
    ):
        raise ValueError("version must be major.minor.patch")
    return tuple(int(part) for part in version.split("."))


def _utc_timestamp(value):
    # Root timestamps are ISO strings, not Unix seconds or naive local time.
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC ISO time")
    return value.astimezone(timezone.utc)


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Version
    revision: Revision


class Job(Candidate):
    job_id: JobID
    action: Literal["download", "install"]
    started_at: datetime
    root_updated_at: datetime | None = None
    acknowledged: bool = False

    @field_validator("started_at", "root_updated_at", mode="before")
    @classmethod
    def timestamps(cls, value):
        return None if value is None else _utc_timestamp(value)


class CachedState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    phase: Phase = "idle"
    candidate: Candidate | None = None
    job: Job | None = None
    fallback_job: Job | None = None
    install_guard: bool = False
    progress: int | None = Field(default=None, ge=0, le=100)
    last_checked_at: datetime | None = None
    message: str = Field(default="", max_length=2000)
    error: str | None = Field(default=None, max_length=2000)

    @field_validator("last_checked_at", mode="before")
    @classmethod
    def timestamp(cls, value):
        return None if value is None else _utc_timestamp(value)


class RootStatus(Candidate):
    # Extra diagnostic fields in future helpers do not change job identity.
    model_config = ConfigDict(extra="ignore")
    job_id: JobID
    phase: Literal["downloading", "ready", "installing", "succeeded", "failed"]
    message: str = Field(default="", max_length=2000)
    error: str | None = Field(default=None, max_length=2000)
    progress: int | None = Field(default=None, ge=0, le=100)
    updated_at: datetime

    @field_validator("updated_at", mode="before")
    @classmethod
    def timestamp(cls, value):
        return _utc_timestamp(value)


class UpdateError(Exception):
    def __init__(self, detail: str, status_code: int = 503):
        super().__init__(detail)
        self.status_code = status_code


def read_json(path: Path, limit: int = MAX_JSON_BYTES, *, root: bool = False) -> dict:
    """Read bounded regular files, refusing symlinks and special files.

    Root results must also come from a root-owned directory and inode. The
    Windows branch is only for isolated tests; installed helpers require Linux.
    """
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("update metadata must not be a symlink")
    if root and os.name == "posix":
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != ROOT_UID or parent.st_mode & 0o022:
            raise ValueError("root update directory has unsafe ownership or permissions")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("update metadata must be a regular file with one link")
        if root and os.name == "posix" and (info.st_uid != ROOT_UID or info.st_mode & 0o022):
            raise ValueError("root update metadata has unsafe ownership or permissions")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("update metadata exceeds its size limit")
    try:
        parsed = json.loads(data)
    except RecursionError as exc:
        raise ValueError("update metadata is too deeply nested") from exc
    if not isinstance(parsed, dict):
        raise ValueError("update metadata must be a JSON object")
    return parsed


def process_identity(pid: int) -> dict:
    """Read root process identity from Linux procfs without executing a command."""
    directory = PROC_ROOT / str(pid)
    if directory.stat().st_uid != ROOT_UID:
        raise ValueError("updater process is not root-owned")
    with (directory / "stat").open(encoding="ascii") as stream:
        fields = stream.read(4096).rsplit(")", 1)[1].split()
    if fields[0] in {"Z", "X"}:
        raise ProcessLookupError("updater process has exited")
    with (PROC_ROOT / "sys/kernel/random/boot_id").open(encoding="ascii") as stream:
        boot = stream.read(128).strip()
    return {"pid": pid, "start": fields[19], "boot": boot}


def atomic_json(path: Path, value: dict) -> None:
    """Replace a small JSON file only after both its bytes and rename are durable."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("update metadata destination must be a regular file")
    data = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("update metadata exceeds its size limit")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def unsupported_reason() -> str | None:
    """Local capability detection; no subprocesses or remote requests on GET."""
    if sys.platform != "linux":
        return "In-panel updates require a Linux installation with systemd."
    if not Path("/run/systemd/system").is_dir() or not os.access(SYSTEMCTL, os.X_OK):
        return "systemd is unavailable; use the installer to manage this installation."
    for path in (HELPER_PATH, *(UNIT_DIR / name for name in UNITS.values())):
        try:
            info = path.lstat()
        except OSError:
            return "The update helper is not installed. Re-run the installer to enable updates."
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return "The update helper or its units have unsafe ownership or permissions."
    return None


async def _remote_bytes(client: httpx.AsyncClient, url: str) -> bytes:
    async with client.stream("GET", url) as response:
        # Redirects must never turn fixed GitHub endpoints into arbitrary fetches.
        response.raise_for_status()
        data = bytearray()
        async for chunk in response.aiter_bytes():
            data.extend(chunk)
            if len(data) > MAX_REMOTE_BYTES:
                raise UpdateError("GitHub returned oversized update metadata.", 502)
        return bytes(data)


async def discover(current_version: str, current_revision: str | None) -> Candidate | None:
    """Resolve main once, then inspect only that immutable commit's source."""

    async def fetch() -> Candidate | None:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(8.0, connect=5.0),
            follow_redirects=False,
            trust_env=False,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Psiphon-3X-UI-updater",
            },
        ) as client:
            commit = json.loads(await _remote_bytes(client, MAIN_URL))
            revision = commit.get("sha") if isinstance(commit, dict) else None
            if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
                raise UpdateError("GitHub returned an invalid main revision.", 502)
            source = (
                await _remote_bytes(client, f"{SOURCE_URL}/{revision}/panel/__init__.py")
            ).decode("utf-8")
            versions = re.findall(
                r"^__version__\s*=\s*[\"\']([0-9]+\.[0-9]+\.[0-9]+)[\"\'][ \t]*\r?$",
                source,
                re.MULTILINE,
            )
            if len(versions) != 1:
                raise UpdateError("The main revision has no unambiguous panel version.", 502)
            candidate = Candidate(version=versions[0], revision=revision)
            comparison = (version_key(candidate.version) > version_key(current_version)) - (
                version_key(candidate.version) < version_key(current_version)
            )
            if comparison < 0 or current_revision == candidate.revision:
                return None
            if comparison > 0:
                return candidate
            # Legacy builds with no SHA compare versions only. Known builds may
            # accept a same-version fix, but never a rollback or divergent main.
            if current_revision is None:
                return None
            if not re.fullmatch(r"[0-9a-f]{40}", current_revision):
                raise UpdateError("The installed revision metadata is invalid.", 502)
            comparison_data = json.loads(
                await _remote_bytes(
                    client,
                    f"{REPOSITORY_API}/compare/{current_revision}...{revision}?per_page=1",
                )
            )
            if not isinstance(comparison_data, dict) or comparison_data.get("status") not in {
                "ahead",
                "behind",
                "identical",
                "diverged",
            }:
                raise UpdateError("GitHub returned an invalid revision comparison.", 502)
            return candidate if comparison_data["status"] == "ahead" else None

    try:
        return await asyncio.wait_for(fetch(), CHECK_TIMEOUT_SECONDS)
    except UpdateError:
        raise
    except (httpx.HTTPError, ValueError, TypeError, KeyError, RecursionError, TimeoutError) as exc:
        raise UpdateError("Unable to check GitHub for updates. Try again later.", 502) from exc


async def dispatch(action: Literal["download", "install"]) -> bool:
    """Start a fixed service; False means the short enqueue acknowledgement timed out.

    A timeout is ambiguous: systemd may already have accepted the start. Keep the
    job reserved until its root status arrives or the acknowledgement deadline
    expires, rather than letting a second request overwrite accepted intent.
    """
    if action not in UNITS:
        raise ValueError("unknown update action")
    try:
        process = await asyncio.create_subprocess_exec(
            SYSTEMCTL,
            "--no-block",
            "--no-ask-password",
            "start",
            UNITS[action],
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError as exc:
        raise UpdateError(
            "Unable to start the update helper. Check the installed service units."
        ) from exc
    try:
        code = await asyncio.wait_for(process.wait(), DISPATCH_TIMEOUT_SECONDS)
    except (TimeoutError, asyncio.CancelledError) as exc:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        return False
    if code != 0:
        raise UpdateError("The update service refused to start. Check its polkit rule and journal.")
    return True


class UpdateManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.directory = settings.updates_dir or settings.db_path.parent / "updates"
        self.cache_path = self.directory / "cache.json"
        self.request_path = self.directory / "request.json"
        self.root_directory = settings.update_state_dir
        self.current_version = __version__
        self.current_revision = get_build_revision()
        self._lock = asyncio.Lock()
        self._mutations = 0
        self._dispatching = False
        self._recover_root = False
        try:
            self._state = CachedState.model_validate(read_json(self.cache_path))
        except FileNotFoundError:
            self._state = CachedState()
            self._recover_root = True
        except (OSError, ValueError):
            self._state = CachedState(
                phase="failed", error="The update cache could not be read. Check again to recover."
            )
            self._recover_root = True
        if self._state.phase == "checking":
            self._state.phase = "failed"
            self._state.error = "The previous update check was interrupted. Check again to retry."
        if self._state.phase in {"downloading", "ready", "installing", "succeeded"} and (
            self._state.job is None
            or self._state.candidate is None
            or self._state.job.revision != self._state.candidate.revision
            or self._state.job.version != self._state.candidate.version
        ):
            self._state = CachedState(phase="failed", error="The cached update job is invalid.")
            self._recover_root = True

    def _commit(self, state: CachedState) -> None:
        atomic_json(self.cache_path, state.model_dump(mode="json"))
        self._state = state

    def _record(self, state: CachedState) -> None:
        """Root truth must still govern maintenance when local cache writes fail."""
        try:
            self._commit(state)
        except (OSError, ValueError):
            self._state = state
            _log.warning("Unable to persist the reconciled update status", exc_info=True)

    def _root_status(self) -> RootStatus | None:
        try:
            root = RootStatus.model_validate(
                read_json(self.root_directory / "status.json", root=True)
            )
            if root.updated_at > utcnow() + timedelta(minutes=1):
                raise ValueError("root status timestamp is in the future")
            return root
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return None

    def _installed_matches(self, job: Job) -> bool:
        try:
            marker = read_json(self.root_directory / "installed.json", root=True)
            return (
                marker.get("version") == job.version == self.current_version
                and marker.get("revision") == job.revision == self.current_revision
            )
        except (OSError, ValueError):
            return False

    def _install_active(self) -> bool:
        """Keep maintenance while root is working or activation needs recovery.

        The UI deadline is not proof that a worker stopped. The transaction is
        root-private, so inspect its inode rather than its contents; it exists
        until activation or rollback has completed.
        """
        try:
            transaction = (self.root_directory / "transaction.json").lstat()
            if stat.S_ISREG(transaction.st_mode) and (
                os.name != "posix" or transaction.st_uid == ROOT_UID
            ):
                return True
        except OSError:
            pass
        try:
            active = read_json(self.root_directory / "active.json", root=True)
            process = active.get("process")
            if active.get("action") != "install" or not isinstance(process, dict):
                return False
            pid = process.get("pid")
            return type(pid) is int and pid > 0 and process == process_identity(pid)
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            return False

    def _reconcile(self) -> None:
        if self._dispatching:
            return
        state = self._state.model_copy(deep=True)
        root = self._root_status()
        root_install_active = self._install_active()
        if self._recover_root:
            self._recover_root = False
            if root is not None:
                state.candidate = Candidate(version=root.version, revision=root.revision)
                state.job = Job(
                    version=root.version,
                    revision=root.revision,
                    job_id=root.job_id,
                    action="install" if root.phase in {"installing", "succeeded"} else "download",
                    started_at=root.updated_at,
                )
                state.phase = "installing" if state.job.action == "install" else "downloading"
        job = state.job
        if job is None or state.phase in {"idle", "available", "checking"}:
            state.install_guard = root_install_active
            if state != self._state:
                self._record(state)
            return
        fallback = state.fallback_job
        if (
            fallback is not None
            and job.action == "download"
            and root is not None
            and root.phase == "ready"
            and root.job_id == fallback.job_id
            and root.revision == fallback.revision
            and root.version == fallback.version
            and root.updated_at >= job.started_at - timedelta(seconds=1)
            and (fallback.root_updated_at is None or root.updated_at > fallback.root_updated_at)
        ):
            # A failed replacement leaves the previous staged job intact. Only
            # a fresh helper result may restore it; the old ready result cannot
            # cancel a newly queued replacement.
            state.job = job = fallback
            state.candidate = Candidate(version=fallback.version, revision=fallback.revision)
            state.fallback_job = None
        matching = root is not None and (
            root.job_id == job.job_id
            and root.revision == job.revision
            and root.version == job.version
        )
        if matching and root.updated_at >= job.started_at - timedelta(seconds=1):
            fresh = job.root_updated_at is None or root.updated_at > job.root_updated_at
            allowed = (
                root.phase in {"downloading", "ready", "failed"}
                if job.action == "download"
                else root.phase in {"installing", "succeeded", "failed"}
            )
            if fresh and allowed:
                job.root_updated_at = root.updated_at
                job.acknowledged = True
                state.phase = root.phase
                state.message = root.message
                state.error = root.error
                state.progress = root.progress
                if root.phase == "succeeded" and not self._installed_matches(job):
                    state.phase = "failed"
                    state.progress = None
                    state.error = "The helper result does not match the running panel build. Check the update service journal."
                elif root.phase == "failed" and not state.error:
                    state.progress = None
                    state.error = "The update helper failed. Check its service journal, then retry."
                elif root.phase == "failed":
                    state.progress = None
                if root.phase in {"ready", "succeeded"}:
                    state.fallback_job = None
        if state.phase in {"downloading", "installing"}:
            age = (utcnow() - job.started_at).total_seconds()
            limit = (
                DOWNLOAD_TIMEOUT_SECONDS if job.action == "download" else INSTALL_TIMEOUT_SECONDS
            )
            if not job.acknowledged and age > ACK_TIMEOUT_SECONDS:
                state.phase = "failed"
                state.error = "The update helper did not acknowledge this job. Check its service journal, then retry."
            elif age > limit:
                state.phase = "failed"
                state.error = "The update helper exceeded its time limit. Check its service journal before retrying."
        state.install_guard = state.phase == "installing" or root_install_active
        if state != self._state:
            self._record(state)

    def _available(self) -> bool:
        candidate = self._state.candidate
        return candidate is not None and (
            version_key(candidate.version) > version_key(self.current_version)
            or (
                candidate.version == self.current_version
                and self.current_revision is not None
                and candidate.revision != self.current_revision
            )
        )

    def _snapshot(self) -> dict:
        state = self._state
        interval = self.settings.update_check_interval
        reason = unsupported_reason()
        next_check = (
            state.last_checked_at + timedelta(seconds=interval)
            if interval and state.last_checked_at and reason is None
            else None
        )
        return {
            "current_version": self.current_version,
            "current_revision": self.current_revision,
            "available_version": state.candidate.version if state.candidate else None,
            "available_revision": state.candidate.revision if state.candidate else None,
            "phase": state.phase,
            "update_available": self._available(),
            "last_checked_at": state.last_checked_at.isoformat() if state.last_checked_at else None,
            "next_check_at": next_check.isoformat() if next_check else None,
            "check_interval_seconds": interval,
            "job_id": state.job.job_id if state.job else None,
            "install_guard": state.install_guard,
            "progress": state.progress,
            "message": state.message,
            "error": state.error,
            "supported": reason is None,
            "unsupported_reason": reason,
        }

    async def status(self) -> dict:
        async with self._lock:
            self._reconcile()
            return self._snapshot()

    def _require_supported(self) -> None:
        if reason := unsupported_reason():
            raise UpdateError(reason)

    def _require_free(self) -> None:
        if (
            self._state.phase in {"checking", "downloading", "installing"}
            or self._state.install_guard
            or self._dispatching
        ):
            raise UpdateError(
                "Another update operation is active. Refresh status and try again.", 409
            )

    async def begin_mutation(self) -> None:
        async with self._lock:
            self._reconcile()
            if self._state.phase == "installing" or self._state.install_guard:
                raise UpdateError("Panel installation is in progress. Wait for it to finish.", 409)
            self._mutations += 1

    def end_mutation(self) -> None:
        # ASGI application completion includes streamed bodies and background
        # work; no await here, so cancellation cannot leak the reservation.
        self._mutations -= 1

    async def check(self, *, download: bool = False) -> dict:
        async with self._lock:
            self._reconcile()
            self._require_supported()
            self._require_free()
            # A completed download is already the result of the Update action.
            # Periodic checks cannot invalidate an open confirmation dialog.
            if self._state.phase == "ready":
                return self._snapshot()
            previous = self._state.model_copy(deep=True)
            checking = previous.model_copy(deep=True)
            checking.phase, checking.error, checking.message = (
                "checking",
                None,
                "Checking main for updates.",
            )
            try:
                self._commit(checking)
            except (OSError, ValueError) as exc:
                raise UpdateError(
                    "Unable to save update state. Check the updates directory permissions."
                ) from exc
        try:
            candidate = await discover(self.current_version, self.current_revision)
        except asyncio.CancelledError:
            async with self._lock:
                self._record(previous)
            raise
        except UpdateError as exc:
            async with self._lock:
                previous.phase, previous.error = "failed", str(exc)
                previous.last_checked_at = utcnow()
                previous.message = "Update check failed."
                self._record(previous)
            raise
        async with self._lock:
            state = self._state.model_copy(deep=True)
            state.candidate = candidate
            state.job = None
            state.fallback_job = None
            state.last_checked_at = utcnow()
            state.phase = "available" if candidate else "idle"
            state.error = None
            state.message = (
                "A panel update is available." if candidate else "Your panel is up to date."
            )
            try:
                self._commit(state)
            except (OSError, ValueError) as exc:
                self._state = previous
                raise UpdateError(
                    "Unable to save the update check. Try again after checking disk space."
                ) from exc
            if download and candidate:
                previous = self._reserve("download", candidate)
            else:
                return self._snapshot()
        return await self._enqueue("download", previous)

    def _reserve(self, action: Literal["download", "install"], candidate: Candidate) -> CachedState:
        previous = self._state.model_copy(deep=True)
        state = previous.model_copy(deep=True)
        state.fallback_job = (
            previous.job if action == "download" and previous.phase == "ready" else None
        )
        job_id = state.job.job_id if action == "install" and state.job else uuid.uuid4().hex
        state.job = Job(
            version=candidate.version,
            revision=candidate.revision,
            job_id=job_id,
            action=action,
            started_at=utcnow(),
            root_updated_at=previous.job.root_updated_at
            if action == "install" and previous.job
            else None,
        )
        state.phase = "downloading" if action == "download" else "installing"
        state.install_guard = action == "install"
        state.progress = 0 if action == "install" else None
        state.message, state.error = f"Queued panel {action}.", None
        request = {"action": action, "job_id": job_id, **candidate.model_dump()}
        try:
            # Durable reservation first: a restart must not accept a second
            # request after the helper has already consumed the first one.
            self._commit(state)
            atomic_json(self.request_path, request)
        except (OSError, ValueError) as exc:
            previous.error = "Unable to write the update request. Check disk space and permissions."
            self._record(previous)
            raise UpdateError(previous.error) from exc
        self._dispatching = True
        return previous

    async def _enqueue(self, action: Literal["download", "install"], previous: CachedState) -> dict:
        try:
            acknowledged = await dispatch(action)
        except asyncio.CancelledError:
            # The service may already have been queued. Leave durable intent
            # intact; reconciling its root result is safer than resubmission.
            raise
        except UpdateError as exc:
            async with self._lock:
                with contextlib.suppress(OSError):
                    self.request_path.unlink()
                previous.error = str(exc)
                previous.message = f"Could not queue panel {action}. Try again."
                self._record(previous)
            raise
        else:
            async with self._lock:
                if not acknowledged:
                    state = self._state.model_copy(deep=True)
                    state.message = "Waiting for the update helper to acknowledge the queued job."
                    self._record(state)
                return self._snapshot()
        finally:
            self._dispatching = False

    async def download(self, revision: str) -> dict:
        async with self._lock:
            self._reconcile()
            self._require_supported()
            self._require_free()
            candidate = self._state.candidate
            if candidate is None or revision != candidate.revision or not self._available():
                raise UpdateError(
                    "This update candidate is stale. Check again before downloading.", 409
                )
            previous = self._reserve("download", candidate)
        return await self._enqueue("download", previous)

    async def install(self, job_id: str, confirm: bool) -> dict:
        if confirm is not True:
            raise UpdateError("Explicit installation confirmation is required.", 400)
        async with self._lock:
            self._reconcile()
            self._require_supported()
            self._require_free()
            state = self._state
            if state.phase != "ready" or state.job is None or state.job.job_id != job_id:
                raise UpdateError(
                    "This downloaded job is stale. Review the current download first.", 409
                )
            root = self._root_status()
            if root is None or (
                root.phase != "ready"
                or root.job_id != job_id
                or root.revision != state.job.revision
                or root.version != state.job.version
            ):
                raise UpdateError(
                    "The helper has not verified this download. Refresh status first.", 409
                )
            if not self._available():
                raise UpdateError(
                    "This download does not update the running panel. Check again.", 409
                )
            if self._mutations:
                raise UpdateError(
                    "Wait for current panel operations to finish before installing.", 409
                )
            previous = self._reserve("install", state.candidate)
        return await self._enqueue("install", previous)

    async def watchdog(self) -> None:
        """Check immediately when overdue, then schedule from the durable check time."""
        interval = self.settings.update_check_interval
        if interval == 0:
            return
        while True:
            async with self._lock:
                self._reconcile()
                now = utcnow()
                last = self._state.last_checked_at
                # A clock reset must not suppress checks for an unbounded time.
                delay = (
                    max(0.0, (last + timedelta(seconds=interval) - now).total_seconds())
                    if last
                    else 0
                )
                delay = min(delay, interval)
                pinned = self._state.install_guard or self._state.phase in {
                    "checking",
                    "downloading",
                    "ready",
                    "installing",
                }
            if unsupported_reason() is not None:
                await asyncio.sleep(interval)
            elif pinned:
                await asyncio.sleep(POLL_SECONDS)
            elif delay:
                await asyncio.sleep(delay)
            else:
                try:
                    await self.check()
                except UpdateError as exc:
                    _log.warning("Automatic panel update check failed: %s", exc)
                    # Includes local persistence/permission errors, which cannot
                    # necessarily record a last_checked_at retry deadline.
                    await asyncio.sleep(interval)


@lru_cache(maxsize=1)
def get_manager() -> UpdateManager:
    return UpdateManager(get_settings())
