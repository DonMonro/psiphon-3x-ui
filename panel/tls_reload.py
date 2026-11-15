"""Automatically apply renewed certificates without mutating a serving context.

Uvicorn/asyncio retain the listener SSLContext for the lifetime of the server.
Its SNI callback selects an immutable, already validated context for each new
handshake, including bare-IP clients that send no SNI. Renewals are built from
private snapshots and published with their content digest in one assignment.
A partial write, unreadable file, or mismatched key cannot damage the active
context; established connections are unaffected.

This module does not issue certificates. The operator's existing issuer keeps
renewing the configured source files; the watchdog picks them up automatically.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import ssl
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from uvicorn.config import create_ssl_context

from . import runtime

_log = logging.getLogger(__name__)
_MAX_PEM_BYTES = 1024 * 1024


@dataclass(frozen=True)
class PairSnapshot:
    cert: bytes
    key: bytes
    digest: str


@dataclass(frozen=True)
class CertificateInfo:
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True)
class AppliedPair:
    context: ssl.SSLContext
    digest: str
    certificate: CertificateInfo
    applied_at: datetime


@dataclass(frozen=True)
class TLSOptions:
    protocol: int = ssl.PROTOCOL_TLS_SERVER
    cert_reqs: int = ssl.CERT_NONE
    ca_certs: str | None = None
    ciphers: str | None = None
    password: str | None = None

    def create_context(self, cert: Path, key: Path) -> ssl.SSLContext:
        # An explicit empty password prevents OpenSSL from prompting on stdin.
        return create_ssl_context(
            certfile=str(cert),
            keyfile=str(key),
            password=self.password if self.password is not None else "",
            ssl_version=self.protocol,
            cert_reqs=self.cert_reqs,
            ca_certs=self.ca_certs,
            ciphers=self.ciphers,
        )


def _read_pem(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f"TLS source is not a regular file: {path}")
        data = stream.read(_MAX_PEM_BYTES + 1)
    if len(data) > _MAX_PEM_BYTES:
        raise ValueError(f"TLS file exceeds the 1 MiB limit: {path}")
    return data


def read_pair(cert: Path, key: Path) -> PairSnapshot:
    """Capture bounded file contents; never infer identity from path or mtime."""
    cert_bytes, key_bytes = _read_pem(cert), _read_pem(key)
    digest = hashlib.sha256()
    digest.update(len(cert_bytes).to_bytes(8, "big"))
    digest.update(cert_bytes)
    digest.update(key_bytes)
    return PairSnapshot(cert_bytes, key_bytes, digest.hexdigest())


def pair_fingerprint(cert: Path, key: Path) -> str | None:
    """Best-effort content identity for dashboard diagnostics."""
    try:
        return read_pair(cert, key).digest
    except (OSError, ValueError):
        return None


@contextmanager
def snapshot_files(pair: PairSnapshot) -> Iterator[tuple[Path, Path]]:
    """Keep key snapshots private and remove them even when loading fails."""
    with tempfile.TemporaryDirectory(prefix="psiphon-panel-tls-") as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        cert.write_bytes(pair.cert)
        key.write_bytes(pair.key)
        key.chmod(0o600)
        yield cert, key


def _certificate_info(cert: Path) -> CertificateInfo:
    # CPython's bundled OpenSSL decoder avoids a new production dependency.
    # cert_time_to_seconds handles OpenSSL's fixed English date format without
    # depending on the process locale (datetime.strptime would do so).
    decoded = ssl._ssl._test_decode_cert(str(cert))
    return CertificateInfo(
        datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notBefore"]), timezone.utc),
        datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), timezone.utc),
    )


def read_cert_expiry(cert: Path) -> datetime | None:
    try:
        captured = PairSnapshot(_read_pem(cert), b"", "")
        with snapshot_files(captured) as (snapshot_cert, _):
            return _certificate_info(snapshot_cert).not_after
    except (OSError, ValueError, KeyError, AttributeError):
        return None


def _reject_encrypted_key(pair: PairSnapshot, options: TLSOptions) -> None:
    if options.password:
        return
    blocks = re.finditer(
        rb"^-----BEGIN ([A-Z ]*PRIVATE KEY)-----[ \t]*\r?\n"
        rb"((?:[A-Za-z-]+:[^\r\n]*\r?\n)*)",
        pair.key,
        re.MULTILINE,
    )
    for block in blocks:
        if block[1] == b"ENCRYPTED PRIVATE KEY" or re.search(
            rb"^Proc-Type:[ \t]*4[ \t]*,[ \t]*ENCRYPTED[ \t]*\r?$", block[2], re.MULTILINE
        ):
            raise ValueError("encrypted private keys require a configured TLS password")


def build_candidate(pair: PairSnapshot, options: TLSOptions) -> AppliedPair:
    _reject_encrypted_key(pair, options)
    with snapshot_files(pair) as (cert, key):
        context = options.create_context(cert, key)
        info = _certificate_info(cert)
    return AppliedPair(context, pair.digest, info, datetime.now(timezone.utc))


def _require_current_certificate(info: CertificateInfo) -> None:
    now = datetime.now(timezone.utc)
    if info.not_after <= now:
        raise ValueError("certificate has expired; waiting for a valid renewed pair")
    if info.not_before > now:
        raise ValueError("certificate is not yet valid; check the server clock")


def validate_pair(cert: Path, key: Path) -> tuple[bool, str]:
    """Check matching key, certificate syntax, and validity without side effects."""
    try:
        candidate = build_candidate(read_pair(cert, key), TLSOptions())
        _require_current_certificate(candidate.certificate)
    except (OSError, ValueError, KeyError, AttributeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, "TLS pair loads and certificate is current"


class TLSController:
    """A stable listener with an atomic reference to the last-good TLS pair."""

    def __init__(
        self, cert: Path, key: Path, initial: AppliedPair, options: TLSOptions | None = None
    ) -> None:
        self.cert = cert
        self.key = key
        self.options = options or TLSOptions()
        self.current = initial
        self.listener_context = initial.context
        self.last_error: str | None = None
        self.listener_context.sni_callback = self._select_context

    def _select_context(self, connection, server_name, initial_context) -> None:
        # OpenSSL calls this even when server_name is None (bare IP/no SNI).
        # No filesystem I/O or context mutation is allowed in the handshake.
        connection.context = self.current.context

    def reload(self, *, force: bool = False) -> dict:
        try:
            snapshot = read_pair(self.cert, self.key)
            if not force and snapshot.digest == self.current.digest:
                self.last_error = None
                return {"changed": False, "reloaded": False, "reason": "already applied"}
            candidate = build_candidate(snapshot, self.options)
            _require_current_certificate(candidate.certificate)
        except (OSError, ValueError, KeyError, AttributeError) as exc:
            detail = f"{type(exc).__name__}: {exc}"
            if detail != self.last_error:
                _log.warning(
                    "TLS renewal not applied; retaining the active certificate: %s", detail
                )
            self.last_error = detail
            # Retry the same files next tick too: a permission repair might
            # leave the content digest and timestamps entirely unchanged.
            return {"changed": False, "reloaded": False, "error": detail}

        self.current = candidate
        self.last_error = None
        _log.info("TLS certificate renewed automatically from %s", self.cert)
        return {"changed": True, "reloaded": True}


def last_applied_fingerprint() -> str | None:
    controller = runtime.get_tls_controller()
    return controller.current.digest if controller else None


def run_tick() -> dict:
    controller = runtime.get_tls_controller()
    if controller is None:
        return {"skipped": "no-managed-tls-listener"}
    return controller.reload()


async def watchdog(interval_seconds: float) -> None:
    if interval_seconds <= 0:
        return
    while True:
        try:
            run_tick()
        except Exception:
            _log.exception("Unexpected TLS watchdog error; will retry")
        await asyncio.sleep(interval_seconds)


class TLSStartupCancelled(Exception):
    """Normal shutdown while configured HTTPS is waiting for usable files."""


class TLSConfig(uvicorn.Config):
    """Initialize from exact snapshots inside each Uvicorn serving process.

    Loading in the worker preserves debug reload: SSLContexts and callbacks
    never enter the supervisor's pickled configuration. Configured HTTPS waits
    for usable files at startup rather than ever opening a plaintext listener.
    """

    def __init__(self, *args, startup_retry_interval: float = 60, **kwargs) -> None:
        # Keep SSLContext's modern Python/OpenSSL cipher defaults. Uvicorn's
        # historical "TLSv1" cipher list excludes modern TLS 1.2 suites.
        kwargs.setdefault("ssl_ciphers", None)
        super().__init__(*args, **kwargs)
        self.startup_retry_interval = startup_retry_interval
        self.startup_cancelled = False

    def _wait_for_retry(self) -> None:
        # Uvicorn's signal handler sets a flag rather than interrupting
        # Config.load(). Check it in short sleep slices so systemd stop and
        # the debug supervisor's terminate/join do not hang on missing PEMs.
        deadline = time.monotonic() + self.startup_retry_interval
        while not self.startup_cancelled:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(remaining, 0.1))
        raise TLSStartupCancelled

    def load(self) -> None:
        runtime.reset_runtime_state()
        if not self.is_ssl:
            super().load()
            return
        if not self.ssl_certfile or not self.ssl_keyfile:
            raise ValueError("both TLS certificate and private-key paths are required")

        cert, key = Path(self.ssl_certfile), Path(self.ssl_keyfile)
        options = TLSOptions(
            protocol=self.ssl_version,
            cert_reqs=self.ssl_cert_reqs,
            ca_certs=self.ssl_ca_certs,
            ciphers=self.ssl_ciphers,
            password=self.ssl_keyfile_password,
        )
        last_error = None
        while True:
            if self.startup_cancelled:
                raise TLSStartupCancelled
            try:
                pair = read_pair(cert, key)
                initial = build_candidate(pair, options)
                break
            except (OSError, ValueError, KeyError, AttributeError) as exc:
                if self.startup_retry_interval <= 0:
                    raise
                detail = f"{type(exc).__name__}: {exc}"
                if detail != last_error:
                    _log.warning(
                        "HTTPS startup waiting for a usable certificate/key pair: %s", detail
                    )
                last_error = detail
                self._wait_for_retry()

        if self.startup_cancelled:
            raise TLSStartupCancelled
        # Only certificate loading is retried. Application import/configuration
        # failures must propagate normally rather than be misreported as TLS.
        with snapshot_files(pair) as (snapshot_cert, snapshot_key):
            original_cert, original_key = self.ssl_certfile, self.ssl_keyfile
            try:
                self.ssl_certfile, self.ssl_keyfile = str(snapshot_cert), str(snapshot_key)
                super().load()
            finally:
                self.ssl_certfile, self.ssl_keyfile = original_cert, original_key
        # The listener has not bound yet: install the context constructed from
        # the captured bytes, together with that exact digest, before serving.
        self.ssl = initial.context
        controller = TLSController(cert, key, initial, options)
        runtime.set_tls_controller(controller)
        if initial.certificate.not_after <= datetime.now(timezone.utc):
            # Keep TLS available so renewal can still be detected unattended.
            # The browser will correctly reject this until a valid renewal arrives.
            _log.warning(
                "Configured TLS certificate has expired; automatic renewal monitoring is active"
            )


class TLSServer(uvicorn.Server):
    """Forward shutdown into synchronous TLS startup without parent callbacks.

    Only simple config state is passed to debug workers; no bound callback or
    SSLContext is constructed in the supervisor's process.
    """

    def handle_exit(self, sig, frame) -> None:
        if isinstance(self.config, TLSConfig):
            self.config.startup_cancelled = True
        super().handle_exit(sig, frame)

    async def serve(self, sockets=None) -> None:
        try:
            await super().serve(sockets=sockets)
        except TLSStartupCancelled:
            # No listener or lifespan was started, so there is nothing to
            # tear down. Uvicorn restores its signal handlers while unwinding.
            _log.info("HTTPS startup cancelled by shutdown")
