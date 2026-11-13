"""Shared certificate fixtures for real TLS renewal regressions."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@pytest.fixture
def tls_pair_factory(tmp_path):
    """Create valid, expired, or future-dated pairs without openssl subprocesses.

    Calling with the same name overwrites the same two paths, exactly as an
    external certificate issuer does during renewal. Each call rotates the key
    and serial. Both DNS and bare-IP handshakes are covered by the SANs.
    """

    def mint(
        name: str = "panel",
        *,
        directory: Path | None = None,
        days: int = 7,
        future: bool = False,
    ) -> tuple[Path, Path]:
        destination = directory or tmp_path
        destination.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        not_after = now + timedelta(days=days)
        not_before = min(now - timedelta(minutes=5), not_after - timedelta(days=1))
        if future:
            not_before = now + timedelta(days=1)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path = destination / f"{name}.pem"
        key_path = destination / f"{name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path

    return mint


@pytest.fixture
def tls_controller_factory(tls_pair_factory):
    """Initialize a real managed listener without binding a TCP socket."""
    from panel import runtime
    from panel.tls_reload import TLSConfig

    runtime.reset_runtime_state()

    async def app(scope, receive, send):
        body = b'{"status":"ok"}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def make(name="panel", **kwargs):
        cert, key = tls_pair_factory(name, **kwargs)
        config = TLSConfig(
            app,
            ssl_certfile=str(cert),
            ssl_keyfile=str(key),
            startup_retry_interval=0,
            lifespan="off",
            log_level="error",
        )
        config.load()
        return cert, key, runtime.get_tls_controller(), config

    yield make
    runtime.reset_runtime_state()
