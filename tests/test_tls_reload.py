"""Real TLS handshakes and unattended same-path certificate renewal regressions."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization

from panel import runtime, tls_reload


def _handshake(context, hostname="localhost", version=ssl.TLSVersion.TLSv1_3):
    """Drive real OpenSSL handshakes in memory, including clients without SNI."""
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE  # disposable self-signed test certificates only
    client_context.minimum_version = client_context.maximum_version = version
    incoming, outgoing, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(incoming, outgoing, server_hostname=hostname)
    server = context.wrap_bio(server_in, server_out, server_side=True)
    complete = [False, False]
    for _ in range(100):
        for index, peer in enumerate((client, server)):
            if complete[index]:
                continue
            try:
                peer.do_handshake()
                complete[index] = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        if outgoing.pending:
            server_in.write(outgoing.read())
        if server_out.pending:
            incoming.write(server_out.read())
        if all(complete):
            return client, server, incoming, server_out
    pytest.fail("TLS handshake did not complete")


def _peer_certificate(context, hostname="localhost", version=ssl.TLSVersion.TLSv1_3):
    return _handshake(context, hostname, version)[0].getpeercert(binary_form=True)


def _expected_certificate(cert):
    return ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))


class TestSnapshotAndValidation:
    def test_fingerprint_is_content_based_even_when_mtimes_and_sizes_match(self, tls_pair_factory):
        cert, key = tls_pair_factory()
        old = tls_reload.pair_fingerprint(cert, key)
        times = cert.stat()
        # Whitespace changes the byte-pair digest but not the byte length.
        contents = cert.read_bytes().replace(b"\n", b" ", 1)
        cert.write_bytes(contents)
        os.utime(cert, ns=(times.st_atime_ns, times.st_mtime_ns))
        assert cert.stat().st_size == times.st_size
        assert tls_reload.pair_fingerprint(cert, key) != old

    def test_missing_or_unreadable_pair_has_no_fingerprint(
        self, tmp_path, monkeypatch, tls_pair_factory
    ):
        assert tls_reload.pair_fingerprint(tmp_path / "cert", tmp_path / "key") is None
        cert, key = tls_pair_factory()

        def denied(path):
            raise PermissionError("unreadable source")

        monkeypatch.setattr(tls_reload, "_read_pem", denied)
        assert tls_reload.pair_fingerprint(cert, key) is None

    def test_snapshots_are_private_and_removed_on_error(self, tls_pair_factory):
        cert, key = tls_pair_factory()
        snapshot = tls_reload.read_pair(cert, key)
        with pytest.raises(RuntimeError), tls_reload.snapshot_files(snapshot) as (c, k):
            assert c.read_bytes() == snapshot.cert
            assert k.read_bytes() == snapshot.key
            if os.name == "posix":
                assert k.stat().st_mode & 0o777 == 0o600
                assert k.parent.stat().st_mode & 0o777 == 0o700
            raise RuntimeError("load failed")
        assert not k.exists()
        assert not k.parent.exists()

    def test_expiry_is_timezone_aware(self, tls_pair_factory):
        cert, _ = tls_pair_factory(days=7)
        expiry = tls_reload.read_cert_expiry(cert)
        assert expiry.tzinfo == timezone.utc
        assert timedelta(days=6) < expiry - datetime.now(timezone.utc) < timedelta(days=8)

    @pytest.mark.parametrize("contents", [b"", b"not a certificate"])
    def test_expiry_unknown_for_invalid_files(self, tmp_path, contents):
        cert = tmp_path / "invalid.pem"
        cert.write_bytes(contents)
        assert tls_reload.read_cert_expiry(cert) is None
        assert tls_reload.read_cert_expiry(tmp_path / "absent") is None

    def test_valid_pair_passes_and_mismatched_key_fails(self, tls_pair_factory):
        cert, key = tls_pair_factory()
        assert tls_reload.validate_pair(cert, key)[0] is True
        _, different_key = tls_pair_factory("different")
        ok, detail = tls_reload.validate_pair(cert, different_key)
        assert ok is False
        assert "MISMATCH" in detail

    @pytest.mark.parametrize(
        "kwargs, message", [({"days": -1}, "expired"), ({"future": True}, "not yet valid")]
    )
    def test_expired_and_future_pairs_are_refused(self, tls_pair_factory, kwargs, message):
        cert, key = tls_pair_factory(**kwargs)
        ok, detail = tls_reload.validate_pair(cert, key)
        assert ok is False
        assert message in detail

    @pytest.mark.parametrize(
        "key_format",
        [serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL],
    )
    def test_encrypted_key_never_prompts_on_stdin(self, tls_pair_factory, key_format):
        cert, key = tls_pair_factory()
        private_key = serialization.load_pem_private_key(key.read_bytes(), password=None)
        key.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                key_format,
                serialization.BestAvailableEncryption(b"test-password"),
            )
        )
        ok, detail = tls_reload.validate_pair(cert, key)
        assert ok is False
        assert "encrypted private keys" in detail

    @pytest.mark.parametrize(
        "preamble",
        [
            b"Bag Attributes\n    friendlyName: ENCRYPTED panel backup\n",
            b"Proc-Type: 4,ENCRYPTED\nmetadata preceding an unencrypted key\n",
        ],
    )
    def test_encryption_words_in_preamble_do_not_reject_valid_keys(
        self, tls_pair_factory, preamble
    ):
        cert, key = tls_pair_factory()
        key.write_bytes(preamble + key.read_bytes())
        assert tls_reload.validate_pair(cert, key)[0] is True

    def test_absent_password_is_explicitly_noninteractive(self, tls_pair_factory, monkeypatch):
        cert, key = tls_pair_factory()
        real_create = tls_reload.create_ssl_context
        seen = []

        def capture(**kwargs):
            seen.append(kwargs["password"])
            return real_create(**kwargs)

        monkeypatch.setattr(tls_reload, "create_ssl_context", capture)
        tls_reload.build_candidate(tls_reload.read_pair(cert, key), tls_reload.TLSOptions())
        assert seen == [""]

    def test_oversized_source_is_rejected(self, tls_pair_factory):
        cert, key = tls_pair_factory()
        cert.write_bytes(b"x" * (1024 * 1024 + 1))
        ok, detail = tls_reload.validate_pair(cert, key)
        assert ok is False
        assert "1 MiB" in detail


class TestAutomaticRenewal:
    @pytest.mark.parametrize("hostname", ["localhost", None, "127.0.0.1", "::1"])
    @pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
    def test_new_handshakes_use_renewed_pair_without_restart(
        self, tls_controller_factory, tls_pair_factory, hostname, version
    ):
        cert, key, controller, config = tls_controller_factory()
        listener = config.ssl
        before = _peer_certificate(listener, hostname, version)
        old_connection, server, incoming, outgoing = _handshake(listener, hostname, version)
        tls_pair_factory()  # overwrite both files at exactly the same paths
        assert controller.reload()["reloaded"] is True
        assert config.ssl is listener, "the captured listener object must not be replaced"
        after = _peer_certificate(listener, hostname, version)
        assert after == _expected_certificate(cert)
        assert after != before
        server.write(b"existing connection survives")
        incoming.write(outgoing.read())
        assert old_connection.read() == b"existing connection survives"
        assert old_connection.getpeercert(binary_form=True) == before

    def test_unchanged_skips_but_force_revalidates(self, tls_controller_factory):
        _, _, controller, _ = tls_controller_factory()
        applied = controller.current
        assert controller.reload()["reason"] == "already applied"
        assert controller.current is applied
        assert controller.reload(force=True)["reloaded"] is True
        assert controller.current is not applied
        assert controller.current.digest == applied.digest

    @pytest.mark.parametrize("failure", ["missing", "garbage", "mismatch", "expired", "future"])
    def test_invalid_renewal_retains_last_good_context_and_recovers(
        self, tls_controller_factory, tls_pair_factory, failure
    ):
        cert, key, controller, config = tls_controller_factory()
        active = controller.current
        before = _peer_certificate(config.ssl)
        if failure == "missing":
            key.unlink()
        elif failure == "garbage":
            cert.write_text("garbage", encoding="ascii")
        elif failure == "mismatch":
            different_cert, _ = tls_pair_factory("different")
            cert.write_bytes(different_cert.read_bytes())
        else:
            tls_pair_factory(**({"days": -1} if failure == "expired" else {"future": True}))
        assert controller.reload()["reloaded"] is False
        assert controller.last_error
        assert controller.current is active
        assert _peer_certificate(config.ssl) == before
        tls_pair_factory()
        assert controller.reload()["reloaded"] is True
        assert controller.last_error is None
        assert _peer_certificate(config.ssl) == _expected_certificate(cert)

    def test_permission_failure_retries_even_when_files_do_not_change(
        self, tls_controller_factory, tls_pair_factory, monkeypatch, caplog
    ):
        _, _, controller, _ = tls_controller_factory()
        tls_pair_factory()
        real_read = tls_reload.read_pair
        with monkeypatch.context() as denied:

            def fail(*args):
                raise PermissionError("renewed key is temporarily unreadable")

            denied.setattr(tls_reload, "read_pair", fail)
            with caplog.at_level("WARNING", logger="panel.tls_reload"):
                assert not controller.reload()["reloaded"]
                assert not controller.reload()["reloaded"]
            assert sum("temporarily unreadable" in record.message for record in caplog.records) == 1
        assert tls_reload.read_pair is real_read
        assert controller.reload()["reloaded"] is True

    def test_renewal_before_first_tick_is_not_adopted_without_loading(
        self, tls_controller_factory, tls_pair_factory
    ):
        cert, key, controller, config = tls_controller_factory()
        startup_digest = controller.current.digest
        tls_pair_factory()
        assert controller.current.digest == startup_digest
        assert tls_reload.run_tick()["reloaded"] is True
        assert controller.current.digest == tls_reload.pair_fingerprint(cert, key)
        assert _peer_certificate(config.ssl) == _expected_certificate(cert)

    def test_external_write_during_validation_cannot_poison_listener(
        self, tls_controller_factory, tls_pair_factory, monkeypatch
    ):
        cert, key, controller, config = tls_controller_factory()
        tls_pair_factory()
        expected = _expected_certificate(cert)
        candidate_digest = tls_reload.pair_fingerprint(cert, key)
        real_build = tls_reload.build_candidate

        def build_then_break(pair, options):
            candidate = real_build(pair, options)
            key.write_bytes(b"broken after validation")
            return candidate

        monkeypatch.setattr(tls_reload, "build_candidate", build_then_break)
        assert controller.reload()["reloaded"] is True
        assert controller.current.digest == candidate_digest
        assert _peer_certificate(config.ssl) == expected
        assert not controller.reload()["reloaded"]
        assert _peer_certificate(config.ssl) == expected

    async def test_watchdog_applies_without_an_api_call(
        self, tls_controller_factory, tls_pair_factory
    ):
        cert, key, controller, _ = tls_controller_factory()
        tls_pair_factory()
        task = asyncio.create_task(tls_reload.watchdog(0.01))
        try:
            for _ in range(100):
                if controller.current.digest == tls_reload.pair_fingerprint(cert, key):
                    break
                await asyncio.sleep(0.01)
            assert controller.current.digest == tls_reload.pair_fingerprint(cert, key)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def test_interval_zero_disables_watchdog(self, monkeypatch):
        monkeypatch.setattr(
            tls_reload, "run_tick", lambda: pytest.fail("watchdog must stay disabled")
        )
        await tls_reload.watchdog(0)


class TestStartup:
    def test_missing_pair_fails_closed(self, tmp_path):
        config = tls_reload.TLSConfig(
            "panel.main:app",
            ssl_certfile=str(tmp_path / "absent.pem"),
            ssl_keyfile=str(tmp_path / "absent.key"),
            startup_retry_interval=0,
        )
        with pytest.raises(OSError):
            config.load()
        assert config.loaded is False
        assert runtime.get_tls_controller() is None

    def test_startup_waits_for_repaired_files_without_plaintext_fallback(
        self, tmp_path, tls_pair_factory, monkeypatch
    ):
        cert, key = tmp_path / "panel.pem", tmp_path / "panel.key"
        config = tls_reload.TLSConfig(
            "panel.main:app",
            ssl_certfile=str(cert),
            ssl_keyfile=str(key),
            startup_retry_interval=1,
            lifespan="off",
        )
        attempts = []

        def repair_files():
            assert not config.loaded
            assert runtime.get_tls_controller() is None
            attempts.append(config.startup_retry_interval)
            tls_pair_factory()

        monkeypatch.setattr(config, "_wait_for_retry", repair_files)
        config.load()
        assert attempts == [1]
        assert isinstance(config.ssl, ssl.SSLContext)
        assert _peer_certificate(config.ssl) == _expected_certificate(cert)
        runtime.reset_runtime_state()

    def test_retry_wait_uses_short_sleep_slices(self, monkeypatch):
        config = tls_reload.TLSConfig("panel.main:app", startup_retry_interval=0.25)
        clock = [0.0]
        sleeps = []

        def advance(delay):
            sleeps.append(delay)
            clock[0] += delay

        monkeypatch.setattr(tls_reload.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(tls_reload.time, "sleep", advance)
        config._wait_for_retry()
        assert sleeps == pytest.approx([0.1, 0.1, 0.05])

    def test_retry_wait_cancels_before_sleeping(self, monkeypatch):
        config = tls_reload.TLSConfig("panel.main:app")
        config.startup_cancelled = True
        monkeypatch.setattr(
            tls_reload.time, "sleep", lambda delay: pytest.fail("cancelled startup must not sleep")
        )
        with pytest.raises(tls_reload.TLSStartupCancelled):
            config._wait_for_retry()

    @pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
    async def test_server_signals_cancel_missing_tls_before_lifespan_or_listener(
        self, tmp_path, monkeypatch, sig
    ):
        config = tls_reload.TLSConfig(
            "panel.main:app",
            ssl_certfile=str(tmp_path / "absent.pem"),
            ssl_keyfile=str(tmp_path / "absent.key"),
            startup_retry_interval=60,
        )
        server = tls_reload.TLSServer(config)
        from uvicorn.server import HANDLED_SIGNALS

        original = {handled: signal.getsignal(handled) for handled in HANDLED_SIGNALS}
        sleeps = []

        def stop_during_retry(delay):
            sleeps.append(delay)
            assert delay <= 0.1
            assert not config.loaded
            assert not server.started
            assert not hasattr(server, "lifespan")
            handler = signal.getsignal(sig)
            assert handler == server.handle_exit
            handler(sig, None)

        monkeypatch.setattr(tls_reload.time, "sleep", stop_during_retry)
        monkeypatch.setattr(signal, "raise_signal", lambda received: None)
        try:
            await server.serve()
            assert len(sleeps) == 1
            assert server.should_exit
            assert config.startup_cancelled
            assert not config.loaded
            assert not server.started
            assert not hasattr(server, "lifespan")
            assert not hasattr(server, "servers")
            assert runtime.get_tls_controller() is None
            assert {handled: signal.getsignal(handled) for handled in HANDLED_SIGNALS} == original
        finally:
            for handled, handler in original.items():
                signal.signal(handled, handler)
            runtime.reset_runtime_state()

    def test_expired_startup_can_recover_on_renewal(self, tls_controller_factory, tls_pair_factory):
        cert, _, controller, config = tls_controller_factory(days=-1)
        assert controller.current.certificate.not_after < datetime.now(timezone.utc)
        tls_pair_factory()
        assert controller.reload()["reloaded"] is True
        assert _peer_certificate(config.ssl) == _expected_certificate(cert)

    def test_plain_http_config_clears_old_runtime_state(self, tls_controller_factory):
        tls_controller_factory()
        config = tls_reload.TLSConfig("panel.main:app", lifespan="off")
        config.load()
        assert config.ssl is None
        assert runtime.get_tls_controller() is None

    def test_application_errors_are_not_retried_as_certificate_errors(
        self, tls_pair_factory, monkeypatch
    ):
        cert, key = tls_pair_factory()
        config = tls_reload.TLSConfig(
            "nonexistent_tls_test_app:app",
            ssl_certfile=str(cert),
            ssl_keyfile=str(key),
            startup_retry_interval=1,
        )
        monkeypatch.setattr(
            tls_reload.time, "sleep", lambda delay: pytest.fail("app failures must not be retried")
        )
        with pytest.raises(SystemExit):
            config.load()
        assert runtime.get_tls_controller() is None

    @pytest.mark.parametrize("interval", [-1, 86401])
    def test_invalid_monitor_intervals_are_refused(self, interval):
        from pydantic import ValidationError

        from panel.config import Settings

        with pytest.raises(ValidationError):
            Settings(_env_file=None, tls_reload_interval=interval)

    async def test_lifespan_starts_and_cancels_the_watchdog(
        self, tls_controller_factory, monkeypatch
    ):
        from types import SimpleNamespace

        from panel import main

        cert, key, _, _ = tls_controller_factory()
        monkeypatch.setattr(main, "init_db", lambda: None)
        monkeypatch.setattr(
            main,
            "get_settings",
            lambda: SimpleNamespace(
                tls_cert=cert,
                tls_key=key,
                tls_reload_interval=60,
            ),
        )
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def watch(interval):
            assert interval == 60
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        monkeypatch.setattr(tls_reload, "watchdog", watch)
        async with main.lifespan(main.app):
            await asyncio.wait_for(started.wait(), timeout=1)
        assert cancelled.is_set()


async def test_real_uvicorn_automatically_renews_same_path_pair(
    tls_controller_factory, tls_pair_factory
):
    """Prove actual TCP handshakes, HTTP responses and watchdog-driven rotation."""
    cert, key, controller, config = tls_controller_factory()
    server = tls_reload.TLSServer(config)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    watcher = None

    async def wait_until(predicate):
        async def wait():
            while not predicate():
                if serving.done():
                    await serving
                    pytest.fail("Uvicorn stopped unexpectedly")
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait(), timeout=10)

    async def connect():
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=client_context,
            server_hostname="127.0.0.1",
        )
        peer = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        await writer.wait_closed()
        assert b"200 OK" in response
        assert b'{"status":"ok"}' in response
        return peer

    try:
        await wait_until(lambda: server.started)
        watcher = asyncio.create_task(tls_reload.watchdog(0.01))
        first = await connect()
        original_cert, original_key = cert.read_bytes(), key.read_bytes()
        cert.write_bytes(b"incomplete renewal")
        await wait_until(lambda: controller.last_error is not None)
        assert await connect() == first
        cert.write_bytes(original_cert)
        key.write_bytes(original_key)
        tls_pair_factory()
        expected_digest = tls_reload.pair_fingerprint(cert, key)
        await wait_until(lambda: controller.current.digest == expected_digest)
        assert await connect() == _expected_certificate(cert)
        assert await connect() != first
    finally:
        if watcher:
            watcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watcher
        server.should_exit = True
        await asyncio.wait_for(serving, timeout=10)
        sock.close()
