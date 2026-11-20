"""Credential recovery revokes persistent sessions without changing the vault key."""

from __future__ import annotations

import contextlib
import io
import sqlite3
import tarfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from panel import auth, config, db
from panel.models import AdminAuthState, Settings, XuiLink

OLD_PASSWORD = "correct-horse-battery-staple"
NEW_PASSWORD = "a-different-recovery-password"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "session-recovery-test-secret")
    monkeypatch.setenv("PSIPHON3XUI_HTTPS_ONLY", "0")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")
    config.get_settings.cache_clear()
    monkeypatch.setattr(db, "_engine", None)
    monkeypatch.setattr(db, "_session_factory", None)
    auth.login_rate_limit_reset()
    db.init_db()
    engine = db.get_engine()
    with Session(engine) as session:
        session.add(
            Settings(
                id=1,
                panel_port=18001,
                admin_user="admin",
                admin_pass_hash=auth.hash_password(OLD_PASSWORD),
                wizard_completed=True,
            )
        )
        session.commit()
    from panel import main

    monkeypatch.setattr(main, "_CSRF_ENFORCE", False)
    try:
        with TestClient(main.app) as test_client:
            yield test_client
    finally:
        engine.dispose()
        auth.login_rate_limit_reset()
        config.get_settings.cache_clear()


def _login(client, password=OLD_PASSWORD):
    response = client.post("/auth/login", json={"user": "admin", "password": password})
    assert response.status_code == 204, response.text
    return client.cookies[auth.SESSION_COOKIE_NAME]


def _reset_from_other_process(*, password=NEW_PASSWORD):
    """Use an independent connection, as the local recovery CLI does."""
    engine = create_engine(f"sqlite:///{config.get_settings().db_path}")
    try:
        with Session(engine) as session:
            settings = session.get(Settings, 1)
            settings.admin_pass_hash = auth.hash_password(password)
            generation = auth.revoke_admin_sessions(session)
            session.commit()
            return generation
    finally:
        engine.dispose()


def test_new_login_embeds_persistent_random_generation(client):
    token = _login(client)
    payload = auth.verify_session(token)
    with Session(db.get_engine()) as session:
        stored = auth.get_session_generation(session)
    assert payload == {"sub": "admin", "generation": stored}
    assert len(bytes.fromhex(stored)) == 32


def test_other_process_recovery_rejects_old_cookie_and_preserves_vault(client):
    stored_creds = {"username": "upstream-admin", "password": "upstream-secret"}
    with Session(db.get_engine()) as session:
        encrypted = auth.encrypt_creds(stored_creds)
        session.add(
            XuiLink(
                id=1,
                base_url="http://127.0.0.1:2053",
                username="upstream-admin",
                password_enc=encrypted,
            )
        )
        session.commit()
    old_cookie = _login(client)
    _reset_from_other_process()
    for path in ("/api/me", "/auth/csrf", "/api/wizard", "/api/dashboard/username"):
        assert client.get(path).status_code == 401, path
    assert (
        client.post("/auth/login", json={"user": "admin", "password": OLD_PASSWORD}).status_code
        == 401
    )
    assert _login(client, NEW_PASSWORD) != old_cookie
    assert client.get("/api/me").status_code == 200
    with Session(db.get_engine()) as session:
        assert session.get(XuiLink, 1).password_enc == encrypted
        settings = session.get(Settings, 1)
        assert settings.panel_port == 18001
        assert settings.wizard_completed is True
        assert settings.admin_user == "admin"
    assert auth.decrypt_creds(encrypted) == stored_creds


def test_revocation_and_password_change_roll_back_together(client):
    _login(client)
    with Session(db.get_engine()) as session:
        before = auth.get_session_generation(session)
        settings = session.get(Settings, 1)
        settings.admin_pass_hash = auth.hash_password(NEW_PASSWORD)
        assert auth.revoke_admin_sessions(session) != before
        session.rollback()
        assert auth.get_session_generation(session) == before
        assert auth.verify_password(OLD_PASSWORD, session.get(Settings, 1).admin_pass_hash)
    assert client.get("/api/me").status_code == 200


def test_boot_preserves_generation_and_existing_cookie(client):
    token = _login(client)
    db.init_db()
    db.init_db()
    assert client.get("/api/me").status_code == 200
    assert client.cookies[auth.SESSION_COOKIE_NAME] == token


def test_legacy_database_gets_auth_state_without_reseeding_credentials(client):
    with Session(db.get_engine()) as session:
        old_hash = session.get(Settings, 1).admin_pass_hash
    AdminAuthState.__table__.drop(db.get_engine())
    db.init_db()
    with Session(db.get_engine()) as session:
        assert auth.get_session_generation(session)
        settings = session.get(Settings, 1)
        assert settings.admin_pass_hash == old_hash
        assert settings.wizard_completed is True
        assert settings.panel_port == 18001
    _login(client)
    assert client.get("/api/me").status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {"sub": "admin"},
        {"sub": None, "generation": "x"},
        {"sub": ["admin"], "generation": "x"},
        {"sub": "admin", "generation": None},
        {"sub": "admin", "generation": ["x"]},
        {"sub": "admin", "generation": "é"},
        {"sub": "admin", "generation": "x"},
        ["admin"],
    ],
)
def test_legacy_or_malformed_signed_cookie_is_rejected(client, payload):
    cookie = auth.sign_session(payload)
    client.cookies.set(auth.SESSION_COOKIE_NAME, cookie)
    assert client.get("/api/me").status_code == 401


def test_missing_auth_state_fails_closed_without_recreating_nonce(client):
    _login(client)
    with Session(db.get_engine()) as session:
        session.execute(delete(AdminAuthState))
        session.commit()
    assert client.get("/api/me").status_code == 401
    response = client.post("/auth/login", json={"user": "admin", "password": OLD_PASSWORD})
    assert response.status_code == 503
    with Session(db.get_engine()) as session:
        assert auth.get_session_generation(session) is None


def test_login_racing_reset_cannot_issue_fresh_cookie_with_old_password(client, monkeypatch):
    from panel import main

    original_verify = main.verify_password
    recovery_generation = None

    def verify_and_reset(password, password_hash):
        nonlocal recovery_generation
        verified = original_verify(password, password_hash)
        if recovery_generation is None:
            recovery_generation = _reset_from_other_process()
        return verified

    monkeypatch.setattr(main, "verify_password", verify_and_reset)
    token = _login(client)
    assert auth.verify_session(token)["generation"] != recovery_generation
    assert client.get("/api/me").status_code == 401
    _login(client, NEW_PASSWORD)
    assert client.get("/api/me").status_code == 200


def test_generation_read_ignores_cached_auth_object(client):
    with Session(db.get_engine()) as session:
        cached = session.get(AdminAuthState, 1)
        original = cached.session_generation
        changed = _reset_from_other_process()
        assert cached.session_generation == original
        assert auth.get_session_generation(session) == changed


def test_revoke_replaces_instead_of_reusing_missing_generation(client):
    with Session(db.get_engine()) as session:
        session.execute(delete(AdminAuthState))
        generated = auth.revoke_admin_sessions(session)
        session.commit()
        assert session.scalar(select(AdminAuthState.session_generation)) == generated
        assert len(bytes.fromhex(generated)) == 32


def _archive_database(data):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("panel.db")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def _restore(client, payload):
    return client.post(
        "/api/dashboard/restore",
        files={"file": ("backup.tar", payload, "application/x-tar")},
    )


@pytest.mark.parametrize("journal_mode", ["delete", "wal"])
def test_restore_does_not_resurrect_recovered_or_current_sessions(client, journal_mode):
    with db.get_engine().connect() as connection:
        assert (
            connection.exec_driver_sql(f"PRAGMA journal_mode={journal_mode}").scalar()
            == journal_mode
        )
    original = _login(client)
    backup = client.post("/api/dashboard/backup")
    assert backup.status_code == 200
    _reset_from_other_process()
    recovered = _login(client, NEW_PASSWORD)
    restored = _restore(client, backup.content)
    assert restored.status_code == 200, restored.text
    assert restored.json()["restored_panel_db"] is True
    assert client.get("/api/me").status_code == 401
    client.cookies.clear()
    client.cookies.set(auth.SESSION_COOKIE_NAME, original)
    assert client.get("/api/me").status_code == 401
    # Full database restore intentionally restores the backed-up credentials,
    # but requires a new sign-in, never an old browser cookie.
    client.cookies.clear()
    fresh = _login(client)
    assert auth.verify_session(fresh)["generation"] not in {
        auth.verify_session(original)["generation"],
        auth.verify_session(recovered)["generation"],
    }
    assert client.get("/api/me").status_code == 200


def test_restore_legacy_database_initializes_new_auth_generation(client, tmp_path):
    original = _login(client)
    backup = client.post("/api/dashboard/backup")
    with tarfile.open(fileobj=io.BytesIO(backup.content), mode="r") as archive:
        candidate = tmp_path / "legacy.db"
        candidate.write_bytes(archive.extractfile("panel.db").read())
    with contextlib.closing(sqlite3.connect(candidate)) as connection:
        connection.execute("DROP TABLE admin_auth_state")
        connection.commit()
    restored = _restore(client, _archive_database(candidate.read_bytes()))
    assert restored.status_code == 200, restored.text
    assert client.get("/api/me").status_code == 401
    fresh = _login(client)
    assert auth.verify_session(fresh)["generation"] != auth.verify_session(original)["generation"]
    assert client.get("/api/me").status_code == 200


@pytest.mark.parametrize("payload", [b"not a database", b"SQLite format 3\x00broken"])
def test_invalid_database_restore_preserves_login_and_credentials(client, payload):
    token = _login(client)
    restored = _restore(client, _archive_database(payload))
    assert restored.status_code == 400, restored.text
    assert client.get("/api/me").status_code == 200
    assert (
        auth.verify_session(_login(client))["generation"]
        == auth.verify_session(token)["generation"]
    )


def test_interrupted_database_restore_rolls_back_partial_copy(client, tmp_path, monkeypatch):
    from panel.dashboard import router as dashboard

    _login(client)
    archive = client.post("/api/dashboard/backup")
    with tarfile.open(fileobj=io.BytesIO(archive.content), mode="r") as source:
        candidate = tmp_path / "larger-backup.db"
        candidate.write_bytes(source.extractfile("panel.db").read())
    with contextlib.closing(sqlite3.connect(candidate)) as connection:
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        connection.execute("CREATE TABLE restore_test_data (payload BLOB)")
        connection.execute("INSERT INTO restore_test_data VALUES (?)", (bytes(page_size * 300),))
        connection.commit()
        assert connection.execute("PRAGMA page_count").fetchone()[0] > 256
    _reset_from_other_process()
    current = _login(client, NEW_PASSWORD)
    # The first SQLite copy step writes 256 pages, then the progress callback
    # aborts before SQLITE_DONE. sqlite3_backup_finish must roll them back.
    monkeypatch.setattr(dashboard, "_RESTORE_TIMEOUT_SECONDS", 0)
    restored = _restore(client, _archive_database(candidate.read_bytes()))
    assert restored.status_code == 409, restored.text
    assert client.get("/api/me").status_code == 200
    assert (
        auth.verify_session(_login(client, NEW_PASSWORD))["generation"]
        == auth.verify_session(current)["generation"]
    )
