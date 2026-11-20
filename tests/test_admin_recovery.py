"""Exercise local credential recovery against real isolated panel databases."""

from __future__ import annotations

import io
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from panel import admin_recovery
from panel.auth import decrypt_creds, encrypt_creds, verify_password
from panel.db import get_engine
from panel.models import AdminAuthState, Country, Settings, Wizard, XuiLink
from tests.test_auth import _client

PASSWORD = "new-panel-password-123"


@pytest.fixture
def panel(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    with Session(get_engine()) as db:
        db.add(Country(code="US", name="United States", enabled=True))
        db.add(Wizard(id=1, current_step="ports", step_data='{"codes":["US"]}'))
        db.add(
            XuiLink(
                id=1,
                base_url="http://127.0.0.1:2053",
                username="upstream-admin",
                password_enc=encrypt_creds({"password": "upstream-secret"}),
            )
        )
        db.commit()
    yield tmp_path / "panel.db", client
    from panel import db

    if db._engine is not None:
        db._engine.dispose()
    db._engine = None
    db._session_factory = None


def _snapshot(path: Path) -> dict:
    with sqlite3.connect(path) as db:
        return {
            name: db.execute(f'SELECT * FROM "{name}" ORDER BY 1').fetchall()
            for (name,) in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        }


def _login(client, *, user="admin", password="correct-horse-battery-staple"):
    return client.post("/auth/login", json={"user": user, "password": password})


def test_show_username_is_read_only_even_for_legacy_database(panel, capsys):
    path, _ = panel
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE admin_auth_state")
    before = path.read_bytes()
    assert admin_recovery.main(["--db", str(path), "show-username"]) == 0
    assert capsys.readouterr().out == "Panel admin username: admin\n"
    assert path.read_bytes() == before
    assert "admin_auth_state" not in _snapshot(path)


def test_show_username_escapes_legacy_terminal_controls(panel, capsys):
    path, _ = panel
    with Session(get_engine()) as db:
        db.get(Settings, 1).admin_user = "legacy\nadmin\x1b[31m"
        db.commit()
    assert admin_recovery.main(["--db", str(path), "show-username"]) == 0
    output = capsys.readouterr().out
    assert output == "Panel admin username: 'legacy\\nadmin\\x1b[31m'\n"
    assert "\\x1b[31m" in output


@pytest.mark.parametrize("new_username", [None, "new-admin"])
def test_reset_changes_only_credentials_and_revokes_existing_sessions(panel, new_username):
    path, client = panel
    assert _login(client).status_code == 204
    assert client.get("/api/me").status_code == 200
    before = _snapshot(path)
    assert admin_recovery.reset_credentials(path, PASSWORD, username=new_username) == (
        new_username or "admin"
    )
    after = _snapshot(path)
    for name, rows in before.items():
        if name not in {"settings", "admin_auth_state"}:
            assert after[name] == rows
    with Session(get_engine()) as db:
        settings = db.get(Settings, 1)
        assert settings.admin_user == (new_username or "admin")
        assert verify_password(PASSWORD, settings.admin_pass_hash)
        assert settings.panel_port == 18001
        assert settings.wizard_completed is False
        assert decrypt_creds(db.get(XuiLink, 1).password_enc) == {"password": "upstream-secret"}
    assert after["admin_auth_state"] != before["admin_auth_state"]
    assert client.get("/api/me").status_code == 401
    assert _login(client).status_code == 401
    assert _login(client, user=new_username or "admin", password=PASSWORD).status_code == 204
    assert client.get("/api/me").json()["user"] == (new_username or "admin")


def test_reset_adds_only_auth_state_to_legacy_database(panel):
    path, _ = panel
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE admin_auth_state")
    before = _snapshot(path)
    admin_recovery.reset_credentials(path, PASSWORD)
    after = _snapshot(path)
    assert set(after) == set(before) | {"admin_auth_state"}
    assert len(after["admin_auth_state"]) == 1
    assert all(after[name] == rows for name, rows in before.items() if name != "settings")


def test_reset_and_nonce_change_roll_back_together(panel, monkeypatch):
    path, _ = panel
    before = _snapshot(path)
    revoke = admin_recovery.revoke_admin_sessions

    def fail_after_revoke(db):
        revoke(db)
        db.flush()
        raise RuntimeError("simulated failure before commit")

    monkeypatch.setattr(admin_recovery, "revoke_admin_sessions", fail_after_revoke)
    with pytest.raises(RuntimeError):
        admin_recovery.reset_credentials(path, PASSWORD, username="new-admin")
    assert _snapshot(path) == before


@pytest.mark.parametrize("password", ["", "short", "a" * 73, "é" * 37, "test\tpassword"])
def test_invalid_passwords_leave_credentials_and_sessions_unchanged(panel, password):
    path, _ = panel
    before = _snapshot(path)
    with pytest.raises(admin_recovery.RecoveryError):
        admin_recovery.reset_credentials(path, password)
    assert _snapshot(path) == before


def test_password_at_bcrypt_byte_limit_is_not_truncated(panel):
    path, _ = panel
    password = "é" * 36
    admin_recovery.reset_credentials(path, password)
    with Session(get_engine()) as db:
        assert verify_password(password, db.get(Settings, 1).admin_pass_hash)


@pytest.mark.parametrize(
    "username", ["", "ab", "-new-admin", "has space", "a" * 65, "new\nadmin", "ادمین"]
)
def test_invalid_username_is_rejected_before_prompt_or_write(panel, monkeypatch, username):
    path, _ = panel
    before = _snapshot(path)
    monkeypatch.setattr(
        admin_recovery, "_prompt_password", lambda: pytest.fail("must reject before prompting")
    )
    assert admin_recovery.main(["--db", str(path), "reset-password", f"--username={username}"]) == 2
    assert _snapshot(path) == before


def test_cli_prompts_without_holding_a_database_lock_and_never_prints_password(
    panel, monkeypatch, capsys
):
    path, _ = panel
    prompts = []

    def getpass(prompt):
        prompts.append(prompt)
        # A second connection can take the write lock while the user types.
        with sqlite3.connect(path, timeout=0) as db:
            db.execute("BEGIN IMMEDIATE")
        return PASSWORD

    monkeypatch.setattr(admin_recovery.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(admin_recovery.sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(admin_recovery.getpass, "getpass", getpass)
    assert admin_recovery.main(["--db", str(path), "reset-password"]) == 0
    assert prompts == ["New panel password: ", "Confirm new panel password: "]
    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    assert "sessions are revoked" in output.out


def test_password_mismatch_does_not_write(panel, monkeypatch, capsys):
    path, _ = panel
    before = _snapshot(path)
    answers = iter([PASSWORD, "different-password"])
    monkeypatch.setattr(admin_recovery.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(admin_recovery.sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(admin_recovery.getpass, "getpass", lambda prompt: next(answers))
    assert admin_recovery.main(["--db", str(path), "reset-password"]) == 2
    assert "do not match" in capsys.readouterr().err
    assert _snapshot(path) == before


def test_noninteractive_password_input_is_rejected(panel, monkeypatch, capsys):
    path, _ = panel
    before = _snapshot(path)
    monkeypatch.setattr(admin_recovery.sys, "stdin", io.StringIO(PASSWORD + "\n"))
    monkeypatch.setattr(
        admin_recovery.getpass, "getpass", lambda prompt: pytest.fail("must not fall back to stdin")
    )
    assert admin_recovery.main(["--db", str(path), "reset-password"]) == 2
    assert "terminal is required" in capsys.readouterr().err
    assert _snapshot(path) == before


def test_getpass_never_falls_back_to_echoed_password(panel, monkeypatch):
    path, _ = panel
    before = _snapshot(path)
    monkeypatch.setattr(admin_recovery.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(admin_recovery.sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(admin_recovery.getpass, "getpass", admin_recovery.getpass.fallback_getpass)
    assert admin_recovery.main(["--db", str(path), "reset-password"]) == 2
    assert _snapshot(path) == before


@pytest.mark.parametrize("exception", [EOFError, KeyboardInterrupt])
def test_cancelled_prompt_leaves_credentials_unchanged(panel, monkeypatch, capsys, exception):
    path, _ = panel
    before = _snapshot(path)

    def cancel():
        raise exception

    monkeypatch.setattr(admin_recovery, "_prompt_password", cancel)
    assert admin_recovery.main(["--db", str(path), "reset-password"]) == 130
    assert "cancelled" in capsys.readouterr().err
    assert _snapshot(path) == before


@pytest.mark.parametrize("command", ["show-username", "reset-password"])
def test_missing_database_is_not_created(tmp_path, monkeypatch, command):
    path = tmp_path / "not-installed" / "panel.db"
    monkeypatch.setattr(
        admin_recovery, "_prompt_password", lambda: pytest.fail("no account to reset")
    )
    assert admin_recovery.main(["--db", str(path), command]) == 2
    assert not path.parent.exists()


def test_uninitialized_database_is_not_seeded(tmp_path, monkeypatch):
    from sqlalchemy import create_engine

    from panel.db import Base

    path = tmp_path / "uninitialized.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    engine.dispose()
    before = _snapshot(path)
    monkeypatch.setattr(
        admin_recovery, "_prompt_password", lambda: pytest.fail("no account to reset")
    )
    assert admin_recovery.main(["--db", str(path), "reset-password"]) == 2
    assert _snapshot(path) == before


def test_busy_database_keeps_credentials_unchanged(panel, monkeypatch, capsys):
    path, _ = panel
    before = _snapshot(path)
    monkeypatch.setattr(admin_recovery, "_prompt_password", lambda: PASSWORD)
    monkeypatch.setattr(admin_recovery, "_DB_TIMEOUT_SECONDS", 0)
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        assert admin_recovery.main(["--db", str(path), "reset-password"]) == 1
    assert "Could not access" in capsys.readouterr().err
    assert _snapshot(path) == before


def test_plaintext_password_argument_is_not_supported_or_echoed(panel, capsys):
    path, _ = panel
    before = _snapshot(path)
    with pytest.raises(SystemExit) as rejected:
        admin_recovery.main(["--db", str(path), "reset-password", "--password", PASSWORD])
    assert rejected.value.code == 2
    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    assert _snapshot(path) == before


def test_database_exception_does_not_print_sql_parameters(panel, monkeypatch, capsys):
    path, _ = panel
    monkeypatch.setattr(admin_recovery, "_prompt_password", lambda: PASSWORD)

    def fail(*args, **kwargs):
        raise OperationalError("UPDATE settings", {"password": PASSWORD}, Exception("failure"))

    monkeypatch.setattr(admin_recovery, "reset_credentials", fail)
    assert admin_recovery.main(["--db", str(path), "reset-password"]) == 1
    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    assert "UPDATE settings" not in output.out + output.err


def test_successive_resets_always_generate_new_session_state(panel):
    path, _ = panel
    with Session(get_engine()) as db:
        before = db.scalar(select(AdminAuthState.session_generation))
    admin_recovery.reset_credentials(path, PASSWORD)
    with Session(get_engine()) as db:
        first = db.scalar(select(AdminAuthState.session_generation))
    admin_recovery.reset_credentials(path, PASSWORD)
    with Session(get_engine()) as db:
        second = db.scalar(select(AdminAuthState.session_generation))
    assert len({before, first, second}) == 3
