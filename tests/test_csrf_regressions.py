"""Regression coverage for wizard CSRF recovery and same-origin flag assets."""

from __future__ import annotations

import shutil
import struct
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from panel import auth, config, db
from panel.models import Settings

ROOT = Path(__file__).resolve().parents[1]
CSRF_ENDPOINTS = ("/auth/csrf", "/api/csrf")
COUNTRIES_BODY = {"mode": "specific", "codes": ["US", "GB"]}
CSRF_ERROR = {"detail": "CSRF token missing or invalid."}


@pytest.fixture
def client(monkeypatch, tmp_path):
    """A logged-in first-run panel with CSRF enforcement really enabled."""
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "csrf-regression-secret")
    monkeypatch.setenv("PSIPHON3XUI_HTTPS_ONLY", "0")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "1")
    monkeypatch.setenv("PSIPHON3XUI_COUNTRIES_FILE", str(config.COUNTRIES_FILE))
    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
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
                admin_user="csrf-admin",
                admin_pass_hash=auth.hash_password("csrf-test-password"),
                wizard_completed=False,
            )
        )
        session.commit()

    from panel import main

    # main may already be imported by another test with CSRF disabled.
    monkeypatch.setattr(main, "_CSRF_ENFORCE", True)
    try:
        with TestClient(main.app, base_url="http://panel.test") as test_client:
            response = test_client.post(
                "/auth/login", json={"user": "csrf-admin", "password": "csrf-test-password"}
            )
            assert response.status_code == 204, response.text
            yield test_client
    finally:
        engine.dispose()
        auth.login_rate_limit_reset()
        config.get_settings.cache_clear()
        config.load_countries.cache_clear()


def _replace_cookie(client, token):
    # Do not create a second same-name cookie with a different domain/path.
    client.cookies.delete(auth.CSRF_COOKIE_NAME)
    if token is not None:
        client.cookies.set(auth.CSRF_COOKIE_NAME, token, domain="panel.test", path="/")


def _expired_token(monkeypatch):
    old_timestamp = int(time.time()) - auth.CSRF_COOKIE_MAX_AGE - 10
    with monkeypatch.context() as clock:
        clock.setattr(TimestampSigner, "get_timestamp", lambda self: old_timestamp)
        return auth.issue_csrf_token()


def _assert_countries_unchanged(client):
    state = client.get("/api/wizard").json()
    assert state["current_step"] == "countries"
    assert "countries" not in state["step_data"]


@pytest.mark.parametrize("endpoint", CSRF_ENDPOINTS)
def test_second_tab_token_read_does_not_break_first_tab_submission(client, endpoint):
    """Tabs share a cookie jar, but tab A may still hold its original header."""
    token_a = client.get("/auth/csrf").json()["token"]
    for _ in range(3):
        response = client.get(endpoint)
        assert response.status_code == 200
        assert response.json()["token"] == token_a
        assert client.cookies.get(auth.CSRF_COOKIE_NAME) == token_a
        assert response.headers["cache-control"] == "no-store"
        # No sliding cookie expiry beyond the token's original signed age.
        assert "set-cookie" not in response.headers

    response = client.post(
        "/api/wizard/countries",
        json=COUNTRIES_BODY,
        headers={auth.CSRF_HEADER_NAME: token_a},
    )
    assert response.status_code == 200, response.text
    assert response.json()["current_step"] == "ports"
    state = client.get("/api/wizard").json()
    assert state["step_data"]["countries"]["codes"] == ["GB", "US"]


@pytest.mark.parametrize("endpoint", CSRF_ENDPOINTS)
@pytest.mark.parametrize("cookie_state", ["missing", "unsigned", "tampered", "expired"])
def test_token_endpoint_recovers_unusable_cookie(client, endpoint, cookie_state, monkeypatch):
    old_token = {
        "missing": None,
        "unsigned": "not-signed",
        "tampered": auth.issue_csrf_token() + "tampered",
        "expired": _expired_token(monkeypatch),
    }[cookie_state]
    _replace_cookie(client, old_token)
    response = client.get(endpoint)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    token = response.json()["token"]
    assert token != old_token
    assert token == client.cookies.get(auth.CSRF_COOKIE_NAME)
    assert auth.verify_csrf_token(token)
    assert "httponly" not in response.headers["set-cookie"].lower()
    assert "samesite=lax" in response.headers["set-cookie"].lower()
    submission = client.post(
        "/api/wizard/countries",
        json=COUNTRIES_BODY,
        headers={auth.CSRF_HEADER_NAME: token},
    )
    assert submission.status_code == 200, submission.text


@pytest.mark.parametrize("endpoint", CSRF_ENDPOINTS)
def test_token_endpoint_requires_a_session(client, endpoint):
    client.cookies.delete(auth.SESSION_COOKIE_NAME)
    response = client.get(endpoint)
    assert response.status_code == 401
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize("missing", ["header", "cookie"])
def test_missing_csrf_component_rejects_countries_without_mutating(client, missing):
    token = client.cookies.get(auth.CSRF_COOKIE_NAME)
    headers = {auth.CSRF_HEADER_NAME: token}
    if missing == "header":
        headers = {}
    else:
        _replace_cookie(client, None)
    response = client.post("/api/wizard/countries", json=COUNTRIES_BODY, headers=headers)
    assert response.status_code == 403
    assert response.json() == CSRF_ERROR
    _assert_countries_unchanged(client)


def test_mismatched_signed_tokens_are_rejected(client):
    response = client.post(
        "/api/wizard/countries",
        json=COUNTRIES_BODY,
        headers={auth.CSRF_HEADER_NAME: auth.issue_csrf_token()},
    )
    assert response.status_code == 403
    assert response.json() == CSRF_ERROR
    _assert_countries_unchanged(client)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_matching_but_unsigned_cookie_and_header_are_rejected(client, method):
    _replace_cookie(client, "attacker-chosen-token")
    response = client.request(
        method,
        "/api/wizard/countries",
        json=COUNTRIES_BODY,
        headers={auth.CSRF_HEADER_NAME: "attacker-chosen-token"},
    )
    assert response.status_code == 403
    assert response.json() == CSRF_ERROR
    _assert_countries_unchanged(client)


@pytest.mark.parametrize("kind", ["expired", "tampered", "wrong-secret", "wrong-purpose"])
def test_matching_invalid_signed_tokens_are_rejected(client, kind, monkeypatch):
    if kind == "expired":
        token = _expired_token(monkeypatch)
    elif kind == "tampered":
        token = auth.issue_csrf_token() + "tampered"
    elif kind == "wrong-secret":
        token = URLSafeTimedSerializer("another-secret", salt=auth.CSRF_SERIALIZER_SALT).dumps(
            {"t": "nonce"}
        )
    else:
        token = auth.sign_session({"sub": "csrf-admin"})
    _replace_cookie(client, token)
    response = client.post(
        "/api/wizard/countries", json=COUNTRIES_BODY, headers={auth.CSRF_HEADER_NAME: token}
    )
    assert response.status_code == 403
    assert response.json() == CSRF_ERROR
    _assert_countries_unchanged(client)


def test_malformed_non_ascii_header_is_a_403_not_a_500(client):
    response = client.post(
        "/api/wizard/countries",
        json=COUNTRIES_BODY,
        headers=[(b"X-CSRF-Token", b"\xff")],
    )
    assert response.status_code == 403
    assert response.json() == CSRF_ERROR
    _assert_countries_unchanged(client)


def test_all_catalog_flags_are_served_as_local_pngs(client):
    catalog = client.get("/api/countries").json()["countries"]
    assert catalog
    for country in catalog:
        response = client.get(f"/static/flags/{country['code'].lower()}.png")
        assert response.status_code == 200, country["code"]
        assert response.headers["content-type"] == "image/png", country["code"]
        image = response.content
        assert image.startswith(b"\x89PNG\r\n\x1a\n"), country["code"]
        assert image[12:16] == b"IHDR", country["code"]
        width, height = struct.unpack(">II", image[16:24])
        assert width == 40 and 0 < height <= 80, country["code"]
        assert image.endswith(b"IEND\xaeB`\x82"), country["code"]


@pytest.mark.parametrize("page", ["wizard", "dashboard"])
def test_flag_templates_use_same_origin_and_handle_missing_images(page):
    source = (ROOT / "panel" / "static" / f"{page}.html").read_text(encoding="utf-8")
    assert "'/static/flags/' + c.code.toLowerCase() + '.png'" in source
    assert "flagcdn.com" not in source
    assert '@error="$el.hidden = true"' in source


def test_spa_csrf_behavior_in_javascript():
    """Execute the actual inline SPA functions, not string assertions alone.

    Node 18+ is sufficient; no npm packages are required. CI's Ubuntu runner
    includes Node. Python-only developer environments skip this one check.
    """
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the executable SPA regression checks")
    result = subprocess.run(
        [node, "--test", str(ROOT / "tests" / "js" / "csrf-client.test.cjs")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
