"""HTTP contract tests for authenticated, CSRF-protected update routes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from panel import auth, config, db, updates
from panel.models import Settings


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "updates-router-secret")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "1")
    monkeypatch.setenv("PSIPHON3XUI_UPDATE_CHECK_INTERVAL", "0")
    clear_manager_cache = updates.get_manager.cache_clear
    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
    clear_manager_cache()
    monkeypatch.setattr(db, "_engine", None)
    monkeypatch.setattr(db, "_session_factory", None)
    db.init_db()
    with db.get_session_factory()() as session:
        session.add(
            Settings(
                id=1,
                panel_port=18001,
                admin_user="admin",
                admin_pass_hash=auth.hash_password("password"),
                wizard_completed=False,
            )
        )
        session.commit()
    from panel import main

    monkeypatch.setattr(main, "_CSRF_ENFORCE", True)
    with TestClient(main.app) as test_client:
        assert (
            test_client.post(
                "/auth/login", json={"user": "admin", "password": "password"}
            ).status_code
            == 204
        )
        yield test_client
    clear_manager_cache()
    config.get_settings.cache_clear()
    config.load_countries.cache_clear()


@pytest.fixture
def fake_manager(monkeypatch, tmp_path):
    manager = SimpleNamespace(
        status=lambda: _status(),
        check=lambda: _status(phase="downloading"),
        download=lambda revision: _status(phase="downloading"),
        install=lambda job_id, confirm: _status(phase="installing"),
    )

    async def status(**kwargs):
        return _status(**kwargs)

    async def check(**kwargs):
        return _status(phase="downloading")

    async def download(revision):
        return _status(phase="downloading")

    async def install(job_id, confirm):
        return _status(phase="installing")

    manager.status, manager.check, manager.download, manager.install = (
        status,
        check,
        download,
        install,
    )
    monkeypatch.setattr(updates, "get_manager", lambda: manager)
    return manager


def _status(*, phase="available"):
    return {
        "current_version": "1.0.5",
        "current_revision": None,
        "available_version": "1.0.6",
        "available_revision": "b" * 40,
        "phase": phase,
        "update_available": True,
        "last_checked_at": None,
        "next_check_at": None,
        "check_interval_seconds": 0,
        "job_id": "c" * 32 if phase in {"downloading", "installing", "ready"} else None,
        "message": "",
        "error": None,
        "supported": True,
        "unsupported_reason": None,
    }


def csrf(client):
    return client.cookies[auth.CSRF_COOKIE_NAME]


def test_get_requires_auth_and_never_checks_upstream(tmp_path, monkeypatch):
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "no-auth-secret")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "1")
    config.get_settings.cache_clear()
    updates.get_manager.cache_clear()
    from panel.main import app

    with TestClient(app) as unauthenticated:
        response = unauthenticated.get("/api/updates")
    assert response.status_code == 401


def test_get_returns_cached_local_state(client, fake_manager):
    response = client.get("/api/updates")
    assert response.status_code == 200
    assert response.json()["phase"] == "available"
    assert response.headers["cache-control"] == "no-store"


def test_posts_require_csrf_even_with_a_session(client, fake_manager):
    response = client.post("/api/updates/check", json={})
    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF token missing or invalid."}


def test_check_is_authenticated_and_csrf_protected(client, fake_manager):
    response = client.post("/api/updates/check", json={}, headers={"X-CSRF-Token": csrf(client)})
    assert response.status_code == 202
    assert response.json()["phase"] == "downloading"


def test_empty_check_body_only(client, fake_manager):
    headers = {"X-CSRF-Token": csrf(client)}
    assert (
        client.post("/api/updates/check", json={"revision": "b" * 40}, headers=headers).status_code
        == 422
    )
    assert client.post("/api/updates/check", json=None, headers=headers).status_code == 422


def test_download_schema_rejects_stale_or_malformed_revision_before_manager(client, fake_manager):
    headers = {"X-CSRF-Token": csrf(client)}
    assert (
        client.post("/api/updates/download", json={"revision": "main"}, headers=headers).status_code
        == 422
    )
    assert (
        client.post(
            "/api/updates/download", json={"revision": "B" * 40}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/updates/download", json={"revision": "b" * 40, "extra": 1}, headers=headers
        ).status_code
        == 422
    )


def test_install_requires_strict_true_and_exact_job_shape(client, fake_manager):
    headers = {"X-CSRF-Token": csrf(client)}
    body = {"job_id": "c" * 32, "confirm": True}
    assert (
        client.post(
            "/api/updates/install", json={"job_id": "c" * 32, "confirm": 1}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/updates/install", json={"job_id": "c" * 32, "confirm": "true"}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/updates/install", json={"job_id": "c" * 32, "confirm": False}, headers=headers
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/updates/install", json={**body, "extra": "x"}, headers=headers
        ).status_code
        == 422
    )
    response = client.post("/api/updates/install", json=body, headers=headers)
    assert response.status_code == 202
    assert response.json()["phase"] == "installing"


def test_router_converts_update_errors_to_status(client, monkeypatch):
    async def conflict():
        raise updates.UpdateError("stale job", 409)

    manager = SimpleNamespace(status=conflict, check=conflict, download=conflict, install=conflict)
    monkeypatch.setattr(updates, "get_manager", lambda: manager)
    response = client.get("/api/updates")
    assert response.status_code == 409
    assert response.json() == {"detail": "stale job"}
    assert response.headers["cache-control"] == "no-store"


def test_update_routes_are_available_before_wizard_completion(client, fake_manager):
    response = client.get("/api/updates")
    assert response.status_code == 200


def test_health_uses_package_version_and_revision(monkeypatch):
    from panel import main

    monkeypatch.setattr(main, "get_build_revision", lambda: "d" * 40)
    assert main.health() == {"status": "ok", "version": main.app.version, "revision": "d" * 40}


def test_session_can_reauthenticate_to_inspect_active_update_recovery(client, monkeypatch):
    async def blocked():
        raise updates.UpdateError("Panel installation is in progress. Wait for it to finish.", 409)

    async def status():
        return {**_status(phase="failed"), "install_guard": True}

    manager = SimpleNamespace(
        begin_mutation=blocked,
        end_mutation=lambda: pytest.fail("Unreserved mutation was released"),
        status=status,
    )
    monkeypatch.setattr(updates, "get_manager", lambda: manager)
    assert client.post("/auth/logout").status_code == 204
    assert client.get("/api/updates").status_code == 401
    assert (
        client.post("/auth/login", json={"user": "admin", "password": "password"}).status_code
        == 204
    )
    assert client.get("/api/updates").json()["install_guard"] is True
    assert (
        client.post(
            "/api/dashboard/reapply", json={}, headers={"X-CSRF-Token": csrf(client)}
        ).status_code
        == 409
    )
