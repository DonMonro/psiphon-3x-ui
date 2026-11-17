"""Update protocol regressions using disposable files and mocked external work."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from panel import config, updates

OLD = "a" * 40
NEW = "b" * 40
OTHER = "c" * 40
NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = config.Settings(
        _env_file=None,
        db_path=tmp_path / "prefix" / "panel.db",
        update_state_dir=tmp_path / "root-state",
        update_check_interval=0,
    )
    clock = [NOW]
    # Model an upgrade from 1.0.5 regardless of the source checkout's version.
    monkeypatch.setattr(updates, "__version__", "1.0.5")
    monkeypatch.setattr(updates, "utcnow", lambda: clock[0])
    monkeypatch.setattr(updates, "get_build_revision", lambda: OLD)
    monkeypatch.setattr(updates, "unsupported_reason", lambda: None)
    monkeypatch.setattr(updates, "ROOT_UID", getattr(os, "getuid", lambda: 0)())
    candidate = updates.Candidate(version="1.0.6", revision=NEW)
    discover = AsyncMock(return_value=candidate)
    dispatch = AsyncMock(return_value=True)
    monkeypatch.setattr(updates, "discover", discover)
    monkeypatch.setattr(updates, "dispatch", dispatch)
    manager = updates.UpdateManager(settings)

    def advance(seconds=1):
        clock[0] += timedelta(seconds=seconds)
        return clock[0]

    def root(phase, *, identity=None, **fields):
        job = identity or manager._state.job
        value = {
            "version": job.version,
            "revision": job.revision,
            "job_id": job.job_id,
            "phase": phase,
            "message": f"Root phase {phase}",
            "error": None,
            "updated_at": advance().isoformat(),
            **fields,
        }
        updates.atomic_json(settings.update_state_dir / "status.json", value)
        return value

    return SimpleNamespace(
        manager=manager,
        settings=settings,
        candidate=candidate,
        discover=discover,
        dispatch=dispatch,
        advance=advance,
        root=root,
    )


@pytest.mark.parametrize(
    "available, installed, revision, expected",
    [
        ("1.0.10", "1.0.9", None, True),
        ("1.0.9", "1.0.10", OLD, False),
        ("2.0.0", "1.99.99", OLD, True),
        ("1.0.5", "1.0.5", None, False),
        ("1.0.5", "1.0.5", NEW, False),
    ],
)
@respx.mock
async def test_discovery_numeric_ordering_and_legacy_revision(
    available, installed, revision, expected
):
    respx.get(updates.MAIN_URL).respond(json={"sha": NEW})
    pinned = respx.get(f"{updates.SOURCE_URL}/{NEW}/panel/__init__.py").respond(
        text=f'__version__ = "{available}"\nraise RuntimeError("never execute")\n'
    )
    result = await updates.discover(installed, revision)
    assert bool(result) is expected
    assert pinned.called
    assert all("/main/panel/" not in str(call.request.url) for call in respx.calls)
    if result:
        assert result.revision == NEW
        assert result.version == available


@pytest.mark.parametrize(
    "ancestry, offered",
    [("ahead", True), ("behind", False), ("diverged", False), ("identical", False)],
)
@respx.mock
async def test_same_version_requires_verified_descendant(ancestry, offered):
    respx.get(updates.MAIN_URL).respond(json={"sha": NEW})
    respx.get(f"{updates.SOURCE_URL}/{NEW}/panel/__init__.py").respond(
        text='__version__ = "1.0.5"\n'
    )
    comparison = respx.get(f"{updates.REPOSITORY_API}/compare/{OLD}...{NEW}?per_page=1").respond(
        json={"status": ancestry}
    )
    assert bool(await updates.discover("1.0.5", OLD)) is offered
    assert comparison.called


@pytest.mark.parametrize("body", [{"sha": "main"}, {"sha": "../evil"}, [], {}, {"sha": 123}])
@respx.mock
async def test_discovery_rejects_unpinned_revision(body):
    respx.get(updates.MAIN_URL).respond(json=body)
    with pytest.raises(updates.UpdateError):
        await updates.discover("1.0.5", OLD)
    assert len(respx.calls) == 1


@pytest.mark.parametrize(
    "source",
    [
        'print("version missing")\n',
        '__version__ = "1.0.6"\n__version__ = "1.0.7"\n',
        '__version__ = "1.0.6-rc1"\n',
        '__version__ = "01.0.6"\n',
    ],
)
@respx.mock
async def test_discovery_rejects_malformed_or_ambiguous_version(source):
    respx.get(updates.MAIN_URL).respond(json={"sha": NEW})
    respx.get(f"{updates.SOURCE_URL}/{NEW}/panel/__init__.py").respond(text=source)
    with pytest.raises(updates.UpdateError):
        await updates.discover("1.0.5", OLD)


@pytest.mark.parametrize("status_code", [301, 403, 404, 429, 500])
@respx.mock
async def test_discovery_does_not_follow_redirects_or_ignore_upstream_errors(status_code):
    respx.get(updates.MAIN_URL).respond(
        status_code=status_code, headers={"location": "https://unexpected.example/"}
    )
    with pytest.raises(updates.UpdateError):
        await updates.discover("1.0.5", OLD)
    assert len(respx.calls) == 1


@respx.mock
async def test_discovery_bounds_response_size(monkeypatch):
    monkeypatch.setattr(updates, "MAX_REMOTE_BYTES", 128)
    respx.get(updates.MAIN_URL).respond(content=b"x" * 129)
    with pytest.raises(updates.UpdateError, match="oversized"):
        await updates.discover("1.0.5", OLD)


@respx.mock
async def test_discovery_surfaces_timeout():
    respx.get(updates.MAIN_URL).mock(side_effect=httpx.ReadTimeout("no response"))
    with pytest.raises(updates.UpdateError):
        await updates.discover("1.0.5", OLD)


@pytest.mark.parametrize("revision", [NEW, None, "main", 5])
def test_build_metadata_reads_only_matching_packaged_identity(tmp_path, monkeypatch, revision):
    import panel

    path = tmp_path / "build.json"
    path.write_text(
        json.dumps({"version": panel.__version__, "revision": revision}), encoding="utf-8"
    )
    monkeypatch.setattr(panel, "_BUILD_METADATA", path)
    panel.get_build_revision.cache_clear()
    try:
        assert panel.get_build_revision() == (NEW if revision == NEW else None)
        path.write_text(json.dumps({"version": "99.0.0", "revision": NEW}), encoding="utf-8")
        panel.get_build_revision.cache_clear()
        assert panel.get_build_revision() is None
    finally:
        panel.get_build_revision.cache_clear()


async def test_get_only_reads_local_state_and_is_honest_when_unsupported(env, monkeypatch):
    monkeypatch.setattr(updates, "unsupported_reason", lambda: "No systemd on Windows")
    status = await env.manager.status()
    assert status["phase"] == "idle"
    assert status["supported"] is False
    assert status["unsupported_reason"] == "No systemd on Windows"
    assert status["current_revision"] == OLD
    env.discover.assert_not_awaited()
    env.dispatch.assert_not_awaited()
    with pytest.raises(updates.UpdateError) as error:
        await env.manager.check(download=True)
    assert error.value.status_code == 503


def test_update_interval_defaults_to_five_minutes(monkeypatch):
    monkeypatch.delenv("PSIPHON3XUI_UPDATE_CHECK_INTERVAL", raising=False)
    assert config.Settings(_env_file=None).update_check_interval == 300


@pytest.mark.parametrize("interval", [0, 600])
def test_update_interval_respects_environment_override(monkeypatch, interval):
    monkeypatch.setenv("PSIPHON3XUI_UPDATE_CHECK_INTERVAL", str(interval))
    assert config.Settings(_env_file=None).update_check_interval == interval


async def test_check_persists_candidate_and_five_minute_deadline_without_download(env):
    env.settings.update_check_interval = 300
    first = await env.manager.check()
    assert first["phase"] == "available"
    assert first["check_interval_seconds"] == 300
    assert first["last_checked_at"] == NOW.isoformat()
    assert first["next_check_at"] == (NOW + timedelta(minutes=5)).isoformat()
    env.dispatch.assert_not_awaited()
    restored = updates.UpdateManager(env.settings)
    assert await restored.status() == first
    assert not restored.request_path.exists()


async def test_check_and_download_writes_exact_pinned_protocol(env):
    result = await env.manager.check(download=True)
    assert result["phase"] == "downloading"
    assert len(result["job_id"]) == 32
    assert updates.read_json(env.manager.request_path) == {
        "action": "download",
        "job_id": result["job_id"],
        "revision": NEW,
        "version": "1.0.6",
    }
    env.dispatch.assert_awaited_once_with("download")


async def test_ready_job_survives_restart_and_periodic_checks(env):
    downloading = await env.manager.check(download=True)
    env.root("ready")
    ready = await env.manager.status()
    assert ready["phase"] == "ready"
    restored = updates.UpdateManager(env.settings)
    assert await restored.status() == ready
    env.discover.reset_mock()
    assert (await restored.check())["job_id"] == downloading["job_id"]
    assert (await restored.check(download=True))["phase"] == "ready"
    env.discover.assert_not_awaited()


async def test_install_consent_is_exact_and_helper_confirmed(env):
    downloading = await env.manager.check(download=True)
    with pytest.raises(updates.UpdateError) as not_ready:
        await env.manager.install(downloading["job_id"], True)
    assert not_ready.value.status_code == 409
    env.root("ready")
    await env.manager.status()
    for consent in (False, 1, "true", None):
        with pytest.raises(updates.UpdateError) as missing_consent:
            await env.manager.install(downloading["job_id"], consent)
        assert missing_consent.value.status_code == 400
    with pytest.raises(updates.UpdateError) as stale:
        await env.manager.install("f" * 32, True)
    assert stale.value.status_code == 409
    result = await env.manager.install(downloading["job_id"], True)
    assert result["phase"] == "installing"
    assert updates.read_json(env.manager.request_path)["action"] == "install"
    assert (await env.manager.status())["phase"] == "installing", (
        "old ready result must not undo installation"
    )
    with pytest.raises(updates.UpdateError) as duplicate:
        await env.manager.install(downloading["job_id"], True)
    assert duplicate.value.status_code == 409
    assert env.dispatch.await_count == 2


async def test_stale_revision_and_replaced_job_are_rejected(env):
    await env.manager.check()
    with pytest.raises(updates.UpdateError) as stale_revision:
        await env.manager.download(OTHER)
    assert stale_revision.value.status_code == 409
    first = await env.manager.download(NEW)
    env.root("ready")
    second = await env.manager.download(NEW)  # explicit replacement, a new UUID
    assert first["job_id"] != second["job_id"]
    env.root("ready")
    with pytest.raises(updates.UpdateError) as stale_job:
        await env.manager.install(first["job_id"], True)
    assert stale_job.value.status_code == 409
    assert (await env.manager.status())["job_id"] == second["job_id"]


async def test_failed_replacement_download_restores_fresh_root_ready_job(env):
    first = await env.manager.check(download=True)
    env.root("ready")
    await env.manager.status()
    previous_job = env.manager._state.job.model_copy(deep=True)
    env.advance()
    second = await env.manager.download(NEW)
    assert second["job_id"] != first["job_id"]
    # The original ready result must not prematurely undo the queued download.
    assert (await env.manager.status())["phase"] == "downloading"
    env.root("ready", identity=previous_job, error="Replacement download failed")
    restored = updates.UpdateManager(env.settings)
    status = await restored.status()
    assert status["phase"] == "ready"
    assert status["job_id"] == first["job_id"]
    assert status["error"] == "Replacement download failed"
    assert (await restored.install(first["job_id"], True))["phase"] == "installing"


async def test_missing_root_ready_result_cannot_authorize_install(env):
    result = await env.manager.check(download=True)
    env.root("ready")
    await env.manager.status()
    (env.settings.update_state_dir / "status.json").unlink()
    with pytest.raises(updates.UpdateError) as unverified:
        await env.manager.install(result["job_id"], True)
    assert unverified.value.status_code == 409
    env.dispatch.assert_awaited_once_with("download")


async def test_status_and_conflicts_do_not_wait_for_remote_check(env):
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow_discover(*args):
        entered.set()
        await release.wait()
        return env.candidate

    env.discover.side_effect = slow_discover
    checking = asyncio.create_task(env.manager.check())
    try:
        await asyncio.wait_for(entered.wait(), 1)
        status = await asyncio.wait_for(env.manager.status(), 1)
        assert status["phase"] == "checking"
        with pytest.raises(updates.UpdateError) as busy:
            await asyncio.wait_for(env.manager.check(download=True), 1)
        assert busy.value.status_code == 409
    finally:
        release.set()
        await checking


async def test_slow_dispatch_keeps_status_responsive_and_reserves_job(env):
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow_dispatch(action):
        entered.set()
        await release.wait()
        return True

    env.dispatch.side_effect = slow_dispatch
    pending = asyncio.create_task(env.manager.check(download=True))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        status = await asyncio.wait_for(env.manager.status(), 1)
        assert status["phase"] == "downloading"
        with pytest.raises(updates.UpdateError) as busy:
            await asyncio.wait_for(env.manager.download(NEW), 1)
        assert busy.value.status_code == 409
    finally:
        release.set()
        await pending


@pytest.mark.parametrize("action", ["download", "install"])
async def test_rejected_enqueue_restores_an_actionable_state(env, action):
    await env.manager.check(download=action == "install")
    if action == "install":
        env.root("ready")
        ready = await env.manager.status()

        async def call():
            return await env.manager.install(ready["job_id"], True)
    else:

        async def call():
            return await env.manager.download(NEW)

    env.dispatch.side_effect = updates.UpdateError("polkit denied")
    with pytest.raises(updates.UpdateError, match="polkit denied"):
        await call()
    state = await env.manager.status()
    assert state["phase"] == ("ready" if action == "install" else "available")
    assert "polkit denied" in state["error"]


async def test_ambiguous_enqueue_stays_reserved_until_acknowledgement_timeout(env):
    env.dispatch.return_value = False
    await env.manager.check(download=True)
    assert (await env.manager.status())["phase"] == "downloading"
    env.advance(updates.ACK_TIMEOUT_SECONDS + 1)
    status = await env.manager.status()
    assert status["phase"] == "failed"
    assert "acknowledge" in status["error"]
    assert (await updates.UpdateManager(env.settings).status())["phase"] == "failed"


async def test_job_runtime_timeout_and_late_successful_download_recovery(env):
    await env.manager.check(download=True)
    env.root("downloading")
    await env.manager.status()
    env.advance(updates.DOWNLOAD_TIMEOUT_SECONDS + 1)
    assert (await env.manager.status())["phase"] == "failed"
    env.root("ready")
    assert (await env.manager.status())["phase"] == "ready"


async def test_other_job_or_non_iso_root_timestamp_cannot_change_pinned_job(env):
    result = await env.manager.check(download=True)
    env.root("ready", job_id="f" * 32)
    assert (await env.manager.status())["phase"] == "downloading"
    env.root("ready", updated_at=NOW.timestamp())
    status = await env.manager.status()
    assert status["phase"] == "downloading"
    assert status["job_id"] == result["job_id"]


async def test_root_error_is_durable_and_actionable(env):
    await env.manager.check(download=True)
    env.root("failed", error="Archive checksum did not match")
    state = await env.manager.status()
    assert state["phase"] == "failed"
    assert "checksum" in state["error"]
    assert await updates.UpdateManager(env.settings).status() == state


async def test_install_success_requires_root_health_result_and_running_identity(env, monkeypatch):
    downloading = await env.manager.check(download=True)
    env.root("ready")
    await env.manager.install(downloading["job_id"], True)
    env.root("installing")
    updates.atomic_json(
        env.settings.update_state_dir / "installed.json", env.candidate.model_dump()
    )
    assert (await env.manager.status())["phase"] == "installing"
    monkeypatch.setattr(updates, "__version__", env.candidate.version)
    monkeypatch.setattr(updates, "get_build_revision", lambda: NEW)
    restarted = updates.UpdateManager(env.settings)
    assert (await restarted.status())["phase"] == "installing"
    env.root("succeeded")
    final = await restarted.status()
    assert final["phase"] == "succeeded"
    assert final["current_revision"] == NEW
    assert final["update_available"] is False
    assert (await env.manager.status())["phase"] == "failed", (
        "old running process cannot claim the new build"
    )


async def test_corrupt_panel_cache_recovers_root_ready_identity(env):
    result = await env.manager.check(download=True)
    env.root("ready")
    env.manager.cache_path.write_text("broken json", encoding="utf-8")
    restored = updates.UpdateManager(env.settings)
    state = await restored.status()
    assert state["phase"] == "ready"
    assert state["job_id"] == result["job_id"]


async def test_failed_cache_replace_keeps_previous_complete_state(env, monkeypatch):
    await env.manager.check()
    before = env.manager.cache_path.read_bytes()

    def no_space(*args):
        raise OSError("disk full")

    monkeypatch.setattr(updates.os, "replace", no_space)
    with pytest.raises(updates.UpdateError):
        await env.manager.download(NEW)
    assert env.manager.cache_path.read_bytes() == before
    assert (await env.manager.status())["phase"] == "available"
    assert not list(env.manager.directory.glob(".cache.json.*"))
    env.dispatch.assert_not_awaited()


async def test_install_waits_for_mutation_and_blocks_new_mutations(env):
    result = await env.manager.check(download=True)
    env.root("ready")
    await env.manager.begin_mutation()
    try:
        with pytest.raises(updates.UpdateError) as busy:
            await env.manager.install(result["job_id"], True)
        assert busy.value.status_code == 409
    finally:
        env.manager.end_mutation()
    await env.manager.install(result["job_id"], True)
    with pytest.raises(updates.UpdateError) as maintenance:
        await env.manager.begin_mutation()
    assert maintenance.value.status_code == 409


async def test_install_timeout_keeps_maintenance_until_root_worker_exits(env, monkeypatch):
    download = await env.manager.check(download=True)
    env.root("ready")
    await env.manager.install(download["job_id"], True)
    env.root("installing")
    await env.manager.status()
    identity = {"pid": 123, "start": "456", "boot": "same-boot"}
    updates.atomic_json(
        env.settings.update_state_dir / "active.json",
        {"action": "install", "process": identity},
    )
    monkeypatch.setattr(updates, "process_identity", lambda pid: identity)
    env.advance(updates.INSTALL_TIMEOUT_SECONDS + 1)
    status = await env.manager.status()
    assert status["phase"] == "failed"
    assert status["install_guard"] is True
    with pytest.raises(updates.UpdateError):
        await env.manager.begin_mutation()
    with pytest.raises(updates.UpdateError):
        await env.manager.check(download=True)
    # PID reuse or a different boot cannot pin maintenance indefinitely.
    monkeypatch.setattr(updates, "process_identity", lambda pid: {**identity, "boot": "other"})
    assert (await env.manager.status())["install_guard"] is False
    await env.manager.begin_mutation()
    env.manager.end_mutation()


async def test_incomplete_root_transaction_keeps_maintenance_after_failed_result(env):
    download = await env.manager.check(download=True)
    env.root("ready")
    await env.manager.install(download["job_id"], True)
    transaction = env.settings.update_state_dir / "transaction.json"
    updates.atomic_json(transaction, {"step": "rolling_back"})
    env.root("failed", error="Rollback requires recovery")
    restored = updates.UpdateManager(env.settings)
    assert (await restored.status())["install_guard"] is True
    with pytest.raises(updates.UpdateError):
        await restored.begin_mutation()
    transaction.unlink()
    assert (await restored.status())["install_guard"] is False


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership boundary")
async def test_untrusted_root_status_is_not_accepted(env, monkeypatch):
    await env.manager.check(download=True)
    env.root("ready")
    monkeypatch.setattr(updates, "ROOT_UID", os.getuid() + 1)
    assert (await env.manager.status())["phase"] == "downloading"


async def test_zero_interval_disables_watch(env):
    await env.manager.watchdog()
    env.discover.assert_not_awaited()


async def test_overdue_watch_starts_promptly_without_downloading(env):
    env.settings.update_check_interval = 300
    checked = asyncio.Event()

    async def candidate(*args):
        checked.set()
        return env.candidate

    env.discover.side_effect = candidate
    task = asyncio.create_task(env.manager.watchdog())
    try:
        await asyncio.wait_for(checked.wait(), 1)
        assert (await env.manager.status())["phase"] == "available"
        env.dispatch.assert_not_awaited()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


async def test_watch_uses_persisted_due_time_then_checks(env, monkeypatch):
    env.settings.update_check_interval = 300
    await env.manager.check()
    env.advance(60)
    restored = updates.UpdateManager(env.settings)
    env.discover.reset_mock()
    sleeps = []

    async def advance_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 1:
            raise asyncio.CancelledError
        env.advance(seconds)

    monkeypatch.setattr(updates.asyncio, "sleep", advance_sleep)
    with pytest.raises(asyncio.CancelledError):
        await restored.watchdog()
    assert sleeps == [240, 300]
    env.discover.assert_awaited_once()
    env.dispatch.assert_not_awaited()


async def test_watch_cancellation_interrupts_discovery_and_releases_state(env):
    env.settings.update_check_interval = 300
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def hanging_discovery(*args):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    env.discover.side_effect = hanging_discovery
    task = asyncio.create_task(env.manager.watchdog())
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    assert cancelled.is_set()
    assert (await env.manager.status())["phase"] != "checking"


@pytest.mark.parametrize("action", ["download", "install"])
async def test_dispatch_only_starts_exact_fixed_unit(monkeypatch, action):
    process = SimpleNamespace(wait=AsyncMock(return_value=0), kill=lambda: None)
    spawn = AsyncMock(return_value=process)
    monkeypatch.setattr(updates.asyncio, "create_subprocess_exec", spawn)
    assert await updates.dispatch(action) is True
    assert spawn.call_args.args == (
        updates.SYSTEMCTL,
        "--no-block",
        "--no-ask-password",
        "start",
        updates.UNITS[action],
    )


async def test_lifespan_starts_and_cancels_update_checker(env, monkeypatch):
    from panel import main

    env.settings.update_check_interval = 300
    monkeypatch.setattr(main, "get_settings", lambda: env.settings)
    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(updates, "get_manager", lambda: env.manager)
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def watch():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(env.manager, "watchdog", watch)
    async with main.lifespan(main.app):
        await asyncio.wait_for(entered.wait(), 1)
    assert cancelled.is_set()
