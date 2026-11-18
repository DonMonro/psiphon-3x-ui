"""Privileged updater behavior with private files and mocked host operations.

No systemd, pip, network, or production path is touched. Descriptor/lock cases
run on POSIX; transaction, archive and service contracts also run on Windows.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sqlite3
import stat
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from installer import update_panel as helper

ROOT = Path(__file__).resolve().parents[1]
OLD = {"version": "1.0.5", "revision": "a" * 40}
JOB = {"job_id": "b" * 32, "version": "1.0.6", "revision": "c" * 40}
POSIX = pytest.mark.skipif(os.name != "posix", reason="Linux descriptor and flock semantics")


def archive_bytes(*, extra=None, revision=JOB["revision"], version=JOB["version"]):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        root = "psiphon-3x-ui-" + revision
        sources = {
            "panel/__init__.py": f'__version__ = "{version}"\n'.encode(),
            "pyproject.toml": f'[project]\nversion = "{version}"\n'.encode(),
            "panel/main.py": b"# no execution during download\n",
            **{entry[0]: b"# managed file\n" for entry in helper.MANAGED.values()},
        }
        for name, data in sources.items():
            member = tarfile.TarInfo(root + "/" + name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra:
            extra(archive, root)
    return output.getvalue()


@pytest.fixture
def host(tmp_path, monkeypatch):
    uid = getattr(os, "getuid", lambda: 0)()
    gid = getattr(os, "getgid", lambda: 0)()
    paths = helper.Paths(
        prefix=tmp_path / "prefix",
        state=tmp_path / "state",
        lock_dir=tmp_path / "run",
        libexec=tmp_path / "libexec" / "panel",
        systemd=tmp_path / "systemd",
        polkit=tmp_path / "polkit",
    )
    for path in (paths.prefix, paths.libexec.parent, paths.libexec, paths.systemd, paths.polkit):
        path.mkdir(exist_ok=True, mode=0o700)
    files = helper.Files(paths, gid, uid, owner=uid, anchor=tmp_path)
    payload = archive_bytes()

    class Upstream:
        def main_revision(self):
            return JOB["revision"]

        def download(self, revision, writer):
            assert revision == JOB["revision"]
            writer.write(payload)
            return hashlib.sha256(payload).hexdigest()

    updater = helper.Updater(paths, files, upstream=Upstream())
    updater.layout()
    files.put_json(paths.state / "installed.json", OLD, 0o640)
    for name, entry in helper.MANAGED.items():
        files.write(paths.destination(name), ("old " + name).encode(), entry[3])
    files.write(paths.state / "recovery.py", b"old updater", 0o600)
    env = (
        f"PSIPHON3XUI_DB_PATH={(paths.prefix / 'panel.db').as_posix()}\n"
        "PSIPHON3XUI_HOST=0.0.0.0\nPSIPHON3XUI_PORT=2053\n"
        "PSIPHON3XUI_SESSION_SECRET=keep-this-secret\nCUSTOM_VALUE=keep-this-too\n"
    ).encode()
    files.write(paths.prefix / "panel.env", env, 0o660)
    with contextlib.closing(sqlite3.connect(paths.prefix / "panel.db")) as db, db:
        db.execute("CREATE TABLE settings (value TEXT)")
        db.execute("INSERT INTO settings VALUES ('old credentials')")
    (paths.prefix / "panel.db").chmod(0o600)
    commands = []
    active = [True]

    def systemctl(*args, **kwargs):
        commands.append(args)
        if args[0] == "stop":
            active[0] = False
        elif args[0] == "start":
            active[0] = True
        if args[:2] == ("show", "--property=ActiveState"):
            return 0, b"active" if active[0] else b"inactive"
        if args[:2] == ("show", "--property=MainPID"):
            return 0, b"123" if active[0] else b"0"
        return 0, b""

    monkeypatch.setattr(updater, "systemctl", systemctl)
    health = []
    monkeypatch.setattr(updater, "wait_health", lambda settings, expected: health.append(expected))
    return SimpleNamespace(
        updater=updater,
        paths=paths,
        files=files,
        commands=commands,
        active=active,
        health=health,
        env=env,
        payload=payload,
        root=tmp_path,
    )


def stage(host):
    host.updater.download({**JOB, "action": "download"})


def prepare_fake(host, monkeypatch):
    def prepare(request, attempt):
        host.updater.verify_stage(request)
        venv = host.paths.state / "venvs" / attempt
        host.files.mkdir(venv, 0o750)
        return venv, {key: ("new " + key).encode() for key in helper.MANAGED}

    monkeypatch.setattr(host.updater, "prepare", prepare)


@pytest.mark.parametrize(
    "change",
    [
        {"url": "https://bad.example/file"},
        {"job_id": "../bad"},
        {"revision": "main"},
        {"version": "1.0.6;id"},
        {"action": "shell"},
    ],
)
def test_requests_reject_extra_fields_and_nonliteral_identity(change):
    raw = json.dumps({**JOB, "action": "install", **change}).encode()
    with pytest.raises(helper.UpdateError):
        helper.request_from_bytes(raw, "install")


def test_request_duplicate_keys_rejected():
    with pytest.raises(helper.UpdateError, match="Duplicate"):
        helper.request_from_bytes(b'{"action":"download","action":"install"}', "install")


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/repos/DonMonro/psiphon-3x-ui/commits/main",
        "https://api.github.com.evil.test/repos/DonMonro/psiphon-3x-ui/commits/main",
        "https://api.github.com/repos/other/repo/commits/main",
        "https://evil@api.github.com/repos/DonMonro/psiphon-3x-ui/commits/main",
        "https://codeload.github.com/DonMonro/psiphon-3x-ui/tar.gz/main",
        "https://codeload.github.com/DonMonro/psiphon-3x-ui/tar.gz/" + "a" * 40 + "?x=1",
    ],
)
def test_only_fixed_https_repository_resources_are_allowed(url):
    with pytest.raises(helper.UpdateError):
        helper.validate_url(url)


@pytest.mark.parametrize(
    "kind", ["traversal", "symlink", "hardlink", "device", "duplicate", "file-parent"]
)
def test_archives_reject_unsafe_members_before_execution(tmp_path, kind):
    def extra(archive, root):
        member = tarfile.TarInfo(root + "/extra")
        if kind == "traversal":
            member.name = root + "/../outside"
        elif kind == "symlink":
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
        elif kind == "hardlink":
            member.type, member.linkname = tarfile.LNKTYPE, root + "/panel/main.py"
        elif kind == "device":
            member.type = tarfile.CHRTYPE
        elif kind == "duplicate":
            member.name = root + "/panel/main.py"
        elif kind == "file-parent":
            member.name = root + "/panel/main.py/child"
        archive.addfile(member)

    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(archive_bytes(extra=extra))
    with pytest.raises(helper.UpdateError):
        helper.inspect_archive(archive, JOB["revision"], JOB["version"])
    assert not (tmp_path / "outside").exists()


def test_archive_size_budget_includes_padding(tmp_path, monkeypatch):
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(archive_bytes())
    monkeypatch.setattr(helper, "MAX_EXPANDED", 100)
    with pytest.raises(helper.UpdateError, match="Expanded"):
        helper.inspect_archive(archive, JOB["revision"], JOB["version"])


def test_download_is_pinned_and_never_executes_build_or_systemd(host, monkeypatch):
    monkeypatch.setattr(
        helper, "run_command", lambda *a, **kw: pytest.fail("download executed code")
    )
    stage(host)
    status = host.files.json(host.paths.state / "status.json")
    assert status["phase"] == "ready"
    assert status["revision"] == JOB["revision"]
    assert host.updater.ready() == JOB
    assert host.commands == []
    assert (host.paths.prefix / "panel.env").read_bytes() == host.env


def test_download_refuses_changed_main_without_discarding_ready_job(host, monkeypatch):
    stage(host)
    monkeypatch.setattr(host.updater.upstream, "main_revision", lambda: "d" * 40)
    with pytest.raises(helper.UpdateError, match="Main has changed"):
        host.updater.download({**JOB, "job_id": "e" * 32})
    assert host.updater.ready() == JOB
    assert host.updater.verify_stage(JOB).exists()


def test_install_rechecks_private_digest_and_exact_job(host):
    stage(host)
    with pytest.raises(helper.UpdateError, match="does not identify"):
        host.updater.verify_stage({**JOB, "job_id": "d" * 32})
    archive = host.paths.state / "jobs" / JOB["job_id"] / "source.tar.gz"
    archive.write_bytes(b"tampered")
    with pytest.raises(helper.UpdateError, match="digest changed"):
        host.updater.install(JOB)
    assert not host.commands


def test_build_failure_does_not_stop_or_change_working_panel(host, monkeypatch):
    stage(host)

    def fail(*args):
        raise helper.UpdateError("Build failed")

    monkeypatch.setattr(host.updater, "prepare", fail)
    with pytest.raises(helper.UpdateError, match="Build failed"):
        host.updater.install(JOB)
    assert host.commands == []
    assert host.updater.installed() == OLD
    assert host.updater.transaction() is None


def test_success_preserves_data_and_records_verified_build(host, monkeypatch):
    stage(host)
    prepare_fake(host, monkeypatch)
    host.updater.install(JOB)
    assert host.updater.installed() == helper.identity(JOB)
    final_status = host.files.json(host.paths.state / "status.json")
    assert final_status["phase"] == "succeeded"
    assert final_status["progress"] == 100
    assert host.health == [helper.identity(JOB)]
    assert host.updater.transaction() is None
    assert host.updater.ready() is None
    assert (host.paths.prefix / "panel.env").read_bytes() == host.env
    assert "-I -m panel" in host.paths.destination("override").read_text()
    with contextlib.closing(sqlite3.connect(host.paths.prefix / "panel.db")) as db, db:
        assert db.execute("SELECT value FROM settings").fetchone()[0] == "old credentials"


def test_failed_activation_restores_database_environment_units_and_old_build(host, monkeypatch):
    stage(host)
    prepare_fake(host, monkeypatch)

    def health(settings, expected):
        if expected == helper.identity(JOB):
            host.files.write(host.paths.prefix / "panel.env", b"damaged")
            with contextlib.closing(sqlite3.connect(host.paths.prefix / "panel.db")) as db, db:
                db.execute("UPDATE settings SET value='candidate change'")
            raise helper.UpdateError("candidate failed health")
        host.health.append(expected)

    monkeypatch.setattr(host.updater, "wait_health", health)
    with pytest.raises(helper.UpdateError, match="candidate failed health"):
        host.updater.install(JOB)
    assert host.updater.installed() == OLD
    assert host.health == [OLD]
    assert host.updater.transaction() is None
    assert host.files.json(host.paths.state / "status.json")["rollback_health_verified"] is True
    assert not host.paths.destination("override").exists()
    assert host.paths.destination("panel_unit").read_bytes() == b"old panel_unit"
    assert (host.paths.prefix / "panel.env").read_bytes() == host.env
    with contextlib.closing(sqlite3.connect(host.paths.prefix / "panel.db")) as db, db:
        assert db.execute("SELECT value FROM settings").fetchone()[0] == "old credentials"


def test_power_loss_at_activation_recovers_before_boot_without_start_cycle(host, monkeypatch):
    stage(host)
    prepare_fake(host, monkeypatch)
    original = host.files.write

    class PowerLoss(BaseException):
        pass

    def interrupted(path, data, *args, **kwargs):
        if path == host.paths.destination("override"):
            raise PowerLoss()
        return original(path, data, *args, **kwargs)

    monkeypatch.setattr(host.files, "write", interrupted)
    with pytest.raises(PowerLoss):
        host.updater.install(JOB)
    assert host.updater.transaction()["step"] == "activating"
    monkeypatch.setattr(host.files, "write", original)
    host.commands.clear()
    host.updater.recover(restart=False)
    assert not any(command[0] in {"start", "stop"} for command in host.commands)
    assert host.paths.destination("panel_unit").read_bytes() == b"old panel_unit"
    assert host.updater.installed() == OLD
    assert host.updater.transaction() is None
    result = host.files.json(host.paths.state / "status.json")
    assert result["rollback_restored"] and not result["rollback_health_verified"]


def test_failed_rollback_keeps_transaction_for_retry(host, monkeypatch):
    stage(host)
    prepare_fake(host, monkeypatch)
    monkeypatch.setattr(
        host.updater, "wait_health", lambda *a: (_ for _ in ()).throw(helper.UpdateError("offline"))
    )
    with pytest.raises(helper.UpdateError, match="rollback is incomplete"):
        host.updater.install(JOB)
    assert host.updater.transaction() is not None
    assert host.files.json(host.paths.state / "status.json")["rollback_restored"] is False
    monkeypatch.setattr(host.updater, "wait_health", lambda *a: None)
    host.updater.recover(restart=True)
    assert host.updater.transaction() is None


def test_commit_recovery_finishes_result_without_rolling_back(host, monkeypatch):
    stage(host)
    prepare_fake(host, monkeypatch)
    original = host.updater.finish_commit
    monkeypatch.setattr(
        host.updater, "finish_commit", lambda value: (_ for _ in ()).throw(OSError("disk full"))
    )
    with pytest.raises(helper.UpdateError, match="passed health verification"):
        host.updater.install(JOB)
    assert host.updater.transaction()["step"] == "committed"
    host.commands.clear()
    monkeypatch.setattr(host.updater, "finish_commit", original)
    host.updater.recover()
    assert not host.commands
    assert host.updater.installed() == helper.identity(JOB)
    assert host.files.json(host.paths.state / "status.json")["phase"] == "succeeded"


def test_download_post_exit_only_marks_interrupted_download(host):
    host.updater.status(JOB, "installing", "Do not touch this")
    host.updater.recover(download_only=True)
    assert host.files.json(host.paths.state / "status.json")["phase"] == "installing"
    host.updater.status(JOB, "downloading", "Interrupted")
    host.updater.recover(download_only=True)
    assert host.files.json(host.paths.state / "status.json")["phase"] == "failed"
    assert not host.commands


def test_bootstrap_installs_current_helper_and_units_with_inherited_metadata(host):
    source = host.root / "source"
    source.mkdir()
    for key in ("download_unit", "install_unit", "recover_unit", "update_helper"):
        relative = helper.MANAGED[key][0]
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    metadata = source / "build.json"
    host.files.put_json(metadata, OLD)
    host.updater.setup(source, metadata)
    assert host.updater.installed() == OLD
    assert (host.paths.state / "recovery.py").read_bytes() == (
        ROOT / "installer/update_panel.py"
    ).read_bytes()
    assert host.paths.destination("install_unit").read_bytes().count(b"ExecStopPost=") == 1


def test_service_units_keep_lock_and_recovery_outside_panel_cgroup():
    download = (ROOT / "systemd/psiphon-3x-ui-update-download.service").read_text()
    install = (ROOT / "systemd/psiphon-3x-ui-update-install.service").read_text()
    recovery = (ROOT / "systemd/psiphon-3x-ui-update-recover.service").read_text()
    for unit in (download, install, recovery):
        assert "WorkingDirectory=/" in unit
        assert "RuntimeDirectory=psiphon-3x-ui-updater" in unit
        assert "RuntimeDirectoryPreserve=yes" in unit
        assert "EnvironmentFile=" not in unit
        assert "PartOf=" not in unit and "BindsTo=" not in unit
    assert "recovery.py recover --after-job" in install
    assert "recovery.py recover --download-job" in download
    assert "TimeoutStartSec=2700s" in install
    assert "RemainAfterExit=yes" in recovery
    assert "recover --boot" in recovery
    assert "ReadWritePaths=/opt/psiphon-3x-ui " in install


@POSIX
def test_shared_lock_excludes_second_owner_and_retains_inherited_lock(host):
    with (
        helper.operation_lock(host.files),
        pytest.raises(helper.BusyError),
        helper.operation_lock(host.files),
    ):
        pass
    import fcntl

    lock_path = host.paths.lock_dir / "operation.lock"
    fd = os.open(lock_path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with helper.operation_lock(host.files, fd):
            pass
        with pytest.raises(helper.BusyError), helper.operation_lock(host.files):
            pass
    finally:
        os.close(fd)


@POSIX
def test_panel_cannot_substitute_inbox_or_symlink_a_root_input(host):
    outside = host.root / "outside"
    outside.write_text("must remain unchanged")
    link = host.paths.inbox / "request.json"
    link.symlink_to(outside)
    with pytest.raises((helper.UpdateError, OSError)):
        host.updater.request("install")
    assert outside.read_text() == "must remain unchanged"
    assert stat.S_IMODE(host.paths.inbox.stat().st_mode) == 0o770
