"""Server launcher authorization, trusted path selection, and privilege boundary."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from installer import admin_recovery as launcher

POSIX = pytest.mark.skipif(os.name != "posix", reason="Linux ownership, no-follow, and flock")


def test_installed_configuration_is_only_literal_prefix_and_accounts():
    value = launcher.installation(
        b'{"prefix":"/srv/custom-panel","user":"panel_user","group":"panel_group"}'
    )
    assert value == {
        "prefix": Path("/srv/custom-panel"),
        "user": "panel_user",
        "group": "panel_group",
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"prefix": "/"},
        {"prefix": "/opt/../etc"},
        {"prefix": "/opt/./panel"},
        {"prefix": "/opt/$(id)"},
        {"prefix": "/opt/panel;id"},
        {"prefix": "relative/path"},
        {"user": "root;id"},
        {"user": 42},
        {"group": "../root"},
        {"command": "execute me"},
    ],
)
def test_configuration_refuses_paths_accounts_and_extra_execution_fields(changes):
    values = {"prefix": "/opt/panel", "user": "panel", "group": "panel", **changes}
    with pytest.raises(launcher.RecoveryError):
        launcher.installation(json.dumps(values).encode())


def test_configuration_duplicate_field_is_rejected():
    with pytest.raises(launcher.RecoveryError, match="duplicate"):
        launcher.installation(
            b'{"prefix":"/opt/panel","user":"panel","group":"panel","user":"root"}'
        )


@pytest.mark.parametrize(
    "contents",
    [
        "PSIPHON3XUI_DB_PATH=/etc/other.db\n",
        "PSIPHON3XUI_DB_PATH=$(touch /tmp/sentinel)\n",
        "PSIPHON3XUI_DB_PATH='/opt/panel/panel.db\n",
        "PSIPHON3XUI_DB_PATH=/opt/panel/panel.db\nPSIPHON3XUI_DB_PATH=/opt/panel/panel.db\n",
    ],
)
def test_environment_cannot_redirect_recovery_or_execute_commands(contents):
    with pytest.raises(launcher.RecoveryError):
        launcher.database_path(contents.encode(), Path("/opt/panel"))


def test_environment_only_reads_database_path_and_ignores_secrets_or_other_shell_text():
    prefix = Path("/opt/panel")
    data = (
        "PSIPHON3XUI_SESSION_SECRET=never-forward-this\n"
        "$(must-not-execute)\n"
        f'PSIPHON3XUI_DB_PATH="{prefix / "panel.db"}"\n'
    ).encode()
    assert launcher.database_path(data, prefix) == prefix / "panel.db"
    assert launcher.database_path(b"# no override\n", prefix) == prefix / "panel.db"


def test_active_interpreter_uses_the_updater_environment(monkeypatch):
    host = launcher.Host()
    attempt = "a" * 32 + "-" + "b" * 32
    expected = host.state / "venvs" / attempt / "bin" / "python"
    monkeypatch.setattr(
        launcher,
        "read_file",
        lambda *a, **kw: f"[Service]\nExecStart=\nExecStart={expected} -I -m panel\n".encode(),
    )
    assert launcher.active_python(host, Path("/opt/panel")) == expected


@pytest.mark.parametrize(
    "contents",
    [
        "ExecStart=/usr/bin/python3 -m panel\n",
        "ExecStart=\nExecStart=/tmp/python -I -m panel\n",
        "ExecStart=\nExecStart=/var/lib/psiphon-3x-ui-updater/venvs/../python -I -m panel\n",
        "ExecStart=\nExecStart=/var/lib/psiphon-3x-ui-updater/venvs/invalid/bin/python -I -m panel\n",
        "ExecStart=\nExecStart=/var/lib/psiphon-3x-ui-updater/venvs/"
        + "a" * 32
        + "-"
        + "b" * 32
        + "/bin/python -c 'arbitrary code'\n",
    ],
)
def test_active_interpreter_refuses_unexpected_paths_and_arguments(monkeypatch, contents):
    monkeypatch.setattr(launcher, "read_file", lambda *a, **kw: contents.encode())
    with pytest.raises(launcher.RecoveryError):
        launcher.active_python(launcher.Host(), Path("/opt/panel"))


def test_help_works_before_requiring_linux_root_or_configuration(capsys):
    with pytest.raises(SystemExit) as error:
        launcher.main(["--help"])
    assert error.value.code == 0
    assert "show-username" in capsys.readouterr().out


def test_bad_arguments_do_not_echo_a_mistaken_password(capsys):
    with pytest.raises(SystemExit) as error:
        launcher.main(["reset-password", "--password", "secret-must-not-echo"])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert "secret-must-not-echo" not in output.out + output.err


def test_main_refuses_an_unprivileged_caller_without_opening_installation(monkeypatch):
    monkeypatch.setattr(launcher.sys, "platform", "linux")
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(
        launcher, "run_recovery", lambda *a: pytest.fail("unprivileged caller opened recovery")
    )
    with pytest.raises(SystemExit) as error:
        launcher.main(["show-username"])
    assert error.value.code == 2


@pytest.fixture
def fake_host(tmp_path, monkeypatch):
    host = launcher.Host(state=tmp_path / "state", lock_dir=tmp_path / "run")
    host.state.mkdir()
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    database = prefix / "panel.db"
    database.write_bytes(b"existing database")
    calls, audits, locks = [], [], []
    lock_fd = 91

    @contextlib.contextmanager
    def locked(_host):
        locks.append(True)
        yield lock_fd
        locks.append(False)

    monkeypatch.setattr(launcher, "operation_lock", locked)
    monkeypatch.setattr(
        launcher,
        "installation",
        lambda _data: {"prefix": prefix, "user": "panel", "group": "panel"},
    )
    monkeypatch.setattr(
        launcher,
        "read_file",
        lambda path, *a, **kw: b"{}" if path.name == "admin.json" else b"# default database\n",
    )
    monkeypatch.setattr(launcher, "protected_directory", lambda *a, **kw: None)
    monkeypatch.setattr(launcher, "active_python", lambda *a: prefix / "venv/bin/python")
    monkeypatch.setattr(launcher, "check_python", lambda *a: None)
    monkeypatch.setitem(
        sys.modules, "pwd", SimpleNamespace(getpwnam=lambda _name: SimpleNamespace(pw_uid=1234))
    )
    monkeypatch.setitem(
        sys.modules, "grp", SimpleNamespace(getgrnam=lambda _name: SimpleNamespace(gr_gid=2345))
    )
    monkeypatch.setattr(launcher, "audit_reset", lambda: audits.append(True))
    monkeypatch.setenv("PYTHONPATH", "untrusted caller code")
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "never-forward-this")

    def run(command, **kwargs):
        assert locks[-1] is True
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(launcher.subprocess, "run", run)
    return SimpleNamespace(
        host=host,
        prefix=prefix,
        database=database,
        calls=calls,
        locks=locks,
        audits=audits,
        lock_fd=lock_fd,
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["show-username"],
        ["reset-password"],
        ["reset-password", "--username", "new-admin"],
    ],
)
def test_launcher_drops_privileges_strips_environment_and_holds_lock(fake_host, arguments):
    assert launcher.run_recovery(fake_host.host, arguments) == 0
    command, options = fake_host.calls[0]
    assert command == [
        str(fake_host.prefix / "venv/bin/python"),
        "-I",
        "-m",
        "panel.admin_recovery",
        "--db",
        str(fake_host.database),
        *arguments,
    ]
    assert options["user"] == 1234
    assert options["group"] == 2345
    assert options["extra_groups"] == []
    assert options["pass_fds"] == (fake_host.lock_fd,)
    assert options["umask"] == 0o077
    assert options["cwd"] == "/"
    assert set(options["env"]) == {"PATH", "LANG", "LC_ALL"}
    assert "shell" not in options
    assert fake_host.locks == [True, False]
    assert fake_host.audits == ([] if arguments == ["show-username"] else [True])


def test_missing_database_fails_without_creating_one_or_running_panel(fake_host):
    fake_host.database.unlink()
    with pytest.raises(FileNotFoundError):
        launcher.run_recovery(fake_host.host, ["reset-password"])
    assert not fake_host.calls
    assert not fake_host.database.exists()


def test_failed_child_is_not_audited_as_a_successful_reset(fake_host, monkeypatch):
    monkeypatch.setattr(launcher.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=2))
    assert launcher.run_recovery(fake_host.host, ["reset-password"]) == 2
    assert not fake_host.audits


@pytest.mark.parametrize("invoking", ["1234", "1234\nsecret-must-not-log"])
def test_success_audit_only_records_sanitized_invoking_uid(monkeypatch, invoking):
    entries = []
    monkeypatch.setitem(
        sys.modules,
        "syslog",
        SimpleNamespace(
            openlog=lambda *a: None,
            syslog=lambda level, message: entries.append(message),
            LOG_PID=1,
            LOG_AUTHPRIV=2,
            LOG_NOTICE=3,
        ),
    )
    monkeypatch.setenv("SUDO_UID", invoking)
    launcher.audit_reset()
    assert entries == [
        "Panel admin credentials reset by invoking uid "
        + ("1234" if invoking == "1234" else "unknown")
        + "."
    ]


@POSIX
def test_real_lock_excludes_another_owner_and_interrupted_update(tmp_path):
    host = launcher.Host(
        state=tmp_path / "state",
        lock_dir=tmp_path / "run",
        owner=os.getuid(),
        anchor=tmp_path,
    )
    host.state.mkdir()
    with (
        launcher.operation_lock(host),
        pytest.raises(launcher.RecoveryError, match="running"),
        launcher.operation_lock(host),
    ):
        pytest.fail("second owner acquired installer lock")
    (host.state / "transaction.json").write_bytes(b"interrupted")
    with pytest.raises(launcher.RecoveryError, match="interrupted"), launcher.operation_lock(host):
        pytest.fail("recovery entered an interrupted activation")


@POSIX
def test_inherited_operation_lock_outlives_the_launcher_context(tmp_path):
    host = launcher.Host(
        state=tmp_path / "state",
        lock_dir=tmp_path / "run",
        owner=os.getuid(),
        anchor=tmp_path,
    )
    host.state.mkdir()
    with contextlib.ExitStack() as stack:
        with launcher.operation_lock(host) as fd:
            assert not os.get_inheritable(fd)
            child = stack.enter_context(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        "import os, sys; os.fstat(int(sys.argv[1])); sys.stdin.buffer.read(1)",
                        str(fd),
                    ],
                    stdin=subprocess.PIPE,
                    pass_fds=(fd,),
                )
            )
        with pytest.raises(launcher.RecoveryError, match="running"), launcher.operation_lock(host):
            pytest.fail("the lock was released while the recovery child was still running")
        child.communicate(b"1", timeout=5)
        assert child.returncode == 0
    with launcher.operation_lock(host):
        pass


@POSIX
def test_configuration_reader_refuses_symlink_and_group_writable_config(tmp_path):
    host = launcher.Host(owner=os.getuid(), anchor=tmp_path)
    source = tmp_path / "real.json"
    source.write_bytes(b"{}")
    source.chmod(0o600)
    link = tmp_path / "alias.json"
    link.symlink_to(source)
    with pytest.raises(OSError):
        launcher.read_file(link, host)
    source.chmod(0o660)
    with pytest.raises(launcher.RecoveryError, match="permissions"):
        launcher.read_file(source, host)
    assert launcher.read_file(source, host, panel_gid=os.getgid()) == b"{}"
