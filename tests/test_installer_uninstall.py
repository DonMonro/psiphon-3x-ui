"""Exercise uninstall shell paths with host operations replaced by harmless stubs."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "install.sh"


def _bash() -> str:
    bash = shutil.which("bash")
    if not bash and os.name == "nt":
        candidate = Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Git/bin/bash.exe"
        if candidate.is_file():
            bash = str(candidate)
    if not bash:
        pytest.skip("installer tests require Bash")
    return bash


def _run_shell(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    # Load real functions and constants, but replace the entrypoint. No
    # installation/uninstallation runs unless a test explicitly invokes it.
    source = INSTALL_SH.read_text(encoding="utf-8").rsplit('\nmain "$@"', 1)[0]
    script = tmp_path / "uninstall-test.sh"
    script.write_text(
        source
        + '\nwarn() { printf "%s\\n" "$*" >&2; }\n'
        + 'info() { printf "%s\\n" "$*"; }\n'
        + 'ok() { printf "%s\\n" "$*"; }\n'
        + "sleep() { :; }\n"
        + body,
        encoding="utf-8",
        newline="\n",
    )
    return subprocess.run([_bash(), script.as_posix()], capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "[::]", "*"])
def test_uninstall_reads_saved_port_and_only_kills_panel_owned_listener(tmp_path, address):
    env_file = tmp_path / "panel.env"
    env_file.write_text('PSIPHON3XUI_PORT="2053"\n', encoding="utf-8")
    result = _run_shell(
        tmp_path,
        f"""
ENV_FILE={shlex.quote(env_file.as_posix())}
unset PANEL_PORT PSIPHON3XUI_PORT
id() {{ printf '%s\\n' 1234; }}
ps() {{
    case "$*" in
        *101) printf '%s\\n' ' 1234' ;;
        *) printf '%s\\n' ' 0' ;;
    esac
}}
ss() {{
    cat <<'LISTENERS'
State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
LISTEN 0 128 {address}:2053 0.0.0.0:* users:(("python",pid=101,fd=7),("other",pid=102,fd=8))
LISTEN 0 128 0.0.0.0:12053 0.0.0.0:* users:(("python",pid=103,fd=7))
LISTENERS
}}
kill() {{ printf 'KILL %s\\n' "$*"; }}
_purge_orphan_panel_listeners
printf '%s\\n' completed
""",
    )
    assert result.returncode == 0, result.stderr
    assert "unbound variable" not in result.stderr
    assert "KILL -9 101\n" in result.stdout
    assert "KILL -9 102" not in result.stdout
    assert "103" not in result.stdout + result.stderr
    assert "not owned by psiphon3xui" in result.stderr
    assert "completed" in result.stdout


@pytest.mark.parametrize("saved_port", [None, "", "0", "65536", "2053;false", "999999999999"])
def test_uninstall_skips_listener_lookup_when_saved_port_is_missing_or_invalid(
    tmp_path, saved_port
):
    env_file = tmp_path / "panel.env"
    if saved_port is not None:
        env_file.write_text(f"PSIPHON3XUI_PORT={saved_port}\n", encoding="utf-8")
    result = _run_shell(
        tmp_path,
        f"""
ENV_FILE={shlex.quote(env_file.as_posix())}
unset PANEL_PORT PSIPHON3XUI_PORT
ss() {{ printf '%s\\n' unexpected-listener-lookup; }}
kill() {{ printf '%s\\n' unexpected-kill; }}
_purge_orphan_panel_listeners
printf '%s\\n' completed
""",
    )
    assert result.returncode == 0, result.stderr
    assert "unbound variable" not in result.stderr
    assert "No valid panel port" in result.stderr
    assert "unexpected-" not in result.stdout + result.stderr
    assert "completed" in result.stdout


def test_uninstall_does_not_claim_3xui_entries_removed_after_skipped_cleanup(tmp_path):
    missing = shlex.quote((tmp_path / "missing").as_posix())
    result = _run_shell(
        tmp_path,
        f"""
VENV_DIR={missing}
DB_PATH={missing}
ENV_FILE={missing}
unset PANEL_PORT PSIPHON3XUI_PORT
systemctl() {{ :; }}
rm() {{ printf '%s\\n' mocked-file-removal; }}
id() {{ return 1; }}
getent() {{ return 1; }}
userdel() {{ printf '%s\\n' unexpected-user-removal; }}
groupdel() {{ printf '%s\\n' unexpected-group-removal; }}
_remove_stale_sudoers_dropin() {{ :; }}
run_uninstall <<<'yes'
""",
    )
    assert result.returncode == 0, result.stderr
    assert "Skipping 3x-ui cleanup" in result.stderr
    assert "unbound variable" not in result.stderr
    assert "Psiphon-3X-UI uninstalled" in result.stdout
    assert "see the cleanup result above" in result.stdout
    assert "were removed" not in result.stdout
    assert "unexpected-" not in result.stdout + result.stderr
