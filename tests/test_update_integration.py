"""Build identity and fixed installer/polkit integration regressions."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from installer import write_build_metadata

ROOT = Path(__file__).resolve().parents[1]


def _source(tmp_path: Path) -> Path:
    (tmp_path / "panel" / "data").mkdir(parents=True)
    (tmp_path / "panel" / "__init__.py").write_text('__version__ = "1.2.3"\n', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n', encoding="utf-8")
    return tmp_path


def test_metadata_reads_versions_without_executing_source(tmp_path, monkeypatch):
    root = _source(tmp_path)
    with (root / "panel" / "__init__.py").open("a", encoding="utf-8") as source:
        source.write('raise RuntimeError("source must not execute")\n')
    revision = "a" * 40
    monkeypatch.setattr(
        write_build_metadata.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            stdout=revision if "rev-parse" in command else ""
        ),
    )
    assert write_build_metadata.write_metadata(root) == {"version": "1.2.3", "revision": revision}
    assert json.loads((root / "panel/data/build.json").read_text()) == {
        "version": "1.2.3",
        "revision": revision,
    }


@pytest.mark.parametrize("changed", [" M panel/main.py\n", "?? panel/new_feature.py\n"])
def test_dirty_checkout_does_not_claim_a_published_revision(tmp_path, monkeypatch, changed):
    root = _source(tmp_path)
    monkeypatch.setattr(
        write_build_metadata.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            stdout="a" * 40 if "rev-parse" in command else changed
        ),
    )
    assert write_build_metadata.write_metadata(root)["revision"] is None


def test_no_git_source_has_unknown_revision(tmp_path, monkeypatch):
    root = _source(tmp_path)

    def missing(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(write_build_metadata.subprocess, "run", missing)
    assert write_build_metadata.write_metadata(root)["revision"] is None


def test_inconsistent_source_version_fails_before_writing(tmp_path):
    root = _source(tmp_path)
    (root / "pyproject.toml").write_text('[project]\nversion = "1.2.4"\n')
    with pytest.raises(ValueError, match="same"):
        write_build_metadata.write_metadata(root)
    assert not (root / "panel/data/build.json").exists()


def test_manual_install_and_uninstall_lock_before_modifying_installation():
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    main = source.split("main() {", 1)[1].split("print_summary()", 1)[0]
    uninstall = source.split("run_uninstall() {", 1)[1].split("# --- Phase 24", 1)[0]
    assert uninstall.index("Uninstall cancelled.") < uninstall.index("acquire_install_lock")
    assert uninstall.index("acquire_install_lock") < uninstall.index("Cleaning 3x-ui entries")
    install = main.split("esac", 1)[1]
    assert install.index("acquire_install_lock") < install.index("ensure_install_dir")
    assert install.index("acquire_install_lock") < install.index("run_prepare_user")
    panel = (ROOT / "installer/panel_install.sh").read_text(encoding="utf-8")
    assert panel.index("run_update_install") < panel.index("if ! systemctl start psiphon-3x-ui")
    assert "50-panel-update.conf" in panel


def test_uninstall_removes_only_updater_dropin_and_fixed_workspace():
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    uninstall = source.split("run_uninstall() {", 1)[1].split("# --- Phase 24", 1)[0]
    for unit in ("download", "install", "recover"):
        assert f"psiphon-3x-ui-update-{unit}.service" in uninstall
    assert "rm -f /usr/local/libexec/psiphon-3x-ui/update_panel.py" in uninstall
    assert "rm -rf /var/lib/psiphon-3x-ui-updater" in uninstall
    assert "psiphon-3x-ui.service.d/50-panel-update.conf" in uninstall
    assert "psiphon-3x-ui.service.d/*.conf" not in uninstall
    assert "rm -rf /run/psiphon-3x-ui-updater" not in uninstall


def test_polkit_only_allows_start_of_two_exact_update_units():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required to execute polkit rule")
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let rule;
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), {
  polkit: {Result: {YES: 'yes', NOT_HANDLED: 'no'}, addRule: r => {rule = r;}},
});
function check(unit, verb, user = 'psiphon3xui', id = 'org.freedesktop.systemd1.manage-units') {
  return rule({id, lookup: key => ({unit, verb})[key]}, {user});
}
for (const unit of ['psiphon-3x-ui-update-download.service', 'psiphon-3x-ui-update-install.service']) {
  assert.equal(check(unit, 'start'), 'yes');
  for (const verb of ['stop', 'restart', 'enable', 'reload']) assert.equal(check(unit, verb), 'no');
  assert.equal(check(unit, 'start', 'other'), 'no');
  assert.equal(check(unit, 'start', 'psiphon3xui', 'org.freedesktop.systemd1.manage-unit-files'), 'no');
}
for (const unit of ['psiphon-3x-ui-update-recover.service', 'psiphon-3x-ui-update-other.service',
                    'psiphon-3x-ui-update-install@evil.service', 'arbitrary.service']) {
  assert.equal(check(unit, 'start'), 'no');
}
assert.equal(check('psiphon-3x-ui.service', 'restart'), 'yes');
assert.equal(check('psiphon-3x-ui.service', 'stop'), 'no');
assert.equal(check('psiphon-tunnel@US.service', 'start'), 'yes');
"""
    result = subprocess.run(
        [node, "-e", script, str(ROOT / "systemd/49-psiphon-3x-ui.rules")],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
