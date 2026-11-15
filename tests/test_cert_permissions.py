"""Permission companion safety and installer lifecycle regressions."""

from __future__ import annotations

import os
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from installer import cert_permissions

ROOT = Path(__file__).resolve().parents[1]
POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="descriptor permission repair is Linux-only"
)


@pytest.mark.parametrize("part", ["cert", "key"])
@pytest.mark.parametrize(
    "preamble", [b"Bag Attributes\n    friendlyName: panel\n", b"issuer metadata\n" * 400]
)
def test_pem_blocks_after_textual_preambles_are_recognized(tls_pair_factory, part, preamble):
    cert, key = tls_pair_factory()
    source = cert if part == "cert" else key
    source.write_bytes(preamble + source.read_bytes())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with source.open("rb") as stream:
        assert cert_permissions._contains_pem(stream.fileno())


@pytest.mark.parametrize(
    "contents",
    [
        b"notes about -----BEGIN CERTIFICATE----- without a PEM block\n",
        b"-----BEGIN PRIVATE KEY-----\nYWJj\n",
        b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END PRIVATE KEY-----\n",
        b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
    ],
)
def test_non_pem_text_and_incomplete_blocks_are_not_repaired(tmp_path, contents):
    source = tmp_path / "notes.txt"
    source.write_bytes(contents)
    with source.open("rb") as stream:
        assert not cert_permissions._contains_pem(stream.fileno())


def test_pem_detection_has_a_bounded_read(tls_pair_factory):
    cert, _ = tls_pair_factory()
    cert.write_bytes(b"metadata\n" * (1024 * 1024 // 9 + 1) + cert.read_bytes())
    with cert.open("rb") as stream:
        assert not cert_permissions._contains_pem(stream.fileno())


@POSIX_ONLY
def test_preambled_pems_are_repaired_but_unrelated_text_is_untouched(tmp_path, tls_pair_factory):
    directory = tmp_path / "certs"
    cert, key = tls_pair_factory(directory=directory)
    for source in (cert, key):
        source.write_bytes(b"Bag Attributes\n    friendlyName: panel\n" + source.read_bytes())
        source.chmod(0o600)
    notes = directory / "notes.txt"
    notes.write_bytes(b"notes about -----BEGIN PRIVATE KEY-----\n")
    notes.chmod(0o600)
    cert_permissions.repair_permissions(directory, os.getgid(), owner_uid=os.getuid())
    assert stat.S_IMODE(cert.stat().st_mode) == 0o640
    assert stat.S_IMODE(key.stat().st_mode) == 0o640
    assert stat.S_IMODE(notes.stat().st_mode) == 0o600


@POSIX_ONLY
def test_renewed_pems_become_group_readable_without_world_access(tmp_path, tls_pair_factory):
    directory = tmp_path / "certs"
    cert, key = tls_pair_factory(directory=directory)
    directory.chmod(0o777)
    cert.chmod(0o644)
    key.chmod(0o600)
    unrelated = directory / "notes.txt"
    unrelated.write_text("not a certificate", encoding="ascii")
    unrelated.chmod(0o600)
    changed = cert_permissions.repair_permissions(directory, os.getgid(), owner_uid=os.getuid())
    assert changed > 0
    assert stat.S_IMODE(directory.stat().st_mode) == 0o750
    assert stat.S_IMODE(cert.stat().st_mode) == 0o640
    assert stat.S_IMODE(key.stat().st_mode) == 0o640
    assert stat.S_IMODE(unrelated.stat().st_mode) == 0o600
    assert cert_permissions.repair_permissions(directory, os.getgid(), owner_uid=os.getuid()) == 0
    # A renewed key is a replacement inode, root-only again in production.
    tls_pair_factory(directory=directory)
    key.chmod(0o600)
    cert_permissions.repair_permissions(directory, os.getgid(), owner_uid=os.getuid())
    assert stat.S_IMODE(key.stat().st_mode) == 0o640


@POSIX_ONLY
def test_symlink_outside_tree_and_hardlinks_are_never_chmoded(tmp_path, tls_pair_factory):
    directory = tmp_path / "managed"
    directory.mkdir()
    cert, key = tls_pair_factory("outside")
    cert.chmod(0o600)
    key.chmod(0o600)
    (directory / "external.pem").symlink_to(cert)
    (directory / "external-directory").symlink_to(tmp_path, target_is_directory=True)
    os.link(key, directory / "hardlink.key")
    cert_permissions.repair_permissions(directory, os.getgid(), owner_uid=os.getuid())
    assert stat.S_IMODE(cert.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


@POSIX_ONLY
def test_internal_symlink_targets_are_repaired_via_real_directory(tmp_path, tls_pair_factory):
    directory = tmp_path / "managed"
    actual = directory / "archive"
    cert, key = tls_pair_factory(directory=actual)
    key.chmod(0o600)
    (directory / "current.pem").symlink_to(cert)
    (directory / "current.key").symlink_to(key)
    cert_permissions.repair_permissions(directory, os.getgid(), owner_uid=os.getuid())
    assert stat.S_IMODE(key.stat().st_mode) == 0o640
    assert (directory / "current.key").is_symlink()


@POSIX_ONLY
def test_symlinked_directory_components_are_refused(tmp_path, tls_pair_factory):
    directory = tmp_path / "actual"
    tls_pair_factory(directory=directory)
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OSError):
        cert_permissions.repair_permissions(link, os.getgid(), owner_uid=os.getuid())


@POSIX_ONLY
def test_missing_directory_is_normal_and_relative_paths_are_refused(tmp_path):
    assert cert_permissions.repair_permissions(tmp_path / "absent", os.getgid()) == 0
    with pytest.raises(ValueError, match="absolute"):
        cert_permissions.repair_permissions(Path("relative"), os.getgid())


def test_unit_uses_root_owned_isolated_helper_and_scoped_write_paths():
    unit = (ROOT / "systemd" / "psiphon-cert-perms.service").read_text(encoding="utf-8")
    assert "Type=oneshot" in unit
    assert "User=root" in unit
    assert "python3 -I /usr/local/libexec/psiphon-3x-ui/cert_permissions.py" in unit
    assert "ReadWritePaths=-/root/cert -/opt/psiphon-3x-ui/tls" in unit
    assert "chmod -R" not in unit
    assert "EnvironmentFile=" not in unit, "the root helper must never execute panel.env"


def test_timer_runs_every_minute_and_panel_requests_boot_repair():
    timer = (ROOT / "systemd" / "psiphon-cert-perms.timer").read_text(encoding="utf-8")
    panel = (ROOT / "systemd" / "psiphon-3x-ui.service").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=60s" in timer
    assert "AccuracySec=1s" in timer
    assert "Persistent=" not in timer, "Persistent only applies to calendar timers"
    assert "After=network-online.target psiphon-cert-perms.service" in panel
    assert "Wants=network-online.target psiphon-cert-perms.service" in panel


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="separate service UID permission checks require root on Linux",
)
def test_sticky_prefix_blocks_tls_substitution_but_keeps_panel_writable():
    with tempfile.TemporaryDirectory(prefix="tls-prefix-") as temporary:
        prefix = Path(temporary)
        os.chown(prefix, 0, 65534)
        prefix.chmod(0o3775)
        tls = prefix / "tls"
        tls.mkdir(mode=0o750)
        os.chown(tls, 0, 65534)
        for name in ("panel.db", "panel.env"):
            source = prefix / name
            source.touch(mode=0o660)
            source.chmod(0o660)
            os.chown(source, 65534 if name == "panel.db" else 0, 65534)
        for name, owner, mode in (("config", 0, 0o2775), ("data", 65534, 0o700)):
            directory = prefix / name
            directory.mkdir()
            os.chown(directory, owner, 65534)
            directory.chmod(mode)
        program = """
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
root = Path(sys.argv[1])
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
replacement = root / "replacement"
replacement.mkdir()
for operation in (
    lambda: (root / "tls").rename(root / "tls-old"),
    lambda: (root / "tls").rmdir(),
    lambda: replacement.rename(root / "tls"),
):
    try:
        operation()
    except PermissionError:
        pass
    else:
        raise AssertionError("service UID replaced a root-owned TLS entry")
with closing(sqlite3.connect(root / "panel.db")) as connection:
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE status (value INTEGER)")
    connection.commit()
    assert (root / "panel.db-wal").exists()
    assert (root / "panel.db-shm").exists()
with closing(sqlite3.connect(root / "panel.db")) as connection:
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("INSERT INTO status VALUES (1)")
    assert (root / "panel.db-journal").exists()
    connection.commit()
assert not (root / "panel.db-journal").exists()
(root / "panel.env").write_text("PSIPHON3XUI_PORT=8443\\n")
(root / "config" / "US.json").write_text("{}")
(root / "data" / "US").mkdir()
"""
        result = subprocess.run(
            [sys.executable, "-I", "-c", program, str(prefix)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert tls.is_dir()


def test_upgrade_stops_panel_before_changing_live_sqlite_ownership():
    prepare = (ROOT / "installer" / "prepare_user.sh").read_text(encoding="utf-8")
    stop = prepare.index("systemctl stop psiphon-3x-ui.service")
    assert stop < prepare.index('chown -R root:"${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}"')
    assert stop < prepare.index('chmod 3775 "${INSTALL_PREFIX}"')
    guard = prepare[prepare.index("if systemctl cat psiphon-3x-ui.service") : stop]
    assert "then" in guard
    assert '|| die "Could not stop the panel' in prepare


def test_installer_protects_tls_entries_without_blocking_sqlite_sidecars():
    prepare = (ROOT / "installer" / "prepare_user.sh").read_text(encoding="utf-8")
    install = (ROOT / "installer" / "panel_install.sh").read_text(encoding="utf-8")
    assert 'chmod 3775 "${INSTALL_PREFIX}"' in prepare
    assert 'install -d -m 3775 -o root -g "${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}"' in install
    assert 'chmod 2775 "${INSTALL_PREFIX}"' not in prepare
    assert "install -d -m 2775" not in install
    create_tls = install.index(
        'install -d -m 0750 -o root -g "${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}/tls"'
    )
    assert create_tls < install.index("systemctl enable --now psiphon-cert-perms.timer")
    assert 'chown "${PSIPHON3XUI_USER}:${PSIPHON3XUI_GROUP}" "${DB_PATH}"' in install
    assert '"${DB_PATH}-wal" "${DB_PATH}-shm" "${DB_PATH}-journal"' in install
    assert 'chown "${PSIPHON3XUI_USER}:${PSIPHON3XUI_GROUP}" "${sidecar}"' in install
    assert 'chmod 0660 "${ENV_FILE}"' in install


def test_installer_registers_units_before_enabling_and_removes_all_on_uninstall():
    installer = (ROOT / "installer" / "panel_install.sh").read_text(encoding="utf-8")
    begin = installer.index("local CERT_PERMS_UNIT_SRC=")
    activation = installer.index("systemctl enable --now psiphon-cert-perms.timer", begin)
    assert installer.index("systemctl daemon-reload", begin) < activation
    assert 'install -m 0755 -o root -g root "${CERT_PERMS_HELPER_SRC}"' in installer
    assert "chmod -R a+rX /root/cert" not in installer
    uninstall = (ROOT / "install.sh").read_text(encoding="utf-8")
    stop = uninstall.index("systemctl stop psiphon-cert-perms.service")
    remove = uninstall.index("rm -f /usr/local/libexec/psiphon-3x-ui/cert_permissions.py")
    assert stop < remove
    assert "systemctl disable --now psiphon-cert-perms.timer" in uninstall
    assert "/etc/systemd/system/psiphon-cert-perms.timer" in uninstall
