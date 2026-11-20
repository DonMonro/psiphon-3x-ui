"""Public recovery help offers the same server commands as the local tool."""

from __future__ import annotations

import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOGIN = ROOT / "panel" / "static" / "login.html"


class RecoveryMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.trigger = {}
        self.dialog = {}
        self.commands = {}
        self.copy_buttons = []
        self._command = None
        self._in_dialog = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "dialog" and attrs.get("id") == "login-recovery":
            self.dialog = attrs
            self._in_dialog = True
        if attrs.get("x-ref") == "recoveryTrigger":
            self.trigger = attrs
        if self._in_dialog and tag == "code" and "x-ref" in attrs:
            self._command = attrs["x-ref"]
            self.commands[self._command] = ""
        if self._in_dialog and "recovery-copy" in attrs.get("class", "").split():
            self.copy_buttons.append(attrs)

    def handle_data(self, data):
        if self._command:
            self.commands[self._command] += data

    def handle_endtag(self, tag):
        if tag == "code":
            self._command = None
        if tag == "dialog":
            self._in_dialog = False


def test_recovery_dialog_is_reachable_and_contains_all_three_runnable_commands():
    page = LOGIN.read_text(encoding="utf-8")
    markup = RecoveryMarkup()
    markup.feed(page)
    assert markup.trigger["type"] == "button"
    assert markup.trigger["aria-haspopup"] == "dialog"
    assert markup.trigger["aria-controls"] == "login-recovery"
    assert markup.dialog["aria-labelledby"] == "recovery-title"
    assert markup.dialog["aria-describedby"] == "recovery-help"
    assert markup.dialog["@close"] == "onRecoveryClosed()"
    assert markup.commands == {
        "usernameCommand": "sudo psiphon-3x-ui-admin show-username",
        "passwordCommand": "sudo psiphon-3x-ui-admin reset-password",
        "credentialsCommand": "sudo psiphon-3x-ui-admin reset-password --username new-admin",
    }
    assert len(markup.copy_buttons) == 3
    assert all(button.get("aria-label") for button in markup.copy_buttons)
    assert "hosting provider’s console" in page
    assert "replace <code>new-admin</code>" in page
    assert "current installer once" in page


def test_login_recovery_handlers_in_javascript():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for executable login recovery checks")
    result = subprocess.run(
        [node, "--test", str(ROOT / "tests" / "js" / "login-recovery.test.cjs")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
