"""Credential-form regressions against the dashboard's actual inline JavaScript.

Node runs the handlers with a mocked network, without npm packages. Only these
JS tests skip when Node is unavailable; markup and API tests still run. Real
Alpine/DOM interactions are checked separately in the browser.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

DASHBOARD = Path(__file__).resolve().parents[1] / "panel" / "static" / "dashboard.html"


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inputs = {}
        self.buttons = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and "x-model" in attrs:
            self.inputs[attrs["x-model"]] = attrs
        elif tag == "button" and "@click" in attrs:
            self.buttons[attrs["@click"]] = attrs


@pytest.fixture(scope="module")
def markup():
    parsed = _Markup()
    parsed.feed(DASHBOARD.read_text(encoding="utf-8"))
    return parsed


_JS_HARNESS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const inline = html.match(/<script>([\s\S]*?)<\/script>/);
assert(inline, 'dashboard inline script must exist');
const calls = [];
const notices = [];
const plain = value => JSON.parse(JSON.stringify(value));
function response(status, body) {
  return {
    status, ok: status >= 200 && status < 300,
    text: async () => typeof body === 'string' ? body : JSON.stringify(body),
  };
}
let respond = () => response(200, {changed: true, username: 'ops-admin', rotated: true});
const context = vm.createContext({
  window: {}, document: {cookie: ''},
  setTimeout: () => 0, clearTimeout: () => {},
  setInterval: () => 0, clearInterval: () => {},
  fetch: async (url, options = {}) => {
    calls.push({url, method: options.method || 'GET', headers: plain(options.headers || {}),
                body: options.body ? JSON.parse(options.body) : null});
    return respond(url, options);
  },
});
vm.runInContext(inline[1], context, {filename: 'dashboard.html', timeout: 1000});
const app = context.appDashboard();
app.notify = (text, kind = 'ok') => notices.push({text, kind});
app._csrfHeaders = async () => ({'X-CSRF-Token': 'test-csrf'});
function validUsername() {
  Object.assign(app.username, {
    current: 'admin', next: 'ops-admin', password: ' old-password ', reveal: true,
  });
}
function validPassword() {
  Object.assign(app.rotate, {
    current: ' old-password ', next: ' new-password ', confirm: ' new-password ',
    revealCurrent: true, revealNext: true, revealConfirm: true,
  });
}
"""


@pytest.fixture(scope="module")
def run_js():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for executable dashboard JavaScript regressions")

    def run(code):
        script = _JS_HARNESS + "\n(async () => {\n" + code
        script += '\nprocess.stdout.write("dashboard-js-ok\\n");\n})().catch(error => {\n'
        script += "console.error(error); process.exitCode = 1;\n});\n"
        result = subprocess.run(
            [node, "-", str(DASHBOARD)],
            input=script,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.strip() == "dashboard-js-ok", "JavaScript check did not finish"

    return run


def test_tls_status_reports_active_expiry_not_just_the_disk_file(run_js):
    run_js("""
      respond = () => response(200, {
        enabled: true, tls_active: true,
        cert_path: '/root/cert/ip/fullchain.pem', key_path: '/root/cert/ip/privkey.pem',
        active_cert_not_after: '2030-02-03T04:05:00+00:00', active_cert_expired: false,
        cert_not_after: '2040-01-01T00:00:00+00:00', cert_expired: false,
        auto_reload_enabled: true, reload_interval_seconds: 60,
      });
      await app.loadHttpsStatus();
      assert.equal(app.tls.active, true);
      assert.match(app.tls.status, /active certificate valid until 2030-02-03/);
      assert.match(app.tls.status, /automatic renewal checks every 60 seconds/);
      assert(!app.tls.status.includes('2040'));
    """)


def test_invalid_tls_renewal_is_reported_as_retained_not_applied(run_js):
    run_js(r"""
      respond = () => response(200, {
        enabled: true, tls_active: true, renewal_pending: true,
        active_cert_not_after: '2030-01-01T00:00:00+00:00', active_cert_expired: false,
        reload_error: 'certificate/key mismatch', auto_reload_enabled: true,
        reload_interval_seconds: 60,
      });
      await app.loadHttpsStatus();
      assert.match(app.tls.status, /renewal not applied: certificate\/key mismatch/);
      assert.match(app.tls.status, /previous certificate retained/);
      assert(!app.tls.status.includes('applying automatically'));
    """)


def test_tls_periodic_status_refresh_preserves_unsaved_paths(run_js):
    run_js("""
      const intervals = [];
      const cleared = [];
      context.setInterval = (callback, delay) => { intervals.push({callback, delay}); return 7; };
      context.clearInterval = id => cleared.push(id);
      app.refreshAll = async () => {};
      await app.init();
      await new Promise(resolve => setImmediate(resolve));
      app.section = 'settings';
      app.tls.cert = '/my/unsaved-cert.pem';
      app.tls.key = '/my/unsaved-key.pem';
      respond = () => response(200, {enabled: false, cert_path: '/server/cert', key_path: '/server/key'});
      assert.equal(intervals[0].delay, 60000);
      await intervals[0].callback();
      assert.equal(app.tls.cert, '/my/unsaved-cert.pem');
      assert.equal(app.tls.key, '/my/unsaved-key.pem');
      app.destroy();
      assert.deepEqual(cleared, [7]);
    """)


def test_current_username_is_an_editable_manual_input(markup):
    field = markup.inputs["username.current"]
    assert "disabled" not in field
    assert "readonly" not in field
    assert "value" not in field
    assert field["autocomplete"] == "off"
    assert markup.inputs["username.next"]["autocomplete"] == "off"


def test_current_username_starts_blank_and_init_does_not_overwrite_typing(run_js):
    run_js("""
      assert.equal(app.username.current, '');
      app.refreshAll = async () => {};
      app.loadHttpsStatus = () => {};
      app.username.current = 'manually-typed';
      await app.init();
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(app.username.current, 'manually-typed');
      assert.deepEqual(calls, []);
    """)


def test_rotation_button_is_disabled_while_request_is_pending(markup, run_js):
    expression = markup.buttons["rotatePassword()"][":disabled"]
    run_js(f"""
      const disabled = vm.runInNewContext({json.dumps(expression)}, {{
        busy: {{rotate: true}}, rotate: {{next: 'valid-password', confirm: 'valid-password'}},
      }});
      assert.equal(disabled, true);
    """)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"detail": "current password does not match"}, "current password does not match"),
        (
            {
                "detail": [
                    {
                        "loc": ["body", "new_password"],
                        "msg": "Too short",
                        "input": "PASSWORD-SENTINEL",
                        "ctx": {"value": "PASSWORD-SENTINEL"},
                    }
                ]
            },
            "New password: Too short",
        ),
        (
            {
                "detail": [
                    {"loc": ["body", "current_username"], "msg": "Required"},
                    {"loc": ["body", "new_username"], "msg": "Invalid characters"},
                ]
            },
            "Current admin username: Required; New username: Invalid characters",
        ),
        ({"detail": {"msg": "Invalid request", "input": "PASSWORD-SENTINEL"}}, "Invalid request"),
        ({"detail": {"message": "Try again"}}, "Try again"),
        (
            {"detail": [{"loc": ["body", "constructor"], "msg": "Invalid request"}]},
            "Invalid request",
        ),
        ({"detail": {}}, "HTTP 422"),
        ({"detail": []}, "HTTP 422"),
        ({"detail": [None, {}, 123]}, "HTTP 422"),
        ({"detail": None}, "HTTP 422"),
        ({"detail": 123}, "HTTP 422"),
        (None, "HTTP 422"),
        ([], "HTTP 422"),
        ("unexpected JSON string", "HTTP 422"),
    ],
)
def test_error_formatter_handles_validation_and_unknown_shapes(run_js, body, expected):
    run_js(f"""
      const text = app._errorMessage({json.dumps(body)}, 422);
      assert.equal(text, {json.dumps(expected)});
      assert(!text.includes('[object Object]'));
      assert(!text.includes('PASSWORD-SENTINEL'));
    """)


@pytest.mark.parametrize(
    ("method", "busy"), [("changeUsername", "user"), ("rotatePassword", "rotate")]
)
@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (
            422,
            {
                "detail": [
                    {
                        "loc": ["body", "current_password"],
                        "msg": "Invalid value",
                        "input": "PASSWORD-SENTINEL",
                    }
                ]
            },
            "Current password: Invalid value",
        ),
        (401, {"detail": "current password does not match"}, "current password does not match"),
        (403, {"detail": "CSRF token missing or invalid."}, "CSRF token missing or invalid."),
        (500, "Internal Server Error", "Internal Server Error"),
        (500, "", "HTTP 500"),
        (502, None, "HTTP 502"),
    ],
)
def test_both_handlers_report_readable_errors_and_recover_busy_state(
    run_js, method, busy, status, body, expected
):
    run_js(f"""
      validUsername(); validPassword();
      const before = plain({{username: app.username, rotate: app.rotate}});
      respond = () => response({status}, {json.dumps(body)});
      await app[{json.dumps(method)}]();
      assert.equal(calls.length, 1);
      assert.equal(app.busy[{json.dumps(busy)}], false);
      assert.equal(notices.at(-1).kind, 'err');
      assert(notices.at(-1).text.includes({json.dumps(expected)}));
      assert(!notices.at(-1).text.includes('[object Object]'));
      assert(!notices.at(-1).text.includes('PASSWORD-SENTINEL'));
      assert.deepEqual(plain({{username: app.username, rotate: app.rotate}}), before);
    """)


@pytest.mark.parametrize("changed", [True, False])
def test_username_submission_sends_manual_value_and_clears_all_fields(run_js, changed):
    run_js(f"""
      validUsername();
      app.username.current = 'Old Admin';
      respond = () => response(200, {{changed: {json.dumps(changed)}, username: 'ops-admin'}});
      await app.changeUsername();
      assert.deepEqual(calls[0], {{
        url: '/api/dashboard/change-username', method: 'POST',
        headers: {{'X-CSRF-Token': 'test-csrf', 'Content-Type': 'application/json'}},
        body: {{current_username: 'Old Admin', current_password: ' old-password ', new_username: 'ops-admin'}},
      }});
      assert.deepEqual(plain(app.username), {{current: '', next: '', password: '', reveal: false}});
      assert.equal(app.busy.user, false);
      assert.equal(notices.at(-1).text, {json.dumps("username changed to ops-admin" if changed else "username is unchanged")});
    """)


def test_password_submission_preserves_whitespace_and_resets_reveal_flags(run_js):
    run_js("""
      validPassword();
      await app.rotatePassword();
      assert.deepEqual(calls[0], {
        url: '/api/dashboard/rotate-password', method: 'POST',
        headers: {'X-CSRF-Token': 'test-csrf', 'Content-Type': 'application/json'},
        body: {current_password: ' old-password ', new_password: ' new-password '},
      });
      assert.deepEqual(plain(app.rotate), {
        current: '', next: '', confirm: '',
        revealCurrent: false, revealNext: false, revealConfirm: false,
      });
      assert.equal(app.busy.rotate, false);
      assert.equal(notices.at(-1).text, 'password rotated');
    """)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"current": ""}, "current admin username"),
        ({"current": "x" * 65}, "current admin username"),
        ({"password": ""}, "current password"),
        ({"next": ""}, "New username"),
        ({"next": "ab"}, "New username"),
        ({"next": "x" * 65}, "New username"),
        ({"next": "has space"}, "New username"),
        ({"next": "admin\n"}, "New username"),
        ({"next": "مدیر"}, "New username"),
    ],
)
def test_username_preflight_rejects_invalid_values_without_a_request(run_js, overrides, message):
    run_js(f"""
      validUsername();
      Object.assign(app.username, {json.dumps(overrides)});
      await app.changeUsername();
      assert.deepEqual(calls, []);
      assert.equal(app.busy.user, false);
      assert.equal(notices.at(-1).kind, 'err');
      assert(notices.at(-1).text.includes({json.dumps(message)}));
    """)


@pytest.mark.parametrize(
    ("current", "next_username"),
    [("a", "abc"), ("Old Admin", "A._-123"), ("مدیر", "x" * 64), ("🔒" * 64, "ops-admin")],
)
def test_username_preflight_accepts_existing_formats_and_new_name_boundaries(
    run_js, current, next_username
):
    run_js(f"""
      validUsername();
      app.username.current = {json.dumps(current)};
      app.username.next = {json.dumps(next_username)};
      await app.changeUsername();
      assert.equal(calls.length, 1);
      assert.equal(calls[0].body.current_username, {json.dumps(current)});
      assert.equal(calls[0].body.new_username, {json.dumps(next_username)});
    """)


@pytest.mark.parametrize(
    ("current", "next_password", "confirmation", "message"),
    [
        ("", "valid-password", "valid-password", "current password"),
        ("old-password", "", "", "8 and 128"),
        ("old-password", "short", "short", "8 and 128"),
        ("old-password", "x" * 129, "x" * 129, "8 and 128"),
        ("old-password", "🔒" * 7, "🔒" * 7, "8 and 128"),
        ("old-password", "🔒" * 129, "🔒" * 129, "8 and 128"),
        ("old-password", "valid-password", "different-password", "do not match"),
    ],
)
def test_password_preflight_rejects_invalid_values_without_a_request(
    run_js, current, next_password, confirmation, message
):
    run_js(f"""
      validPassword();
      Object.assign(app.rotate, {{current: {json.dumps(current)}, next: {json.dumps(next_password)},
                                 confirm: {json.dumps(confirmation)}}});
      await app.rotatePassword();
      assert.deepEqual(calls, []);
      assert.equal(app.busy.rotate, false);
      assert.equal(notices.at(-1).kind, 'err');
      assert(notices.at(-1).text.includes({json.dumps(message)}));
    """)


@pytest.mark.parametrize("password", ["x" * 8, "x" * 128, "🔒" * 8, "🔒" * 128])
def test_password_preflight_counts_code_points_like_the_request_schema(run_js, password):
    # This tests the client/schema boundary, not bcrypt's separate byte limit.
    run_js(f"""
      validPassword();
      app.rotate.next = app.rotate.confirm = {json.dumps(password)};
      await app.rotatePassword();
      assert.equal(calls.length, 1);
      assert.equal(calls[0].body.new_password, {json.dumps(password)});
    """)


@pytest.mark.parametrize(
    ("method", "busy"), [("changeUsername", "user"), ("rotatePassword", "rotate")]
)
def test_credential_handlers_prevent_duplicate_pending_requests(run_js, method, busy):
    run_js(f"""
      validUsername(); validPassword();
      let finish, started;
      const requestStarted = new Promise(resolve => {{started = resolve;}});
      respond = () => new Promise(resolve => {{
        finish = () => resolve(response(500, 'Try again'));
        started();
      }});
      const first = app[{json.dumps(method)}]();
      const second = app[{json.dumps(method)}]();
      await requestStarted;
      assert.equal(calls.length, 1);
      assert.equal(app.busy[{json.dumps(busy)}], true);
      finish();
      await Promise.all([first, second]);
      assert.equal(app.busy[{json.dumps(busy)}], false);
      respond = () => response(200, {{changed: true, username: 'ops-admin', rotated: true}});
      await app[{json.dumps(method)}]();
      assert.equal(calls.length, 2);
      assert.equal(notices.at(-1).kind, 'ok');
    """)


@pytest.mark.parametrize(
    ("method", "busy"), [("changeUsername", "user"), ("rotatePassword", "rotate")]
)
def test_credential_handlers_recover_from_network_failure(run_js, method, busy):
    run_js(f"""
      validUsername(); validPassword();
      respond = () => {{throw new Error('connection refused');}};
      await app[{json.dumps(method)}]();
      assert.equal(app.busy[{json.dumps(busy)}], false);
      assert.equal(notices.at(-1).text, 'network error: connection refused');
    """)
