const assert = require("node:assert/strict");
const test = require("node:test");
const { Controller, Notification } = require("../../panel/static/assets/updates.js");

const REVISION = "a".repeat(40);
const JOB = "b".repeat(32);
const candidate = {
  current_version: "1.0.5", current_revision: "c".repeat(40),
  available_version: "1.0.6", available_revision: REVISION,
  phase: "available", update_available: true, job_id: null,
  supported: true, message: "", error: null,
};
const ready = {
  ...candidate, phase: "ready", job_id: JOB,
  available_version: "1.0.6", available_revision: REVISION,
};
const idle = {
  ...candidate, phase: "idle", update_available: false,
  available_version: null, available_revision: null,
};

function clock() {
  let now = 0, next = 0;
  const timers = new Map();
  return {
    now: () => now,
    setTimer: (callback, delay) => {
      const id = ++next;
      timers.set(id, { at: now + delay, callback });
      return id;
    },
    clearTimer: id => timers.delete(id),
    tick(ms) {
      const end = now + ms;
      while (true) {
        const due = [...timers.entries()].filter(([, timer]) => timer.at <= end)
          .sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        now = due[1].at;
        timers.delete(due[0]);
        due[1].callback();
      }
      now = end;
    },
    pending: () => timers.size,
  };
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status, headers: { "Content-Type": "application/json" },
  });
}
function controller(fetch, extra = {}) {
  let cookie = "psiphon3xui_csrf=token";
  const calls = [];
  const instance = new Controller({
    fetch: async (url, options = {}) => {
      calls.push({ url, options });
      return fetch(url, options, () => cookie, value => { cookie = value; });
    },
    cookie: () => cookie,
    setTimer: () => 0,
    clearTimer: () => {},
    render: () => {},
    ...extra,
  });
  return { instance, calls };
}

test("manual check downloads but never installs automatically", async () => {
  const h = controller(async url => url === "/api/updates/check"
    ? response({...ready, phase: "downloading", job_id: JOB})
    : response(ready));
  h.instance.status = {...candidate, phase: "idle", update_available: false};
  await h.instance.check();
  assert.deepEqual(h.calls.map(call => call.url), ["/api/updates/check"]);
  assert.equal(h.calls[0].options.method, "POST");
  assert.deepEqual(JSON.parse(h.calls[0].options.body), {});
  assert.equal(h.instance.status.phase, "downloading");
  assert.equal(h.calls.some(call => call.url.endsWith("/install")), false);
});

test("Update still checks when clicked before the initial status response", async () => {
  let resolveInitial;
  const initial = new Promise(resolve => { resolveInitial = resolve; });
  const h = controller(async url => url === "/api/updates"
    ? initial : response({...ready, phase: "downloading"}));
  const refresh = h.instance.refresh();
  await h.instance.check();
  assert.deepEqual(h.calls.map(call => call.url), ["/api/updates", "/api/updates/check"]);
  resolveInitial(response({...candidate, phase: "idle", update_available: false}));
  await refresh;
  assert.equal(h.instance.status.phase, "downloading");
  assert.equal(h.calls.some(call => call.url.endsWith("/install")), false);
});

test("automatic discovery shows a download notification without sending consent", async () => {
  const h = controller(async () => response(candidate));
  await h.instance.refresh();
  const model = h.instance.model();
  assert.equal(model.visible, true);
  assert.equal(model.action, "download");
  assert.match(model.title, /1\.0\.6.*available/);
  assert.equal(h.instance.dialogTarget, null);
  assert.deepEqual(h.calls.map(call => call.url), ["/api/updates"]);
});

test("download completion prompts for installation and Later keeps it ready", async () => {
  const h = controller(async url => url.endsWith("/download")
    ? response({...ready, phase: "downloading"}) : response(ready));
  h.instance.status = candidate;
  await h.instance.download();
  assert.equal(h.instance.dialogTarget, null);
  await h.instance.refresh();
  assert.deepEqual(h.instance.dialogTarget, {job_id: JOB, revision: REVISION, version: "1.0.6"});
  h.instance.cancel();
  await h.instance.refresh();
  assert.equal(h.instance.status.phase, "ready");
  assert.equal(h.instance.dialogTarget, null);
  assert.equal(h.instance.model().action, "review");
  assert.equal(h.calls.some(call => call.url.endsWith("/install")), false);
});

test("a changed downloaded job invalidates the open installation confirmation", async () => {
  const h = controller(async () => response({...ready, job_id: "d".repeat(32)}));
  h.instance.status = ready;
  h.instance.review();
  await h.instance.confirm();
  assert.equal(h.instance.dialogTarget, null);
  assert.equal(h.instance.watch, null);
  assert.equal(h.calls.some(call => call.url.endsWith("/install")), false);
});

test("installation confirmation waits for current panel operations", async () => {
  let busy = true;
  const h = controller(async () => response(ready), {hostBusy: () => busy});
  h.instance.status = ready;
  h.instance.review();
  assert.equal(h.instance.dialogTarget, null);
  assert.equal(h.instance.model().blocked, true);
  busy = false;
  h.instance.hostChanged();
  assert.equal(h.instance.dialogTarget.job_id, JOB);
  busy = true;
  await h.instance.confirm();
  assert.equal(h.calls.length, 0);
});

test("Later cancels the prompt without sending a request", () => {
  const h = controller(async () => response(ready));
  h.instance.status = ready;
  h.instance.dialogTarget = { job_id: JOB, revision: REVISION, version: "1.0.6" };
  h.instance.cancel();
  assert.equal(h.instance.dialogTarget, null);
  assert.equal(h.calls.length, 0);
});

test("install consent sends the exact captured job once", async () => {
  const h = controller(async url => {
    if (url === "/api/updates") return response(ready);
    if (url === "/api/updates/install") return response({...ready, phase: "installing"});
    throw new Error(`unexpected ${url}`);
  });
  h.instance.status = ready;
  h.instance.dialogTarget = { job_id: JOB, revision: REVISION, version: "1.0.6" };
  await h.instance.confirm();
  const installs = h.calls.filter(call => call.url === "/api/updates/install");
  assert.equal(installs.length, 1);
  assert.deepEqual(JSON.parse(installs[0].options.body), {job_id: JOB, confirm: true});
  assert.equal(h.instance.watch.job_id, JOB);
});

test("CSRF retry is limited to one fresh token", async () => {
  const h = controller(async (url, options, readCookie, setCookie) => {
    if (url === "/api/updates/check") {
      if (options.headers["X-CSRF-Token"] === "old") return response({detail: "CSRF token missing or invalid."}, 403);
      return response({...candidate, phase: "idle", update_available: false});
    }
    if (url === "/auth/csrf") {
      setCookie("psiphon3xui_csrf=new");
      return response({token: "new"});
    }
    throw new Error(`unexpected ${url}`);
  });
  h.instance.cookie = () => "psiphon3xui_csrf=old";
  h.instance.status = {...candidate, phase: "idle", update_available: false};
  await h.instance.check();
  assert.deepEqual(h.calls.map(call => call.url), ["/api/updates/check", "/auth/csrf", "/api/updates/check"]);
});

test("network loss after consent never resends install", async () => {
  const h = controller(async url => {
    if (url === "/api/updates") return response(ready);
    if (url === "/api/updates/install") throw new Error("connection reset");
    throw new Error(`unexpected ${url}`);
  });
  h.instance.status = ready;
  h.instance.dialogTarget = { job_id: JOB, revision: REVISION, version: "1.0.6" };
  await h.instance.confirm();
  assert.equal(h.calls.filter(call => call.url === "/api/updates/install").length, 1);
  assert.equal(h.instance.watch.job_id, JOB);
  await h.instance.refreshNow();
  assert.equal(h.instance.watch, null);
  assert.equal(h.instance.dialogTarget, null);
  assert.equal(h.calls.filter(call => call.url === "/api/updates/install").length, 1);
});

test("reload requires matching server verified identity", () => {
  let reloads = 0;
  const h = controller(async () => response(ready), { reload: () => { reloads += 1; } });
  h.instance.status = {...ready, phase: "succeeded", current_version: "1.0.6", current_revision: REVISION};
  h.instance.watch = {job_id: JOB, revision: REVISION, version: "1.0.6", started: Date.now()};
  h.instance.accept(h.instance.status);
  assert.equal(h.instance.verified, true);
  h.instance.reload();
  assert.equal(reloads, 1);
});

test("recovery guard blocks updates and host mutations until root releases it", async () => {
  const guarded = {...ready, phase: "failed", install_guard: true, error: "Recovery pending"};
  const h = controller(async () => response(guarded));
  h.instance.accept(guarded);
  assert.equal(h.instance.isInstalling(), true);
  assert.equal(h.instance.model().action, "refresh");
  assert.equal(h.instance.model().triggerDisabled, false);
  assert.equal(h.instance.model().triggerLabel, "Refresh status");
  assert.match(h.instance.model().title, /recovery/);
  await h.instance.check();
  await h.instance.perform("download", {revision: REVISION});
  h.instance.review();
  assert.equal(h.instance.dialogTarget, null);
  assert.deepEqual(h.calls.map(call => call.url), ["/api/updates"]);
  h.instance.accept({...guarded, install_guard: false});
  assert.equal(h.instance.isInstalling(), false);
  assert.equal(h.instance.model().action, "check");
  const fresh = controller(async () => response(guarded));
  fresh.instance.accept({...guarded, phase: "idle", error: null});
  assert.equal(fresh.instance.model().visible, true);
  assert.equal(fresh.instance.model().action, "refresh");
});

test("recovery guard invalidates consent and withholds reload", () => {
  let reloads = 0;
  const h = controller(async () => response(ready), {reload: () => { reloads++; }});
  h.instance.accept(ready);
  h.instance.review();
  assert.equal(h.instance.dialogTarget.job_id, JOB);
  h.instance.accept({...ready, install_guard: true});
  assert.equal(h.instance.dialogTarget, null);
  h.instance.accept({...ready, phase: "succeeded", install_guard: true,
    current_version: "1.0.6", current_revision: REVISION});
  h.instance.reload();
  assert.equal(reloads, 0);
  assert.equal(h.instance.verified, false);
});

test("notification reflects configured automatic check cadence", () => {
  const h = controller(async () => response(candidate));
  h.instance.accept(candidate);
  assert.match(h.instance.model().detail, /every 5 minutes/);
  h.instance.accept({...candidate, check_interval_seconds: 0});
  assert.match(h.instance.model().detail, /Automatic update checks are disabled/);
  h.instance.accept({...candidate, check_interval_seconds: 3600});
  assert.match(h.instance.model().detail, /every 1 hour\./);
  h.instance.accept({...candidate, check_interval_seconds: 21600});
  assert.match(h.instance.model().detail, /every 6 hours/);
});

test("successful manual check shows green Up to date for exactly three seconds", async () => {
  const timers = clock();
  const h = controller(async () => response(idle), timers);
  await h.instance.refresh();
  assert.equal(h.instance.model().triggerLabel, "Check for Updates");
  assert.equal(h.instance.notification.current, null);
  await h.instance.check();
  assert.equal(h.instance.model().triggerLabel, "Up to date");
  assert.equal(h.instance.model().triggerState, "current");
  timers.tick(2000);
  await h.instance.refresh();
  timers.tick(999);
  assert.equal(h.instance.model().triggerLabel, "Up to date");
  timers.tick(1);
  assert.equal(h.instance.model().triggerLabel, "Check for Updates");
  assert.equal(h.instance.model().triggerState, "");
  assert.ok(h.instance.notification.current, "bubble has its own four-second lifetime");
  timers.tick(1000);
  assert.equal(h.instance.notification.current, null);
  h.instance.destroy();
  assert.equal(timers.pending(), 0);
});

test("failed or unavailable checks never claim to be up to date", async () => {
  for (const result of [response({detail: "Offline"}, 502),
    response({...idle, supported: false, unsupported_reason: "Unavailable"}),
    response({...idle, phase: "failed", error: "Check failed"})]) {
    const h = controller(async () => result);
    await h.instance.check();
    assert.notEqual(h.instance.model().triggerLabel, "Up to date");
    assert.notEqual(h.instance.model().triggerState, "current");
  }
});

test("a newer available status cancels old green feedback", async () => {
  const timers = clock();
  const h = controller(async () => response(idle), timers);
  await h.instance.check();
  h.instance.accept(candidate);
  h.instance.emit();
  assert.equal(h.instance.model().triggerState, "available");
  assert.equal(h.instance.model().triggerLabel, "Update available");
  timers.tick(3000);
  assert.equal(h.instance.model().triggerState, "available");
  h.instance.destroy();
});

test("callout stays while hovered or focused and expires four seconds after leaving", () => {
  const timers = clock();
  const notice = new Notification(timers);
  notice.show({key: "one", title: "Saved"});
  timers.tick(3999);
  notice.hold("hovered", true);
  timers.tick(10000);
  assert.equal(notice.current.title, "Saved");
  notice.hold("focused", true);
  notice.hold("hovered", false);
  timers.tick(10000);
  assert.ok(notice.current);
  notice.hold("focused", false);
  timers.tick(3999);
  assert.ok(notice.current);
  timers.tick(1);
  assert.equal(notice.current, null);
});

test("cached polls do not revive expired callouts or replace ordinary feedback", async () => {
  const timers = clock();
  const h = controller(async () => response(candidate), timers);
  await h.instance.refresh();
  timers.tick(4000);
  assert.equal(h.instance.notification.current, null);
  await h.instance.refresh();
  assert.equal(h.instance.notification.current, null);
  h.instance.notify("Settings saved", "ok");
  await h.instance.refresh();
  assert.equal(h.instance.notification.current.title, "Settings saved");
  timers.tick(3999);
  assert.ok(h.instance.notification.current);
  timers.tick(1);
  assert.equal(h.instance.notification.current, null);
  await h.instance.refresh();
  assert.equal(h.instance.notification.current, null);
  h.instance.destroy();
});

test("an explicit click shows an expired unsupported or authentication message again", async () => {
  for (const status of [200, 401]) {
    const timers = clock();
    const h = controller(async () => status === 401
      ? response({detail: "Session expired"}, status)
      : response({...idle, supported: false, unsupported_reason: "Unsupported installation"}), timers);
    await h.instance.refresh();
    timers.tick(4000);
    assert.equal(h.instance.notification.current, null);
    await h.instance.activate();
    assert.ok(h.instance.notification.current);
    assert.equal(h.instance.notification.current.signIn, status === 401);
    h.instance.destroy();
  }
});

test("footer keeps recovery and reconnect status accessible after the bubble expires", async () => {
  for (const status of [
    {...ready, phase: "failed", install_guard: true, error: "Recovery pending"},
    {...ready, phase: "downloading"},
    {...ready, phase: "succeeded"},
  ]) {
    const timers = clock();
    const h = controller(async () => response(status), timers);
    h.instance.accept(status);
    if (status.phase === "downloading") h.instance.failure(new Error("Offline"));
    h.instance.emit();
    timers.tick(4000);
    assert.equal(h.instance.notification.current, null);
    assert.equal(h.instance.model().triggerLabel, "Refresh status");
    assert.equal(h.instance.model().triggerDisabled, false);
    await h.instance.activate();
    assert.deepEqual(h.calls.map(call => call.url), ["/api/updates"]);
    h.instance.destroy();
  }
});

test("new feedback replaces the old expiry and repeated feedback restarts its timer", () => {
  const timers = clock();
  const h = controller(async () => response(idle), timers);
  h.instance.notify("First");
  timers.tick(3000);
  h.instance.notify("Second", "warn");
  timers.tick(3000);
  assert.equal(h.instance.notification.current.title, "Second");
  assert.equal(h.instance.notification.current.kind, "warn");
  h.instance.notify("Second", "warn");
  timers.tick(3999);
  assert.ok(h.instance.notification.current);
  timers.tick(1);
  assert.equal(h.instance.notification.current, null);
  h.instance.destroy();
  assert.equal(timers.pending(), 0);
});

test("expired availability callout leaves a yellow footer action that starts downloading", async () => {
  const timers = clock();
  const h = controller(async url => response(url.endsWith("/download")
    ? {...ready, phase: "downloading"} : candidate), timers);
  await h.instance.refresh();
  timers.tick(4000);
  assert.equal(h.instance.notification.current, null);
  assert.equal(h.instance.model().triggerState, "available");
  await h.instance.activate();
  assert.equal(h.instance.model().triggerLabel, "Downloading…");
  assert.equal(h.instance.model().triggerState, "available");
  assert.deepEqual(h.calls.map(call => call.url), ["/api/updates", "/api/updates/download"]);
  h.instance.destroy();
});

test("footer can reopen installation confirmation after Later and callout expiry", async () => {
  const timers = clock();
  const h = controller(async () => response(ready), timers);
  await h.instance.refresh();
  h.instance.review();
  h.instance.cancel();
  timers.tick(4000);
  assert.equal(h.instance.notification.current, null);
  h.instance.activate();
  assert.equal(h.instance.dialogTarget.job_id, JOB);
  assert.equal(h.calls.some(call => call.url.endsWith("/install")), false);
  h.instance.destroy();
});
