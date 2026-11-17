const assert = require("node:assert/strict");
const test = require("node:test");
const { Controller } = require("../../panel/static/assets/updates.js");

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
  assert.equal(h.instance.model().triggerDisabled, true);
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
  h.instance.accept({...candidate, check_interval_seconds: 0});
  assert.match(h.instance.model().detail, /Automatic update checks are disabled/);
  h.instance.accept({...candidate, check_interval_seconds: 3600});
  assert.match(h.instance.model().detail, /every 1 hour\./);
  h.instance.accept({...candidate, check_interval_seconds: 21600});
  assert.match(h.instance.model().detail, /every 6 hours/);
});
