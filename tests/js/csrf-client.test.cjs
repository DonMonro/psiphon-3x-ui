// Execute the real inline SPA code with a mocked browser/network.
// Uses only Node's standard library (Node 18+); pytest invokes this suite too.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const root = path.resolve(__dirname, "../..");
const csrfError = { detail: "CSRF token missing or invalid." };
const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "Content-Type": "application/json" },
});

function boot(page, cookie = "") {
  const document = { cookie };
  const window = { location: { href: "" } };
  const calls = [];
  let handler = async (url) => { throw new Error(`unexpected request: ${url}`); };
  const context = vm.createContext({
    document, window, Headers, Response, FormData, TextDecoder, console,
    setTimeout: () => 0, clearTimeout: () => {},
    setInterval: () => 0, clearInterval: () => {},
    fetch: async (url, options = {}) => {
      calls.push({ url, options, headers: new Headers(options.headers) });
      return handler(url, options);
    },
  });
  const html = fs.readFileSync(path.join(root, "panel/static", `${page}.html`), "utf8");
  for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
    vm.runInContext(match[1], context, { filename: `${page}.html`, timeout: 1000 });
  }
  const factory = page === "wizard" ? "appWizard" : "appDashboard";
  const app = vm.runInContext(`${factory}()`, context, { timeout: 1000 });
  return { app, document, window, calls, respond: (fn) => { handler = fn; } };
}

for (const page of ["wizard", "dashboard"]) {
  test(`${page}: read the live cookie on every mutation`, async () => {
    const h = boot(page, "other=value;psiphon3xui_csrf=token-a; last=value");
    assert.equal((await h.app._csrfHeaders())["X-CSRF-Token"], "token-a");
    // A login or refresh in another tab changes the shared cookie jar.
    h.document.cookie = "psiphon3xui_csrf=token-b";
    assert.equal((await h.app._csrfHeaders())["X-CSRF-Token"], "token-b");
    assert.equal(h.calls.length, 0);
  });

  test(`${page}: obtain a missing token without caching the endpoint`, async () => {
    const h = boot(page);
    h.respond(async (url, options) => {
      assert.equal(url, "/auth/csrf");
      assert.equal(options.credentials, "same-origin");
      assert.equal(options.cache, "no-store");
      h.document.cookie = "psiphon3xui_csrf=minted-token";
      return jsonResponse({ token: "minted-token" });
    });
    assert.equal((await h.app._csrfHeaders())["X-CSRF-Token"], "minted-token");
    assert.equal((await h.app._csrfHeaders())["X-CSRF-Token"], "minted-token");
    assert.equal(h.calls.length, 1);
  });

  test(`${page}: use the response token when the cookie is unreadable`, async () => {
    const h = boot(page);
    h.respond(async () => jsonResponse({ token: "response-token" }));
    assert.equal((await h.app._csrfHeaders())["X-CSRF-Token"], "response-token");
  });

  test(`${page}: prefer a cookie updated while the response body was read`, async () => {
    const h = boot(page);
    h.respond(async () => {
      const response = jsonResponse({ token: "older-token" });
      response.json = async () => {
        h.document.cookie = "psiphon3xui_csrf=newer-token";
        return { token: "older-token" };
      };
      return response;
    });
    assert.equal((await h.app._csrfHeaders())["X-CSRF-Token"], "newer-token");
  });

  test(`${page}: force a real refresh after a rejected existing cookie`, async () => {
    const h = boot(page, "psiphon3xui_csrf=expired-token");
    h.respond(async (url, options) => {
      if (url === "/auth/csrf") {
        assert.equal(options.cache, "no-store");
        h.document.cookie = "psiphon3xui_csrf=fresh-token";
        return jsonResponse({ token: "fresh-token" });
      }
      const header = new Headers(options.headers).get("X-CSRF-Token");
      return header === "fresh-token" ? jsonResponse({ ok: true }) : jsonResponse(csrfError, 403);
    });
    const response = await h.app._mutatingFetch("/api/mutation", {
      method: "POST",
      headers: await h.app._csrfHeaders(),
      body: "unchanged-body",
    });
    assert.equal(response.status, 200);
    assert.deepEqual(h.calls.map((c) => c.url), ["/api/mutation", "/auth/csrf", "/api/mutation"]);
    assert.equal(h.calls[2].options.body, "unchanged-body");
    assert.equal(h.calls[2].headers.get("X-CSRF-Token"), "fresh-token");
  });

  test(`${page}: recover when the cookie rotates between header creation and POST`, async () => {
    const h = boot(page, "psiphon3xui_csrf=tab-a-token");
    const originalHeaders = await h.app._csrfHeaders();
    h.document.cookie = "psiphon3xui_csrf=tab-b-token";
    h.respond(async (url, options) => {
      if (url === "/auth/csrf") return jsonResponse({ token: "tab-b-token" });
      const header = new Headers(options.headers).get("X-CSRF-Token");
      return header === "tab-b-token" ? jsonResponse({ ok: true }) : jsonResponse(csrfError, 403);
    });
    const response = await h.app._mutatingFetch("/api/mutation", {
      method: "PATCH", headers: originalHeaders,
    });
    assert.equal(response.status, 200);
    assert.equal(h.calls.length, 3);
  });

  test(`${page}: retry at most once`, async () => {
    const h = boot(page, "psiphon3xui_csrf=original-token");
    h.respond(async (url) => {
      if (url === "/auth/csrf") {
        h.document.cookie = "psiphon3xui_csrf=new-token";
        return jsonResponse({ token: "new-token" });
      }
      return jsonResponse(csrfError, 403);
    });
    const response = await h.app._mutatingFetch("/api/mutation", {
      method: "DELETE", headers: await h.app._csrfHeaders(),
    });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), csrfError);
    assert.equal(h.calls.length, 3);
  });

  test(`${page}: never replay unrelated or malformed 403 responses`, async () => {
    for (const body of [
      { detail: "permission denied" }, { detail: "CSRF permission denied" },
      { detail: { reason: "forbidden" } }, { detail: ["forbidden"] }, null,
    ]) {
      const h = boot(page);
      h.respond(async () => jsonResponse(body, 403));
      const response = await h.app._mutatingFetch("/api/mutation", { method: "POST" });
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), body);
      assert.equal(h.calls.length, 1);
    }
    const h = boot(page);
    h.respond(async () => new Response("Forbidden", { status: 403 }));
    const response = await h.app._mutatingFetch("/api/mutation", { method: "POST" });
    assert.equal(await response.text(), "Forbidden");
    assert.equal(h.calls.length, 1);
  });

  test(`${page}: preserve success and non-CSRF statuses without consuming bodies`, async () => {
    for (const status of [200, 400, 401, 409, 422, 500]) {
      const h = boot(page);
      h.respond(async () => jsonResponse({ status }, status));
      const response = await h.app._mutatingFetch("/api/mutation", { method: "POST" });
      assert.equal(response.status, status);
      assert.deepEqual(await response.json(), { status });
      assert.equal(h.calls.length, 1);
    }
  });

  test(`${page}: do not retry safe methods`, async () => {
    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      const h = boot(page);
      h.respond(async () => jsonResponse(csrfError, 403));
      const response = await h.app._mutatingFetch("/api/read", { method });
      assert.equal(response.status, 403);
      assert.equal(h.calls.length, 1);
    }
  });

  test(`${page}: preserve Headers, credentials, signal, and multipart body on retry`, async () => {
    const h = boot(page, "psiphon3xui_csrf=old-token");
    const body = new FormData();
    body.append("file", "backup-data");
    const signal = new AbortController().signal;
    h.respond(async (url, options) => {
      if (url === "/auth/csrf") {
        h.document.cookie = "psiphon3xui_csrf=new-token";
        return jsonResponse({ token: "new-token" });
      }
      return new Headers(options.headers).get("X-CSRF-Token") === "new-token"
        ? jsonResponse({ ok: true }) : jsonResponse(csrfError, 403);
    });
    const originalHeaders = new Headers({ "x-csrf-token": "old-token", "X-Other": "keep" });
    const response = await h.app._mutatingFetch("/api/restore", {
      method: "post", headers: originalHeaders, body, signal, credentials: "same-origin",
    });
    assert.equal(response.status, 200);
    const retry = h.calls[2];
    assert.equal(retry.options.body, body);
    assert.equal(retry.options.signal, signal);
    assert.equal(retry.options.credentials, "same-origin");
    assert.equal(retry.headers.get("X-Other"), "keep");
    assert.equal(retry.headers.get("X-CSRF-Token"), "new-token");
    assert.equal(retry.headers.has("Content-Type"), false);
    assert.equal(originalHeaders.get("X-CSRF-Token"), "old-token");
  });

  test(`${page}: do not send another mutation after a failed refresh`, async () => {
    const h = boot(page, "psiphon3xui_csrf=rejected-token");
    h.respond(async (url) => url === "/auth/csrf"
      ? jsonResponse({ detail: "unavailable" }, 503) : jsonResponse(csrfError, 403));
    await assert.rejects(() => h.app._mutatingFetch("/api/mutation", { method: "POST" }), /503/);
    assert.deepEqual(h.calls.map((c) => c.url), ["/api/mutation", "/auth/csrf"]);
  });

  test(`${page}: redirect on session expiry during refresh, without replay`, async () => {
    const h = boot(page, "psiphon3xui_csrf=rejected-token");
    h.respond(async (url) => url === "/auth/csrf"
      ? jsonResponse({ detail: "not authenticated" }, 401) : jsonResponse(csrfError, 403));
    await assert.rejects(() => h.app._mutatingFetch("/api/mutation", { method: "POST" }), /session expired/);
    assert.equal(h.window.location.href, "/login");
    assert.equal(h.calls.length, 2);
  });

  test(`${page}: do not replay after a network error`, async () => {
    const h = boot(page);
    h.respond(async () => { throw new Error("offline"); });
    await assert.rejects(() => h.app._mutatingFetch("/api/mutation", { method: "POST" }), /offline/);
    assert.equal(h.calls.length, 1);
  });

  test(`${page}: reject an empty token response`, async () => {
    const h = boot(page);
    h.respond(async () => jsonResponse({ token: "" }));
    await assert.rejects(() => h.app._csrfHeaders(), /CSRF token unavailable/);
    assert.equal(h.calls.length, 1);
  });
}

test("wizard: countries submission recovers CSRF and advances exactly once", async () => {
  const h = boot("wizard", "psiphon3xui_csrf=stale-token");
  h.app.form.countries = { mode: "specific", codes: ["US", "GB"] };
  let mutations = 0;
  h.respond(async (url, options) => {
    if (url === "/auth/csrf") {
      h.document.cookie = "psiphon3xui_csrf=valid-token";
      return jsonResponse({ token: "valid-token" });
    }
    assert.equal(url, "/api/wizard/countries");
    assert.equal(options.method, "POST");
    assert.equal(options.credentials, "same-origin");
    assert.deepEqual(JSON.parse(options.body), { mode: "specific", codes: ["US", "GB"] });
    if (new Headers(options.headers).get("X-CSRF-Token") !== "valid-token") {
      return jsonResponse(csrfError, 403);
    }
    mutations += 1;
    return jsonResponse({
      current_step: "ports", is_completed: false, step_index: 1,
      steps: ["countries", "ports"],
      step_data: { countries: { mode: "specific", codes: ["GB", "US"], count: 2 } },
    });
  });
  await h.app.submitCountries();
  assert.equal(h.app.state.current_step, "ports");
  assert.equal(h.app.busy, false);
  assert.equal(h.app.toast.kind, "ok");
  assert.equal(mutations, 1);
  assert.equal(h.calls.length, 3);
});
