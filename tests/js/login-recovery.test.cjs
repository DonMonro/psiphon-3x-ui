// Run the real login handlers without a network or external JavaScript packages.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function boot({ clipboard, legacyCopy = false } = {}) {
  const calls = [];
  let selected = null;
  let focused = false;
  const dialog = {
    open: false,
    showModal() { this.open = true; },
    close() { this.open = false; },
    getBoundingClientRect() { return { left: 100, right: 500, top: 100, bottom: 600 }; },
  };
  const selection = { removeAllRanges() {}, addRange(range) { selected = range.element; } };
  const context = vm.createContext({
    navigator: { clipboard },
    window: { getSelection: () => selection },
    document: {
      createRange: () => ({ selectNodeContents(element) { this.element = element; } }),
      execCommand: (name) => { calls.push(name); return legacyCopy; },
    },
    fetch: () => { throw new Error("Recovery help must not contact the server"); },
  });
  const html = fs.readFileSync(path.resolve(__dirname, "../../panel/static/login.html"), "utf8");
  for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
    vm.runInContext(match[1], context, { filename: "login.html", timeout: 1000 });
  }
  const app = vm.runInContext("appLogin()", context);
  app.$refs = { recoveryDialog: dialog, recoveryTrigger: { focus() { focused = true; } } };
  return { app, dialog, calls, selection: () => selected, focused: () => focused };
}

test("recovery help opens modally and restores focus after every native close", () => {
  const h = boot();
  h.app.recoveryMessage = "Previous copy result";
  h.app.openRecovery();
  assert.equal(h.dialog.open, true);
  assert.equal(h.app.recoveryOpen, true);
  assert.equal(h.app.recoveryMessage, "");
  h.app.closeRecovery();
  assert.equal(h.dialog.open, false);
  // The native close event is also fired when Escape dismisses the dialog.
  h.app.onRecoveryClosed();
  assert.equal(h.app.recoveryOpen, false);
  assert.equal(h.focused(), true);
});

test("clicks inside dialog content or padding keep help open; backdrop dismisses", () => {
  const h = boot();
  h.app.openRecovery();
  h.app.closeRecoveryBackdrop({ target: {}, clientX: 10, clientY: 10 });
  assert.equal(h.dialog.open, true);
  h.app.closeRecoveryBackdrop({ target: h.dialog, clientX: 120, clientY: 120 });
  assert.equal(h.dialog.open, true);
  h.app.closeRecoveryBackdrop({ target: h.dialog, clientX: 20, clientY: 120 });
  assert.equal(h.dialog.open, false);
});

test("copy writes the displayed runnable command exactly", async () => {
  let copied;
  const h = boot({ clipboard: { writeText: async (text) => { copied = text; } } });
  const command = "sudo psiphon-3x-ui-admin reset-password --username new-admin";
  await h.app.copyRecoveryCommand({ textContent: command });
  assert.equal(copied, command);
  assert.match(h.app.recoveryMessage, /Command copied/);
  assert.deepEqual(h.calls, []);
});

for (const clipboard of [undefined, { writeText: async () => { throw new Error("denied"); } }]) {
  test(`copy falls back on HTTP or denied permission (${Boolean(clipboard)})`, async () => {
    const h = boot({ clipboard, legacyCopy: true });
    const command = { textContent: "sudo psiphon-3x-ui-admin show-username" };
    await h.app.copyRecoveryCommand(command);
    assert.equal(h.selection(), command);
    assert.deepEqual(h.calls, ["copy"]);
    assert.match(h.app.recoveryMessage, /Command copied/);
  });
}

test("copy never reports success when the browser only allows manual selection", async () => {
  const h = boot();
  const command = { textContent: "sudo psiphon-3x-ui-admin reset-password" };
  await h.app.copyRecoveryCommand(command);
  assert.equal(h.selection(), command);
  assert.match(h.app.recoveryMessage, /Select the command/);
  assert.doesNotMatch(h.app.recoveryMessage, /Command copied/);
});
