/* Shared dashboard/wizard update controls. The server owns the five-minute check;
 * browser polling reads cached status only. No transition grants install consent.
 */
(function (global) {
  "use strict";

  const PHASES = new Set(["idle", "checking", "available", "downloading", "ready", "installing", "succeeded", "failed"]);
  const ACTIVE = new Set(["checking", "downloading", "installing"]);
  const CSRF_REJECTION = "CSRF token missing or invalid.";
  const REVISION = /^[a-f0-9]{40}$/;
  const JOB = /^[a-f0-9]{32}$/;
  const VERSION = /^\d+\.\d+\.\d+$/;

  // One footer callout serves update status and ordinary panel feedback. A
  // repeated cached status must not bring back a callout that already expired.
  class Notification {
    constructor(options = {}) {
      this.setTimer = options.setTimer || global.setTimeout.bind(global);
      this.clearTimer = options.clearTimer || global.clearTimeout.bind(global);
      this.onChange = options.onChange || (() => {});
      this.current = null;
      this.timer = null;
      this.hovered = false;
      this.focused = false;
    }

    show(message) {
      this.current = message;
      this.schedule();
      this.onChange();
    }

    schedule() {
      this.clearTimer(this.timer);
      this.timer = null;
      if (!this.current || this.hovered || this.focused) return;
      this.timer = this.setTimer(() => {
        this.timer = null;
        this.current = null;
        this.hovered = false;
        this.focused = false;
        this.onChange();
      }, 5000);
    }

    hold(source, held) {
      this[source] = held;
      this.schedule();
    }

    destroy() {
      this.clearTimer(this.timer);
      this.current = null;
    }
  }

  class RequestError extends Error {
    constructor(message, status = 0, csrfRejected = false) {
      super(message);
      this.status = status;
      this.csrfRejected = csrfRejected;
    }
  }

  const text = value => typeof value === "string" ? value : "";
  const candidate = status => status && VERSION.test(status.available_version || "")
    && REVISION.test(status.available_revision || "");
  const ready = status => candidate(status) && status.phase === "ready" && JOB.test(status.job_id || "");
  const targetOf = status => ({
    job_id: status.job_id, revision: status.available_revision, version: status.available_version,
  });
  const sameTarget = (status, target) => !!status && !!target && status.job_id === target.job_id
    && status.available_revision === target.revision && status.available_version === target.version;

  class Controller {
    constructor(options = {}) {
      this.fetch = options.fetch || global.fetch.bind(global);
      this.cookie = options.cookie || (() => global.document.cookie);
      this.now = options.now || (() => Date.now());
      this.setTimer = options.setTimer || global.setTimeout.bind(global);
      this.clearTimer = options.clearTimer || global.clearTimeout.bind(global);
      this.reloadPage = options.reload || (() => global.location.reload());
      this.hostBusy = options.hostBusy || (() => false);
      this.canPrompt = options.canPrompt || (() => true);
      this.renderView = options.render || (() => {});
      this.pollDelay = options.pollDelay || 30000;
      this.activeDelay = options.activeDelay || 2000;
      this.requestTimeout = options.requestTimeout || 30000;
      // Match the server's 50-minute installation budget. This is a limit on
      // browser verification, not proof that the root process has stopped.
      this.installTimeout = options.installTimeout || 3000 * 1000;
      this.status = null;
      this.action = "";
      this.error = "";
      this.statusError = false;
      this.authExpired = false;
      this.visible = false;
      this.pendingPrompt = false;
      this.dialogTarget = null;
      this.watch = null;
      this.timedOut = false;
      this.verified = false;
      this.epoch = 0;
      this.polling = false;
      this.timer = null;
      this.destroyed = false;
      this.requests = new Set();
      this.upToDate = false;
      this.feedbackTimer = null;
      this.awaitingCheck = false;
      this.lastUpdateKey = null;
      this.notification = new Notification({
        setTimer: this.setTimer, clearTimer: this.clearTimer, onChange: () => this.emit(),
      });
    }

    emit() {
      if (this.destroyed) return;
      const model = this.model();
      const key = JSON.stringify([model.title, model.detail, model.error, model.blockMessage,
        model.action, model.signIn]);
      if (model.visible && key !== this.lastUpdateKey) {
        this.lastUpdateKey = key;
        this.notification.show({
          key, title: model.title, detail: model.detail, error: model.error,
          blockMessage: model.blockMessage, action: model.action, label: model.label,
          signIn: model.signIn, kind: model.error ? "err" : model.triggerState === "available"
            ? "warn" : this.upToDate || this.verified ? "ok" : "",
        });
      }
      this.renderView(this);
    }

    notify(message, kind = "ok") {
      if (this.destroyed || !text(message)) return;
      this.notification.show({
        key: `notice:${message}`, title: message, detail: "", error: "",
        blockMessage: "", action: "", label: "", signIn: false, kind,
      });
    }

    clearFeedback() {
      this.clearTimer(this.feedbackTimer);
      this.feedbackTimer = null;
      this.upToDate = false;
    }

    isInstalling() {
      return this.action === "install" || !!this.watch || this.status?.phase === "installing"
        || this.status?.install_guard === true;
    }

    busy() {
      return !!this.action || ACTIVE.has(this.status?.phase) || !!this.watch
        || this.status?.install_guard === true;
    }

    async request(path, options = {}) {
      if (this.destroyed) throw new RequestError("Update controls were closed.");
      const abort = new AbortController();
      this.requests.add(abort);
      const timeout = this.setTimer(() => abort.abort(), this.requestTimeout);
      try {
        const response = await this.fetch(path, {
          credentials: "same-origin", cache: "no-store", ...options, signal: abort.signal,
        });
        const raw = await response.text();
        let body;
        try { body = JSON.parse(raw); } catch (_) { body = null; }
        if (!response.ok) {
          const detail = text(body?.detail) || text(body?.message) || `HTTP ${response.status}`;
          throw new RequestError(detail, response.status,
            response.status === 403 && body?.detail === CSRF_REJECTION);
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
          throw new RequestError("The panel returned an unreadable update response.");
        }
        return body;
      } catch (error) {
        if (error.name === "AbortError") throw new RequestError("The request timed out.");
        throw error;
      } finally {
        this.clearTimer(timeout);
        this.requests.delete(abort);
      }
    }

    async csrf(force = false) {
      const read = () => {
        const entry = this.cookie().split(";").map(value => value.trim())
          .find(value => value.startsWith("psiphon3xui_csrf="));
        return entry ? entry.slice("psiphon3xui_csrf=".length) : "";
      };
      let token = force ? "" : read();
      if (!token) {
        const body = await this.request("/auth/csrf");
        token = read() || body.token;
      }
      if (!text(token)) throw new RequestError("CSRF token unavailable. Refresh the page and try again.");
      return token;
    }

    async post(action, body, beforeSend = () => {}) {
      let token = await this.csrf();
      for (let attempt = 0; attempt < 2; attempt++) {
        // Also runs after token refresh: cancelling during preflight must not send consent.
        beforeSend();
        try {
          return await this.request(`/api/updates/${action}`, {
            method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
            body: JSON.stringify(body),
          });
        } catch (error) {
          // Only this exact middleware rejection guarantees no endpoint side effects.
          if (attempt || error.status !== 403 || error.message !== CSRF_REJECTION) throw error;
          token = await this.csrf(true);
        }
      }
    }

    accept(status) {
      if (!status || !PHASES.has(status.phase) || typeof status.supported !== "boolean"
          || typeof status.current_version !== "string" || typeof status.update_available !== "boolean"
          || (["available", "downloading", "ready", "installing"].includes(status.phase) && !candidate(status))
          || (["ready", "installing"].includes(status.phase) && !JOB.test(status.job_id || ""))) {
        throw new RequestError("The panel returned an invalid update status. Refresh status to try again.");
      }
      this.status = status;
      this.statusError = false;
      this.authExpired = false;
      if (status.phase !== "idle") this.clearFeedback();
      if (this.awaitingCheck && status.phase !== "checking") {
        this.awaitingCheck = false;
        if (status.supported && status.phase === "idle" && !status.update_available
            && status.install_guard !== true && !status.error) {
          this.upToDate = true;
          this.feedbackTimer = this.setTimer(() => {
            this.upToDate = false;
            this.feedbackTimer = null;
            this.emit();
          }, 3000);
        }
      }
      if (status.phase !== "idle" || !status.supported || status.install_guard === true) this.visible = true;
      // A failed install enqueue restores the previously ready cache entry.
      // Drop the local restart watch when the server proves that exact job is
      // still ready; never retry consent implicitly. An uncertain dispatch
      // remains installing and continues the reconnecting watch instead.
      if (this.watch && status.phase === "ready" && sameTarget(status, this.watch)) {
        this.watch = null;
        this.timedOut = false;
        this.pendingPrompt = false;
        this.error = text(status.error) || "Installation was not queued. Review the downloaded update before trying again.";
      }
      if (this.dialogTarget && (!ready(status) || !sameTarget(status, this.dialogTarget)
          || !status.supported || status.install_guard === true)) {
        this.cancel();
        this.error = "The downloaded update changed. Review the current version before installing.";
      }
      if (status.phase === "installing" && !this.watch) {
        this.watch = { ...targetOf(status), started: this.now() };
      }
      this.verified = false;
      if (status.phase === "failed") {
        this.watch = null;
        this.timedOut = false;
        this.pendingPrompt = false;
        this.error = text(status.error) || text(status.message) || "The update failed. Check again to retry.";
      } else if (status.phase === "succeeded") {
        // A live connection alone proves nothing. Require the server's durable
        // success and the installed identity; a different job cannot finish ours.
        const target = this.watch || (candidate(status) ? targetOf(status) : null);
        this.verified = status.install_guard !== true && !!target && status.job_id === target.job_id
          && status.current_revision === target.revision && status.current_version === target.version;
        if (this.verified) {
          this.watch = null;
          this.timedOut = false;
          this.pendingPrompt = false;
          this.error = "";
        } else {
          this.error = "The server has not verified this update's installed version and revision. Refresh status before reloading.";
        }
      }
      this.maybePrompt();
    }

    maybePrompt() {
      if (this.pendingPrompt && ready(this.status) && this.status.supported && !this.action
          && !this.isInstalling() && !this.statusError && !this.hostBusy() && this.canPrompt()) {
        this.dialogTarget = targetOf(this.status);
        this.pendingPrompt = false;
      }
    }

    schedule() {
      this.clearTimer(this.timer);
      this.timer = null;
      if (this.destroyed || this.timedOut || this.authExpired) return;
      const active = this.busy() || this.pendingPrompt;
      this.timer = this.setTimer(() => this.refresh(), active ? this.activeDelay : this.pollDelay);
    }

    expired() {
      if (!this.watch || this.now() - this.watch.started < this.installTimeout) return false;
      this.timedOut = true;
      this.error = "Installation has not been verified within 50 minutes. It may still be running. Refresh status before trying another installation.";
      this.visible = true;
      return true;
    }

    failure(error, prefix = "Could not read update status") {
      this.awaitingCheck = false;
      this.clearFeedback();
      this.visible = true;
      this.statusError = true;
      this.authExpired = error.status === 401;
      this.error = this.authExpired ? "Your session expired. Sign in again to manage updates."
        : this.watch ? "Reconnecting to the panel. Installation is not yet verified."
          : `${prefix}: ${error.message || "network unavailable"}`;
    }

    async refresh() {
      if (this.destroyed || this.polling || this.action) return;
      if (this.expired()) { this.emit(); this.schedule(); return; }
      this.polling = true;
      const epoch = this.epoch;
      try {
        const status = await this.request("/api/updates");
        if (epoch !== this.epoch || this.destroyed) return;
        if (this.statusError) this.error = "";
        this.accept(status);
      } catch (error) {
        if (epoch === this.epoch && !this.destroyed) this.failure(error);
      } finally {
        this.polling = false;
        this.expired();
        this.emit();
        this.schedule();
      }
    }

    async refreshNow() {
      // This reads cached status, including after an ambiguous install response.
      this.lastUpdateKey = null;
      this.timedOut = false;
      this.authExpired = false;
      if (this.watch) this.watch.started = this.now();
      return this.refresh();
    }

    async perform(action, body) {
      if (this.destroyed || this.busy()) return;
      // A user can check before the initial cached-status read finishes.
      // The check endpoint validates support and serializes operations itself,
      // so that first click must still issue a check rather than silently return.
      if (this.statusError || this.status?.supported === false
          || (!this.status && action !== "check")) return this.refreshNow();
      this.action = action;
      this.clearFeedback();
      this.awaitingCheck = action === "check";
      this.epoch++;
      this.visible = true;
      this.error = "";
      this.pendingPrompt = true;
      this.clearTimer(this.timer);
      this.emit();
      try {
        this.accept(await this.post(action, body));
        if (this.status.phase === "idle" || this.status.phase === "failed") this.pendingPrompt = false;
      } catch (error) {
        this.pendingPrompt = false;
        this.failure(error, action === "check" ? "Could not check for updates" : "Could not download the update");
        if (error.status === 409) this.error = "The update changed or another operation is active. Refresh status and review it again.";
      } finally {
        this.action = "";
        this.maybePrompt();
        this.emit();
        this.schedule();
      }
    }

    async check() {
      if (this.timedOut || this.statusError || this.status?.supported === false
          || this.status?.install_guard === true) return this.refreshNow();
      if (ready(this.status)) return this.review();
      return this.perform("check", {});
    }

    activate() {
      // Every state remains reachable after its temporary callout disappears.
      if (this.timedOut || this.statusError || this.status?.supported === false
          || this.status?.install_guard === true
          || (this.status?.phase === "succeeded" && !this.verified)) return this.refreshNow();
      if (this.verified) return this.reload();
      if (ready(this.status)) return this.review();
      if (this.status?.phase === "available") return this.download();
      return this.check();
    }

    async download() {
      if (!candidate(this.status) || this.status.phase !== "available") return;
      return this.perform("download", { revision: this.status.available_revision });
    }

    review() {
      if (!ready(this.status) || !this.status.supported || this.busy() || this.statusError) return;
      this.error = "";
      this.lastUpdateKey = null;
      this.pendingPrompt = true;
      this.maybePrompt();
      this.emit();
      this.schedule();
    }

    cancel() {
      this.dialogTarget = null;
      this.pendingPrompt = false;
      this.emit();
    }

    async confirm() {
      const target = this.dialogTarget;
      // The dialog's captured identity is mandatory even for programmatic calls.
      if (!target || this.busy() || this.statusError || !ready(this.status)
          || !this.status.supported || !sameTarget(this.status, target)) return;
      if (this.hostBusy()) { this.emit(); return; }
      this.action = "install";
      this.epoch++;
      this.error = "";
      this.clearTimer(this.timer);
      this.emit();
      let sent = false;
      try {
        // Revalidate staged identity immediately before consent, even if another
        // tab replaced the job since the dialog was opened.
        this.accept(await this.request("/api/updates"));
        if (this.dialogTarget !== target) return;
        const status = await this.post("install", { job_id: target.job_id, confirm: true }, () => {
          if (this.destroyed || (!sent && this.dialogTarget !== target)) throw new RequestError("Installation cancelled.");
          if (this.hostBusy() || !ready(this.status) || !sameTarget(this.status, target) || !this.status.supported) {
            throw new RequestError("Wait for the current panel operation, then review the update again.");
          }
          if (!sent) {
            sent = true;
            this.watch = { ...target, started: this.now() };
            this.cancel();
          }
        });
        this.accept(status);
      } catch (error) {
        // A server/proxy failure may occur after installation was queued.
        // Keep watching on 5xx/network loss; only a fresh status may prove
        // that the exact staged job still needs a new confirmation.
        if (sent && [400, 401, 403, 409, 422].includes(error.status)) {
          this.watch = null;
          this.pendingPrompt = false;
        }
        if (!sent && this.dialogTarget !== target) return;
        this.failure(error, "Could not start installation");
        if (error.status === 409) this.error = "This downloaded job is no longer current. Refresh status and confirm the new job separately.";
      } finally {
        this.action = "";
        this.emit();
        this.schedule();
      }
    }

    reload() {
      if (this.verified && !this.isInstalling() && !this.hostBusy() && !this.statusError) this.reloadPage();
    }

    hostChanged() {
      this.maybePrompt();
      this.emit();
    }

    destroy() {
      this.destroyed = true;
      this.clearTimer(this.timer);
      this.clearFeedback();
      this.notification.destroy();
      for (const request of this.requests) request.abort();
    }

    model() {
      const status = this.status;
      const version = status?.available_version || "";
      const interval = status?.check_interval_seconds ?? 300;
      const cadence = interval === 0 ? "Automatic update checks are disabled."
        : `Automatic update checks run every ${interval % 3600 === 0
          ? `${interval / 3600} ${interval === 3600 ? "hour" : "hours"}`
          : interval % 60 === 0 ? `${interval / 60} ${interval === 60 ? "minute" : "minutes"}`
            : `${interval} ${interval === 1 ? "second" : "seconds"}`}.`;
      let title = "Panel updates";
      let detail = cadence;
      let action = "", label = "";
      if (status?.supported === false) {
        title = "In-panel updates are unavailable";
        detail = text(status.unsupported_reason) || "This installation does not support updates from the panel.";
      } else if (status?.install_guard === true && status.phase !== "installing") {
        title = "Panel update recovery is pending";
        detail = "The installer is still running or recovery needs to finish. Panel changes remain paused. Refresh status; if this persists, check the update service journal.";
        action = "refresh"; label = "Refresh status";
      } else if (this.timedOut) {
        title = "Update result not confirmed";
        detail = "The installation may still be running. Check its status before continuing.";
        action = "refresh"; label = "Refresh status";
      } else if (this.watch || status?.phase === "installing") {
        title = `Installing panel version ${this.watch?.version || version}`;
        detail = "The panel may disconnect while it restarts. Waiting for the server to verify the update.";
      } else if (this.action === "check" || status?.phase === "checking") {
        title = "Checking for a panel update…";
        detail = "If a new version is available, it will download before you choose whether to install it.";
      } else if (this.action === "download" || status?.phase === "downloading") {
        title = version ? `Downloading panel version ${version}…` : "Downloading the panel update…";
        detail = "You will be asked for permission before installation.";
      } else if (status?.phase === "available") {
        title = `Panel version ${version} is available`;
        detail = `Download the update, then choose when to install it. ${cadence}`;
        action = "download"; label = "Download";
      } else if (status?.phase === "ready") {
        title = `Panel version ${version} is ready to install`;
        detail = "The download is saved. Installation starts only after your confirmation.";
        action = "review"; label = "Install…";
      } else if (status?.phase === "succeeded") {
        title = this.verified ? `Panel version ${status.current_version} is installed` : "Checking the installation result";
        detail = this.verified ? "The server verified the update. Reload to use the updated panel." : "Installation is not yet verified.";
        action = this.verified ? "reload" : "refresh"; label = this.verified ? "Reload panel" : "Refresh status";
      } else if (status?.phase === "failed") {
        title = "Panel update failed";
        detail = "Review the error before trying again.";
        action = "check"; label = "Check again";
      } else if (status?.phase === "idle") {
        title = "Your panel is up to date";
        detail = `Installed version ${status.current_version}. ${cadence}`;
      }
      if (this.statusError && !this.watch) { action = "refresh"; label = "Refresh status"; }
      const blocked = (ready(status) || !!this.dialogTarget || this.verified) && this.hostBusy();
      const needsRefresh = this.timedOut || this.statusError || status?.supported === false
        || (status?.install_guard === true && status.phase !== "installing")
        || (status?.phase === "succeeded" && !this.verified);
      let triggerLabel = "Check for Updates", triggerState = "";
      if (needsRefresh) triggerLabel = "Refresh status";
      else {
        if (this.upToDate) { triggerLabel = "Up to date"; triggerState = "current"; }
        else if (this.watch || status?.phase === "installing") triggerLabel = "Installing…";
        else if (this.action === "check" || status?.phase === "checking") triggerLabel = "Checking…";
        else if (this.action === "download" || status?.phase === "downloading") {
          triggerLabel = "Downloading…"; triggerState = "available";
        } else if (status?.phase === "available") {
          triggerLabel = "Update available"; triggerState = "available";
        } else if (status?.phase === "ready") {
          triggerLabel = "Install update…"; triggerState = "available";
        } else if (this.verified) triggerLabel = "Reload panel";
      }
      return {
        title, detail, action, label, blocked, triggerLabel, triggerState,
        visible: this.visible || !!this.error,
        triggerDisabled: !!this.action || (!needsRefresh
          && (status?.install_guard === true || ACTIVE.has(status?.phase) || !!this.watch)),
        actionDisabled: !!this.action || ((action === "review" || action === "reload") && blocked),
        blockMessage: blocked ? "Wait for the current panel operation to finish before installing or reloading." : "",
        error: this.error, signIn: this.authExpired,
      };
    }
  }

  const TEMPLATE = `
    <section class="updates-banner" id="update-notification" data-update-banner hidden aria-label="Panel notification" tabindex="0">
      <div class="updates-copy">
        <div role="status" aria-live="polite" aria-atomic="true">
          <strong data-update-title></strong>
          <p data-update-detail></p>
          <p class="updates-error" data-update-error hidden></p>
          <p class="updates-wait" data-update-wait hidden></p>
        </div>
      </div>
      <div class="updates-actions">
        <a href="/login" data-update-signin hidden>Sign in again</a>
        <button type="button" data-update-primary hidden></button>
      </div>
    </section>
    <dialog class="updates-dialog" id="update-confirm-dialog" aria-labelledby="update-confirm-title"
            aria-describedby="update-confirm-version update-confirm-note update-confirm-error">
      <article>
        <h2 id="update-confirm-title">Install panel update?</h2>
        <p id="update-confirm-version">Install version <strong data-update-version></strong>?</p>
        <p class="updates-revision">Revision <code data-update-revision></code></p>
        <p id="update-confirm-note">The panel will briefly disconnect while it restarts. Your settings,
          admin credentials, tunnels and 3x-ui configuration are preserved. This updates the companion panel only.</p>
        <p class="updates-wait" data-update-dialog-wait hidden></p>
        <p class="updates-error" id="update-confirm-error" data-update-dialog-error role="alert" hidden></p>
        <footer>
          <button type="button" class="secondary" data-update-later autofocus>Later</button>
          <button type="button" data-update-confirm>Install update</button>
        </footer>
      </article>
    </dialog>`;

  function createView(root) {
    const mount = root.querySelector("[data-panel-updates]");
    const trigger = root.querySelector("[data-update-trigger]");
    mount.innerHTML = TEMPLATE;
    const get = name => mount.querySelector(`[data-update-${name}]`);
    const dialog = mount.querySelector("dialog");
    const banner = get("banner");
    const listeners = [];
    const listen = (element, event, handler) => {
      element.addEventListener(event, handler);
      listeners.push(() => element.removeEventListener(event, handler));
    };
    const setText = (element, value) => { if (element.textContent !== value) element.textContent = value; };
    const message = (element, value) => { setText(element, value); element.hidden = !value; };
    let focusBefore = null;
    let controller;
    return {
      bind(value) {
        controller = value;
        trigger.setAttribute("aria-live", "polite");
        listen(trigger, "click", () => controller.activate());
        listen(banner, "mouseenter", () => controller.notification.hold("hovered", true));
        listen(banner, "mouseleave", () => controller.notification.hold("hovered", false));
        listen(banner, "focusin", () => controller.notification.hold("focused",
          banner.matches(":focus-visible") || !!banner.querySelector(":focus-visible")));
        listen(banner, "pointerdown", () => controller.notification.hold("focused", false));
        listen(banner, "focusout", event => {
          if (!banner.contains(event.relatedTarget)) controller.notification.hold("focused", false);
        });
        listen(get("primary"), "click", () => {
          const action = controller.model().action;
          if (action === "refresh") controller.refreshNow();
          else if (["download", "review", "check", "reload"].includes(action)) controller[action]();
        });
        listen(get("later"), "click", () => controller.cancel());
        listen(get("confirm"), "click", () => controller.confirm());
        listen(dialog, "cancel", event => { event.preventDefault(); controller.cancel(); });
        listen(dialog, "close", () => { if (!dialog.open) controller.cancel(); });
      },
      render(value) {
        const model = value.model();
        const notice = value.notification.current;
        banner.hidden = !notice;
        banner.dataset.phase = value.status?.phase || "idle";
        banner.dataset.kind = notice?.kind || "";
        trigger.disabled = model.triggerDisabled;
        trigger.dataset.state = model.triggerState;
        trigger.setAttribute("aria-expanded", notice ? "true" : "false");
        trigger.setAttribute("aria-busy", value.busy() && !value.timedOut ? "true" : "false");
        setText(trigger, model.triggerLabel);
        setText(get("title"), notice?.title || "");
        message(get("detail"), notice?.detail || "");
        message(get("error"), notice?.error || "");
        message(get("wait"), notice?.blockMessage || "");
        get("signin").hidden = !notice?.signIn;
        const primary = get("primary");
        primary.hidden = !notice?.action || notice.signIn;
        primary.disabled = model.actionDisabled;
        setText(primary, notice?.label || "");
        const target = value.dialogTarget;
        message(get("dialog-error"), value.error);
        message(get("dialog-wait"), model.blockMessage);
        get("confirm").disabled = !!value.action || model.blocked || value.statusError;
        get("confirm").setAttribute("aria-busy", value.action === "install" ? "true" : "false");
        if (target) {
          setText(get("version"), target.version);
          setText(get("revision"), target.revision);
          setText(get("confirm"), `Install version ${target.version}`);
          if (!dialog.open) {
            focusBefore = root.ownerDocument.activeElement;
            dialog.showModal();
            get("later").focus();
          }
        } else if (dialog.open) {
          dialog.close();
          const destination = focusBefore?.isConnected && !focusBefore.disabled
            && !focusBefore.closest("[hidden]") ? focusBefore : !trigger.disabled ? trigger : root;
          if (destination === root) root.setAttribute("tabindex", "-1");
          destination.focus({ preventScroll: true });
          focusBefore = null;
        }
      },
      destroy() {
        for (const remove of listeners) remove();
        if (dialog.open) dialog.close();
      },
    };
  }

  const mounted = new WeakMap();
  function mount(host, root, mutations) {
    if (!root || mounted.has(root)) return;
    const view = createView(root);
    let pendingMutations = 0;
    const controller = new Controller({
      hostBusy: () => pendingMutations > 0 || (typeof host.busy === "boolean" ? host.busy
        : Object.values(host.busy || {}).some(Boolean)),
      canPrompt: () => !host.warnModal?.open && !host.ports?.open && !host.ports?.enable_open && !host.reclone?.open,
      render: value => view.render(value),
    });
    view.bind(controller);
    // Track entire handlers, including CSRF lookup and the wizard SSE body.
    // This covers mutations without busy flags and prevents new work during install.
    const originals = new Map();
    for (const name of mutations) {
      const original = host[name];
      originals.set(name, original);
      host[name] = async function (...args) {
        if (controller.isInstalling()) {
          host.notify("Wait for the panel update result before changing settings or tunnels.", "warn");
          return;
        }
        pendingMutations++;
        controller.hostChanged();
        try { return await original.apply(this, args); }
        finally { pendingMutations--; controller.hostChanged(); }
      };
    }
    const onFocus = () => { if (!global.document.hidden && !controller.timedOut) controller.refresh(); };
    global.addEventListener("focus", onFocus);
    global.document.addEventListener("visibilitychange", onFocus);
    mounted.set(root, { controller, cleanup() {
      global.removeEventListener("focus", onFocus);
      global.document.removeEventListener("visibilitychange", onFocus);
      view.destroy();
      for (const [name, original] of originals) host[name] = original;
    } });
    controller.emit();
    controller.refresh();
  }

  function unmount(root) {
    const entry = root && mounted.get(root);
    if (!entry) return;
    entry.controller.destroy();
    entry.cleanup();
    mounted.delete(root);
  }

  function notify(root, message, kind = "ok") {
    const entry = root && mounted.get(root);
    if (entry) entry.controller.notify(message, kind);
  }

  const api = { Controller, Notification, mount, unmount, notify };
  if (typeof module === "object" && module.exports) module.exports = api;
  else global.PanelUpdates = api;
})(typeof window !== "undefined" ? window : globalThis);
