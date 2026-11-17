# In-panel updates

## Implementation contract

Updates follow this repository's existing `main` channel. Discovery resolves `DonMonro/psiphon-3x-ui` main to an immutable Git SHA, reads that commit's version, and compares it with the installed version/revision. It never imports fetched Python. Normal installation records the installed SHA. Unknown legacy revisions compare versions; recorded revisions also allow same-version fixes on main. A lower version is never offered. When an installed revision is known, same-version candidates must be verified descendants of that revision so an older/diverged main head is not presented as an upgrade.

The authenticated dashboard and wizard expose a Check for Updates control below the version at the bottom of the page. Clicking it checks and, if needed, downloads the pinned candidate. A speech bubble beside the version offers Download for automatically discovered updates; it stays visible while hovered and disappears after five seconds otherwise. Download completion presents an in-panel confirmation with the exact version. Only an explicit Install action submits installation consent. Closing the prompt leaves the download ready.

A FastAPI lifespan task checks on startup when due and then every five minutes, persisting the last-check time and candidate across panel restarts. The browser polls cached local status; it never schedules upstream checks. All update routes require the current admin session and all POSTs remain under existing CSRF protection.

## Privilege boundary and storage

The panel never runs pip, downloaded shell scripts, or arbitrary systemd commands. A root-owned, standard-library-only helper at `/usr/local/libexec/psiphon-3x-ui/update_panel.py` runs in fixed download/install oneshot services. Polkit permits the panel account only to start those exact two units. Units do not read `panel.env` and run `/usr/bin/python3 -I` from `/`.

- Panel request/cache directory: `<prefix>/updates`, root-owned and panel-group-writable (0770), with the root-owned directory entry protected by the prefix's sticky bit. Panel writes `request.json` atomically.
- Shared operation lock: `/run/psiphon-3x-ui-updater/operation.lock`, within a root-owned 0755 directory. Manual install/uninstall holds flock on FD 9 throughout; helper setup/record accept `--lock-fd 9` to reuse the verified inherited descriptor. Systemd worker invocations acquire this same lock. The update-selected ExecStart override is `/etc/systemd/system/psiphon-3x-ui.service.d/50-panel-update.conf`; manual reinstall removes only this managed override.
- Root workspace: `/var/lib/psiphon-3x-ui-updater`, root-owned and group-readable (0750). Root writes `status.json` and `installed.json` atomically (0640). Archives, staging metadata, and candidate virtualenvs remain root-owned.
- Requests are small bounded JSON objects, never paths, URLs, shell text, or environment. The root helper validates exact fields, UUID/job identity, SHA, version, expected action, and staged identity. All untrusted file opens reject symlinks and nonregular files. Root work paths cannot be group/world writable.
- Download revalidates the requested commit against the fixed repository's main, fetches a SHA-pinned archive over HTTPS from GitHub, validates structure/size/version, and stores a digest plus immutable staging identity. No downloaded code runs during download.
- Install verifies root-owned stage identity and digest, safely extracts regular files/directories only, and builds/installs the panel into a fresh permanent virtualenv before stopping the existing panel. It retains the old virtualenv for rollback, preserves panel.db/panel.env/config/TLS, and restarts only the companion panel. Psiphon core and 3x-ui are separate upstream products and are not upgraded by this button.
- Installation performs a local version/revision health check, restores the previous panel on failure, and writes a durable result. It does not reseed credentials, invoke the interactive full installer, or use panel-controlled environment variables as root. Timeouts and interrupted jobs must become actionable errors, not permanent busy states. A packaged `panel/data/build.json` supplies the installed revision to `/api/health`; both the ordinary installer and staged builder generate it before wheel build. The privileged helper also updates the fixed managed panel unit, cert permission helper/units, updater helper/units, and polkit rule from the authenticated candidate (with backups and rollback); never executes `install.sh`. User configuration and tunnel/3x-ui state are untouched. Boot-time recovery must restore an interrupted activation transaction before the panel starts.

## API contract

Base path `/api/updates`:

- `GET /api/updates`: cached status, no remote lookup.
- `POST /api/updates/check`: check now and queue download when an update exists. Empty JSON body.
- `POST /api/updates/download`: download the currently offered candidate. Body `{ "revision": "<40 hex SHA>" }`; stale candidate requests return 409.
- `POST /api/updates/install`: explicit consent for the exact downloaded job. Body `{ "job_id": "<uuid hex>", "confirm": true }`; missing/false confirmation is refused, stale jobs return 409.

Status shape:

```json
{
  "current_version": "1.0.7",
  "current_revision": null,
  "available_version": null,
  "available_revision": null,
  "phase": "idle",
  "update_available": false,
  "last_checked_at": null,
  "next_check_at": null,
  "check_interval_seconds": 300,
  "job_id": null,
  "install_guard": false,
  "message": "",
  "error": null,
  "supported": true,
  "unsupported_reason": null
}
```

Phases: `idle`, `checking`, `available`, `downloading`, `ready`, `installing`, `succeeded`, `failed`. POST operations return this status (202 while work is queued). A lock prevents concurrent check/download/install requests. A ready job remains pinned until explicitly replaced; the periodic checker cannot replace a staged or installing update. A successful install is shown only after root health verification; browser network loss during restart means reconnecting, not success. A failed enqueue restores an actionable state.

Root request shape: `{ "action": "download|install", "job_id": "<32 lower hex UUID>", "revision": "<40 lower hex SHA>", "version": "<major.minor.patch>" }`. Status includes the same job_id/revision/version plus `phase`, `message`, `error`, and `updated_at` (UTC ISO string). Installed marker: `{ "revision": "<SHA or null>", "version": "<version>" }`.

## Verification

Test semantic ordering, same-version revisions, malformed/unavailable upstream responses, persistence and five-minute scheduling, duplicate actions, authentication/CSRF, explicit/stale confirmation, helper path/URL/archive boundaries, build failure and rollback, restart result reconciliation, and frontend notification/download/confirmation/reconnect behavior. Run repository lint/format/test gates and shellcheck. Exercise dashboard and wizard in the browser using a disposable database and a deterministic update adapter; never install a real update on the development host. Build a wheel and verify bundled update assets.
