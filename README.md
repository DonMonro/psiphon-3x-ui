# Psiphon-3X-UI

> Per-country egress for [3x-ui](https://github.com/MHSanaei/3x-ui), powered by
> [Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core).

Psiphon-3X-UI installs alongside an existing 3x-ui panel on an Ubuntu server and
gives each country you select its own internet exit. It runs one
`psiphon-tunnel-core` process per country, clones one 3x-ui inbound per country,
and writes the Xray routing that binds them together — so traffic arriving on a
country's inbound egresses in that country.

One install command, one web panel, no manual Xray editing.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](#development)
[![Platform: Ubuntu 20.04+](https://img.shields.io/badge/platform-Ubuntu%2020.04%2B-e95420)](#requirements)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688)](https://fastapi.tiangolo.com/)

---

## How it works

```
client ──► 3x-ui inbound clone [🇺🇸 US]:<public_port> ──► local SOCKS5
             │  Xray routing rule                              │
             │  (inboundTag → outboundTag=psiphon-out-US)       ▼
             └── Xray socks outbound 127.0.0.1:<socks_port>   psiphon-tunnel-core
                   (top-level outbounds[])                  (EgressRegion=US) ──► internet (US exit)
```

Enabling a country creates three things, and the panel keeps all three in sync:

| Layer | Artifact |
| ----- | -------- |
| Psiphon | systemd unit `psiphon-tunnel@<CC>.service`, tunnel-core with `EgressRegion=<CC>`, listening as SOCKS5 on `127.0.0.1:<socks_port>` |
| 3x-ui | a clone of an inbound you choose, on `<public_port>`, remarked `[ 🇺🇸 United States ] :<public_port>` |
| Xray | a `socks` outbound tagged `psiphon-out-<CC>` plus a `routing.rules[]` entry binding the cloned inbound to it |

A SQLite database (`panel.db`) is the source of truth mapping country ↔ port pair
↔ cloned inbound id. 33 Psiphon egress regions ship in
[`panel/data/countries.yaml`](panel/data/countries.yaml) and the list is editable
without code changes.

---

## Requirements

- Ubuntu 20.04+ or 22.04+, x86-64, root access
- Python 3.10+ (3.11 recommended)
- [3x-ui](https://github.com/MHSanaei/3x-ui) installed on the **same host** —
  optional, but required for inbound cloning. Without it the panel still manages
  Psiphon tunnels and exposes local SOCKS5 proxies.
- Outbound internet access. The installer installs a Go toolchain and builds
  `psiphon-tunnel-core` from source (upstream publishes no `linux_amd64` binary;
  nothing is redistributed here).

---

## Install

```bash
sudo bash <(curl -sL https://raw.githubusercontent.com/DonMonro/psiphon-3x-ui/main/install.sh) \
  || sudo bash <(wget -qO- https://raw.githubusercontent.com/DonMonro/psiphon-3x-ui/main/install.sh)
```

If `raw.githubusercontent.com` rate-limits you (bash reports errors like
`429:: command not found`), clone instead — same code, no CDN:

```bash
rm -rf /tmp/p3x && git clone --depth 1 https://github.com/DonMonro/psiphon-3x-ui.git /tmp/p3x && sudo bash /tmp/p3x/install.sh
```

The installer:

1. Installs system dependencies (`python3-venv`, `git`, `golang-go`, `jq`, `curl`, …).
2. Builds `psiphon-tunnel-core` from the pinned upstream tag (`v2.0.39`).
3. Creates the unprivileged `psiphon3xui` user and the `/opt/psiphon-3x-ui` prefix.
4. Prompts for a panel port and admin username/password — type your own, or press
   Enter for a generated value.
5. Registers and starts `psiphon-3x-ui.service`, then prints the URL and
   credentials (also logged to `/opt/psiphon-3x-ui/install.log`).

It does **not** manage a host firewall — open the panel port and your public
inbound ports yourself.

### Upgrading

`install.sh` is idempotent: re-running upgrades the panel in place and preserves
`panel.db` and the session secret, so existing sessions and countries survive.
The installer tracks the `main` branch — push a commit, re-run the installer, and
the change is live. No tag or release step. Override the ref with
`PSIPHON3XUI_REPO_REF=<branch>` for testing.

### Uninstall

```bash
sudo bash <(curl -sL https://raw.githubusercontent.com/DonMonro/psiphon-3x-ui/main/install.sh) --uninstall
```

Type `yes` to confirm. This removes the panel service, the install prefix, and —
in 3x-ui — **only** the inbounds, outbounds, and routing rules this panel
created. Inbounds and outbounds you made yourself are never touched.

---

## First run

Log in at `http://<SERVER_IP>:<PORT>` to enter a seven-step wizard:

| Step | What happens |
| ---- | ------------ |
| 1. Countries | Pick the egress regions to enable. |
| 2. Ports | Accept the recommended SOCKS and public port ranges, or set your own. Already-listening ports and collisions with the panel port are rejected. |
| 3. Apply | Server-sent-events stream: write each country's config, start its systemd unit, probe its SOCKS5 listener. |
| 4. Detect 3x-ui | Auto-probe the local 3x-ui panel, or paste its URL. |
| 5. Credentials | Verify a real login against the 3x-ui API. The password is encrypted at rest. |
| 6. Template | List existing inbounds and choose one to clone. |
| 7. Clone | SSE stream: clone the template once per country and bind the Xray routing. A mid-run failure rolls back the clones already made. |

Finishing the wizard unlocks the management dashboard; the wizard does not
reappear.

---

## Management dashboard

- **Countries** — enable/disable a tunnel, edit its ports, ping it through its own
  SOCKS proxy, re-clone its inbound, tail its journal, or delete it.
- **Re-apply** — rewrite every config, restart every unit, re-clone unhealthy inbounds.
- **Backup / restore** — download a tar archive of `panel.db` plus every per-country
  config, and upload one back (zip-slip protected).
- **Settings** — rotate the admin password (the current one is re-verified first) and
  change the panel port (collision-checked against tunnel ports).

The SPA is plain HTML + Alpine.js + Pico.css served as static files — no build step.

---

## API surface

Every route below except `/api/health`, `/api/countries`, `/api/i18n/{locale}`,
and the auth endpoints requires a signed session cookie. Mutating requests
additionally require the CSRF header. Interactive OpenAPI docs are generated from
the code at `/docs` and are authoritative.

| Verb | Path | Purpose |
| ---- | ---- | ------- |
| GET | `/api/health` | liveness probe |
| GET | `/api/countries` | selectable egress regions |
| GET | `/api/i18n/{locale}` | translation bundle (`en` ships today) |
| POST | `/auth/login` · `/auth/logout` | set / clear session + CSRF cookies (204) |
| GET | `/auth/csrf` | mint or refresh the CSRF cookie |
| GET | `/api/me` | current user + `wizard_completed` |
| GET | `/api/wizard` | current step + step data |
| POST | `/api/wizard/countries` · `/ports` · `/xui-detect` · `/xui-creds` · `/clone-template` | wizard steps 1, 2, 4, 5, 6 |
| POST | `/api/wizard/apply` · `/clone` | wizard steps 3 and 7 (SSE) |
| POST | `/api/wizard/back` | return to the previous step |
| GET | `/api/wizard/inbounds` | list 3x-ui inbounds |
| GET | `/api/dashboard/countries` | country cards |
| PATCH · DELETE | `/api/dashboard/countries/{code}` | enable/disable · teardown |
| POST | `/api/dashboard/countries/{code}/_ping` · `_reclone` · `_ports` | latency probe · re-clone inbound · change ports |
| GET | `/api/dashboard/tunnels/{code}/logs` | journal tail |
| POST | `/api/dashboard/reapply` | rewrite, restart, re-clone unhealthy |
| POST | `/api/dashboard/backup` · `/restore` | tar archive out · in |
| POST | `/api/dashboard/rotate-password` · `/change-panel-port` | credential and port changes |

---

## Security

- **bcrypt** password hashing; the admin password is never stored in plaintext.
- **Signed session cookies** (`itsdangerous`) keyed off a 32-byte secret generated
  at install time and preserved across upgrades. 12-hour TTL.
- **CSRF** signed double-submit cookie, constant-time compared on
  POST/PUT/PATCH/DELETE. The SSE endpoints and the login flow are exempt by
  design (`EventSource` cannot send custom headers).
- **Login rate limiting** — 10 attempts per 60s per IP by default, returning 429
  without burning bcrypt CPU. A successful login clears the bucket.
- **3x-ui credentials encrypted at rest** in `panel.db` with a dedicated salt, so
  the blob cannot be replayed as a session cookie.
- **Password rotation re-verifies the current password**, so a stolen session
  cookie alone cannot take over the account.
- **systemd hardening** — dedicated unprivileged `psiphon3xui` user,
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and only
  the capability needed to bind the chosen port.

**Deploy notes.** The installer binds the panel on `0.0.0.0`, so it is reachable
on every interface as soon as the port is open. Put it behind TLS and restrict
access at the edge. Out of scope for v1: 2FA/WebAuthn, per-device request
signing, IP allowlists.

### HTTPS

The panel serves plain HTTP by default and is not prompted for TLS at install
time. The recommended setup is [Caddy](https://caddyserver.com/) on 443
reverse-proxying to the panel port, which handles Let's Encrypt for you. To
terminate TLS in the panel itself, set `PSIPHON3XUI_TLS_CERT`,
`PSIPHON3XUI_TLS_KEY`, and `PSIPHON3XUI_HTTPS_ONLY=true` in
`/opt/psiphon-3x-ui/panel.env` and restart the service; that also flips the
`Secure` flag on the session and CSRF cookies.

---

## Configuration

Runtime settings live in `panel.config.Settings` (env prefix `PSIPHON3XUI_`).
The installer writes `/opt/psiphon-3x-ui/panel.env`, read by systemd via
`EnvironmentFile=`. Edit it and `systemctl restart psiphon-3x-ui` to apply.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `PSIPHON3XUI_HOST` | `127.0.0.1` in code; installer writes `0.0.0.0` | uvicorn bind host |
| `PSIPHON3XUI_PORT` | `8080` in code; chosen at install | uvicorn bind port |
| `PSIPHON3XUI_SESSION_SECRET` | `dev-only-change-me` | signs session cookies and encrypts stored 3x-ui credentials — **must** be set in production |
| `PSIPHON3XUI_DB_PATH` | `/opt/psiphon-3x-ui/panel.db` | SQLite database |
| `PSIPHON3XUI_PSIPHON_BINARY` | `/opt/psiphon-3x-ui/bin/psiphon-tunnel-core` | binary the per-country units execute |
| `PSIPHON3XUI_PSIPHON_CONFIG_DIR` | `/opt/psiphon-3x-ui/config` | per-country generated configs |
| `PSIPHON3XUI_COUNTRIES_FILE` | packaged `panel/data/countries.yaml` | egress-region list |
| `PSIPHON3XUI_TLS_CERT` / `_TLS_KEY` | unset | panel-terminated TLS |
| `PSIPHON3XUI_HTTPS_ONLY` | `false` | mark cookies `Secure` |
| `PSIPHON3XUI_CSRF_ENFORCE` | `true` | CSRF middleware toggle |
| `PSIPHON3XUI_LOGIN_RATE_LIMIT` / `_LOGIN_RATE_WINDOW` | `10` / `60` | login attempts per window (seconds) |
| `PSIPHON3XUI_DEBUG` | `false` | reload + dev tooling |

`PSIPHON3XUI_SESSION_SECRET` is required by any out-of-band tooling that decrypts
stored credentials — for example `python -m panel.uninstall` must run with
`panel.env` sourced, or the 3x-ui signature check fails and nothing is removed.

### Psiphon upstream values

Per-country tunnels work with no configuration. The upstream fields
tunnel-core needs (`PropagationChannelId`, `SponsorId`, the remote server list
URL and its signature public key, and three modern additional fields) are the
**public bootstrap values shipped inside every public Psiphon client**, baked into
[`panel/psiphon/__init__.py`](panel/psiphon/__init__.py) as `_PUBLIC_*` constants.
They are not commercial secrets.

Commercial Psiphon sponsors whose values differ can override them via
`PSIPHON_PROPAGATION_CHANNEL_ID`, `PSIPHON_SPONSOR_ID`,
`PSIPHON_REMOTE_SERVER_LIST_URL`, and
`PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY` in `panel.env`. An override
that looks like a placeholder (all-`F`s, all-`0`s, a `"..."` stub, a non-base64
key, a non-HTTP URL) is rejected at config-write time with
`PsiphonCredentialError` rather than deathlooping the tunnel. Formats and
rejection rules are in
[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md#psiphon-inc-upstream-credentials--optional-overrides-phase-24).

---

## Development

The panel is cross-platform and testable on any host; the installer and systemd
units are Ubuntu-only.

```bash
pip install -r tests/requirements.txt
pip install -e .

PSIPHON3XUI_SESSION_SECRET=ci-secret pytest tests -ra
ruff check panel tests
ruff format --check panel tests
shellcheck -S warning install.sh installer/*.sh
python -m panel                      # dev server on 127.0.0.1:8080
```

Build the wheel from the **repository root** — `pyproject.toml` lives there and
setuptools resolves `panel/` relative to it:

```bash
python -m build --wheel --outdir dist
```

Run the four gates above before pushing; the installer deploys `main` directly,
so `main` is the release channel.

---

## Documentation

| Document | Contents |
| -------- | -------- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | component map, data flow, per-country routing layer |
| [`docs/XUI_API.md`](docs/XUI_API.md) | the verified 3x-ui API contract and request/response shapes |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | install failure modes, Go-version gotchas, credential overrides |
| [`docs/COUNTRIES.md`](docs/COUNTRIES.md) | editing the egress-region list |
| [`plans/ROADMAP.md`](plans/ROADMAP.md) | phased development history |

---

## License

Released under the [MIT License](LICENSE). Psiphon-3X-UI is an independent
project and is not affiliated with or endorsed by Psiphon Inc. or the 3x-ui
project. It redistributes neither `psiphon-tunnel-core` nor `3x-ui`; see
[`LICENSE`](LICENSE) for the third-party notices.
