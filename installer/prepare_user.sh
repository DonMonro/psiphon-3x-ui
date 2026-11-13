#!/usr/bin/env bash
# ============================================================================
# installer/prepare_user.sh — create the system user/group that owns the install prefix
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_prepare_user().
#
# This is the FIRST runtime step in install.sh (before any helper that needs to
# `chgrp`/`install -g` into ${PSIPHON3XUI_GROUP}). It must never run *after*
# psiphon_install.sh or panel_install.sh, otherwise their `install -g` /
# `chown :group` will fail with "invalid group".
#
# Idempotent: re-running checks `getent group` / `id <user>` first.
# ============================================================================

run_prepare_user() {
    # `${PSIPHON3XUI_USER}` / `${PSIPHON3XUI_GROUP}` are declared in install.sh
    # with defaults of "psiphon3xui".
    info "Ensuring system user/group '${PSIPHON3XUI_USER}'/'${PSIPHON3XUI_GROUP}' …"

    if ! getent group "${PSIPHON3XUI_GROUP}" >/dev/null 2>&1; then
        groupadd --system "${PSIPHON3XUI_GROUP}" \
            || die "groupadd ${PSIPHON3XUI_GROUP} failed."
    fi
    if ! id "${PSIPHON3XUI_USER}" >/dev/null 2>&1; then
        useradd --system --gid "${PSIPHON3XUI_GROUP}" \
            --home-dir "${INSTALL_PREFIX}" --no-create-home \
            --shell /usr/sbin/nologin "${PSIPHON3XUI_USER}" \
            || die "useradd ${PSIPHON3XUI_USER} failed."
    fi

    # Hotfix #10 (Bug #4): add the panel service user to the systemd-journal
    # + adm groups so that the panel's `journalctl -u psiphon-tunnel@<CODE>`
    # calls in panel/dashboard/router.py's _journalctl_lines() don't fail
    # with "No journal files were opened due to insufficient permissions".
    # Without these supplementary groups the operator sees:
    #   logs failed: journalctl failed: journalctl -u psiphon-tunnel@US.service
    #     -> exit 1: ... users in groups 'adm', 'systemd-journal' can see all
    #     messages ... insufficient permissions.
    # `usermod -aG` is idempotent (no-op if already a member). Re-runs of
    # install.sh are safe. The user MUST re-login / the systemd unit MUST be
    # restarted after the group change is baked for membership to take effect
    # — that's handled by the panel-install step's `systemctl restart` at the
    # end of the installer.
    for grp in systemd-journal adm; do
        if getent group "${grp}" >/dev/null 2>&1; then
            usermod --append --groups "${grp}" "${PSIPHON3XUI_USER}" \
                || warn "usermod --groups ${grp} ${PSIPHON3XUI_USER} failed"
        else
            warn "group '${grp}' missing on this host — journalctl may still fail"
        fi
    done

    # Sticky permissions require any live SQLite journals to finish before ownership changes.
    if systemctl cat psiphon-3x-ui.service >/dev/null 2>&1; then
        systemctl stop psiphon-3x-ui.service \
            || die "Could not stop the panel before updating directory permissions."
    fi
    # Setgid keeps service-created SQLite sidecars and tunnel data in the panel group.
    mkdir -p "${CONFIG_DIR}" "${BIN_DIR}" "${VENV_DIR}"
    chown -R root:"${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}" 2>/dev/null || true
    # Sticky protects root-owned TLS directory entries without blocking SQLite sidecars.
    chmod 3775 "${INSTALL_PREFIX}" || die "Could not protect the install prefix."
    chmod 2775 "${CONFIG_DIR}" 2>/dev/null || true
    chmod 0750 "${BIN_DIR}" 2>/dev/null || true

    ok "Service user '${PSIPHON3XUI_USER}' and group '${PSIPHON3XUI_GROUP}' ready."
}
