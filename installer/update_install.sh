#!/usr/bin/env bash
# Register the fixed updater using trusted source, under the installer's FD 9 lock.
run_update_install() {
    local helper_src="${SCRIPT_DIR}/installer/update_panel.py"
    local metadata="${SCRIPT_DIR}/panel/data/build.json"
    [[ -s "${helper_src}" && -r "${metadata}" ]] \
        || die "Missing updater source or build metadata."
    # setup creates/validates protected destinations before copying its own code;
    # shell install -d must not follow a panel-precreated inbox symlink.
    ( cd / && /usr/bin/python3 -I "${helper_src}" setup \
        --prefix "${INSTALL_PREFIX}" --user "${PSIPHON3XUI_USER}" \
        --group "${PSIPHON3XUI_GROUP}" --source "${SCRIPT_DIR}" \
        --metadata "${metadata}" --lock-fd 9 ) \
        || die "Could not register the privileged panel updater."
    ok "Privileged staged updater registered."
}
