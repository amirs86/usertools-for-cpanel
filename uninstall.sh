#!/bin/bash
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# UserTools for cPanel — uninstaller.
#
# Removes the plugin files, the WHM page + AppConfig entry, the hook and the
# CageFS entry. Keeps /var/log/usertools.log and both policy files unless
# --purge is passed. Idempotent: missing pieces are skipped quietly.
#
# Usage (as root): ./uninstall.sh [--purge] [--dry-run] [--yes]
# (Also reachable as ./install.sh --uninstall [--purge] [--dry-run] [--yes].)
#
# Unit tests source this file (main() is NOT run on source). Run:
#   bash tests/test_install.sh
set -u

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared helpers (tool_bin, dest, die, info) live in install.sh; sourcing it
# never runs main (guarded there). Die clearly if it is missing.
# The shared log helpers use USERTOOLS_LOG_PREFIX per call: set it before
# sourcing so every info/die/pass/fail below prints usertools-uninstall.
USERTOOLS_LOG_PREFIX="usertools-uninstall"
if [ -f "$SRC/install.sh" ]; then
    # shellcheck disable=SC1091
    source "$SRC/install.sh"
else
    echo "usertools-uninstall: error: install.sh missing next to uninstall.sh" >&2
    exit 1
fi

remove_path() { # path dry: rm -rf (dry prints only)
    if [ "$2" = "1" ]; then
        echo "dry-run: remove $1"
        return 0
    fi
    if [ -e "$(dest "$1")" ] || [ -L "$(dest "$1")" ]; then
        rm -rf "$(dest "$1")" || { echo "usertools-uninstall: warning: cannot remove $1"; return 1; }
        info "removed $1"
    else
        info "already gone: $1"
    fi
    return 0
}

uninstall_files() { # dry purge: ordered removal + verification rows
    local dry="$1" purge="$2" mh upl unreg restartsrv ctl
    if [ "$dry" = "1" ]; then
        echo "dry-run: manage_hooks delete module UserTools::Hook::AppSetup"
        echo "dry-run: uninstall_plugin <plugin dir> --theme=jupiter"
        echo "dry-run: unregister_appconfig /var/cpanel/apps/usertools.conf"
        echo "dry-run: remove files"
        echo "dry-run: restartsrv_cpsrvd"
        echo "dry-run: remove /etc/cagefs/conf.d/usertools.cfg + cagefsctl --force-update (if present)"
        return 0
    fi
    # 1. Hook deregistration first, while the .pm still exists.
    if mh="$(tool_bin manage_hooks /usr/local/cpanel/bin/manage_hooks)"; then
        "$mh" delete module UserTools::Hook::AppSetup >/dev/null 2>&1 \
            || info "warning: manage_hooks delete failed (run: $mh delete module UserTools::Hook::AppSetup)"
    else
        info "warning: manage_hooks not found (run: /usr/local/cpanel/bin/manage_hooks delete module UserTools::Hook::AppSetup)"
    fi
    # 2. uninstall_plugin while the plugin dir (install.json) still exists.
    # (uninstall_plugin doc: same filepath + --theme form as install.)
    if upl="$(tool_bin uninstall_plugin /usr/local/cpanel/scripts/uninstall_plugin)"; then
        "$upl" "$(dest "$CPANEL/3rdparty/usertools/plugin")" --theme=jupiter >/dev/null 2>&1 \
            || info "warning: uninstall_plugin failed (remove it by hand)"
    else
        info "warning: uninstall_plugin not found (remove it by hand)"
    fi
    # 3. unregister_appconfig with the conf path (it removes the conf itself;
    # the remove below is the safety net).
    if unreg="$(tool_bin unregister_appconfig /usr/local/cpanel/bin/unregister_appconfig)"; then
        "$unreg" "$(dest /var/cpanel/apps/usertools.conf)" >/dev/null 2>&1 \
            || info "warning: unregister_appconfig failed (remove it by hand)"
    else
        info "warning: unregister_appconfig not found (remove it by hand)"
    fi
    # 4. Remove files.
    remove_path /usr/local/cpanel/Cpanel/Admin/Modules/UserTools "$dry"
    remove_path /usr/local/cpanel/Cpanel/API/UserTools.pm "$dry"
    remove_path /usr/local/cpanel/3rdparty/usertools "$dry"
    remove_path /usr/local/cpanel/base/frontend/jupiter/user_tools "$dry"
    remove_path /usr/local/cpanel/whostmgr/docroot/cgi/addon_usertools_settings.cgi "$dry"
    remove_path /usr/local/cpanel/whostmgr/docroot/addon/usertools "$dry"
    remove_path /var/cpanel/apps/usertools.conf "$dry"
    remove_path /var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm "$dry"
    # Only our own entries, and only if empty: never other perl5/lib content.
    rmdir "$(dest /var/cpanel/perl5/lib/UserTools/Hook)" 2>/dev/null || true
    rmdir "$(dest /var/cpanel/perl5/lib/UserTools)" 2>/dev/null || true
    # Log rotation is shipped config: always removed (kept confs/log are the
    # policy files and the audit log itself, not the rotation entry).
    remove_path /etc/logrotate.d/usertools "$dry"
    # Auto-update cron is policy-managed: always removed on uninstall.
    remove_path /etc/cron.d/usertools-update "$dry"
    if [ -e "$(dest /etc/cagefs/conf.d/usertools.cfg)" ]; then
        rm -f "$(dest /etc/cagefs/conf.d/usertools.cfg)" \
            || info "warning: cannot remove CageFS entry"
        if ctl="$(cagefs_bin)"; then
            "$ctl" --force-update >/dev/null 2>&1 \
                || info "warning: cagefsctl --force-update failed (run it by hand)"
        else
            info "warning: cagefsctl not found (CageFS entry removed, update it by hand)"
        fi
    fi
    # 5. cpsrvd restart (AppConfig removal applies on restart).
    if restartsrv="$(tool_bin restartsrv_cpsrvd /usr/local/cpanel/scripts/restartsrv_cpsrvd)"; then
        "$restartsrv" >/dev/null 2>&1 \
            || info "warning: cpsrvd restart failed (entries clear on next restart)"
    else
        info "warning: restartsrv_cpsrvd not found (entries clear on next cpsrvd restart)"
    fi
    if [ "$purge" = "1" ]; then
        remove_path /etc/usertools.conf "$dry"
        remove_path /etc/usertools.private.conf "$dry"
        remove_path /var/log/usertools.log "$dry"
    else
        info "kept /etc/usertools.conf, /etc/usertools.private.conf and /var/log/usertools.log (use --purge to remove)"
    fi
    verify_uninstall
}

verify_uninstall() { # : PASS/FAIL rows; 0 when fully removed
    local fails=0 mh
    if mh="$(tool_bin manage_hooks /usr/local/cpanel/bin/manage_hooks)"; then
        if "$mh" list 2>/dev/null | grep -q 'UserTools::Hook::AppSetup'; then
            echo "usertools-uninstall: [FAIL] hook still registered"; fails=1
        else
            echo "usertools-uninstall: [PASS] hook gone (manage_hooks list)"
        fi
    else
        if [ -e "$(dest /var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm)" ]; then
            echo "usertools-uninstall: [FAIL] hook file remains"; fails=1
        else
            echo "usertools-uninstall: [PASS] hook gone"
        fi
    fi
    if grep -rq 'usertools_' "$(dest "$CPANEL/base/frontend/jupiter/dynamicui/")" 2>/dev/null; then
        echo "usertools-uninstall: [FAIL] plugin features remain in dynamicui"; fails=1
    else
        echo "usertools-uninstall: [PASS] no usertools_ features in dynamicui"
    fi
    if [ -e "$(dest "$CPANEL/base/frontend/jupiter/user_tools/assets")" ]; then
        echo "usertools-uninstall: [FAIL] page assets remain"; fails=1
    else
        echo "usertools-uninstall: [PASS] page assets gone"
    fi
    if [ -e "$(dest /var/cpanel/apps/usertools.conf)" ]; then
        echo "usertools-uninstall: [FAIL] AppConfig remains"; fails=1
    else
        echo "usertools-uninstall: [PASS] AppConfig gone"
    fi
    return "$fails"
}

main() {
    local purge=0 dry=0 yes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --purge) purge=1 ;;
            --dry-run) dry=1 ;;
            --yes) yes=1 ;;
            -h|--help)
                echo "Usage: ./uninstall.sh [--purge] [--dry-run] [--yes]"
                exit 0 ;;
            *) die "unknown option '$1' (see --help)" ;;
        esac
        shift
    done
    if [ "$yes" = "0" ] && [ "$dry" = "0" ]; then
        printf 'usertools-uninstall: remove UserTools from %s? [y/N] ' "$CPANEL"
        read -r answer
        [ "$answer" = "y" ] || [ "$answer" = "Y" ] || die "aborted"
    fi
    uninstall_files "$dry" "$purge" || die "uninstall verification failed"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
