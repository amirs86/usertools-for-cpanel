#!/bin/bash
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# UserTools for cPanel — full installer.
#
# Installs the plugin files, policy files, WHM page, AppConfig entry and the
# account-creation hook on a cPanel server, then prints a verification table
# and a "What's next" box. Idempotent: re-running changes nothing unless
# something is missing (configs are never overwritten; --upgrade only adds
# missing keys).
#
# Usage (as root on the cPanel server):
#   ./install.sh [--upgrade] [--dry-run] [--yes]
#                [--enable-features=LIST]
#   ./install.sh --uninstall [--purge] [--dry-run] [--yes]
#
#   --upgrade          add missing policy keys, refresh all shipped files
#   --dry-run          print what would change, change nothing
#   --yes              non-interactive (no confirmations)
#   --enable-features=LIST
#                      print the exact WHM Feature Manager steps for LIST
#                      (never edits feature lists silently)
#   --uninstall        remove the plugin (delegates to uninstall.sh);
#   --purge            also remove the policy files and the audit log
#
# Pinned installs: fetch a release tarball + .sha256, verify, extract, then
# run ./install.sh (see bootstrap-install.sh and the README one-liner).
#
# Unit tests source this file (main() is NOT run on source) and drive the
# pure functions with USERTOOLS_DESTDIR/USERTOOLS_* overrides. Run:
#   bash tests/test_install.sh
set -u

# Fixed root PATH: sbin dirs included — AlmaLinux does not merge
# /usr/sbin into /usr/bin, and cagefsctl/sshd live there. Fixed, never
# extended from the inherited value (cron and clean-env callers agree).
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPANEL="${USERTOOLS_CPANEL:-/usr/local/cpanel}"
ETC="${USERTOOLS_ETC:-/etc}"

CONF_NAME="usertools.conf"
PRIVATE_NAME="usertools.private.conf"

# Log prefix (uninstall.sh overrides to usertools-uninstall before sourcing;
# expansion happens per call, so tests and callers may set it after sourcing
# too). Default keeps every install message as before.
USERTOOLS_LOG_PREFIX="${USERTOOLS_LOG_PREFIX:-usertools-install}"

die() { echo "$USERTOOLS_LOG_PREFIX: error: $*" >&2; exit 1; }
info() { echo "$USERTOOLS_LOG_PREFIX: $*"; }
pass() { echo "$USERTOOLS_LOG_PREFIX: [PASS] $*"; }
fail() { echo "$USERTOOLS_LOG_PREFIX: [FAIL] $*"; }

# Prefix a system-absolute path with DESTDIR (tests). Evaluated per call
# because tests set USERTOOLS_DESTDIR after sourcing this file.
dest() { # sys-path: effective path
    printf '%s%s' "${USERTOOLS_DESTDIR:-}" "$1"
}

is_root() { [ "$(id -u)" = "0" ]; }

# Parse one effective-config value out of `sshd -T` output (lowercase
# keywords). List keywords join every matching line space-separated; port
# takes the first line (the ssh command needs exactly one port).
sshd_port() { # sshd-T-output: first Port line (one port for the ssh command)
    printf '%s\n' "$1" | awk '$1 == "port" { print $2; exit }'
}
sshd_pick() { # sshd-T-output key: join every matching line space-separated
    printf '%s\n' "$1" | awk -v k="$2" '$1 == k { $1 = ""; sub(/^ /, ""); if (out != "") out = out " "; out = out $0 } END { print out }'
}

# Set one key atomically: write a temp file in the same directory with awk
# (key and value travel as variables, never code, so | & \ * are safe),
# chmod it, then move it into place.
set_key() { # file key value mode
    local dir tmp
    dir="$(dirname "$1")"
    tmp="$(mktemp "$dir/.usertools.XXXXXX")" || die "cannot write in $dir"
    KEY="$2" VALUE="$3" awk '
        BEGIN { done = 0 }
        {
            if (!done && index($0, ENVIRON["KEY"] "=") == 1) {
                print ENVIRON["KEY"] "=" ENVIRON["VALUE"]; done = 1; next
            }
            print
        }
        END { if (!done) print ENVIRON["KEY"] "=" ENVIRON["VALUE"] }
    ' "$1" >"$tmp" 2>/dev/null || [ ! -f "$1" ] || { rm -f "$tmp"; die "cannot update $1"; }
    # A missing source file yields an empty tmp; append path still applies.
    if [ ! -s "$tmp" ]; then
        printf '%s=%s\n' "$2" "$3" >"$tmp" || { rm -f "$tmp"; die "cannot update $1"; }
    fi
    chmod "$4" "$tmp" || { rm -f "$tmp"; die "cannot chmod $tmp"; }
    mv "$tmp" "$1" || { rm -f "$tmp"; die "cannot move $tmp into place"; }
}

# Add a key only when it is missing (upgrades never overwrite values).
ensure_key() { # file key value mode
    if [ -f "$1" ] && grep -q "^$2=" "$1" 2>/dev/null; then
        return 0
    fi
    set_key "$1" "$2" "$3" "$4"
}

write_policy_keys() { # conf private port allowusers allowgroups denyusers denygroups
    set_key "$1" ssh_port "$3" 0644
    set_key "$2" sshd_allowusers "$4" 0600
    set_key "$2" sshd_allowgroups "$5" 0600
    set_key "$2" sshd_denyusers "$6" 0600
    set_key "$2" sshd_denygroups "$7" 0600
}

# --- version + environment -----------------------------------------------------
# cPanel version noodles: "11.134.0.10" or bare "134". Supported: 11.134 LTS+.

version_ok() { # version-string: 0/1 (stdout 1/0)
    local v="$1" a b
    if [[ "$v" =~ ^([0-9]+)\.([0-9]+) ]]; then
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
        if [ "$a" -gt 11 ] || { [ "$a" -eq 11 ] && [ "$b" -ge 134 ]; }; then
            echo 1; return 0
        fi
        echo 0; return 0
    fi
    if [[ "$v" =~ ^([0-9]+)$ ]]; then
        if [ "${BASH_REMATCH[1]}" -ge 134 ]; then echo 1; else echo 0; fi
        return 0
    fi
    echo 0
}

python_ok() { # : 0/1 — python3 present and >= 3.9
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null
}

cagefs_bin() { # : prints the resolved cagefsctl path or nothing
    # Absolute path first (works under env -i / cron minimal PATH and in
    # DESTDIR tests); PATH lookup only as fallback.
    local abs
    abs="$(dest /usr/sbin/cagefsctl)"
    if [ -x "$abs" ] && [ ! -d "$abs" ]; then
        printf '%s' "$abs"; return 0
    fi
    if command -v cagefsctl >/dev/null 2>&1; then
        command -v cagefsctl; return 0
    fi
    return 1
}

cagefs_detected() { # : 0/1 — usable CageFS (binary + marker present)
    cagefs_bin >/dev/null 2>&1 || return 1
    [ -f "$(dest /etc/cagefs/cagefs.mp)" ] || [ -f /etc/cagefs/cagefs.mp ] || return 1
    return 0
}

cagefs_broken() { # : 0 broken / 1 not — marker present but no binary
    # A missing tool must never read as "no CageFS": that would silently
    # skip (and never repair) the entry on a CloudLinux box.
    [ -f "$(dest /etc/cagefs/cagefs.mp)" ] || [ -f /etc/cagefs/cagefs.mp ] || return 1
    cagefs_bin >/dev/null 2>&1 && return 1
    return 0
}

preflight() { # : 0 ok / 1 hard failure (prints a pass/fail table)
    local fails=0
    if [ -n "${USERTOOLS_SKIP_ROOT:-}" ] || is_root; then
        pass "running as root"
    else
        fail "must run as root"; fails=1
    fi
    if [ -x "$(dest "$CPANEL/cpanel")" ] && [ ! -d "$(dest "$CPANEL/cpanel")" ] \
        && [ -d "$(dest "$CPANEL/whostmgr")" ]; then
        pass "cPanel present at $CPANEL"
    else
        fail "cPanel not found at $CPANEL"; fails=1
    fi
    local ver=""
    if [ -f "$(dest "$CPANEL/version")" ]; then
        ver="$(head -n 1 "$(dest "$CPANEL/version")" 2>/dev/null)"
    fi
    if [ "$(version_ok "$ver")" = "1" ]; then
        pass "cPanel version $ver supported"
    else
        fail "cPanel version '${ver:-unknown}' unsupported (need 11.134+)"; fails=1
    fi
    if [ -d "$(dest "$CPANEL/base/frontend/jupiter")" ]; then
        pass "Jupiter theme present"
    else
        fail "Jupiter theme not found"; fails=1
    fi
    if python_ok; then
        pass "python3 >= 3.9 ($(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))'))"
    else
        fail "python3 >= 3.9 required"; fails=1
    fi
    if cagefs_broken; then
        fail "cagefsctl not found but /etc/cagefs/cagefs.mp exists"; fails=1
    elif cagefs_detected; then
        info "CageFS detected (entry will be registered)"
    else
        info "no CageFS (skipping entry)"
    fi
    if [ -f "$(dest /var/cpanel/fileprotect)" ] || [ -f /var/cpanel/fileprotect ]; then
        info "FileProtect is on (installer changes nothing about it)"
    else
        info "FileProtect is off"
    fi
    return "$fails"
}

# --- file manifest ---------------------------------------------------------------
# Each row: source-relative | dest-absolute | mode. Ownership is root:root
# (skipped when not root, e.g. DESTDIR tests).
#
# Page assets ship under BOTH the plain and the .min names (4 rows). The
# page_stylesheets/page_scripts contract is relative to
# /usr/local/cpanel/base/frontend/jupiter/
# (https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-create-a-new-cpanel-interface),
# and on a real 11.138 the Jupiter _assets/master.html.tt asks for the
# minified names (user_tools/assets/usertools.min.css + usertools.min.js) —
# without them the pages load "UserTools failed to load." The .min entries
# are shipped as byte-identical copies of the plain files; keep them in
# sync (tests/test_install.sh compares them).

install_manifest() { # : prints manifest rows
    cat <<'MANIFEST'
admin/Cpanel/Admin/Modules/UserTools/Base.pm|/usr/local/cpanel/Cpanel/Admin/Modules/UserTools/Base.pm|0700
admin/Cpanel/Admin/Modules/UserTools/Shell.pm|/usr/local/cpanel/Cpanel/Admin/Modules/UserTools/Shell.pm|0700
admin/Cpanel/Admin/Modules/UserTools/AppDocroot.pm|/usr/local/cpanel/Cpanel/Admin/Modules/UserTools/AppDocroot.pm|0700
Cpanel/API/UserTools.pm|/usr/local/cpanel/Cpanel/API/UserTools.pm|0644
engine/perm_engine.py|/usr/local/cpanel/3rdparty/usertools/bin/perm_engine.py|0755
engine/recipe_worker.py|/usr/local/cpanel/3rdparty/usertools/bin/recipe_worker.py|0755
VERSION|/usr/local/cpanel/3rdparty/usertools/VERSION|0644
frontend/jupiter/user_tools/fix_home_permissions.html.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/fix_home_permissions.html.tt|0644
frontend/jupiter/user_tools/bulk_permissions.html.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/bulk_permissions.html.tt|0644
frontend/jupiter/user_tools/ownership_report.html.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/ownership_report.html.tt|0644
frontend/jupiter/user_tools/manage_shell.html.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/manage_shell.html.tt|0644
frontend/jupiter/user_tools/app_helper.html.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/app_helper.html.tt|0644
frontend/shared/fix_home_body.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/fix_home_body.tt|0644
frontend/shared/bulk_permissions_body.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/bulk_permissions_body.tt|0644
frontend/shared/ownership_report_body.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/ownership_report_body.tt|0644
frontend/shared/manage_shell_body.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/manage_shell_body.tt|0644
frontend/shared/app_helper_body.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/app_helper_body.tt|0644
frontend/shared/footer.tt|/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/footer.tt|0644
frontend/jupiter/user_tools/assets/usertools.css|/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.css|0644
frontend/jupiter/user_tools/assets/usertools.min.css|/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.min.css|0644
frontend/shared/assets/usertools.js|/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.js|0644
frontend/shared/assets/usertools.min.js|/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.min.js|0644
plugin/install.json|/usr/local/cpanel/3rdparty/usertools/plugin/install.json|0644
whm/cgi/addon_usertools_settings.cgi|/usr/local/cpanel/whostmgr/docroot/cgi/addon_usertools_settings.cgi|0700
whm/views/settings.tt|/usr/local/cpanel/whostmgr/docroot/addon/usertools/settings.tt|0644
hooks/lib/UserTools/Hook/AppSetup.pm|/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm|0644
etc/logrotate.d/usertools|/etc/logrotate.d/usertools|0644
bin/usertools-update|/usr/local/cpanel/3rdparty/usertools/bin/usertools-update|0700
MANIFEST
}

install_icons() { # destdir: copies plugin/icons/* next to install.json
    local plugdir="$1/usr/local/cpanel/3rdparty/usertools/plugin"
    mkdir -p "$plugdir" || return 1
    cp "$SRC"/plugin/icons/*.svg "$plugdir/" || return 1
    chmod 0644 "$plugdir"/*.svg || return 1
    return 0
}

install_one() { # src dest mode dry: copies one file (dry prints only)
    local src="$1" dst
    dst="$(dest "$2")"
    if [ "$4" = "1" ]; then
        echo "dry-run: install $1 -> $2 ($3)"
        return 0
    fi
    [ -f "$SRC/$src" ] || { fail "missing source $src"; return 1; }
    mkdir -p "$(dirname "$dst")" || { fail "cannot mkdir for $2"; return 1; }
    cp "$SRC/$src" "$dst.tmp.$$" || { fail "cannot copy $src"; return 1; }
    chmod "$3" "$dst.tmp.$$" || { rm -f "$dst.tmp.$$"; fail "cannot chmod $2"; return 1; }
    if is_root; then
        chown root:root "$dst.tmp.$$" || { rm -f "$dst.tmp.$$"; fail "cannot chown $2"; return 1; }
    fi
    mv "$dst.tmp.$$" "$dst" || { rm -f "$dst.tmp.$$"; fail "cannot move $2"; return 1; }
    return 0
}

install_files() { # dry: installs the manifest + icons (0 ok)
    local dry="${1:-0}" fails=0 src dst mode
    while IFS='|' read -r src dst mode; do
        [ -n "$src" ] || continue
        install_one "$src" "$dst" "$mode" "$dry" || fails=1
    done < <(install_manifest)
    if [ "$dry" = "1" ]; then
        echo "dry-run: install plugin/icons/*.svg"
    else
        install_icons "${USERTOOLS_DESTDIR:-}" || fails=1
    fi
    return "$fails"
}

install_confs() { # dry upgrade: example confs (never overwrite); upgrade adds missing keys
    local dry="$1" upgrade="$2" conf priv key val
    conf="$(dest "$ETC/$CONF_NAME")"
    priv="$(dest "$ETC/$PRIVATE_NAME")"
    if [ "$dry" = "1" ]; then
        echo "dry-run: ensure $conf (0644) and $priv (0600) from examples"
        return 0
    fi
    mkdir -p "$(dirname "$conf")" || die "cannot mkdir $(dirname "$conf")"
    if [ ! -f "$conf" ]; then
        cp "$SRC/etc/usertools.conf.example" "$conf" || die "cannot write $conf"
        chmod 0644 "$conf" || die "cannot chmod $conf"
        info "created $conf from example"
    fi
    if [ ! -f "$priv" ]; then
        cp "$SRC/etc/usertools.private.conf.example" "$priv" || die "cannot write $priv"
        chmod 0600 "$priv" || die "cannot chmod $priv"
        info "created $priv"
    fi
    if [ "$upgrade" = "1" ]; then
        while IFS= read -r line; do
            case "$line" in
                ''|\;*|\#*|\[* ) ;;
                *=*)
                    key="${line%%=*}"; val="${line#*=}"
                    key="$(printf '%s' "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
                    val="$(printf '%s' "$val" | sed 's/[[:space:]]*[;#].*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
                    [ -n "$key" ] || continue
                    ensure_key "$conf" "$key" "$val" 0644
                    ;;
            esac
        done <"$SRC/etc/usertools.conf.example"
        info "upgrade: missing keys added, existing values kept"
    fi
    return 0
}

# --- server tools ----------------------------------------------------------------------
# cPanel server tools are resolved from their documented absolute path first,
# then PATH (they are not on root's PATH). Every absolute path goes
# through $(dest ...) so DESTDIR tests work.
#
# Paths (cPanel docs):
# - install_plugin: /usr/local/cpanel/scripts/install_plugin
#   (https://docs.cpanel.net/whm/scripts/the-install_plugin-script/):
#   `install_plugin /filepath [--theme=jupiter]`; filepath is an archive
#   (.tar.gz/.bzip2/.zip) or an uncompressed directory; features land in the
#   theme's dynamicui files.
# - register_appconfig: /usr/local/cpanel/bin/register_appconfig
#   (Guide to WHM Plugins - Add Plugins: the script "adds plugin icons to
#   the WHM interface automatically" and configures the ACL).
# - manage_hooks: /usr/local/cpanel/bin/manage_hooks
#   (Guide to Standardized Hooks - The manage_hooks Utility):
#   `manage_hooks add|delete module <Package>` (describe() supplies category,
#   event, stage); `manage_hooks list` shows registered hooks.
# - restartsrv_cpsrvd: /usr/local/cpanel/scripts/restartsrv_cpsrvd
#   (AppConfig applies on cpsrvd restart; services restart docs).

tool_bin() { # name relpath: print resolved path or return 1
    local name="$1" rel="$2" abs
    abs="$(dest "$rel")"
    if [ -x "$abs" ] && [ ! -d "$abs" ]; then
        printf '%s' "$abs"; return 0
    fi
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"; return 0
    fi
    return 1
}

verify_no_cr() { # : PASS/FAIL row, 0 when no installed text file has CR
    local fails=0 src dst f
    while IFS='|' read -r src dst mode; do
        [ -n "$src" ] || continue
        f="$(dest "$dst")"
        if [ -f "$f" ] && grep -q "$(printf '\r')" "$f" 2>/dev/null; then
            fail "CRLF in installed file: $dst"; fails=1
        fi
    done < <(install_manifest)
    for f in "$(dest "$ETC/$CONF_NAME")" "$(dest "$ETC/$PRIVATE_NAME")"; do
        if [ -f "$f" ] && grep -q "$(printf '\r')" "$f" 2>/dev/null; then
            fail "CRLF in installed file: $f"; fails=1
        fi
    done
    if [ "$fails" = "0" ]; then
        pass "no CR in installed text files"
    fi
    return "$fails"
}

hook_registered() { # : 0 registered / 1 not
    local mh
    if mh="$(tool_bin manage_hooks /usr/local/cpanel/bin/manage_hooks)"; then
        "$mh" list 2>/dev/null | grep -q 'UserTools::Hook::AppSetup'
    else
        [ -f "$(dest /var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm)" ]
    fi
}

verify_cgi_executes() { # [perl cgi rundir]: exec row for the installed CGI (0 ok)
    local cperl="${1:-$(dest /usr/local/cpanel/3rdparty/bin/perl)}"
    local cgi="${2:-$(dest "$CPANEL/whostmgr/docroot/cgi/addon_usertools_settings.cgi")}"
    local rundir="${3:-$(dest "$CPANEL/whostmgr/docroot")}"
    case "$cgi" in
        /*) ;;
        *) cgi="$PWD/$cgi" ;;
    esac
    if [ ! -x "$cperl" ] || [ -d "$cperl" ]; then
        info "cpanel perl not present (server-only check skipped)"
        return 0
    fi
    local out
    # `perl -c` ignores the shebang and missed a real exec failure: execute
    # "$cgi" directly so the kernel uses its shebang, just like cpsrvd does
    # (docroot cwd, minimal env), and require both the header and page title.
    # shellcheck disable=SC2086 # USERTOOLS_CGI_ENV holds extra VAR=value words for tests; splitting is intended
    if ! out="$(cd "$rundir" && env -i REMOTE_USER=root REQUEST_METHOD=GET ${USERTOOLS_CGI_ENV:-} "$cgi" 2>&1)"; then
        fail "WHM CGI failed to execute"; return 1
    fi
    if printf '%s' "$out" | grep -q 'Content-type:' \
        && printf '%s' "$out" | grep -q 'UserTools Settings'; then
        pass "WHM CGI executes (header + title)"
    else
        fail "WHM CGI output missing header/title"; return 1
    fi
}

register_plugin() { # dry: install_plugin + AppConfig + hook (warn-only optionals)
    local dry="$1" appconf iplug regapp restartsrv
    appconf="$(dest /var/cpanel/apps/usertools.conf)"
    if [ "$dry" = "1" ]; then
        echo "dry-run: install_plugin <plugin dir> --theme=jupiter; register_appconfig whm/usertools.conf; manage_hooks add module UserTools::Hook::AppSetup"
        return 0
    fi
    if iplug="$(tool_bin install_plugin /usr/local/cpanel/scripts/install_plugin)"; then
        "$iplug" "$(dest "$CPANEL/3rdparty/usertools/plugin")" --theme=jupiter \
            || info "warning: install_plugin failed; fix and re-run, then check the verification table"
    else
        info "warning: install_plugin not found (register the cPanel plugin by hand)"
    fi
    mkdir -p "$(dirname "$appconf")" || die "cannot mkdir $(dirname "$appconf")"
    cp "$SRC/whm/usertools.conf" "$appconf" || die "cannot write $appconf"
    chmod 0644 "$appconf" || die "cannot chmod $appconf"
    if regapp="$(tool_bin register_appconfig /usr/local/cpanel/bin/register_appconfig)"; then
        "$regapp" "$appconf" \
            || info "warning: register_appconfig failed (run it by hand)"
        if restartsrv="$(tool_bin restartsrv_cpsrvd /usr/local/cpanel/scripts/restartsrv_cpsrvd)"; then
            # AppConfig applies on cpsrvd restart (per the WHM plugin docs).
            "$restartsrv" >/dev/null 2>&1 \
                || info "warning: cpsrvd restart failed (WHM page appears after the next restart)"
        else
            info "warning: restartsrv_cpsrvd not found (WHM page appears after the next cpsrvd restart)"
        fi
    else
        info "warning: register_appconfig not found (register the WHM page by hand)"
    fi
    register_hook || true
    return 0
}

register_hook() { # : idempotent module registration (describe() supplies the rest)
    local mh hookpm
    hookpm="UserTools::Hook::AppSetup"
    if ! mh="$(tool_bin manage_hooks /usr/local/cpanel/bin/manage_hooks)"; then
        info "warning: manage_hooks not found (run: /usr/local/cpanel/bin/manage_hooks add module $hookpm)"
        return 0
    fi
    if "$mh" list 2>/dev/null | grep -q "$hookpm"; then
        info "hook already registered (skipping)"
        return 0
    fi
    "$mh" add module "$hookpm" >/dev/null 2>&1 \
        || info "warning: manage_hooks add failed (run: $mh add module $hookpm)"
    return 0
}

cagefs_setup() { # dry: CageFS visibility entry (public paths only, never the private conf)
    # CloudLinux conf.d format is INI: a [section], comment= and a
    # comma-separated paths= list (a bare path list crashes
    # `cagefsctl --force-update` with configparser.MissingSectionHeaderError).
    # See https://docs.cloudlinux.com/cloudlinux_os_components/ and
    # https://cloudlinux.zendesk.com/hc/en-us/articles/4415917359506-How-to-add-third-party-software-into-CageFS
    local dry="$1" cfg ctl
    cfg="$(dest /etc/cagefs/conf.d/usertools.cfg)"
    if cagefs_broken; then
        fail "cagefsctl not found but /etc/cagefs/cagefs.mp exists"
        return 1
    fi
    if ! cagefs_detected; then
        return 0
    fi
    ctl="$(cagefs_bin)" || { fail "cagefsctl not found"; return 1; }
    if [ "$dry" = "1" ]; then
        echo "dry-run: write $cfg and run cagefsctl --force-update"
        return 0
    fi
    mkdir -p "$(dirname "$cfg")" || die "cannot mkdir $(dirname "$cfg")"
    local content tmp
    content="[usertools]
comment=UserTools for cPanel (public paths only; never the private conf)
paths=$CPANEL/3rdparty/usertools/bin/perm_engine.py, $CPANEL/3rdparty/usertools/bin/recipe_worker.py, $CPANEL/3rdparty/usertools/VERSION, $ETC/$CONF_NAME
"
    tmp="$(mktemp "$(dirname "$cfg")/.usertools.XXXXXX")" || die "cannot write in $(dirname "$cfg")"
    printf '%s' "$content" >"$tmp" || { rm -f "$tmp"; die "cannot write $cfg"; }
    # Validate the exact bytes with Python's configparser before installing:
    # a bare path list (or any non-INI content) must fail here, not on the
    # server's `cagefsctl --force-update`.
    if ! command -v python3 >/dev/null 2>&1; then
        rm -f "$tmp"; fail "python3 missing (cannot validate CageFS entry)"; return 1
    fi
    if ! python3 -c 'import configparser,sys; c=configparser.ConfigParser(); c.read(sys.argv[1]); s=c["usertools"]["paths"]' "$tmp" 2>/dev/null; then
        rm -f "$tmp"; fail "CageFS entry failed configparser validation"; return 1
    fi
    chmod 0644 "$tmp" || { rm -f "$tmp"; die "cannot chmod $cfg"; }
    mv "$tmp" "$cfg" || { rm -f "$tmp"; die "cannot move $tmp into place"; }
    if ! "$ctl" --force-update >/dev/null 2>&1; then
        fail "cagefsctl --force-update failed"
        return 1
    fi
    return 0
}

enable_features_help() { # list: print exact WHM steps (never edits silently)
    local list="$1" fpath
    if [[ ! "$list" =~ ^[A-Za-z0-9_.-]+$ ]] || [[ "$list" =~ ^\.+$ ]]; then
        die "invalid feature list name '$list'"
    fi
    fpath="$(dest "/var/cpanel/features/$list")"
    if [ ! -f "$fpath" ]; then
        info "warning: feature list '$list' does not exist on this server"
    fi
    cat <<EOF
usertools-install: to enable the tools for feature list '$list':
  1. WHM >> Home >> Packages >> Feature Manager
  2. Manage feature list '$list'
  3. Tick: usertools_shell usertools_fix_home usertools_bulk_perms
     usertools_ownership_report usertools_app_helper
  4. Save. (Features stay off by default until you do this.)
EOF
}

verify_table() { # : prints PASS/MISSING per installed path + version
    local fails=0 src dst mode eff
    while IFS='|' read -r src dst mode; do
        [ -n "$src" ] || continue
        eff="$(dest "$dst")"
        if [ -f "$eff" ]; then
            if [ "$(stat -c '%a' "$eff")" = "${mode#0}" ] || [ "$(stat -c '%a' "$eff")" = "$mode" ]; then
                pass "$dst ($mode)"
            else
                fail "$dst mode $(stat -c '%a' "$eff") (want $mode)"; fails=1
            fi
        else
            fail "$dst missing"; fails=1
        fi
    done < <(install_manifest)
    if [ -f "$(dest "$ETC/$CONF_NAME")" ]; then
        pass "$ETC/$CONF_NAME present (never overwritten)"
    else
        fail "$ETC/$CONF_NAME missing"; fails=1
    fi
    if grep -rq 'usertools_shell' "$(dest "$CPANEL/base/frontend/jupiter/dynamicui/")" 2>/dev/null; then
        pass "plugin features registered (dynamicui)"
    else
        fail "plugin features not registered"; fails=1
    fi
    if [ -f "$(dest /var/cpanel/apps/usertools.conf)" ]; then
        pass "WHM AppConfig installed"
    else
        fail "WHM AppConfig missing"; fails=1
    fi
    if hook_registered; then
        pass "hook registered"
    else
        fail "hook not registered"; fails=1
    fi
    verify_cgi_executes || fails=1
    verify_no_cr || fails=1
    info "installed version: $(cat "$SRC/VERSION" 2>/dev/null || echo unknown)"
    return "$fails"
}

whats_next() { # : the post-install box
    cat <<'EOF'
usertools-install: What's next
  1. WHM >> Packages >> Feature Manager: tick the 5 usertools_* features
     for the packages that get the tools (off by default), or run:
     ./install.sh --enable-features=LIST
  2. WHM >> Plugins >> UserTools Settings: policy, app packages, updates.
  3. Verify: log in to a test cPanel account on one of those packages and
     open the UserTools pages under Security.
EOF
}

write_sshd_keys() { # : sshd -T probe into both confs (existing behaviour)
    local out port allowusers allowgroups denyusers denygroups conf cur
    command -v sshd >/dev/null 2>&1 || { info "warning: sshd not found (ssh_port left as-is)"; return 0; }
    out="$(sshd -T 2>/dev/null)" || { info "warning: sshd -T failed (ssh_port left as-is)"; return 0; }
    port="$(sshd_port "$out")"
    [ -n "$port" ] || { info "warning: no ssh port found (ssh_port left as-is)"; return 0; }
    allowusers="$(sshd_pick "$out" allowusers)"
    allowgroups="$(sshd_pick "$out" allowgroups)"
    denyusers="$(sshd_pick "$out" denyusers)"
    denygroups="$(sshd_pick "$out" denygroups)"
    conf="$(dest "$ETC/$CONF_NAME")"
    cur=""
    if [ -f "$conf" ]; then
        cur="$(awk -F= '$1 == "ssh_port" { v=$2; sub(/^[ \t]+/, "", v); sub(/[ \t;#].*$/, "", v); print v; exit }' "$conf")"
    fi
    write_policy_keys "$conf" "$(dest "$ETC/$PRIVATE_NAME")" \
        "$port" "$allowusers" "$allowgroups" "$denyusers" "$denygroups"
    # Never print the value itself: only whether it changed.
    if [ "$port" = "$cur" ]; then
        info "ssh_port unchanged"
    else
        info "ssh_port updated"
    fi
    return 0
}

# --- automatic updates cron ---------------------------------------------------------
# /etc/cron.d/usertools-update exists only while auto_update=1.
# Daily at 03:MM with a random minute (spread load); root runs the updater
# with --auto (policy + scope re-read there, never from argv).

update_cron() { # dry: sync the cron file with the auto_update policy
    local dry="$1" conf cron auto minute updater
    conf="$(dest "$ETC/$CONF_NAME")"
    cron="$(dest /etc/cron.d/usertools-update)"
    updater="$(dest "$CPANEL/3rdparty/usertools/bin/usertools-update")"
    if [ "$dry" = "1" ]; then
        echo "dry-run: sync $cron with auto_update policy"
        return 0
    fi
    auto=""
    if [ -f "$conf" ]; then
        auto="$(awk -F= '$1 == "auto_update" { v=$2; sub(/^[ \t]+/, "", v); sub(/[ \t;#].*$/, "", v); print v; exit }' "$conf" 2>/dev/null)"
    fi
    if [ "$auto" = "1" ]; then
        minute=$(( ${RANDOM:-0} % 60 ))
        mkdir -p "$(dirname "$cron")" || die "cannot mkdir $(dirname "$cron")"
        {
            echo "# UserTools for cPanel — automatic updates (managed; change auto_update in $ETC/$CONF_NAME instead)."
            echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            printf '%s %s * * * root %s --auto\n' "$minute" "3" "$updater"
        } >"$cron" || die "cannot write $cron"
        chmod 0644 "$cron" || die "cannot chmod $cron"
        if is_root; then
            chown root:root "$cron" || die "cannot chown $cron"
        fi
        info "auto-update cron installed (daily 03:$(printf '%02d' "$minute"))"
    else
        if [ -e "$cron" ]; then
            rm -f "$cron" || die "cannot remove $cron"
            info "auto-update cron removed (auto_update off)"
        fi
    fi
    return 0
}

# --- installed tarball (rollback source) ----------------------------------------
# Every install saves the tarball it came from as previous/installed.tar.gz
# (0600). The updater moves it to previous/rollback.tar.gz BEFORE installing,
# so --rollback reinstalls the previously installed version, not the one
# just installed. Two sources, in order:
#   1. `git archive` when the tree runs from a git checkout;
#   2. otherwise re-tar the extracted source tree (SRC is the top dir).
# The top directory keeps the release layout (usertools-for-cpanel-vX.Y.Z/)
# so the updater's layout check accepts it.

save_installed_tarball() { # : 0 ok (dry-run handled by caller)
    local prevdir ver top tmp
    prevdir="$(dest "$CPANEL/3rdparty/usertools/previous")"
    mkdir -p "$prevdir" || die "cannot mkdir $prevdir"
    chmod 0700 "$prevdir" || die "cannot chmod $prevdir"
    if [ -f "$SRC/VERSION" ]; then
        ver="$(tr -d ' \t\r\n' <"$SRC/VERSION" 2>/dev/null)"
    else
        ver=""
    fi
    tmp="$(mktemp "$prevdir/.installed.XXXXXX")" || die "cannot write in $prevdir"
    if [ -d "$SRC/.git" ] && command -v git >/dev/null 2>&1; then
        top="usertools-for-cpanel-v${ver}/"
        if git -C "$SRC" archive --format=tar.gz --prefix="$top" HEAD >"$tmp" 2>/dev/null \
            && [ -s "$tmp" ]; then
            chmod 0600 "$tmp" || { rm -f "$tmp"; die "cannot chmod $tmp"; }
            mv "$tmp" "$prevdir/installed.tar.gz" || { rm -f "$tmp"; die "cannot save installed tarball"; }
            chmod 0600 "$prevdir/installed.tar.gz" || die "cannot chmod installed.tar.gz"
            return 0
        fi
        rm -f "$tmp"
        tmp="$(mktemp "$prevdir/.installed.XXXXXX")" || die "cannot write in $prevdir"
    fi
    # Fallback: re-tar the source tree with its directory name as top dir.
    if [ -d "$SRC" ] && [ -f "$SRC/install.sh" ]; then
        if tar -czf "$tmp" -C "$(dirname "$SRC")" "$(basename "$SRC")" 2>/dev/null \
            && [ -s "$tmp" ]; then
            chmod 0600 "$tmp" || { rm -f "$tmp"; die "cannot chmod $tmp"; }
            mv "$tmp" "$prevdir/installed.tar.gz" || { rm -f "$tmp"; die "cannot save installed tarball"; }
            chmod 0600 "$prevdir/installed.tar.gz" || die "cannot chmod installed.tar.gz"
            return 0
        fi
    fi
    rm -f "$tmp"
    die "cannot save installed tarball from $SRC"
}

main() {
    local upgrade=0 dry=0 yes=0 features="" uninstall=0 purge=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --upgrade) upgrade=1 ;;
            --dry-run) dry=1 ;;
            --yes) yes=1 ;;
            --enable-features=*) features="${1#--enable-features=}" ;;
            --enable-features) shift; features="${1:-}"; [ -n "$features" ] || die "--enable-features needs a list name" ;;
            --uninstall) uninstall=1 ;;
            --purge) purge=1 ;;
            -h|--help)
                echo "Usage: ./install.sh [--upgrade] [--dry-run] [--yes] [--enable-features=LIST]"
                echo "       ./install.sh --uninstall [--purge] [--dry-run] [--yes]"
                exit 0 ;;
            *) die "unknown option '$1' (see --help)" ;;
        esac
        shift
    done
    if [ -n "$features" ]; then
        enable_features_help "$features"
    fi
    if [ "$uninstall" = "1" ]; then
        local args=()
        [ "$purge" = "1" ] && args+=(--purge)
        [ "$dry" = "1" ] && args+=(--dry-run)
        [ "$yes" = "1" ] && args+=(--yes)
        exec "$SRC/uninstall.sh" "${args[@]}"
    fi
    if [ "$yes" = "0" ] && [ "$dry" = "0" ]; then
        printf 'usertools-install: install to %s? [y/N] ' "$CPANEL"
        read -r answer
        [ "$answer" = "y" ] || [ "$answer" = "Y" ] || die "aborted"
    fi
    preflight || die "preflight failed; nothing was changed"
    install_files "$dry" || die "file install failed"
    install_confs "$dry" "$upgrade" || die "policy install failed"
    update_cron "$dry" || die "cron update failed"
    if [ "$dry" = "0" ]; then
        write_sshd_keys
        register_plugin "$dry"
        cagefs_setup "$dry" || die "CageFS setup failed"
        verify_table || die "verification failed"
        save_installed_tarball || die "installed tarball save failed"
        whats_next
    else
        info "dry run complete (nothing changed)"
    fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
