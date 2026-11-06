#!/bin/bash
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2016 # fixture scripts below are single-quoted on purpose:
# their $vars must expand when the FIXTURE runs, not when printf writes it.
# Unit tests for install.sh parsing/writing (no root needed: the script is
# sourced, main() is not run). Run:  bash tests/test_install.sh
set -u

here="$(dirname "$0")/.."
# shellcheck disable=SC1091
source "$here/install.sh"
# shellcheck disable=SC1091
source "$here/uninstall.sh"
# shellcheck disable=SC1091
source "$here/bootstrap-install.sh"

fail=0
assert_eq() { # name expected actual
    if [ "$2" = "$3" ]; then
        echo "ok - $1"
    else
        echo "not ok - $1 (expected [$2], got [$3])"
        fail=1
    fi
}

canned="$(printf '%s\n' 'port 2222' 'permitrootlogin no' 'passwordauthentication no' 'allowusers alice bob' 'allowusers carol' 'denygroups bad' 'port 22')"
assert_eq "first port wins" "2222" "$(sshd_port "$canned")"
assert_eq "multi-line allowusers joined" "alice bob carol" "$(sshd_pick "$canned" allowusers)"
assert_eq "denygroups value" "bad" "$(sshd_pick "$canned" denygroups)"
assert_eq "missing key empty" "" "$(sshd_pick "$canned" allowgroups)"

tmp="$(mktemp -d)"
conf="$tmp/usertools.conf"
priv="$tmp/usertools.private.conf"
printf '%s\n' 'enable_shell=1' 'ssh_port=' >"$conf"
: >"$priv"
write_policy_keys "$conf" "$priv" "2222" "alice" "" "" ""
assert_eq "port written" "ssh_port=2222" "$(grep '^ssh_port=' "$conf")"
assert_eq "allowusers in private file" "sshd_allowusers=alice" "$(grep '^sshd_allowusers=' "$priv")"
assert_eq "no names leak to public file" "0" "$(grep -c 'alice' "$conf")"
assert_eq "other keys kept" "enable_shell=1" "$(grep '^enable_shell=' "$conf")"
assert_eq "public mode 644" "644" "$(stat -c '%a' "$conf")"
assert_eq "private mode 600" "600" "$(stat -c '%a' "$priv")"
write_policy_keys "$conf" "$priv" "22" "" "" "" ""
assert_eq "port replaced" "ssh_port=22" "$(grep '^ssh_port=' "$conf")"

# Nasty values round-trip byte-exact (| & \ * user@host).
nasty='a|b&c\d*e?f user@host'
set_key "$priv" sshd_allowusers "$nasty" 0600
assert_eq "nasty value round-trips" "sshd_allowusers=$nasty" "$(grep '^sshd_allowusers=' "$priv")"
set_key "$priv" sshd_allowusers "plain" 0600
assert_eq "nasty value replaced" "sshd_allowusers=plain" "$(grep '^sshd_allowusers=' "$priv")"
assert_eq "single allowusers line" "1" "$(grep -c '^sshd_allowusers=' "$priv")"

# Missing file: created with content.
rm -f "$tmp/new.conf"
set_key "$tmp/new.conf" ssh_port "2222" 0644
assert_eq "created file content" "ssh_port=2222" "$(cat "$tmp/new.conf")"
rm -rf "$tmp"

# --- tool lookup: absolute path first, then PATH ----------------------------------------
tbdir="$(mktemp -d)"
mkdir -p "$tbdir/usr/local/cpanel/bin"
printf '#!/bin/sh\necho ABS\n' >"$tbdir/usr/local/cpanel/bin/faketool"
chmod +x "$tbdir/usr/local/cpanel/bin/faketool"
assert_eq "absolute path wins" "$tbdir/usr/local/cpanel/bin/faketool" \
    "$(USERTOOLS_DESTDIR="$tbdir" PATH=/usr/bin:/bin tool_bin faketool /usr/local/cpanel/bin/faketool)"
pdir2="$(mktemp -d)"
printf '#!/bin/sh\necho PATH\n' >"$pdir2/faketool"
chmod +x "$pdir2/faketool"
assert_eq "PATH fallback works" "$pdir2/faketool" \
    "$(USERTOOLS_DESTDIR="$tbdir" PATH="$pdir2:/usr/bin:/bin" tool_bin faketool /usr/local/cpanel/bin/missing)"
assert_eq "missing tool fails" "1" \
    "$(USERTOOLS_DESTDIR="$tbdir" PATH=/usr/bin:/bin tool_bin faketool /usr/local/cpanel/bin/missing >/dev/null; echo $?)"
rm -rf "$tbdir" "$pdir2"

# --- version gate ------------------------------------------------------------
assert_eq "11.138 ok" "1" "$(version_ok '11.138.0.10')"
assert_eq "11.140 ok" "1" "$(version_ok '11.140.0.1')"
assert_eq "11.134 LTS ok" "1" "$(version_ok '11.134.0.67')"
assert_eq "bare 138 ok" "1" "$(version_ok '138')"
assert_eq "bare 134 ok" "1" "$(version_ok '134')"
assert_eq "11.132 refused" "0" "$(version_ok '11.132.0.1')"
assert_eq "11.110 refused" "0" "$(version_ok '11.110.0.5')"
assert_eq "garbage refused" "0" "$(version_ok 'nope')"
assert_eq "empty refused" "0" "$(version_ok '')"

# --- auto-update cron follows the policy -------------------------------------------
cdir="$(mktemp -d)"
mkdir -p "$cdir/etc"
printf '%s\n' 'auto_update=1' >"$cdir/etc/usertools.conf"
USERTOOLS_DESTDIR="$cdir" USERTOOLS_ETC="/etc" USERTOOLS_CPANEL="/usr/local/cpanel" update_cron 0 >/dev/null
assert_eq "cron installed when on" "1" "$([ -f "$cdir/etc/cron.d/usertools-update" ] && echo 1 || echo 0)"
assert_eq "cron mode 644" "644" "$(stat -c '%a' "$cdir/etc/cron.d/usertools-update")"
assert_eq "cron calls updater --auto" "1" "$(grep -q -- '--auto' "$cdir/etc/cron.d/usertools-update" && echo 1 || echo 0)"
assert_eq "cron daily 03 hour" "1" "$(grep -qE '^[0-9]+ 3 \* \* \* root ' "$cdir/etc/cron.d/usertools-update" && echo 1 || echo 0)"
assert_eq "cron fixed PATH line" "1" "$(grep -q '^PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin$' "$cdir/etc/cron.d/usertools-update" && echo 1 || echo 0)"
assert_eq "cron minute in range" "1" "$(grep -qE '^([0-9]|[1-5][0-9]) 3 ' "$cdir/etc/cron.d/usertools-update" && echo 1 || echo 0)"
printf '%s\n' 'auto_update=0' >"$cdir/etc/usertools.conf"
USERTOOLS_DESTDIR="$cdir" USERTOOLS_ETC="/etc" USERTOOLS_CPANEL="/usr/local/cpanel" update_cron 0 >/dev/null
assert_eq "cron removed when off" "0" "$([ -e "$cdir/etc/cron.d/usertools-update" ] && echo 1 || echo 0)"
out="$(USERTOOLS_DESTDIR="$cdir" update_cron 1)"
assert_eq "dry-run prints sync" "1" "$(printf '%s' "$out" | grep -q 'dry-run: sync' && echo 1 || echo 0)"
rm -rf "$cdir"

# --- upgrade only adds missing keys ------------------------------------------
tmp="$(mktemp -d)"
conf="$tmp/usertools.conf"
printf '%s\n' 'enable_shell=0' 'ssh_port=22' >"$conf"
ensure_key "$conf" enable_shell "1" 0644
assert_eq "existing value kept" "enable_shell=0" "$(grep '^enable_shell=' "$conf")"
ensure_key "$conf" enable_app_helper "1" 0644
assert_eq "missing key added" "enable_app_helper=1" "$(grep '^enable_app_helper=' "$conf")"
rm -rf "$tmp"

# --- full file install into DESTDIR -------------------------------------------
destd="$(mktemp -d)"
USERTOOLS_DESTDIR="$destd" install_files 0 >/dev/null
assert_eq "admin module installed" "1" "$([ -f "$destd/usr/local/cpanel/Cpanel/Admin/Modules/UserTools/Shell.pm" ] && echo 1 || echo 0)"
assert_eq "admin mode 700" "700" "$(stat -c '%a' "$destd/usr/local/cpanel/Cpanel/Admin/Modules/UserTools/Shell.pm")"
assert_eq "uapi mode 644" "644" "$(stat -c '%a' "$destd/usr/local/cpanel/Cpanel/API/UserTools.pm")"
assert_eq "engine mode 755" "755" "$(stat -c '%a' "$destd/usr/local/cpanel/3rdparty/usertools/bin/perm_engine.py")"
assert_eq "space engine installed" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/bin/space_cleaner.py" ] && echo 1 || echo 0)"
assert_eq "space engine mode 755" "755" "$(stat -c '%a' "$destd/usr/local/cpanel/3rdparty/usertools/bin/space_cleaner.py")"
assert_eq "site engine installed" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/bin/site_doctor.py" ] && echo 1 || echo 0)"
assert_eq "site engine mode 755" "755" "$(stat -c '%a' "$destd/usr/local/cpanel/3rdparty/usertools/bin/site_doctor.py")"
assert_eq "recipe worker mode 755" "755" "$(stat -c '%a' "$destd/usr/local/cpanel/3rdparty/usertools/bin/recipe_worker.py")"
assert_eq "jupiter adapter installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/app_helper.html.tt" ] && echo 1 || echo 0)"
assert_eq "shared body staged" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/app_helper_body.tt" ] && echo 1 || echo 0)"
assert_eq "space adapter installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/space_cleaner.html.tt" ] && echo 1 || echo 0)"
assert_eq "space body staged" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/space_cleaner_body.tt" ] && echo 1 || echo 0)"
assert_eq "doctor adapter installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/site_doctor.html.tt" ] && echo 1 || echo 0)"
assert_eq "doctor body staged" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/site_doctor_body.tt" ] && echo 1 || echo 0)"
assert_eq "exposed adapter installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/exposed_files.html.tt" ] && echo 1 || echo 0)"
assert_eq "exposed body staged" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/exposed_files_body.tt" ] && echo 1 || echo 0)"
assert_eq "cron adapter installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/cron_doctor.html.tt" ] && echo 1 || echo 0)"
assert_eq "cron body staged" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/cron_doctor_body.tt" ] && echo 1 || echo 0)"
assert_eq "activity adapter installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/activity.html.tt" ] && echo 1 || echo 0)"
assert_eq "activity body staged" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/shared/activity_body.tt" ] && echo 1 || echo 0)"
assert_eq "whm cgi mode 700" "700" "$(stat -c '%a' "$destd/usr/local/cpanel/whostmgr/docroot/cgi/addon_usertools_settings.cgi")"
assert_eq "hook installed" "1" "$([ -f "$destd/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm" ] && echo 1 || echo 0)"
assert_eq "hook mode 644" "644" "$(stat -c '%a' "$destd/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm")"
assert_eq "updater installed" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/bin/usertools-update" ] && echo 1 || echo 0)"
assert_eq "updater mode 700" "700" "$(stat -c '%a' "$destd/usr/local/cpanel/3rdparty/usertools/bin/usertools-update")"
assert_eq "logrotate installed" "1" "$([ -f "$destd/etc/logrotate.d/usertools" ] && echo 1 || echo 0)"
assert_eq "logrotate mode 644" "644" "$(stat -c '%a' "$destd/etc/logrotate.d/usertools")"
assert_eq "logrotate weekly" "1" "$(grep -q '^    weekly$' "$destd/etc/logrotate.d/usertools" && echo 1 || echo 0)"
assert_eq "logrotate rotate 12" "1" "$(grep -q '^    rotate 12$' "$destd/etc/logrotate.d/usertools" && echo 1 || echo 0)"
assert_eq "logrotate create 0600" "1" "$(grep -q '^    create 0600 root root$' "$destd/etc/logrotate.d/usertools" && echo 1 || echo 0)"
assert_eq "icons staged" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/plugin/app_helper.svg" ] && echo 1 || echo 0)"
assert_eq "space icon staged" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/plugin/space_cleaner.svg" ] && echo 1 || echo 0)"
assert_eq "doctor icon staged" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/plugin/site_doctor.svg" ] && echo 1 || echo 0)"
assert_eq "exposed icon staged" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/plugin/exposed_files.svg" ] && echo 1 || echo 0)"
assert_eq "cron icon staged" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/plugin/cron_doctor.svg" ] && echo 1 || echo 0)"
assert_eq "activity icon staged" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/plugin/activity.svg" ] && echo 1 || echo 0)"
assert_eq "page css installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.css" ] && echo 1 || echo 0)"
assert_eq "page min css installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.min.css" ] && echo 1 || echo 0)"
assert_eq "page js installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.js" ] && echo 1 || echo 0)"
assert_eq "page min js installed" "1" "$([ -f "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.min.js" ] && echo 1 || echo 0)"
assert_eq "page css mode 644" "644" "$(stat -c '%a' "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.css")"
assert_eq "page min css mode 644" "644" "$(stat -c '%a' "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.min.css")"
assert_eq "page js mode 644" "644" "$(stat -c '%a' "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.js")"
assert_eq "page min js mode 644" "644" "$(stat -c '%a' "$destd/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.min.js")"
assert_eq "manifest has all 4 asset rows" "4" "$(install_manifest | grep -c 'user_tools/assets/usertools')"
assert_eq "min css matches plain css" "1" "$(cmp -s "$here/frontend/jupiter/user_tools/assets/usertools.css" "$here/frontend/jupiter/user_tools/assets/usertools.min.css" && echo 1 || echo 0)"
assert_eq "min js matches plain js" "1" "$(cmp -s "$here/frontend/shared/assets/usertools.js" "$here/frontend/shared/assets/usertools.min.js" && echo 1 || echo 0)"

# --- confs: never overwrite; upgrade merges ------------------------------------
USERTOOLS_DESTDIR="$destd" USERTOOLS_ETC="/etc" install_confs 0 0 >/dev/null
assert_eq "conf created" "1" "$([ -f "$destd/etc/usertools.conf" ] && echo 1 || echo 0)"
assert_eq "conf mode 644" "644" "$(stat -c '%a' "$destd/etc/usertools.conf")"
assert_eq "private mode 600" "600" "$(stat -c '%a' "$destd/etc/usertools.private.conf")"
assert_eq "update_repo prefilled" "1" "$(grep -q '^update_repo=amirs86/usertools-for-cpanel' "$destd/etc/usertools.conf" && echo 1 || echo 0)"
for key in enable_shell enable_fix_home enable_bulk_perms enable_ownership_report \
    enable_app_helper enable_space_cleaner enable_site_doctor enable_exposed_files \
    enable_cron_doctor; do
    want="$(grep -E "^$key=" "$here/etc/usertools.conf.example" | head -n 1 | cut -d= -f2 | sed 's/[[:space:]]*[;#].*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
    got="$(grep -E "^$key=" "$destd/etc/usertools.conf" | head -n 1 | cut -d= -f2 | sed 's/[[:space:]]*[;#].*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
    assert_eq "fresh $key matches example" "$want" "$got"
    assert_eq "fresh $key is off" "0" "$got"
done
assert_eq "all nine tool keys off" "0" \
    "$(grep -E '^enable_(shell|fix_home|bulk_perms|ownership_report|app_helper|space_cleaner|site_doctor|exposed_files|cron_doctor)=' "$destd/etc/usertools.conf" | grep -vc '=0')"

# --- confs: re-run and upgrade ------------------------------------------------------
printf '%s\n' 'enable_app_helper=1' >>"$destd/etc/usertools.conf"
USERTOOLS_DESTDIR="$destd" USERTOOLS_ETC="/etc" install_confs 0 0 >/dev/null
assert_eq "re-run keeps single copy" "1" "$(grep -c '^enable_shell=' "$destd/etc/usertools.conf")"
printf 'ssh_port=9999\n' >"$destd/etc/usertools.conf"
printf 'update_repo=custom/repo\n' >>"$destd/etc/usertools.conf"
USERTOOLS_DESTDIR="$destd" USERTOOLS_ETC="/etc" install_confs 0 1 >/dev/null
assert_eq "upgrade keeps ssh_port" "ssh_port=9999" "$(grep '^ssh_port=' "$destd/etc/usertools.conf")"
assert_eq "upgrade adds keys" "1" "$(grep -c '^enable_shell=' "$destd/etc/usertools.conf")"
assert_eq "upgrade keeps update_repo" "1" "$(grep -q '^update_repo=custom/repo$' "$destd/etc/usertools.conf" && echo 1 || echo 0)"

# --- upgrade keeps switches, adds missing at 0, and notices the on tools ---
upd="$(mktemp -d)"
mkdir -p "$upd/etc"
printf '%s\n' 'enable_shell=1' 'enable_fix_home=0' >"$upd/etc/usertools.conf"
out="$(USERTOOLS_DESTDIR="$upd" USERTOOLS_ETC="/etc" install_confs 0 1)"
assert_eq "upgrade keeps on value" "1" "$(grep -q '^enable_shell=1$' "$upd/etc/usertools.conf" && echo 1 || echo 0)"
assert_eq "upgrade keeps off value" "1" "$(grep -q '^enable_fix_home=0$' "$upd/etc/usertools.conf" && echo 1 || echo 0)"
assert_eq "upgrade adds missing at 0" "1" "$(grep -q '^enable_app_helper=0$' "$upd/etc/usertools.conf" && echo 1 || echo 0)"
assert_eq "notice names the on tool" "1" "$(printf '%s' "$out" | grep -q 'Manage Shell' && echo 1 || echo 0)"
assert_eq "notice omits the off tool" "0" "$(printf '%s' "$out" | grep -q 'Fix Home Permissions' && echo 1 || echo 0)"
printf '%s\n' 'enable_ownership_report=1' 'enable_app_helper=1' >>"$upd/etc/usertools.conf"
out="$(USERTOOLS_DESTDIR="$upd" USERTOOLS_ETC="/etc" install_confs 0 1)"
assert_eq "notice lists each on tool" "3" "$(printf '%s' "$out" | grep -oE 'Manage Shell|Ownership Report|App Helper' | wc -l | tr -d ' ')"
printf '%s\n' 'enable_shell=0' >"$upd/etc/usertools.conf"
out="$(USERTOOLS_DESTDIR="$upd" USERTOOLS_ETC="/etc" install_confs 0 1)"
assert_eq "no notice when all are off" "0" "$(printf '%s' "$out" | grep -c 'notice:')"
rm -rf "$upd"

# --- install/upgrade never touch the feature lists --------------------------------
fd="$(mktemp -d)"
mkdir -p "$fd/var/cpanel/features"
printf '%s\n' 'api_shell=0' 'usertools_shell=0' >"$fd/var/cpanel/features/default"
printf '%s\n' 'usertools_shell=1' >"$fd/var/cpanel/features/Mail Only"
fbefore="$(cd "$fd/var/cpanel" && find features -type f -print0 | sort -z | xargs -0 md5sum)"
USERTOOLS_DESTDIR="$fd" USERTOOLS_ETC="/etc" install_confs 0 0 >/dev/null
USERTOOLS_DESTDIR="$fd" USERTOOLS_ETC="/etc" install_confs 0 1 >/dev/null
fafter="$(cd "$fd/var/cpanel" && find features -type f -print0 | sort -z | xargs -0 md5sum)"
assert_eq "install and upgrade leave feature lists byte-identical" "$fbefore" "$fafter"
rm -rf "$fd"

mkdir -p "$destd/usr/local/cpanel/scripts" "$destd/usr/local/cpanel/bin"
export FIX_DYNAMICUI="$destd/usr/local/cpanel/base/frontend/jupiter/dynamicui"
printf '#!/bin/sh\nmkdir -p "$FIX_DYNAMICUI"\nprintf "usertools_shell usertools_fix_home usertools_bulk_perms usertools_ownership_report usertools_app_helper\\n" >"$FIX_DYNAMICUI/dynamicui_usertools.conf"\nexit 0\n' >"$destd/usr/local/cpanel/scripts/install_plugin"
printf '#!/bin/sh\nexit 0\n' >"$destd/usr/local/cpanel/bin/register_appconfig"
printf '#!/bin/sh\nexit 0\n' >"$destd/usr/local/cpanel/scripts/restartsrv_cpsrvd"
printf '#!/bin/sh\nprintf "hook: UserTools::Hook::AppSetup\\n"\nexit 0\n' >"$destd/usr/local/cpanel/bin/manage_hooks"
chmod +x "$destd/usr/local/cpanel/scripts/install_plugin" "$destd/usr/local/cpanel/bin/register_appconfig" \
    "$destd/usr/local/cpanel/scripts/restartsrv_cpsrvd" "$destd/usr/local/cpanel/bin/manage_hooks"
oldpath="$PATH"; PATH=/usr/bin:/bin
USERTOOLS_DESTDIR="$destd" register_plugin 0 >/dev/null
USERTOOLS_DESTDIR="$destd" verify_table >/dev/null; rc=$?
assert_eq "verification passes" "0" "$rc"
PATH="$oldpath"
unset FIX_DYNAMICUI

# --- dry run changes nothing ----------------------------------------------------
dryd="$(mktemp -d)"
out="$(USERTOOLS_DESTDIR="$dryd" install_files 1)"
assert_eq "dry-run prints manifest" "1" "$(printf '%s' "$out" | grep -q 'dry-run: install admin/Cpanel/Admin/Modules/UserTools/Base.pm' && echo 1 || echo 0)"
assert_eq "dry-run writes nothing" "0" "$(find "$dryd" -type f | wc -l | tr -d ' ')"
rm -rf "$dryd"

# --- enable-features only prints -----------------------------------------------
out="$(enable_features_help 'default' 2>&1)"
assert_eq "steps name the list" "1" "$(printf '%s' "$out" | grep -q "feature list 'default'" && echo 1 || echo 0)"
assert_eq "steps name features" "1" "$(printf '%s' "$out" | grep -c 'usertools_app_helper')"
assert_eq "steps start at UserTools Settings" "1" \
    "$(printf '%s' "$out" | grep -q 'UserTools Settings' && echo 1 || echo 0)"
assert_eq "steps say untick per package" "1" \
    "$(printf '%s' "$out" | grep -q 'Untick' && echo 1 || echo 0)"
next="$(whats_next 2>&1)"
assert_eq "next says switches ship off" "1" \
    "$(printf '%s' "$next" | grep -q 'switch ships off' && echo 1 || echo 0)"
assert_eq "next warns all entries appear" "1" \
    "$(printf '%s' "$next" | grep -q 'all ten menu entries appear' && echo 1 || echo 0)"

# --- uninstall order + absolute lookup + verification rows ----------------------------
oroot="$(mktemp -d)"
mkdir -p "$oroot/usr/local/cpanel/scripts" "$oroot/usr/local/cpanel/bin"
mkdir -p "$oroot/usr/local/cpanel/3rdparty/usertools/plugin"
mkdir -p "$oroot/var/cpanel/apps" "$oroot/var/cpanel/perl5/lib/UserTools/Hook"
mkdir -p "$oroot/usr/local/cpanel/base/frontend/jupiter/dynamicui"
printf '{"features":[]}\n' >"$oroot/usr/local/cpanel/3rdparty/usertools/plugin/install.json"
printf 'x\n' >"$oroot/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm"
mkdir -p "$oroot/etc/logrotate.d"
printf 'x\n' >"$oroot/etc/logrotate.d/usertools"
printf 'service=whostmgr\n' >"$oroot/var/cpanel/apps/usertools.conf"
mkdir -p "$oroot/etc/cron.d"
printf 'x\n' >"$oroot/etc/cron.d/usertools-update"
printf 'usertools_shell\n' >"$oroot/usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_usertools.conf"
export TDESTDIR="$oroot" OCALLS="$oroot/calls.txt"
export ODYN="$oroot/usr/local/cpanel/base/frontend/jupiter/dynamicui"
export OAPP="$oroot/var/cpanel/apps/usertools.conf"
: >"$OCALLS"
printf '#!/bin/sh\necho "STEP:hook-$1" >>"$OCALLS"\nif [ "$1" = "delete" ]; then [ -f "$TDESTDIR/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm" ] || exit 3; : >"$TDESTDIR/hooks.txt"; exit 0; fi\nif [ "$1" = "list" ]; then cat "$TDESTDIR/hooks.txt" 2>/dev/null; exit 0; fi\nexit 0\n' >"$oroot/usr/local/cpanel/bin/manage_hooks"
printf '#!/bin/sh\necho "STEP:plugin" >>"$OCALLS"\nprintf "%%s\\n" "$@" >>"$OCALLS"\n[ -f "$TDESTDIR/usr/local/cpanel/3rdparty/usertools/plugin/install.json" ] || exit 4\nrm -f "$ODYN/dynamicui_usertools.conf"\nexit 0\n' >"$oroot/usr/local/cpanel/scripts/uninstall_plugin"
printf '#!/bin/sh\necho "STEP:appconf $1" >>"$OCALLS"\n[ -f "$TDESTDIR/var/cpanel/apps/usertools.conf" ] || exit 5\nrm -f "$OAPP"\nexit 0\n' >"$oroot/usr/local/cpanel/bin/unregister_appconfig"
printf '#!/bin/sh\necho "STEP:cpsrvd" >>"$OCALLS"\nexit 0\n' >"$oroot/usr/local/cpanel/scripts/restartsrv_cpsrvd"
chmod +x "$oroot/usr/local/cpanel/bin/manage_hooks" "$oroot/usr/local/cpanel/scripts/uninstall_plugin" \
    "$oroot/usr/local/cpanel/bin/unregister_appconfig" "$oroot/usr/local/cpanel/scripts/restartsrv_cpsrvd"
oldpath="$PATH"; PATH=/usr/bin:/bin
USERTOOLS_DESTDIR="$oroot" uninstall_files 0 0 >/dev/null; rc=$?
assert_eq "ordered uninstall exits 0" "0" "$rc"
d_hook=$(grep -n '^STEP:hook-delete$' "$OCALLS" | cut -d: -f1)
d_plug=$(grep -n '^STEP:plugin$' "$OCALLS" | cut -d: -f1)
d_app=$(grep -n '^STEP:appconf ' "$OCALLS" | cut -d: -f1)
assert_eq "hook delete first" "1" "$([ "$d_hook" -lt "$d_plug" ] && [ "$d_plug" -lt "$d_app" ] && echo 1 || echo 0)"
assert_eq "uninstall_plugin plugin dir" "1" "$(grep -c '3rdparty/usertools/plugin' "$OCALLS")"
assert_eq "uninstall_plugin jupiter theme" "1" "$(grep -c -- '--theme=jupiter' "$OCALLS")"
assert_eq "unregister conf path" "1" "$(grep -c 'apps/usertools.conf' "$OCALLS")"
assert_eq "hook file gone" "0" "$([ -e "$oroot/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm" ] && echo 1 || echo 0)"
assert_eq "logrotate entry gone" "0" "$([ -e "$oroot/etc/logrotate.d/usertools" ] && echo 1 || echo 0)"
assert_eq "cron entry gone" "0" "$([ -e "$oroot/etc/cron.d/usertools-update" ] && echo 1 || echo 0)"
PATH="$oldpath"
rm -rf "$oroot"
unset TDESTDIR OCALLS ODYN OAPP

# --- verify_uninstall rows, pass and fail ------------------------------------------------
vdir="$(mktemp -d)"
USERTOOLS_DESTDIR="$vdir" verify_uninstall >/dev/null; rc=$?
assert_eq "clean tree verifies" "0" "$rc"
mkdir -p "$vdir/usr/local/cpanel/base/frontend/jupiter/dynamicui"
printf 'usertools_shell\n' >"$vdir/usr/local/cpanel/base/frontend/jupiter/dynamicui/left.conf"
out="$(USERTOOLS_DESTDIR="$vdir" verify_uninstall 2>&1)"; rc=$?
assert_eq "leftover dynamicui fails" "1" "$rc"
assert_eq "fail row printed" "1" "$(printf '%s' "$out" | grep -q 'FAIL.*dynamicui' && echo 1 || echo 0)"
rm "$vdir/usr/local/cpanel/base/frontend/jupiter/dynamicui/left.conf"
mkdir -p "$vdir/usr/local/cpanel/base/frontend/jupiter/user_tools/assets"
printf 'x\n' >"$vdir/usr/local/cpanel/base/frontend/jupiter/user_tools/assets/usertools.min.css"
out="$(USERTOOLS_DESTDIR="$vdir" verify_uninstall 2>&1)"; rc=$?
assert_eq "leftover assets fail" "1" "$rc"
assert_eq "assets fail row printed" "1" "$(printf '%s' "$out" | grep -q 'FAIL.*assets' && echo 1 || echo 0)"
rm -rf "$vdir"

# --- uninstall keeps state, --purge removes --------------------------------------
mkdir -p "$destd/var/log"
printf 'x\n' >"$destd/var/log/usertools.log"
USERTOOLS_DESTDIR="$destd" USERTOOLS_ETC="/etc" USERTOOLS_VAR="/var" uninstall_files 0 0 >/dev/null
assert_eq "plugin tree gone" "0" "$([ -e "$destd/usr/local/cpanel/3rdparty/usertools" ] && echo 1 || echo 0)"
assert_eq "admin module gone" "0" "$([ -e "$destd/usr/local/cpanel/Cpanel/Admin/Modules/UserTools" ] && echo 1 || echo 0)"
assert_eq "log kept" "1" "$([ -f "$destd/var/log/usertools.log" ] && echo 1 || echo 0)"
assert_eq "conf kept" "1" "$([ -f "$destd/etc/usertools.conf" ] && echo 1 || echo 0)"
USERTOOLS_DESTDIR="$destd" USERTOOLS_ETC="/etc" USERTOOLS_VAR="/var" uninstall_files 0 1 >/dev/null
assert_eq "purge removes conf" "0" "$([ -e "$destd/etc/usertools.conf" ] && echo 1 || echo 0)"
assert_eq "purge removes log" "0" "$([ -e "$destd/var/log/usertools.log" ] && echo 1 || echo 0)"
# The installer saves its source as previous/installed.tar.gz (0600).
USERTOOLS_DESTDIR="$destd" save_installed_tarball >/dev/null; rc=$?
assert_eq "installed tarball saved" "0" "$rc"
assert_eq "installed.tar.gz exists" "1" "$([ -f "$destd/usr/local/cpanel/3rdparty/usertools/previous/installed.tar.gz" ] && echo 1 || echo 0)"
assert_eq "installed.tar.gz mode 600" "600" "$(stat -c '%a' "$destd/usr/local/cpanel/3rdparty/usertools/previous/installed.tar.gz")"
assert_eq "installed.tar.gz holds install.sh" "1" "$(tar -tzf "$destd/usr/local/cpanel/3rdparty/usertools/previous/installed.tar.gz" 2>/dev/null | grep -q 'install.sh$' && echo 1 || echo 0)"
rm -rf "$destd"
unset USERTOOLS_DESTDIR USERTOOLS_ETC USERTOOLS_VAR

# --- register_plugin with absolute-path fixtures -------------------------------------
rdir="$(mktemp -d)"
USERTOOLS_DESTDIR="$rdir" install_files 0 >/dev/null
USERTOOLS_DESTDIR="$rdir" USERTOOLS_ETC="/etc" install_confs 0 0 >/dev/null
mkdir -p "$rdir/usr/local/cpanel/scripts" "$rdir/usr/local/cpanel/bin"
export FIX_CALLS="$rdir/calls.txt" FIX_STATE="$rdir/hooks.txt"
export FIX_DYNAMICUI="$rdir/usr/local/cpanel/base/frontend/jupiter/dynamicui"
: >"$FIX_CALLS"; : >"$FIX_STATE"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >>"$FIX_CALLS"\nmkdir -p "$FIX_DYNAMICUI"\nprintf "usertools_shell usertools_fix_home usertools_bulk_perms usertools_ownership_report usertools_app_helper\\n" >"$FIX_DYNAMICUI/dynamicui_usertools.conf"\nexit 0\n' >"$rdir/usr/local/cpanel/scripts/install_plugin"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >>"$FIX_CALLS"\nexit 0\n' >"$rdir/usr/local/cpanel/bin/register_appconfig"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >>"$FIX_CALLS"\nexit 0\n' >"$rdir/usr/local/cpanel/scripts/restartsrv_cpsrvd"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >>"$FIX_CALLS"\nif [ "$1" = "list" ]; then cat "$FIX_STATE" 2>/dev/null; exit 0; fi\nif [ "$1" = "add" ]; then printf "hook: UserTools::Hook::AppSetup\\n" >>"$FIX_STATE"; exit 0; fi\nif [ "$1" = "delete" ]; then : >"$FIX_STATE"; exit 0; fi\nexit 0\n' >"$rdir/usr/local/cpanel/bin/manage_hooks"
chmod +x "$rdir/usr/local/cpanel/scripts/install_plugin" "$rdir/usr/local/cpanel/bin/register_appconfig" \
    "$rdir/usr/local/cpanel/scripts/restartsrv_cpsrvd" "$rdir/usr/local/cpanel/bin/manage_hooks"
oldpath="$PATH"; PATH=/usr/bin:/bin
USERTOOLS_DESTDIR="$rdir" register_plugin 0 >/dev/null
assert_eq "install_plugin plugin dir" "1" "$(grep -c "$rdir/usr/local/cpanel/3rdparty/usertools/plugin" "$FIX_CALLS")"
assert_eq "install_plugin jupiter theme" "1" "$(grep -c -- '--theme=jupiter' "$FIX_CALLS")"
USERTOOLS_DESTDIR="$rdir" register_hook >/dev/null
assert_eq "hook add called once" "1" "$(grep -c '^add$' "$FIX_CALLS")"
USERTOOLS_DESTDIR="$rdir" register_hook >/dev/null
assert_eq "second register skips" "1" "$(grep -c '^add$' "$FIX_CALLS")"
USERTOOLS_DESTDIR="$rdir" verify_table >/dev/null; rc=$?
assert_eq "verification passes with registrations" "0" "$rc"
PATH="$oldpath"
rm -rf "$rdir"
unset FIX_CALLS FIX_STATE FIX_DYNAMICUI

# --- uninstall removes the hook, keeps foreign entries -------------------------------
udir="$(mktemp -d)"
mkdir -p "$udir/usr/local/cpanel/bin" "$udir/var/cpanel/perl5/lib/UserTools/Hook"
touch "$udir/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm"
touch "$udir/var/cpanel/perl5/lib/UserTools/foreign.pm"
export FIX_CALLS="$udir/calls.txt"; : >"$FIX_CALLS"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >>"$FIX_CALLS"\nif [ "$1" = "list" ]; then exit 0; fi\nexit 0\n' >"$udir/usr/local/cpanel/bin/manage_hooks"
chmod +x "$udir/usr/local/cpanel/bin/manage_hooks"
oldpath="$PATH"; PATH=/usr/bin:/bin
USERTOOLS_DESTDIR="$udir" uninstall_files 0 0 >/dev/null
assert_eq "hook delete called" "1" "$(grep -c '^delete$' "$FIX_CALLS")"
assert_eq "hook module form" "1" "$(grep -c 'UserTools::Hook::AppSetup' "$FIX_CALLS")"
assert_eq "hook file gone" "0" "$([ -e "$udir/var/cpanel/perl5/lib/UserTools/Hook/AppSetup.pm" ] && echo 1 || echo 0)"
assert_eq "Hook dir gone when empty" "0" "$([ -e "$udir/var/cpanel/perl5/lib/UserTools/Hook" ] && echo 1 || echo 0)"
assert_eq "foreign entry kept" "1" "$([ -f "$udir/var/cpanel/perl5/lib/UserTools/foreign.pm" ] && echo 1 || echo 0)"
assert_eq "UserTools dir kept when busy" "1" "$([ -d "$udir/var/cpanel/perl5/lib/UserTools" ] && echo 1 || echo 0)"
PATH="$oldpath"
rm -rf "$udir"
unset FIX_CALLS

# --- sshd output never prints values ---------------------------------------------
sdir="$(mktemp -d)"
mkdir -p "$sdir/bin" "$sdir/etc"
printf '#!/bin/sh\nprintf "port 2222\\nallowusers alice\\n"\n' >"$sdir/bin/sshd"
chmod +x "$sdir/bin/sshd"
printf 'ssh_port=2222\n' >"$sdir/etc/usertools.conf"
: >"$sdir/etc/usertools.private.conf"
oldpath="$PATH"; PATH="$sdir/bin:/usr/bin:/bin"
out="$(USERTOOLS_DESTDIR="$sdir" USERTOOLS_ETC="/etc" write_sshd_keys 2>&1)"
assert_eq "same port says unchanged" "1" "$(printf '%s' "$out" | grep -q 'ssh_port unchanged' && echo 1 || echo 0)"
assert_eq "no port value printed" "0" "$(printf '%s' "$out" | grep -c '2222')"
printf 'ssh_port=22\n' >"$sdir/etc/usertools.conf"
out="$(USERTOOLS_DESTDIR="$sdir" USERTOOLS_ETC="/etc" write_sshd_keys 2>&1)"
assert_eq "changed port says updated" "1" "$(printf '%s' "$out" | grep -q 'ssh_port updated' && echo 1 || echo 0)"
assert_eq "no port value on update" "0" "$(printf '%s' "$out" | grep -c '2222')"
PATH="$oldpath"
rm -rf "$sdir"

# --- bootstrap runs when piped (curl ... | bash -s --), not only as a file ----------
# v0.1.0 aborted here under set -u: BASH_SOURCE is unset with no source file.
out="$(bash -s -- --help <"$here/bootstrap-install.sh" 2>&1)"; rc=$?
assert_eq "piped bootstrap --help exits 0" "0" "$rc"
assert_eq "piped bootstrap prints usage" "1" "$(printf '%s\n' "$out" | grep -c '^Usage: bootstrap-install.sh')"
out="$(bash -s -- --version v0.0.0 <"$here/bootstrap-install.sh" 2>&1)"
assert_eq "piped bootstrap reaches argument checks" "1" "$(printf '%s\n' "$out" | grep -c 'pass --repo')"

# --- bootstrap sha256 gate (fixtures, no network) ---------------------------------
bdir="$(mktemp -d)"
printf 'payload\n' >"$bdir/payload.txt"
tar -czf "$bdir/r.tar.gz" -C "$bdir" payload.txt
good="$(sha256sum "$bdir/r.tar.gz" | awk '{ print $1 }')"
verify_tarball "$bdir/r.tar.gz" "$good"
assert_eq "good sha256 passes" "0" "$?"
printf '%s  %s\n' "$good" "$(basename "$bdir/r.tar.gz")" >"$bdir/r.tar.gz.sha256"
verify_tarball "$bdir/r.tar.gz" "$bdir/r.tar.gz.sha256"
assert_eq "sha256 file passes" "0" "$?"
verify_tarball "$bdir/r.tar.gz" "0000000000000000000000000000000000000000000000000000000000000000"
assert_eq "bad sha256 fails" "1" "$?"
# Checksum files are LF; a CRLF file (Windows download/edit) still verifies.
printf '%s  %s\n' "$good" "$(basename "$bdir/r.tar.gz")" >"$bdir/r.tar.gz.sha256"
assert_eq "checksum file has no CR" "0" "$(grep -c "$(printf '\r')" "$bdir/r.tar.gz.sha256")"
printf '%s  %s\r\n' "$good" "$(basename "$bdir/r.tar.gz")" >"$bdir/r.crlf.sha256"
verify_tarball "$bdir/r.tar.gz" "$bdir/r.crlf.sha256"
assert_eq "crlf checksum file passes" "0" "$?"
rm -rf "$bdir"

# --- bootstrap signature gate (fake cosign, file:// repo, no network) ---------------
brel="$(mktemp -d)"
mkdir -p "$brel/acme/widgets/releases/download/v9.9.9" "$brel/pkg"
printf '#!/bin/bash\necho BOOTSTRAP-INSTALLED >>"$BT_MARKER"\n' >"$brel/pkg/install.sh"
chmod +x "$brel/pkg/install.sh"
tar -czf "$brel/acme/widgets/releases/download/v9.9.9/usertools-for-cpanel-v9.9.9.tar.gz" -C "$brel/pkg" install.sh
bgood="$(sha256sum "$brel/acme/widgets/releases/download/v9.9.9/usertools-for-cpanel-v9.9.9.tar.gz" | awk '{ print $1 }')"
printf '%s  %s\n' "$bgood" "usertools-for-cpanel-v9.9.9.tar.gz" >"$brel/acme/widgets/releases/download/v9.9.9/usertools-for-cpanel-v9.9.9.tar.gz.sha256"
printf 'fake-bundle\n' >"$brel/acme/widgets/releases/download/v9.9.9/usertools-for-cpanel-v9.9.9.tar.gz.sigstore.json"
fbin="$(mktemp -d)"
printf '#!/bin/sh\necho "$@" >>"$BT_CALLS"\n[ "$FAKE_COSIGN_RESULT" = "ok" ]\n' >"$fbin/cosign"
chmod +x "$fbin/cosign"
export BT_MARKER="$brel/marker.txt" BT_CALLS="$brel/calls.txt"
rm -f "$BT_MARKER" "$BT_CALLS"
oldpath="$PATH"
export FAKE_COSIGN_RESULT=ok
out="$(PATH="$fbin:/usr/bin:/bin" main --repo acme/widgets --version v9.9.9 --base-url "file://$brel" -- --yes 2>&1)"; rc=$?
assert_eq "good signature installs" "0" "$rc"
assert_eq "installer ran" "1" "$(grep -q BOOTSTRAP-INSTALLED "$BT_MARKER" 2>/dev/null && echo 1 || echo 0)"
assert_eq "pinned identity used" "1" "$(grep -q 'acme/widgets/.github/workflows/ci.yml@refs/tags/v9.9.9' "$BT_CALLS" && echo 1 || echo 0)"
assert_eq "oidc issuer used" "1" "$(grep -q 'https://token.actions.githubusercontent.com' "$BT_CALLS" && echo 1 || echo 0)"
rm -f "$BT_MARKER" "$BT_CALLS"
export FAKE_COSIGN_RESULT=bad
out="$(PATH="$fbin:/usr/bin:/bin" main --repo acme/widgets --version v9.9.9 --base-url "file://$brel" -- --yes 2>&1)"; rc=$?
assert_eq "bad signature refuses" "1" "$rc"
assert_eq "refusal names signature" "1" "$(printf '%s' "$out" | grep -q 'signature mismatch' && echo 1 || echo 0)"
assert_eq "nothing installed" "0" "$([ -e "$BT_MARKER" ] && echo 1 || echo 0)"
export FAKE_COSIGN_RESULT=ok
out="$(PATH=/usr/bin:/bin main --repo acme/widgets --version v9.9.9 --base-url "file://$brel" -- --yes 2>&1)"; rc=$?
assert_eq "missing verifier falls back" "0" "$rc"
assert_eq "fallback warns" "1" "$(printf '%s' "$out" | grep -q 'falling back to sha256' && echo 1 || echo 0)"
assert_eq "fallback installs" "1" "$(grep -q BOOTSTRAP-INSTALLED "$BT_MARKER" 2>/dev/null && echo 1 || echo 0)"
rm -f "$BT_MARKER"
out="$(PATH=/usr/bin:/bin main --repo acme/widgets --version v9.9.9 --base-url "file://$brel" --require-signature -- --yes 2>&1)"; rc=$?
assert_eq "require refuses without verifier" "1" "$rc"
assert_eq "require names cosign" "1" "$(printf '%s' "$out" | grep -q 'cosign not found' && echo 1 || echo 0)"
assert_eq "require installs nothing" "0" "$([ -e "$BT_MARKER" ] && echo 1 || echo 0)"
out="$(PATH="$fbin:/usr/bin:/bin" main --repo acme/widgets --version v9.9.9 --base-url "file://$brel" --require-signature -- --yes 2>&1)"; rc=$?
assert_eq "require installs when verified" "0" "$rc"
assert_eq "verified install ran" "1" "$(grep -q BOOTSTRAP-INSTALLED "$BT_MARKER" 2>/dev/null && echo 1 || echo 0)"
rm -f "$BT_MARKER"
rm "$brel/acme/widgets/releases/download/v9.9.9/usertools-for-cpanel-v9.9.9.tar.gz.sigstore.json"
out="$(PATH="$fbin:/usr/bin:/bin" main --repo acme/widgets --version v9.9.9 --base-url "file://$brel" --require-signature -- --yes 2>&1)"; rc=$?
assert_eq "require refuses without bundle" "1" "$rc"
assert_eq "require names bundle" "1" "$(printf '%s' "$out" | grep -q 'no signature published' && echo 1 || echo 0)"
PATH="$oldpath"
unset BT_MARKER BT_CALLS FAKE_COSIGN_RESULT
rm -rf "$brel" "$fbin"

# --- preflight cpanel check (cpanel is an executable file) -----------------------
pdir="$(mktemp -d)"
mkdir -p "$pdir/usr/local/cpanel/whostmgr" "$pdir/usr/local/cpanel/base/frontend/jupiter"
touch "$pdir/usr/local/cpanel/cpanel" && chmod +x "$pdir/usr/local/cpanel/cpanel"
printf '11.138.0.10\n' >"$pdir/usr/local/cpanel/version"
USERTOOLS_DESTDIR="$pdir" USERTOOLS_SKIP_ROOT=1 preflight >/dev/null; rc=$?
assert_eq "preflight passes with cpanel file" "0" "$rc"
rm "$pdir/usr/local/cpanel/cpanel"
mkdir -p "$pdir/usr/local/cpanel/cpanel"
USERTOOLS_DESTDIR="$pdir" USERTOOLS_SKIP_ROOT=1 preflight >/dev/null; rc=$?
assert_eq "preflight fails with cpanel dir" "1" "$rc"
rm -rf "$pdir"

# --- interpreter lines (root-run code never trusts PATH) --------------------------
shebang_ok=1
while IFS= read -r f; do
    first="$(head -n 1 "$f")"
    case "$f" in
        *.py)
            [ "$first" = '#!/usr/bin/python3' ] || { echo "not ok - $f shebang [$first]"; shebang_ok=0; }
            ;;
        *.cgi)
            [ "$first" = '#!/usr/local/cpanel/3rdparty/bin/perl' ] || { echo "not ok - $f shebang [$first]"; shebang_ok=0; }
            ;;
        *)
            case "$first" in
                '#!'*) echo "not ok - $f unexpected shebang [$first]"; shebang_ok=0 ;;
            esac
            ;;
    esac
done <<EOF
$here/whm/cgi/addon_usertools_settings.cgi
$here/hooks/lib/UserTools/Hook/AppSetup.pm
$here/admin/Cpanel/Admin/Modules/UserTools/Base.pm
$here/admin/Cpanel/Admin/Modules/UserTools/Shell.pm
$here/admin/Cpanel/Admin/Modules/UserTools/AppDocroot.pm
$here/Cpanel/API/UserTools.pm
$here/engine/perm_engine.py
$here/engine/recipe_worker.py
EOF
if [ "$shebang_ok" = "1" ]; then echo "ok - interpreter lines"; else fail=1; fi
case "$(head -c 200 "$here/engine/recipe_worker.py" "$here/engine/perm_engine.py")" in
    *"/usr/bin/env"*) echo "not ok - no /usr/bin/env in engines"; fail=1 ;;
    *) echo "ok - no /usr/bin/env in engines" ;;
esac

# --- verify_cgi_executes with PERL5LIB fakes (execs CGI directly via shebang) -----------
flib="$(mktemp -d)"
mkdir -p "$flib/Cpanel" "$flib/Whostmgr"
sed "1s|^#!.*|#!$(command -v perl)|" "$here/whm/cgi/addon_usertools_settings.cgi" >"$flib/addon_usertools_settings.cgi"
chmod 0700 "$flib/addon_usertools_settings.cgi"
printf 'package Cpanel::Template;\nsub process_template { print "Content-type: text/html; charset=utf-8\\n\\nUserTools Settings\\n"; }\n1;\n' >"$flib/Cpanel/Template.pm"
printf 'package Whostmgr::ACLS;\nsub init_acls { 1 }\nsub hasroot { 1 }\n1;\n' >"$flib/Whostmgr/ACLS.pm"
USERTOOLS_CGI_ENV="PERL5LIB=$flib PATH=/usr/bin:/bin" \
    verify_cgi_executes "$(command -v perl)" "$flib/addon_usertools_settings.cgi" "$flib" >/dev/null; rc=$?
assert_eq "real CGI executes" "0" "$rc"
sed "1s|^#!.*|#!/nonexistent/perl|" "$here/whm/cgi/addon_usertools_settings.cgi" >"$flib/bad_shebang.cgi"
chmod 0700 "$flib/bad_shebang.cgi"
USERTOOLS_CGI_ENV="PERL5LIB=$flib PATH=/usr/bin:/bin" \
    verify_cgi_executes "$(command -v perl)" "$flib/bad_shebang.cgi" "$flib" >/dev/null; rc=$?
assert_eq "bad shebang fails direct exec" "1" "$rc"
printf 'package Cpanel::Template;\nsub process_template { die "broken\\n"; }\n1;\n' >"$flib/Cpanel/Template.pm"
USERTOOLS_CGI_ENV="PERL5LIB=$flib PATH=/usr/bin:/bin" \
    verify_cgi_executes "$(command -v perl)" "$flib/addon_usertools_settings.cgi" "$flib" >/dev/null; rc=$?
assert_eq "broken template fails the row" "1" "$rc"
verify_cgi_executes "$flib/missing-perl" "$flib/addon_usertools_settings.cgi" "$flib" >/dev/null; rc=$?
assert_eq "absent perl skips" "0" "$rc"
rm -rf "$flib"
unset USERTOOLS_CGI_ENV

# --- No OWNER/ placeholder outside usage strings --------------------------------
# Real repo values ship in examples and URLs; only the --repo shape
# descriptions (`--repo OWNER/repo`) may stay generic.
for _f in README.md bootstrap-install.sh; do
    _hits="$(grep -n 'OWNER/' "$here/$_f" | grep -v -- '--repo OWNER/repo' | grep -v -- 'needs OWNER/repo' || true)"
    assert_eq "no OWNER placeholder in $_f" "" "$_hits"
done

# --- line endings (LF-only repo and tarballs) -------------------------------------------
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    assert_eq "no crlf in index" "0" "$(git ls-files --eol | grep -c '^i/crlf' || true)"
    assert_eq "no crlf attrs" "0" "$(git ls-files --eol | grep -c 'eol=crlf' || true)"
    adir="$(mktemp -d)"
    git -c core.eol=lf -c core.autocrlf=false archive HEAD | tar -x -C "$adir"
    # Skip binary files (PNG screenshots contain CR bytes as data).
    assert_eq "archive has no CR" "0" "$(grep -rlI $'\r' "$adir" 2>/dev/null | wc -l | tr -d ' ')"
    # ...but a text file with CR inside the archive must still fail.
    printf 'x\r\n' >>"$adir/VERSION"
    assert_eq "text CR in archive fails" "1" "$(grep -rlI $'\r' "$adir" 2>/dev/null | wc -l | tr -d ' ')"
    rm -rf "$adir"
else
    echo "ok - eol checks skipped (not a git checkout)"
fi

# --- verify_no_cr catches a planted CR --------------------------------------------------
crdir="$(mktemp -d)"
USERTOOLS_DESTDIR="$crdir" install_files 0 >/dev/null
printf 'x\r\n' >>"$crdir/usr/local/cpanel/3rdparty/usertools/VERSION"
USERTOOLS_DESTDIR="$crdir" verify_no_cr >/dev/null; rc=$?
assert_eq "planted CR fails the row" "1" "$rc"
rm -rf "$crdir"

# --- CageFS conf.d INI format (configparser-validated, force-update FAIL) -----------
cgdir="$(mktemp -d)"
mkdir -p "$cgdir/etc/cagefs/conf.d" "$cgdir/etc/cagefs"
touch "$cgdir/etc/cagefs/cagefs.mp"
cgfb="$(mktemp -d)"
printf '#!/bin/sh\ncfg="$CAGEFS_CFG"\npython3 -c '\''import configparser,sys; c=configparser.ConfigParser(); c.read([sys.argv[1]]); s=c["usertools"]["paths"]'\'' "$cfg" 2>/dev/null\nrc=$?\nprintf "%%s\\n" "$*" >>"$CAGEFS_CALLS"\nexit $rc\n' >"$cgfb/cagefsctl"
chmod +x "$cgfb/cagefsctl"
export CAGEFS_CFG="$cgdir/etc/cagefs/conf.d/usertools.cfg" CAGEFS_CALLS="$cgdir/calls.txt"
: >"$CAGEFS_CALLS"
oldpath="$PATH"; PATH="$cgfb:/usr/bin:/bin"
USERTOOLS_DESTDIR="$cgdir" USERTOOLS_ETC="/etc" USERTOOLS_CPANEL="/usr/local/cpanel" cagefs_setup 0 >/dev/null; rc=$?
assert_eq "cagefs INI setup succeeds" "0" "$rc"
assert_eq "cagefs cfg has section" "1" "$(grep -q '^\[usertools\]$' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg has comment" "1" "$(grep -q '^comment=' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg lists perm_engine" "1" "$(grep -q 'perm_engine.py' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg lists space_cleaner" "1" "$(grep -q 'space_cleaner.py' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg lists site_doctor" "1" "$(grep -q 'site_doctor.py' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg lists recipe_worker" "1" "$(grep -q 'recipe_worker.py' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg lists VERSION" "1" "$(grep -q '/VERSION' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg lists public conf" "1" "$(grep -q '/etc/usertools.conf' "$CAGEFS_CFG" && echo 1 || echo 0)"
assert_eq "cagefs cfg hides private conf" "0" "$(grep -c 'usertools.private.conf' "$CAGEFS_CFG")"
assert_eq "cagefs cfg hides updater" "0" "$(grep -c 'usertools-update' "$CAGEFS_CFG")"
assert_eq "cagefs cfg hides previous" "0" "$(grep -c 'previous' "$CAGEFS_CFG")"
assert_eq "cagefs cfg hides plugin dir" "0" "$(grep -c '/plugin' "$CAGEFS_CFG")"
assert_eq "force-update ran" "1" "$(grep -q 'force-update' "$CAGEFS_CALLS" && echo 1 || echo 0)"
python3 -c 'import configparser; c=configparser.ConfigParser(); c.read(["'"$CAGEFS_CFG"'"]); s=c["usertools"]["paths"]' 2>/dev/null
assert_eq "configparser parses entry" "0" "$?"
# bare path list (the old format) must fail the same fixture parse
printf '%s\n' '/usr/local/cpanel/3rdparty/usertools' '/etc/usertools.conf' >"$CAGEFS_CFG"
python3 -c 'import configparser; c=configparser.ConfigParser(); c.read(["'"$CAGEFS_CFG"'"]); s=c["usertools"]["paths"]' 2>/dev/null
assert_eq "bare list fails configparser" "1" "$?"
# force-update non-zero is FAIL and keeps nothing half-written
printf '#!/bin/sh\nexit 1\n' >"$cgfb/cagefsctl"
chmod +x "$cgfb/cagefsctl"
rm -f "$CAGEFS_CFG"
USERTOOLS_DESTDIR="$cgdir" USERTOOLS_ETC="/etc" USERTOOLS_CPANEL="/usr/local/cpanel" cagefs_setup 0 >/dev/null 2>&1; rc=$?
assert_eq "force-update failure is FAIL" "1" "$rc"
PATH="$oldpath"
unset CAGEFS_CFG CAGEFS_CALLS
rm -rf "$cgdir" "$cgfb"

# --- Fixed root PATH + absolute cagefsctl ---------------------------------------
hdir="$(mktemp -d)"
mkdir -p "$hdir/usr/sbin" "$hdir/etc/cagefs"
touch "$hdir/etc/cagefs/cagefs.mp"
printf '#!/bin/sh\necho "H1FORCE $@" >>"$H1_CALLS"\nexit 0\n' >"$hdir/usr/sbin/cagefsctl"
chmod +x "$hdir/usr/sbin/cagefsctl"
export H1_CALLS="$hdir/calls.txt"
: >"$H1_CALLS"
out="$(env -i PATH=/usr/bin:/bin USERTOOLS_DESTDIR="$hdir" USERTOOLS_ETC="/etc" USERTOOLS_CPANEL="/usr/local/cpanel" H1_CALLS="$H1_CALLS" bash -c "source '$here/install.sh'; cagefs_setup 0")"; rc=$?
assert_eq "env -i setup succeeds" "0" "$rc"
assert_eq "force-update ran via absolute path" "1" "$(grep -q 'H1FORCE --force-update' "$H1_CALLS" && echo 1 || echo 0)"
assert_eq "entry written" "1" "$([ -f "$hdir/etc/cagefs/conf.d/usertools.cfg" ] && echo 1 || echo 0)"
USERTOOLS_DESTDIR="$hdir" cagefs_detected >/dev/null; rc=$?
assert_eq "absolute binary detects" "0" "$rc"
USERTOOLS_DESTDIR="$hdir" cagefs_broken >/dev/null; rc=$?
assert_eq "present binary is not broken" "1" "$rc"
rm -f "$hdir/usr/sbin/cagefsctl"
USERTOOLS_DESTDIR="$hdir" cagefs_detected >/dev/null; rc=$?
assert_eq "missing tool is not detected" "1" "$rc"
USERTOOLS_DESTDIR="$hdir" cagefs_broken >/dev/null; rc=$?
assert_eq "marker without binary is broken" "0" "$rc"
USERTOOLS_DESTDIR="$hdir" USERTOOLS_ETC="/etc" USERTOOLS_CPANEL="/usr/local/cpanel" cagefs_setup 0 >/dev/null 2>&1; rc=$?
assert_eq "broken setup is FAIL" "1" "$rc"
unset H1_CALLS
rm -rf "$hdir"

exit "$fail"
