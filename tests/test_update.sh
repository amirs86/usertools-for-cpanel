#!/bin/bash
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2016 # fixture scripts below are single-quoted on purpose:
# their $vars must expand when the FIXTURE runs, not when printf writes it.
# Unit tests for bin/usertools-update (no root, no network: the
# script is sourced, main() is not run; fixture file:// hosts stand in for
# the release API). Run:  bash tests/test_update.sh
set -u

here="$(dirname "$0")/.."
# shellcheck disable=SC1091
source "$here/bin/usertools-update"

fail=0
assert_eq() { # name expected actual
    if [ "$2" = "$3" ]; then
        echo "ok - $1"
    else
        echo "not ok - $1 (expected [$2], got [$3])"
        fail=1
    fi
}

# --- SemVer compare -----------------------------------------------------------
assert_eq "equal" "0" "$(semver_cmp '1.2.3' 'v1.2.3')"
assert_eq "patch newer" "-1" "$(semver_cmp '0.1.0' 'v0.1.1')"
assert_eq "minor newer" "-1" "$(semver_cmp '0.1.9' '0.2.0')"
assert_eq "major newer" "-1" "$(semver_cmp '0.9.9' '1.0.0')"
assert_eq "older" "1" "$(semver_cmp '0.2.0' '0.1.9')"
assert_eq "major older" "1" "$(semver_cmp '1.0.0' '0.9.9')"
assert_eq "whitespace tolerated" "0" "$(semver_cmp '  v1.2.3
' '1.2.3')"
assert_eq "leading zeros numeric" "-1" "$(semver_cmp '1.2.08' '1.2.9')"
semver_cmp '1.2' '1.2.3' >/dev/null 2>&1
assert_eq "short refused" "1" "$?"
semver_cmp 'v1.2.x' '1.2.3' >/dev/null 2>&1
assert_eq "non-numeric refused" "1" "$?"
semver_cmp '' '1.2.3' >/dev/null 2>&1
assert_eq "empty refused" "1" "$?"

# --- tag + scope gating --------------------------------------------------------
assert_eq "release tag ok" "0" "$(valid_tag 'v0.2.0' && echo 0 || echo 1)"
assert_eq "bare version refused" "1" "$(valid_tag '0.2.0' && echo 0 || echo 1)"
assert_eq "latest refused" "1" "$(valid_tag 'latest' && echo 0 || echo 1)"
assert_eq "suffix refused" "1" "$(valid_tag 'v1.2.3-rc1' && echo 0 || echo 1)"
assert_eq "patch scope patch" "0" "$(scope_allows patch '0.1.0' 'v0.1.1' && echo 0 || echo 1)"
assert_eq "patch scope minor refused" "1" "$(scope_allows patch '0.1.0' 'v0.2.0' && echo 0 || echo 1)"
assert_eq "minor scope minor" "0" "$(scope_allows minor '0.1.0' 'v0.2.0' && echo 0 || echo 1)"
assert_eq "minor scope patch" "0" "$(scope_allows minor '0.1.5' 'v0.1.6' && echo 0 || echo 1)"
assert_eq "scope never major" "1" "$(scope_allows minor '0.9.9' 'v1.0.0' && echo 0 || echo 1)"
assert_eq "scope never downgrade" "1" "$(scope_allows patch '0.2.0' 'v0.1.9' && echo 0 || echo 1)"
assert_eq "scope never equal" "1" "$(scope_allows patch '0.1.0' 'v0.1.0' && echo 0 || echo 1)"
assert_eq "bad scope refused" "1" "$(scope_allows major '0.1.0' 'v0.2.0' && echo 0 || echo 1)"

# --- policy_value ---------------------------------------------------------------
pdir="$(mktemp -d)"
printf '%s\n' 'update_repo=acme/widgets' 'auto_update=1  ; comment' '' >"$pdir/policy.conf"
assert_eq "policy read" "acme/widgets" "$(policy_value "$pdir/policy.conf" update_repo)"
assert_eq "policy trimmed" "1" "$(policy_value "$pdir/policy.conf" auto_update)"
assert_eq "policy missing key" "" "$(policy_value "$pdir/policy.conf" nope)"
assert_eq "policy missing file" "" "$(policy_value "$pdir/nope.conf" update_repo)"
rm -rf "$pdir"

# --- fixture release host --------------------------------------------------------
# $fx/host/owner/repo/releases/download/<tag>/{tgz,sha256,bundle}
# $fx/api/repos/owner/repo/releases/latest                           (API JSON)
make_release() {
    fx="$1"; repo="$2"; tag="$3"
    rel="$fx/host/$repo/releases/download/$tag"
    mkdir -p "$rel" "$fx/api/repos/$repo/releases"
    mkdir -p "$fx/pkg/usertools-for-cpanel-$tag"
    printf '#!/bin/bash\necho "UPDATER-INSTALLED $@" >>"$FX_MARKER"\ntag="$(basename "$(dirname "$0")")"\nver="${tag#usertools-for-cpanel-}"\nver="${ver#v}"\nprintf "%%s\\n" "$ver" >"$USERTOOLS_VERSION_FILE"\n' >"$fx/pkg/usertools-for-cpanel-$tag/install.sh"
    chmod +x "$fx/pkg/usertools-for-cpanel-$tag/install.sh"
    tar -czf "$rel/usertools-for-cpanel-$tag.tar.gz" -C "$fx/pkg" "usertools-for-cpanel-$tag"
    ( cd "$rel" && sha256sum "usertools-for-cpanel-$tag.tar.gz" >"usertools-for-cpanel-$tag.tar.gz.sha256" )
    printf 'fixture-bundle\n' >"$rel/usertools-for-cpanel-$tag.tar.gz.sigstore.json"
    printf '{"tag_name":"%s","html_url":"https://example.invalid/r"}\n' "$tag" >"$fx/api/repos/$repo/releases/latest"
}
make_env() {
    fx="$1"
    mkdir -p "$fx/etc" "$fx/base" "$fx/varlog" "$fx/varlib"
    printf 'update_repo=acme/widgets\nauto_update=0\nauto_update_scope=patch\n' >"$fx/etc/usertools.conf"
    printf '%s\n' "$2" >"$fx/base/VERSION"
    export USERTOOLS_TEST_MODE=1
    export USERTOOLS_POLICY="$fx/etc/usertools.conf" USERTOOLS_BASE="$fx/base"
    export USERTOOLS_VERSION_FILE="$fx/base/VERSION" USERTOOLS_PREVIOUS_DIR="$fx/base/previous"
    export USERTOOLS_AUDIT_LOG="$fx/varlog/usertools.log" USERTOOLS_STATUS_FILE="$fx/varlib/autoupdate.status"
    export USERTOOLS_API_BASE="file://$fx/api" USERTOOLS_SKIP_ROOT=1 FX_MARKER="$fx/marker.txt"
    rm -f "$FX_MARKER"
}
make_cosign() {
    fb="$1/fakebin"
    mkdir -p "$fb"
    printf '#!/bin/sh\necho "$@" >>"$FX_CALLS"\n[ "$FAKE_COSIGN" = "ok" ]\n' >"$fb/cosign"
    chmod +x "$fb/cosign"
    export USERTOOLS_COSIGN="$fb/cosign"
    export FX_CALLS="$1/cosign-calls.txt" BT_CALLS="$1/cosign-calls.txt" FAKE_COSIGN="$2"
    rm -f "$FX_CALLS"
}

fx="$(mktemp -d)"
make_release "$fx" "acme/widgets" "v0.1.0"
make_release "$fx" "acme/widgets" "v0.2.0"
make_env "$fx" "0.1.0"
make_cosign "$fx" ok
# Simulate the installer having saved its source (v0.1.0) as installed.
mkdir -p "$fx/base/previous"
cp "$fx/host/acme/widgets/releases/download/v0.1.0/usertools-for-cpanel-v0.1.0.tar.gz" \
    "$fx/base/previous/installed.tar.gz"
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --update --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "update succeeds" "0" "$rc"
assert_eq "new version named" "1" "$(printf '%s' "$out" | grep -q 'updated to v0.2.0' && echo 1 || echo 0)"
assert_eq "installer ran upgrade" "1" "$(grep -q 'UPDATER-INSTALLED --upgrade --yes' "$FX_MARKER" && echo 1 || echo 0)"
assert_eq "installed is the new tarball" "1" "$(cmp -s "$fx/host/acme/widgets/releases/download/v0.2.0/usertools-for-cpanel-v0.2.0.tar.gz" "$fx/base/previous/installed.tar.gz" && echo 1 || echo 0)"
assert_eq "rollback is the old tarball" "1" "$(cmp -s "$fx/host/acme/widgets/releases/download/v0.1.0/usertools-for-cpanel-v0.1.0.tar.gz" "$fx/base/previous/rollback.tar.gz" && echo 1 || echo 0)"
assert_eq "installed mode 600" "600" "$(stat -c '%a' "$fx/base/previous/installed.tar.gz")"
assert_eq "rollback mode 600" "600" "$(stat -c '%a' "$fx/base/previous/rollback.tar.gz")"
assert_eq "VERSION is new after update" "0.2.0" "$(tr -d ' \t\r\n' <"$fx/base/VERSION")"
assert_eq "audit line" "1" "$(grep -q 'update 0.1.0->v0.2.0 (update)' "$fx/varlog/usertools.log" && echo 1 || echo 0)"
assert_eq "identity pinned" "1" "$(grep -q 'acme/widgets/.github/workflows/ci.yml@refs/tags/v0.2.0' "$FX_CALLS" && echo 1 || echo 0)"

# Rollback now, before other updates clobber previous/.
rm -f "$FX_MARKER"
out="$(USERTOOLS_SKIP_ROOT=1 main --rollback 2>&1)"; rc=$?
assert_eq "rollback succeeds" "0" "$rc"
assert_eq "rollback reinstalls" "1" "$(grep -q 'UPDATER-INSTALLED --upgrade --yes' "$FX_MARKER" && echo 1 || echo 0)"
assert_eq "rollback restores VERSION A" "0.1.0" "$(tr -d ' \t\r\n' <"$fx/base/VERSION")"
rm -f "$FX_MARKER" "$FX_CALLS"
export FAKE_COSIGN=ok

# signature failure refuses before installing
rm -f "$FX_MARKER" "$FX_CALLS"
export FAKE_COSIGN=bad
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --update --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "bad signature refuses" "1" "$rc"
assert_eq "refusal names signature" "1" "$(printf '%s' "$out" | grep -qi 'signature' && echo 1 || echo 0)"
assert_eq "no install on refusal" "0" "$([ -e "$FX_MARKER" ] && echo 1 || echo 0)"
export FAKE_COSIGN=ok

# missing cosign refuses (updater requires signatures; fixed paths only)
unset USERTOOLS_COSIGN
out="$(PATH=/usr/bin:/bin main --update --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "missing cosign refuses" "1" "$rc"
assert_eq "refusal names cosign" "1" "$(printf '%s' "$out" | grep -q 'cosign not found' && echo 1 || echo 0)"
export USERTOOLS_COSIGN="$fx/fakebin/cosign"

# cosign_bin accepts only the fixed paths with safe ownership, never PATH.
unset USERTOOLS_COSIGN
out="$(PATH="$fx/fakebin:/usr/bin:/bin" cosign_bin 2>&1)"; rc=$?
assert_eq "PATH cosign ignored" "1" "$rc"
assert_eq "refusal names cosign" "1" "$(printf '%s' "$out" | grep -q 'cosign not found' && echo 1 || echo 0)"
export USERTOOLS_COSIGN="$fx/fakebin/cosign"
out="$(cosign_bin 2>&1)"; rc=$?
assert_eq "test seam accepted" "0" "$rc"
assert_eq "seam path returned" "$fx/fakebin/cosign" "$out"

# downgrade + non-release tags refuse
printf '0.3.0\n' >"$fx/base/VERSION"
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --update --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "downgrade is a no-op" "0" "$rc"
assert_eq "already-current message" "1" "$(printf '%s' "$out" | grep -q 'already current' && echo 1 || echo 0)"
assert_eq "message prefixed once" "usertools-update: already current (0.3.0); nothing to do" "$out"
printf '0.1.0\n' >"$fx/base/VERSION"
printf '{"tag_name":"nightly","html_url":"https://example.invalid/r"}\n' >"$fx/api/repos/acme/widgets/releases/latest"
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --update --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "non-release tag refuses" "1" "$rc"
printf '{"tag_name":"v0.2.0","html_url":"https://example.invalid/r"}\n' >"$fx/api/repos/acme/widgets/releases/latest"

# auto scope gating
printf 'update_repo=acme/widgets\nauto_update=1\nauto_update_scope=patch\n' >"$fx/etc/usertools.conf"
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --auto --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "auto patch+minor refused" "1" "$rc"
assert_eq "scope named" "1" "$(printf '%s' "$out" | grep -q 'outside auto-update scope' && echo 1 || echo 0)"
assert_eq "failed auto leaves install" "0" "$([ -e "$FX_MARKER" ] && echo 1 || echo 0)"
assert_eq "auto status recorded" "1" "$(grep -q '^ok=0$' "$fx/varlib/autoupdate.status" && echo 1 || echo 0)"
make_release "$fx" "acme/widgets" "v0.1.1"
printf '{"tag_name":"v0.1.1","html_url":"https://example.invalid/r"}\n' >"$fx/api/repos/acme/widgets/releases/latest"
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --auto --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "auto patch succeeds" "0" "$rc"
assert_eq "auto status ok" "1" "$(grep -q '^ok=1$' "$fx/varlib/autoupdate.status" && echo 1 || echo 0)"
printf 'update_repo=acme/widgets\nauto_update=0\nauto_update_scope=patch\n' >"$fx/etc/usertools.conf"
rm -f "$FX_MARKER"
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --auto --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "auto off is a no-op" "0" "$rc"
assert_eq "auto off installs nothing" "0" "$([ -e "$FX_MARKER" ] && echo 1 || echo 0)"

# rollback (after the auto patch to v0.1.1, the replaced version is v0.2.0)
rm -f "$FX_MARKER"
out="$(USERTOOLS_SKIP_ROOT=1 main --rollback 2>&1)"; rc=$?
assert_eq "rollback succeeds" "0" "$rc"
assert_eq "rollback reinstalls" "1" "$(grep -q 'UPDATER-INSTALLED --upgrade --yes' "$FX_MARKER" && echo 1 || echo 0)"
assert_eq "rollback restores replaced VERSION" "0.2.0" "$(tr -d ' \t\r\n' <"$fx/base/VERSION")"
rm -rf "$fx/base/previous"
out="$(USERTOOLS_SKIP_ROOT=1 main --rollback 2>&1)"; rc=$?
assert_eq "empty rollback refuses" "1" "$rc"
assert_eq "empty rollback says so" "1" "$(printf '%s' "$out" | grep -q 'no previous version kept' && echo 1 || echo 0)"

# missing repo refuses
printf 'update_repo=\n' >"$fx/etc/usertools.conf"
out="$(PATH="$fx/fakebin:/usr/bin:/bin" main --update --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "missing repo refuses" "1" "$rc"
rm -rf "$fx"
unset USERTOOLS_TEST_MODE USERTOOLS_POLICY USERTOOLS_BASE USERTOOLS_VERSION_FILE USERTOOLS_PREVIOUS_DIR
unset USERTOOLS_AUDIT_LOG USERTOOLS_STATUS_FILE USERTOOLS_API_BASE USERTOOLS_SKIP_ROOT
unset USERTOOLS_COSIGN
unset FX_MARKER FX_CALLS FAKE_COSIGN

# Outside test mode the updater ignores USERTOOLS_* overrides.
tdir="$(mktemp -d)"
printf 'update_repo=acme/widgets\nauto_update=0\nauto_update_scope=patch\n' >"$tdir/policy.conf"
printf '9.9.9\n' >"$tdir/VERSION"
out="$(USERTOOLS_POLICY="$tdir/policy.conf" USERTOOLS_VERSION_FILE="$tdir/VERSION" USERTOOLS_SKIP_ROOT=1 main --update --base-url "file://$fx/host" 2>&1)"; rc=$?
assert_eq "env overrides ignored without test mode" "1" "$rc"
assert_eq "production defaults used" "1" "$(printf '%s' "$out" | grep -q 'update_repo not configured\|installed VERSION missing\|must run as root\|could not determine' && echo 1 || echo 0)"
rm -rf "$tdir"
unset USERTOOLS_POLICY USERTOOLS_VERSION_FILE USERTOOLS_SKIP_ROOT

if [ "$fail" = "0" ]; then
    echo "test_update: all passed"
fi
exit "$fail"
