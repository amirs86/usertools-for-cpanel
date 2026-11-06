#!/bin/bash
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# UserTools for cPanel — release-tarball bootstrap.
#
# Downloads a PINNED release tarball + its .sha256 from GitHub Releases,
# verifies the checksum, extracts, and runs the real installer. Aborts with
# a clear message when verification fails. Extra arguments pass through to
# install.sh (e.g. --yes).
#
# Usage:
#   curl -fsSL https://<host>/bootstrap-install.sh | bash -s -- \
#       --repo amirs86/usertools-for-cpanel --version v0.5.0 [--sha256 HEX] [--require-signature] [--yes]
#   ./bootstrap-install.sh --repo amirs86/usertools-for-cpanel --version v0.5.0
#
# Signature verification: when cosign is installed and the release
# publishes a Sigstore bundle, the tarball's signature is verified against
# the pinned CI identity and any mismatch aborts. Otherwise the sha256 gate
# below applies, with a warning that no signature was checked.
# --require-signature refuses whenever verification is impossible.
#
# --base-url overrides the download host (tests use file:// fixtures).
# Unit tests drive verify_tarball() and main() directly; no network is used there.
set -u

die() { echo "usertools-bootstrap: error: $*" >&2; exit 1; }
info() { echo "usertools-bootstrap: $*"; }

# verify_tarball tarball expected-hex-or-sha256-file: sha256 check (0 ok)
# Checksum files are LF, but tolerate a CRLF file (an admin may have
# downloaded or edited it on Windows) — strip carriage returns before
# comparing, so `sha256sum -c` semantics hold either way.
verify_tarball() {
    local tarball="$1" want="$2" hex
    if [ -f "$want" ]; then
        hex="$(tr -d '\r' <"$want" | awk '{ print $1; exit }')"
    else
        hex="$want"
    fi
    if [[ ! "$hex" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "usertools-bootstrap: error: bad sha256 value" >&2
        return 1
    fi
    echo "$hex  $tarball" | sha256sum -c --status - 2>/dev/null
}

# verify_signature tarball bundle repo ver cosign-bin: cosign check (0 ok)
# Pinned identity: this repo's release workflow on the exact tag, GitHub OIDC.
verify_signature() {
    local tarball="$1" bundle="$2" repo="$3" ver="$4" cosign_bin="$5"
    "$cosign_bin" verify-blob "$tarball" --bundle "$bundle" \
        --certificate-identity "https://github.com/$repo/.github/workflows/ci.yml@refs/tags/$ver" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        >/dev/null 2>&1
}

main() {
    local repo="" ver="" sha="" base="https://github.com" require_sig=0 rest=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --repo) shift; repo="${1:-}"; [ -n "$repo" ] || die "--repo needs OWNER/repo" ;;
            --repo=*) repo="${1#--repo=}" ;;
            --version) shift; ver="${1:-}"; [ -n "$ver" ] || die "--version needs a tag" ;;
            --version=*) ver="${1#--version=}" ;;
            --sha256) shift; sha="${1:-}"; [ -n "$sha" ] || die "--sha256 needs a value" ;;
            --sha256=*) sha="${1#--sha256=}" ;;
            --require-signature) require_sig=1 ;;
            --base-url) shift; base="${1:-}" ;;
            --base-url=*) base="${1#--base-url=}" ;;
            -h|--help)
                echo "Usage: bootstrap-install.sh --repo OWNER/repo --version TAG [--sha256 HEX] [--require-signature] [-- install.sh flags]"
                exit 0 ;;
            --) shift; while [ $# -gt 0 ]; do rest+=("$1"); shift; done; break ;;
            *) rest+=("$1") ;;
        esac
        shift
    done
    [ -n "$repo" ] || die "pass --repo amirs86/usertools-for-cpanel"
    [ -n "$ver" ] || die "pass --version TAG (e.g. v0.1.0)"
    local tgz="usertools-for-cpanel-$ver.tar.gz"
    local sig="$tgz.sigstore.json"
    local tmp
    tmp="$(mktemp -d)" || die "cannot make temp dir"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT
    info "downloading $repo $ver"
    curl -fsSL "$base/$repo/releases/download/$ver/$tgz" -o "$tmp/$tgz" \
        || die "download failed"
    local have_bundle=0 cosign_bin=""
    if curl -fsSL "$base/$repo/releases/download/$ver/$sig" -o "$tmp/$sig" 2>/dev/null; then
        have_bundle=1
    fi
    cosign_bin="$(command -v cosign 2>/dev/null || true)"
    if [ "$have_bundle" = "1" ] && [ -n "$cosign_bin" ]; then
        info "verifying signature"
        verify_signature "$tmp/$tgz" "$tmp/$sig" "$repo" "$ver" "$cosign_bin" \
            || die "signature mismatch (aborting)"
    elif [ "$require_sig" = "1" ]; then
        if [ "$have_bundle" = "0" ]; then
            die "--require-signature: no signature published for $ver (aborting)"
        fi
        die "--require-signature: cosign not found, cannot verify (aborting)"
    elif [ "$have_bundle" = "1" ]; then
        info "warning: signature published but cosign not found; falling back to sha256"
    fi
    if [ -n "$sha" ]; then
        info "verifying with provided sha256"
        verify_tarball "$tmp/$tgz" "$sha" || die "sha256 mismatch (aborting)"
    else
        curl -fsSL "$base/$repo/releases/download/$ver/$tgz.sha256" -o "$tmp/$tgz.sha256" \
            || die "sha256 file download failed"
        info "verifying with release sha256"
        verify_tarball "$tmp/$tgz" "$tmp/$tgz.sha256" || die "sha256 mismatch (aborting)"
    fi
    tar -xzf "$tmp/$tgz" -C "$tmp" || die "extract failed"
    local inst
    inst="$(find "$tmp" -maxdepth 2 -name install.sh | head -n 1)"
    [ -n "$inst" ] || die "no install.sh in tarball"
    info "verified; running the installer"
    bash "$inst" "${rest[@]}"
}

# Piped (curl ... | bash) there is no source file, so BASH_SOURCE is unset;
# fall back to $0 so set -u does not abort before main runs.
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
    main "$@"
fi
