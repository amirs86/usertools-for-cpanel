# Changelog

All notable changes to this project are documented here. Versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Fixed

- The updater no longer prints its name twice ("usertools-update:
  usertools-update: already current").

## [0.1.2] - 2026-10-30

### Changed

- Documentation and code comments cleaned up; internal development notes
  removed from the repository.
- The installer's closing message no longer points at a file that is not
  in the release tarball.

## [0.1.1] - 2026-10-30

### Fixed

- `bootstrap-install.sh` aborted when piped (`curl ... | bash -s --`, the
  README one-liner): `BASH_SOURCE` is unset without a source file and
  `set -u` stopped the script before `main`. Regression test added.
- Releases are no longer marked as pre-releases: the updater looks up
  GitHub's `releases/latest`, which skips pre-releases, so v0.1.0 could not
  be found ("could not determine latest release").
- CI: install pytest for the engine tests; pin shellcheck 0.11.

## [0.1.0] - 2026-10-29 (first public beta)

Tested on cPanel 11.138 (AlmaLinux, Jupiter) and 11.134 LTS (CloudLinux,
CageFS).

- Five user tools: Fix Home Permissions, Bulk Permissions, Ownership
  Report, Manage Shell, and App Helper (detection, maintenance commands,
  Composer/npm deploy jobs, logs, scheduler, readiness, production switch,
  document-root and `.htaccess` helpers).
- WHM "UserTools Settings" page: validated policy editing, feature-list
  steps, opt-in update check, manual "Update now" and optional automatic
  patch/minor updates (signature required, rollback kept), audit log tail.
- Account-creation hook: per-package app layout written as the user,
  verified document-root switch as root.
- Installer, uninstaller and bootstrap with verification tables; releases
  are keyless-signed with Sigstore cosign and verified before install when
  cosign is present (`--require-signature` makes it mandatory).
- Security model: no root file operations on user paths; privileged calls
  take only enums/booleans and are gated by feature, policy and caller;
  every feature is off by default; shell changes are read back and rolled
  back on mismatch; no `.env` value leaves the server except
  `APP_ENV`/`APP_DEBUG`.
- CloudLinux support: alt-php and alt-nodejs discovery, CageFS visibility
  checks with the conf.d remedy, LVE limit hints.
