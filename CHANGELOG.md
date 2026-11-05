# Changelog

All notable changes to this project are documented here. Versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Added

- Space Cleaner: project build caches (`node_modules/.cache`,
  `node_modules/.vite`, `.next/cache`, `.parcel-cache`, `.angular/cache`)
  are recognised only in directories that hold a regular `package.json`
  and are shown in the preview as one row per folder with file, byte and
  inode counts. `.cache/pip` and `.cache/yarn` join the fixed developer
  caches. Both are moved to the trash and restored per batch like the
  other cache categories.

## [0.2.0] - 2026-11-02

### Added

- Site Doctor: read-only check of every website (homepage status, document
  root, `.htaccess` pitfalls, TLS certificate, both error logs) with one
  plain-words verdict per domain, plus one fix (comment out php_value
  lines under PHP-FPM) with preview, backup and undo. Off by default:
  `enable_site_doctor=0` policy key, WHM checkbox, and its own Feature
  Manager feature.
- Site Doctor: check whether a WordPress site serves `xmlrpc.php` and offer a
  marked `.htaccess` deny block when it does, with preview, backup, undo and a
  re-probe. The fix is not offered when Jetpack is installed (it needs
  XML-RPC). Undo removes only its own section, so WordPress's permalink rules
  and later edits survive; a re-probe that still sees the file says so instead
  of reporting success. Off by default with Site Doctor
  (`enable_site_doctor=0`).
- Exposed Files Scanner: engine walk of every document root for files
  that must never be public, probed over HTTP (status + size only,
  bodies never read past a cap); findings served only over a same-host
  HTTPS hop are probed again over TLS. A finding counts as confirmed
  when the served length matches the file on disk, otherwise likely.
  Exposed files can be moved to quarantine (restore available) or
  blocked with a marked `.htaccess` deny rule that matches the mapped
  file (undo removes it), with a re-probe after each action. Names that
  cannot be quoted safely are never written to `.htaccess` (Move only).
  Redirects that cannot be followed, failed HTTPS checks and server
  errors read "not checked" with the reason, never "not exposed".
  Redirects to the `www.` or bare form of a listed domain are followed.
  Off by default: `enable_exposed_files=0` policy key, WHM checkbox,
  and its own Feature Manager feature.
- Cron Doctor: read-only flags over the user's own crontab (every-minute
  schedules, unredirected output, bare `php` without a path, duplicate
  lines, missing script files, `wget`/`curl` of the account's own URLs),
  with one fix in this release (append output redirection to a chosen
  line, full crontab backed up) and an undo that puts back only that
  line, so cron jobs added later are kept. Lines whose output cannot be
  silenced this way (an unescaped `%`, an empty `MAILTO`) are refused.
  Off by default: `enable_cron_doctor=0` policy key, WHM checkbox, and
  its own Feature Manager feature.
- My Activity: every UAPI action that changes something appends one JSON
  line to `~/.cpanel/usertools/activity.jsonl` (0600, capped at 1,000
  lines): time, tool, action, summary counts and an undo reference when
  one exists. The page lists the latest 100 with Undo buttons; each undo
  names the exact change, asks for confirmation, and is refused when a
  newer change exists or it was already undone. No file contents, no secrets in
  the log.
- Space Cleaner: preview and reclaim disk space and inodes across six
  fixed categories (big `error_log` and per-website PHP logs truncated
  in place; crash dumps, framework and WordPress caches, and developer
  caches moved to a trash folder; the plugin's own old job files and
  undo journals deleted). Preview first, confirm dialog with totals,
  progress with cancel, restore per trash batch, empty per batch or
  all. Off by default: `enable_space_cleaner=0` policy key, WHM
  checkbox, and its own Feature Manager feature.

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
