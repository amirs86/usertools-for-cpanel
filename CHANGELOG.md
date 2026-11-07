# Changelog

All notable changes to this project are documented here. Versions follow
[SemVer](https://semver.org/).

## [0.5.2] - 2026-11-07

### Fixed

- App Helper: "Lock the app root" now shows its result directly under the
  button. A lock that is skipped or deferred, because another site lives inside
  the app folder or the website still points at the app root, now says so and
  names the reason, instead of reporting `.htaccess applied.`. The preview shows
  that reason before anything is written.
- App Helper: the lock button no longer disappears after pointing a website at
  the app, and the document root confirmation stays on screen.
- Buttons marked small no longer pick up cPanel Jupiter's `.small { width: 25% }`
  rule, which made them overflow their text at phone widths on every page.

### Changed

- App Helper shows a permanent "App root: locked / not locked" line on each app
  and keeps one lock button in "Point a website here".
- App Helper layout: a single app uses the full width, the command buttons are
  lighter and wrap cleanly under their labels, the add folder controls share one
  row, and the sections are spaced apart.

## [0.5.1] - 2026-11-07

### Changed

- Release build only, with no change to the installed tools: every CI job now
  runs on a fixed Ubuntu version, every action is pinned by commit, and CI
  permissions are read-only except for the job that signs and publishes. A
  test keeps these in place. Releases are still signed the same way, by the
  same workflow, so verification is unchanged.

## [0.5.0] - 2026-11-06

### Security

- **"Off by default" was not true through 0.4.0.** cPanel counts a plugin
  feature with no line in a feature list as enabled, and the installer wrote
  no lines. So on a fresh install, Manage Shell, Fix Home Permissions, Bulk
  Permissions, Ownership Report and App Helper were available to every
  account on any package whose feature list had no line for them. Manage
  Shell let an account pick from `allowed_shell_modes`, which ships as
  `disabled,jailed`. All nine tool switches now ship `0`.
- `enable_fix_home`, `enable_bulk_perms` and `enable_ownership_report` were
  not enforced anywhere, and `enable_app_helper` only stopped document-root
  changes and the account hook. All four now stop every call of their tool.
  Only `1` means on; a missing key or unreadable policy file means off.

### Changed

- **Upgrading does not switch anything off.** A server that already has a
  tool at `1` keeps it, and `--upgrade` prints a notice naming those tools
  and records it in the audit log. Review them in UserTools Settings. The one
  change on a running server: a switch already set to `0`, which used to be
  ignored, now takes effect.
- The setup order is now: switch a tool on in UserTools Settings, then untick
  its feature in Feature Manager for packages that should not have it. All
  ten menu entries appear on a fresh install, and a tool that is off refuses
  with a message. UserTools never writes to cPanel's feature lists.
- The account hook needs `enable_app_helper=1`, so it stays inactive on a
  fresh install until App Helper is switched on.
- My Activity has no switch. It shows an account only its own activity and is
  empty until an enabled tool records something.

## [0.4.0] - 2026-11-06

### Added

- App Helper: the `engines.node` range in `package.json` is checked against
  the real version of each installed Node. The deploy panel says which
  version fits, warns when no installed version matches, and says when it
  cannot tell. A mismatch never blocks the build, and the warning is shown
  again beside a failed build. Apps with no range see no change, and Node
  is not run for them.

### Changed

- App Helper now builds on the newest installed Node that satisfies the
  range. **`>=18` with Node 18 and 24 installed now builds on 24**, where it
  used to build on 18. If an app needs the older version, narrow its range,
  for example to `^18`.
- Reading a Node version is limited to five seconds. On a server where Node
  has not run recently, an account's I/O limit can make the first read
  slower than that, so the panel can show "cannot tell" for the first page
  loads until the files are cached.

### Fixed

- App Helper no longer warns about a range the installed Node satisfies, such
  as `>=18` with only Node 24 installed.
- Ranges with a minor or patch version, `||` alternatives or two bounds, such
  as `>=18.17.0`, `^20.19.0 || >=22.12.0` and `>=18 <21`, are no longer
  ignored.

## [0.3.0] - 2026-11-06

### Added

- Space Cleaner: project build caches (`node_modules/.cache`,
  `node_modules/.vite`, `.next/cache`, `.parcel-cache`, `.angular/cache`)
  are recognised only in directories that hold a regular `package.json`
  and are shown in the preview as one row per folder with file, byte and
  inode counts. `.cache/pip` and `.cache/yarn` join the fixed developer
  caches. Both are moved to the trash and restored per batch like the
  other cache categories. The scan no longer walks into `node_modules`.
- Site Doctor: the homepage check follows up to ten redirects on the same
  IP, the listed domain or its `www.`/bare counterpart, with chain URLs on
  the standard ports and connections on the server-side record port. It
  reports a loop, too many redirects, an off-site hop or the final URL. A
  loop also lists the redirect-related `.htaccess` lines from the document
  root and its parent folders, read-only.
- App Helper: readiness reports `public/storage` as `ok`, `missing` or
  `broken` (a dead symlink, shown with its old target). The existing
  `storage:link` fallback replaces only a dead symlink, after all component
  checks, saves the old target, and restores it if the new link cannot be
  made. The Activity entry carries the old target and an Undo action.
- Site Doctor: when a website's document root is exactly an app root that
  App Helper detected, the verdict says the whole app folder is served
  (including `.env`) and points to App Helper → Document root. A `public/`
  document root or a plain website gets no such hint.

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
