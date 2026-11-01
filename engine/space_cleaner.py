#!/usr/bin/python3
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""space_cleaner.py - unprivileged disk-space cleaner for UserTools for cPanel.

Runs ONLY as an unprivileged cPanel user. It scans the caller's home
directory for safe-to-remove clutter, moves it to a trash folder inside the
home (with restore), truncates oversized log files in place, and deletes the
plugin's own old job files and undo journals. It refuses to run as root.

Security properties (each covered by tests/test_space_cleaner.py):

  * Never follows symlinks. Directories are opened with O_NOFOLLOW and every
    stat uses dir_fd with follow_symlinks=False. Symlinks are recorded and
    left alone; a symlink is never truncated, moved, restored over, or
    descended into.
  * Stays on one filesystem: entries whose st_dev differs from the home top
    are recorded and skipped, so a trash move (rename) can never cross
    filesystems and a restore can never escape the home.
  * Confined to the caller's home: the home is canonicalised with realpath.
    Writes only ever name categories from a fixed server-side list (never
    paths from the caller): the engine itself derives every candidate path
    during its own walk, plus three fixed cache directories, the plugin's
    own jobs/undo folders, and the per-domain PHP logs under ~/logs/.
    Nothing else under ~/logs/ is ever listed for removal.
  * Fixed category list (the only selectable things): error_logs,
    core_dumps, app_cache, wp_cache, dev_caches, usertools_old. Anything
    outside these (backups, mail, settings, keys, the trash itself) is
    untouched. Top-level dotfiles/dotdirs and etc/mail/ssl/tmp/logs/
    access-logs are never descended into.
  * Entries not owned by the caller are recorded and never touched.
    Files with more than one hard link are recorded and never touched
    (truncating or moving them would affect the other name).
  * Truncate keeps the file, its mode and its owner (verified with fstat on
    the opened fd); restore only puts a file back when the original path is
    free and reports conflicts without overwriting.
  * One live job per user: the same lock file as perm_engine.py, so a
    permission run and a cleaner run can never overlap.

Usage:
  space_cleaner.py clean-scan [--category ID ...] [options]
  space_cleaner.py clean-run --category ID ... [options]
  space_cleaner.py trash-restore --batch ID [options]
  space_cleaner.py trash-empty [--batch ID | --all] [options]

  clean-scan   - report per-category counts plus the largest items (changes
                 nothing except pruning trash batches older than the policy).
  clean-run    - move candidates to the trash, truncate big logs, delete the
                 plugin's own old files.
  trash-restore - put one trash batch back (conflicts reported, never
                 overwritten).
  trash-empty  - delete one batch or all batches (cannot be undone).

Trash lives at ~/.usertools-trash/<batch>/ (0700) with the home-relative
layout plus a manifest.json (original path, size, mode, mtime). Batches
older than the cleaner_trash_days policy are pruned at the start of every
scan and run. Trash counts against the account quota until emptied.

Exit codes: 0 ok, 2 usage/validation/refusal, 3 another job running,
4 resource limit (EMFILE/ENFILE: partial run, summary still printed),
5 timed out or interrupted by SIGTERM (partial run, summary still printed),
1 unexpected failure.
"""

import argparse
import json
import os
import re
import signal
import stat
import sys
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX (engine targets Linux)
    fcntl = None  # type: ignore

import perm_engine as pe

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CATEGORIES = (
    "error_logs",
    "core_dumps",
    "app_cache",
    "wp_cache",
    "dev_caches",
    "usertools_old",
)

ERROR_LOG_BASENAME = "error_log"
CORE_RE = re.compile(r"^core(\.[0-9]+)?$")
PHP_LOG_SUFFIX = ".php.error.log"
BATCH_RE = re.compile(r"^[0-9]{8}T[0-9]{6}$")

# Fixed cache directories, home-relative. These live under dotdirs (never
# descended by the main walk), so they are handled as explicit roots after
# verifying each one is a real directory owned by the caller.
DEV_CACHE_RELS = (
    os.path.join(".npm", "_cacache"),
    os.path.join(".cache", "composer"),
    os.path.join(".cache", "usertools", "node-compile-cache"),
)

PHP_LOGS_DIR_REL = "logs"
JOBS_DIR_REL = os.path.join(".cpanel", "usertools", "jobs")
UNDO_DIR_REL = os.path.join(".cpanel", "usertools", "undo")
TRASH_DIRNAME = ".usertools-trash"

JOB_SUFFIXES = (
    ".job.json", ".progress.json", ".result.json", ".stderr.log",
    ".log", ".recipe.json", ".cancelled",
)

DEFAULT_LOG_MIN_MB = 50
DEFAULT_TRASH_DAYS = 7
LOG_MIN_MB_RANGE = (1, 1024)
TRASH_DAYS_RANGE = (1, 90)
USERTOOLS_OLD_DAYS = 30
UNDO_KEEP = 3

LARGEST_N = 20
LARGEST_POOL_CAP = 20000
TOP_N = 10
PATH_CAP = 500

POLICY_LOG_MIN_MB = "cleaner_log_min_mb"
POLICY_TRASH_DAYS = "cleaner_trash_days"


class _WalkDone(Exception):
    """Internal unwind for timeout/interrupt (partial summary still valid)."""


def parse_batch_id(text):
    # type: (str) -> str
    """Clean a trash batch id or raise UsageError (fixed shape only)."""
    if text is not None and BATCH_RE.match(text):
        return text
    raise pe.UsageError("invalid batch id (want YYYYMMDDTHHMMSS): %r" % (text,))


def trash_dir(home):
    # type: (str) -> str
    return os.path.join(home, TRASH_DIRNAME)


def new_batch_id():
    # type: () -> str
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime(time.time()))


def policy_int(policy, key, default, low, high):
    # type: (dict, str, int, int, int) -> int
    """Numeric policy with a fenced range; out-of-range falls back."""
    raw = policy.get(key)
    if raw is None:
        return default
    try:
        value = int(str(raw).strip())
    except ValueError:
        value = -1
    if value < low or value > high:
        pe.eprint("warning: invalid %s %r; using default %d"
                  % (key, raw, default))
        return default
    return value


def new_clean_summary(command, home, dry_run):
    # type: (str, str, bool) -> dict
    summary = {
        "command": command,
        "scope": home,
        "dry_run": dry_run,
        "counts": {
            "scanned": 0,
            "changed": 0,
            "would_change": 0,
            "not_owned": 0,
            "errors": 0,
            "skipped_symlink": 0,
            "skipped_protected": 0,
            "skipped_xdev": 0,
            "skipped_special": 0,
            "skipped_hardlink": 0,
            "trashed_files": 0,
            "trashed_bytes": 0,
            "truncated_files": 0,
            "truncated_bytes": 0,
            "deleted_files": 0,
            "deleted_bytes": 0,
            "restored_files": 0,
            "restore_conflicts": 0,
        },
        "categories": {},
        "categories_omitted": {},
        "top_dirs_size": [],
        "top_dirs_inodes": [],
        "trash": {"bytes": 0, "batches": 0},
        "paths": {
            "trashed": [],
            "truncated": [],
            "deleted": [],
            "restored": [],
            "not_owned": [],
            "skipped_symlink": [],
            "skipped_protected": [],
            "skipped_xdev": [],
            "skipped_special": [],
            "skipped_hardlink": [],
            "errors": [],
        },
        "omitted": {},
        "timed_out": False,
        "interrupted": False,
        "resource_limited": False,
        "trash_batch": None,
        "elapsed_seconds": 0.0,
    }
    for cid in CATEGORIES:
        summary["categories"][cid] = {
            "files": 0, "bytes": 0, "inodes": 0, "largest": [],
        }
    return summary


def _add_capped(summary, key, value):
    # type: (dict, str, object) -> None
    """Append to a paths list with the shared 500-entry cap."""
    lst = summary["paths"][key]
    if len(lst) < PATH_CAP:
        lst.append(value)
    else:
        summary["omitted"][key] = summary["omitted"].get(key, 0) + 1


def record_candidate(summary, cid, hrel, size):
    # type: (dict, str, str, int) -> None
    """Count one candidate file for a category (scan-time bookkeeping)."""
    cat = summary["categories"][cid]
    cat["files"] += 1
    cat["bytes"] += size
    cat["inodes"] += 1
    pool = cat["largest"]
    if len(pool) < LARGEST_POOL_CAP:
        pool.append({"path": hrel, "size": size})
    else:
        summary["categories_omitted"][cid] = \
            summary["categories_omitted"].get(cid, 0) + 1


def finalize_largest(summary):
    # type: (dict) -> None
    """Trim every category pool to the LARGEST_N biggest entries."""
    for cid in CATEGORIES:
        pool = summary["categories"][cid]["largest"]
        pool.sort(key=lambda e: (-e["size"], e["path"]))
        del pool[LARGEST_N:]


def _cat_changed(summary, cid, files, byte_count):
    # type: (dict, str, int, int) -> None
    """Fold per-category action totals into the counts (clean runs)."""
    if cid == "error_logs":
        summary["counts"]["truncated_files"] += files
        summary["counts"]["truncated_bytes"] += byte_count
    elif cid == "usertools_old":
        summary["counts"]["deleted_files"] += files
        summary["counts"]["deleted_bytes"] += byte_count
    else:
        summary["counts"]["trashed_files"] += files
        summary["counts"]["trashed_bytes"] += byte_count
# ---------------------------------------------------------------------------
# Safe filesystem helpers (trash, restore, delete)
# ---------------------------------------------------------------------------

def _ensure_dir_0700(path, stop):
    # type: (str, str) -> None
    """Create a directory tree; levels at/below `stop` end up 0700.

    Never touches anything above `stop` (the home itself must keep its
    mode): only paths inside our own trash tree are passed here.
    """
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise pe.UsageError("cannot create directory %r: %s" % (path, exc))
    head = path
    while True:
        if os.path.isdir(head) and not os.path.islink(head):
            try:
                os.chmod(head, 0o700)
            except OSError:
                pass
        if head == stop:
            break
        parent = os.path.dirname(head)
        if parent == head or not parent or len(parent) < len(stop):
            break
        head = parent


def _ensure_restore_parents(home, hrel):
    # type: (str, str) -> None
    """Create missing restore parents (0700); refuse blocked paths.

    Existing directories keep their modes. A symlink or non-directory on
    the way down aborts the entry so a rename can never travel through a
    link the user planted in the meantime.
    """
    parent = os.path.dirname(hrel)
    if not parent:
        return
    cur = home
    for part in parent.split("/"):
        cur = os.path.join(cur, part)
        if os.path.lexists(cur):
            try:
                st = os.lstat(cur)
            except OSError as exc:
                raise pe.UsageError("%s is blocked: %s" % (hrel, exc))
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise pe.UsageError(
                    "%s is blocked by a non-directory; left in trash" % hrel)
            continue
        try:
            os.mkdir(cur, 0o700)
        except OSError as exc:
            raise pe.UsageError("cannot recreate %s: %s" % (hrel, exc))


def safe_rmtree(root):
    # type: (str) -> int
    """Delete a tree without following symlinks; returns entries removed.

    Only regular files, symlinks (unlinked, never followed) and directories
    are removed. Anything else, or anything not owned by the caller, is left
    in place and raises UsageError at the end so the caller reports it.
    """
    uid = os.getuid()
    problems = []

    def remove_tree(path):
        # type: (str) -> int
        count = 0
        try:
            names = os.listdir(path)
        except OSError as exc:
            problems.append("%s: cannot list: %s" % (path, exc))
            return 0
        for name in names:
            full = os.path.join(path, name)
            try:
                st = os.lstat(full)
            except OSError as exc:
                problems.append("%s: cannot stat: %s" % (full, exc))
                continue
            if stat.S_ISLNK(st.st_mode):
                try:
                    os.unlink(full)
                    count += 1
                except OSError as exc:
                    problems.append("%s: cannot unlink: %s" % (full, exc))
            elif stat.S_ISDIR(st.st_mode):
                if st.st_uid != uid:
                    problems.append("%s: not yours, left alone" % full)
                    continue
                count += remove_tree(full)
                try:
                    os.rmdir(full)
                except OSError as exc:
                    problems.append("%s: cannot remove dir: %s" % (full, exc))
            elif stat.S_ISREG(st.st_mode):
                if st.st_uid != uid:
                    problems.append("%s: not yours, left alone" % full)
                    continue
                try:
                    os.unlink(full)
                    count += 1
                except OSError as exc:
                    problems.append("%s: cannot delete: %s" % (full, exc))
            else:
                problems.append("%s: special file, left alone" % full)
        return count

    removed = remove_tree(root)
    try:
        os.rmdir(root)
    except OSError as exc:
        problems.append("%s: cannot remove dir: %s" % (root, exc))
    if problems:
        raise pe.UsageError("; ".join(problems[:5]))
    return removed


def trash_size(home):
    # type: (str) -> tuple
    """(bytes, batches, entries) currently sitting in the trash."""
    root = trash_dir(home)
    total = 0
    batches = 0
    entries = 0
    try:
        names = os.listdir(root)
    except OSError:
        return 0, 0, 0
    for name in names:
        if not BATCH_RE.match(name):
            continue
        batches += 1
        stack = [os.path.join(root, name)]
        while stack:
            cur = stack.pop()
            try:
                st = os.lstat(cur)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if stat.S_ISDIR(st.st_mode):
                try:
                    for child in os.listdir(cur):
                        stack.append(os.path.join(cur, child))
                except OSError:
                    continue
            elif stat.S_ISREG(st.st_mode):
                total += st.st_size
                entries += 1
    return total, batches, entries


def prune_trash(home, summary, max_days):
    # type: (str, dict, int) -> int
    """Delete trash batches older than max_days; returns batches pruned."""
    root = trash_dir(home)
    try:
        names = os.listdir(root)
    except OSError:
        return 0
    cutoff = time.time() - max_days * 86400
    pruned = 0
    for name in names:
        if not BATCH_RE.match(name):
            continue
        full = os.path.join(root, name)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            continue
        if st.st_mtime > cutoff:
            continue
        try:
            safe_rmtree(full)
            pruned += 1
        except pe.UsageError as exc:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": os.path.join(TRASH_DIRNAME, name),
                         "reason": str(exc)})
    return pruned


def write_manifest(batch_path, entries):
    # type: (str, list) -> None
    """Write the batch manifest atomically."""
    payload = {
        "v": 1,
        "created": time.time(),
        "entries": entries,
    }
    tmp = os.path.join(batch_path, "manifest.json.tmp")
    final = os.path.join(batch_path, "manifest.json")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True, default=str)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, final)
    except OSError as exc:
        raise pe.UsageError("cannot write trash manifest: %s" % exc)


def read_manifest(batch_path):
    # type: (str) -> list
    """Read and validate a batch manifest; UsageError when unusable."""
    final = os.path.join(batch_path, "manifest.json")
    try:
        with open(final, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError) as exc:
        raise pe.UsageError("cannot read trash manifest: %s" % exc)
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise pe.UsageError("trash manifest has an unsupported version")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise pe.UsageError("trash manifest is corrupt")
    clean = []
    for ent in entries:
        if not isinstance(ent, dict):
            raise pe.UsageError("trash manifest is corrupt")
        try:
            rel = pe.validate_home_rel(ent.get("path", ""))
        except pe.UsageError as exc:
            raise pe.UsageError("trash manifest path refused: %s" % exc)
        clean.append({
            "path": rel,
            "size": ent.get("size", 0),
            "mode": ent.get("mode", "0644"),
            "mtime": ent.get("mtime", 0),
        })
    return clean
# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------

class Cleaner(object):
    """Home walker that collects (scan) or acts on (run) candidates."""

    def __init__(self, home, uid, summary, progress_cb, deadline,
                 progress_every, top_dev, categories, floors, acting):
        # type: (str, int, dict, object, object, int, int, object, dict, bool) -> None
        self.home = home
        self.uid = uid
        self.summary = summary
        self.progress_cb = progress_cb
        self.deadline = deadline
        self.progress_every = progress_every
        self.top_dev = top_dev
        self.categories = categories
        self.log_min_bytes = floors["log_min_bytes"]
        self.acting = acting
        self.done = 0
        self.top_stats = {}  # type: dict
        self.trash_batch = None  # type: object
        self.trash_entries = []  # type: list

    def selected(self, cid):
        # type: (str) -> bool
        return self.categories is None or cid in self.categories

    def poll(self):
        # type: () -> None
        """Progress + timeout/interrupt polling; unwinds on stop."""
        self.summary["counts"]["scanned"] = self.done
        if self.progress_every > 0 and self.done % self.progress_every == 0:
            self.progress_cb(self.done, self.summary)
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.summary["timed_out"] = True
            raise _WalkDone()
        if pe.stop_requested():
            self.summary["interrupted"] = True
            raise _WalkDone()

    def tally_top(self, hrel, size):
        # type: (str, int) -> None
        """Fold one entry into the per-top-folder size/inode rollup."""
        if hrel == ".":
            top = "."
        else:
            top = hrel.split("/", 1)[0]
        acc = self.top_stats.get(top)
        if acc is None:
            acc = [0, 0]
            self.top_stats[top] = acc
        acc[0] += size
        acc[1] += 1

    def note_not_owned(self, hrel, st):
        # type: (str, object) -> None
        self.summary["counts"]["not_owned"] += 1
        _add_capped(self.summary, "not_owned",
                    {"path": hrel, "owner": pe.owner_name(st.st_uid)})

    def record_skip(self, kind, hrel, reason=None):
        # type: (str, str, object) -> None
        self.summary["counts"][kind] += 1
        entry = {"path": hrel}  # type: dict
        if reason is not None:
            entry["reason"] = reason
        _add_capped(self.summary, kind, entry)

    # -- entry handling ----------------------------------------------------

    def examine(self, dir_fd, name, hrel):
        # type: (int, str, str) -> object
        """Classify one entry; returns (kind, stat-result-or-None).

        "dir" entries are owned directories to descend; "file" entries are
        owned single-link regular files (category checks run on them);
        anything else is already recorded ("skip").
        """
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as exc:
            if pe._is_resource_error(exc):
                raise pe.ResourceLimitError(
                    "too many open files while examining %s: %s" % (hrel, exc))
            self.summary["counts"]["errors"] += 1
            _add_capped(self.summary, "errors",
                        {"path": hrel, "reason": "cannot stat: %s" % exc})
            return ("skip", None)
        self.done += 1
        self.poll()
        if stat.S_ISLNK(st.st_mode):
            self.record_skip("skipped_symlink", hrel)
            return ("skip", None)
        if st.st_dev != self.top_dev:
            self.record_skip("skipped_xdev", hrel)
            return ("skip", None)
        if stat.S_ISDIR(st.st_mode):
            if st.st_uid != self.uid:
                self.note_not_owned(hrel, st)
                return ("skip", None)
            self.tally_top(hrel, 0)
            return ("dir", st)
        if not stat.S_ISREG(st.st_mode):
            self.record_skip("skipped_special", hrel)
            return ("skip", None)
        if st.st_uid != self.uid:
            self.note_not_owned(hrel, st)
            return ("skip", None)
        if st.st_nlink != 1:
            self.record_skip("skipped_hardlink", hrel,
                             "more than one hard link; left alone")
            return ("skip", None)
        self.tally_top(hrel, st.st_size)
        base = hrel.rsplit("/", 1)[-1]
        if base == ERROR_LOG_BASENAME and self.selected("error_logs") \
                and st.st_size >= self.log_min_bytes:
            self.found("error_logs", hrel, st.st_size,
                       lambda: self.truncate(hrel))
            return ("file", st)
        if CORE_RE.match(base) and self.selected("core_dumps"):
            self.found("core_dumps", hrel, st.st_size,
                       lambda: self.move_to_trash(hrel))
            return ("file", st)
        return ("file", st)

    def found(self, cid, hrel, size, act):
        # type: (str, str, int, object) -> None
        """Record one candidate; act on it when this is a clean run."""
        record_candidate(self.summary, cid, hrel, size)
        if self.acting:
            freed = act()
            _cat_changed(self.summary, cid, 1, freed if freed else 0)
            self.summary["counts"]["changed"] += 1
        else:
            self.summary["counts"]["would_change"] += 1

    # -- actions (clean runs only) ------------------------------------------

    def ensure_trash_batch(self):
        # type: () -> str
        """Create (once) the batch directory for this run."""
        if self.trash_batch is None:
            _ensure_dir_0700(trash_dir(self.home), trash_dir(self.home))
            for _ in range(100):
                name = new_batch_id()
                full = os.path.join(trash_dir(self.home), name)
                try:
                    os.mkdir(full, 0o700)
                except FileExistsError:
                    time.sleep(1)
                    continue
                except OSError as exc:
                    raise pe.UsageError("cannot create trash batch: %s" % exc)
                os.chmod(full, 0o700)
                self.trash_batch = name
                self.summary["trash_batch"] = name
                break
            if self.trash_batch is None:
                raise pe.UsageError("cannot create trash batch: clock stuck")
        return os.path.join(trash_dir(self.home), self.trash_batch)

    def move_to_trash(self, hrel):
        # type: (str) -> int
        """Re-verify then rename one file into the batch; bytes moved."""
        src = os.path.join(self.home, hrel)
        try:
            now = os.lstat(src)
        except OSError as exc:
            raise pe.UsageError("lost race on %s: %s" % (hrel, exc))
        if not stat.S_ISREG(now.st_mode) or now.st_uid != self.uid \
                or now.st_nlink != 1 or now.st_dev != self.top_dev:
            raise pe.UsageError("%s changed during the run; left alone" % hrel)
        batch_path = self.ensure_trash_batch()
        dst = os.path.join(batch_path, hrel)
        _ensure_dir_0700(os.path.dirname(dst), batch_path)
        if os.path.lexists(dst):
            raise pe.UsageError("%s is already in the trash batch" % hrel)
        os.rename(src, dst)
        self.trash_entries.append({
            "path": hrel,
            "size": now.st_size,
            "mode": "%04o" % (stat.S_IMODE(now.st_mode)),
            "mtime": now.st_mtime,
        })
        _add_capped(self.summary, "trashed", {"path": hrel})
        return now.st_size

    def truncate(self, hrel):
        # type: (str) -> int
        """Truncate one verified log file to zero; returns bytes freed."""
        src = os.path.join(self.home, hrel)
        try:
            fd = os.open(src, os.O_WRONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise pe.UsageError("cannot open %s: %s" % (hrel, exc))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != self.uid \
                    or st.st_nlink != 1:
                raise pe.UsageError("%s is not yours alone; left alone" % hrel)
            freed = st.st_size
            os.ftruncate(fd, 0)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        _add_capped(self.summary, "truncated", {"path": hrel})
        return freed

    # -- directory walking ---------------------------------------------------

    def open_dir(self, abs_path, expect, hrel):
        # type: (str, object, str) -> object
        """Open a directory O_NOFOLLOW with (dev, ino) verification."""
        try:
            fd = os.open(abs_path,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            if pe._is_resource_error(exc):
                raise pe.ResourceLimitError(
                    "too many open files while opening %s: %s" % (hrel, exc))
            self.summary["counts"]["errors"] += 1
            _add_capped(self.summary, "errors",
                        {"path": hrel,
                         "reason": "cannot open directory: %s" % exc})
            return None
        if expect is not None:
            try:
                fst = os.fstat(fd)
            except OSError as exc:
                os.close(fd)
                self.summary["counts"]["errors"] += 1
                _add_capped(self.summary, "errors",
                            {"path": hrel,
                             "reason": "cannot stat directory: %s" % exc})
                return None
            if (fst.st_dev, fst.st_ino) != expect:
                os.close(fd)
                self.summary["counts"]["errors"] += 1
                _add_capped(self.summary, "errors",
                            {"path": hrel,
                             "reason": "directory changed during walk; skipped"})
                return None
        return fd

    def list_dir(self, fd, hrel):
        # type: (int, str) -> object
        """List one open directory; None after recording hard errors."""
        try:
            return sorted(os.listdir(fd))
        except OSError as exc:
            if pe._is_resource_error(exc):
                raise pe.ResourceLimitError(
                    "too many open files while listing %s: %s" % (hrel, exc))
            self.summary["counts"]["errors"] += 1
            _add_capped(self.summary, "errors",
                        {"path": hrel,
                         "reason": "cannot list directory: %s" % exc})
            return None

    def verify_file(self, dir_fd, name, hrel):
        # type: (int, str, str) -> object
        """Gate one file for collection: regular, owned, single link."""
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as exc:
            if pe._is_resource_error(exc):
                raise pe.ResourceLimitError("too many open files: %s" % exc)
            self.summary["counts"]["errors"] += 1
            _add_capped(self.summary, "errors",
                        {"path": hrel, "reason": "cannot stat: %s" % exc})
            return None
        self.done += 1
        self.poll()
        if stat.S_ISLNK(st.st_mode):
            self.record_skip("skipped_symlink", hrel)
            return None
        if st.st_dev != self.top_dev:
            self.record_skip("skipped_xdev", hrel)
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_uid != self.uid:
            self.note_not_owned(hrel, st)
            return None
        if st.st_nlink != 1:
            self.record_skip("skipped_hardlink", hrel,
                             "more than one hard link; left alone")
            return None
        self.tally_top(hrel, st.st_size)
        return st

    def detect_roots(self, fd, hrel):
        # type: (int, str) -> None
        """Framework/CMS root detection for owned directories.

        WordPress: wp-config.php plus wp-includes/version.php, both regular
        files. Framework apps: reuse perm_engine.check_app_dir (artisan plus
        vendor/autoload.php plus a composer.json naming the framework).
        Either finding walks only the known cache subfolders (never the
        whole app).
        """
        if self.selected("wp_cache"):
            try:
                cfg = os.stat("wp-config.php", dir_fd=fd, follow_symlinks=False)
                ver = os.stat(os.path.join("wp-includes", "version.php"),
                              dir_fd=fd, follow_symlinks=False)
            except OSError:
                cfg = None
                ver = None
            if cfg is not None and ver is not None \
                    and stat.S_ISREG(cfg.st_mode) and stat.S_ISREG(ver.st_mode):
                self.walk_sub(fd, hrel, "wp-content/cache", "wp_cache")
        if self.selected("app_cache"):
            try:
                found = pe.check_app_dir(fd, hrel)
            except OSError:
                found = None
            if found:
                self.walk_sub(fd, hrel,
                              os.path.join("storage", "framework", "cache", "data"),
                              "app_cache")
                self.walk_views(fd, hrel)

    def open_sub(self, fd, rel):
        # type: (int, str) -> object
        """Open a known cache subfolder O_NOFOLLOW; None when absent."""
        try:
            sub = os.open(rel, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                           dir_fd=fd)
        except OSError:
            return None
        try:
            st = os.fstat(sub)
        except OSError:
            os.close(sub)
            return None
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != self.uid \
                or st.st_dev != self.top_dev:
            os.close(sub)
            return None
        return sub

    def walk_sub(self, fd, hrel, rel, cid):
        # type: (int, str, str, str) -> None
        """Collect every owned single-link file under a cache folder."""
        sub = self.open_sub(fd, rel)
        if sub is None:
            return
        try:
            base = hrel + "/" + rel.replace(os.sep, "/")
            self.walk_open(sub, base, False, cid)
        finally:
            try:
                os.close(sub)
            except OSError:
                pass

    def walk_views(self, fd, hrel):
        # type: (int, str, str) -> None
        """Collect compiled views: storage/framework/views/*.php only."""
        sub = self.open_sub(fd, os.path.join("storage", "framework", "views"))
        if sub is None:
            return
        try:
            base = hrel + "/storage/framework/views"
            names = self.list_dir(sub, base)
            if names is None:
                return
            for name in names:
                if not name.endswith(".php"):
                    continue
                fhrel = base + "/" + name
                st = self.verify_file(sub, name, fhrel)
                if st is None:
                    continue
                self.found("app_cache", fhrel, st.st_size,
                           lambda h=fhrel: self.move_to_trash(h))
        finally:
            try:
                os.close(sub)
            except OSError:
                pass

    def walk_open(self, fd, hrel, enforce_protected, collect_cid):
        # type: (int, str, bool, object) -> None
        """List one open directory and handle every entry.

        enforce_protected skips rule-1 paths (the main home walk).
        collect_cid (or None) collects owned files into that category
        (explicit cache roots and their subfolders).
        """
        names = self.list_dir(fd, hrel)
        if names is None:
            return
        pending = []
        for name in names:
            child = hrel + "/" + name if hrel != "." else name
            if enforce_protected and pe.is_protected_entry(child):
                self.record_skip("skipped_protected", child)
                continue
            kind, st = self.examine(fd, name, child)
            if kind == "dir":
                pending.append((child, st, collect_cid))
            elif kind == "file" and collect_cid is not None \
                    and self.selected(collect_cid):
                self.found(collect_cid, child, st.st_size,
                           lambda h=child: self.move_to_trash(h))
        for child, st, cid in pending:
            sub = self.open_dir(os.path.join(self.home, child),
                                (st.st_dev, st.st_ino), child)
            if sub is None:
                continue
            try:
                if cid is None:
                    self.detect_roots(sub, child)
                self.walk_open(sub, child, enforce_protected, cid)
            finally:
                try:
                    os.close(sub)
                except OSError:
                    pass

    def walk_explicit_dir(self, hrel, cid):
        # type: (str, str) -> None
        """Walk a fixed directory (verified real dir, owned, same dev)."""
        full = os.path.join(self.home, hrel)
        try:
            st = os.lstat(full)
        except OSError:
            return
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            return
        if st.st_uid != self.uid or st.st_dev != self.top_dev:
            self.note_not_owned(hrel, st)
            return
        fd = self.open_dir(full, (st.st_dev, st.st_ino), hrel)
        if fd is None:
            return
        try:
            self.walk_open(fd, hrel, False, cid)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
# ---------------------------------------------------------------------------
# Explicit roots: PHP logs, fixed caches, the plugin's own old files
# ---------------------------------------------------------------------------

def scan_php_logs(cleaner):
    # type: (Cleaner) -> None
    """Per-domain PHP logs (~/logs/*.php.error.log): truncate candidates.

    Only that exact name pattern; everything else in ~/logs/ (including
    archived access logs) is never listed for removal.
    """
    if not cleaner.selected("error_logs"):
        return
    home = cleaner.home
    try:
        dst = os.lstat(os.path.join(home, PHP_LOGS_DIR_REL))
    except OSError:
        return
    if not stat.S_ISDIR(dst.st_mode) or stat.S_ISLNK(dst.st_mode):
        return
    if dst.st_uid != cleaner.uid or dst.st_dev != cleaner.top_dev:
        return
    fd = cleaner.open_dir(os.path.join(home, PHP_LOGS_DIR_REL), None,
                           PHP_LOGS_DIR_REL)
    if fd is None:
        return
    try:
        names = cleaner.list_dir(fd, PHP_LOGS_DIR_REL)
        if names is None:
            return
        for name in names:
            if not name.endswith(PHP_LOG_SUFFIX):
                continue
            hrel = PHP_LOGS_DIR_REL + "/" + name
            st = cleaner.verify_file(fd, name, hrel)
            if st is None or st.st_size < cleaner.log_min_bytes:
                continue
            cleaner.found("error_logs", hrel, st.st_size,
                          lambda h=hrel: cleaner.truncate(h))
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def scan_dev_caches(cleaner):
    # type: (Cleaner) -> None
    """The three fixed developer cache directories (trash contents)."""
    if not cleaner.selected("dev_caches"):
        return
    for rel in DEV_CACHE_RELS:
        cleaner.walk_explicit_dir(rel, "dev_caches")


def scan_usertools_old(cleaner):
    # type: (Cleaner) -> None
    """The plugin's own job files and undo journals (delete, 30d+ only).

    Per tool prefix (first filename segment) the newest three entries are
    always kept, whatever their age; anything younger than 30 days is kept
    too. Unknown files and live-job files are never touched.
    """
    if not cleaner.selected("usertools_old"):
        return
    cutoff = time.time() - USERTOOLS_OLD_DAYS * 86400
    scan_old_dir(cleaner, JOBS_DIR_REL, True, cutoff)
    scan_old_dir(cleaner, UNDO_DIR_REL, False, cutoff)


def scan_old_dir(cleaner, rel, is_jobs, cutoff):
    # type: (Cleaner, str, bool, float) -> None
    """Collect stale plugin files in one fixed directory for deletion."""
    home = cleaner.home
    full = os.path.join(home, rel)
    try:
        dst = os.lstat(full)
    except OSError:
        return
    if not stat.S_ISDIR(dst.st_mode) or stat.S_ISLNK(dst.st_mode):
        return
    if dst.st_uid != cleaner.uid or dst.st_dev != cleaner.top_dev:
        return
    try:
        names = sorted(os.listdir(full))
    except OSError as exc:
        cleaner.summary["counts"]["errors"] += 1
        _add_capped(cleaner.summary, "errors",
                    {"path": rel, "reason": "cannot list: %s" % exc})
        return
    entries = []
    for name in names:
        if is_jobs:
            base = None
            for suffix in JOB_SUFFIXES:
                if name.endswith(suffix):
                    base = name[: -len(suffix)]
                    break
            if base is None or not base:
                continue
        else:
            if not name.endswith(".jsonl.gz") or "-" not in name:
                continue
            base = name
        path = os.path.join(full, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        cleaner.done += 1
        cleaner.poll()
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            continue
        if st.st_uid != cleaner.uid or st.st_dev != cleaner.top_dev:
            cleaner.note_not_owned(rel + "/" + name, st)
            continue
        if st.st_nlink != 1:
            cleaner.record_skip("skipped_hardlink", rel + "/" + name,
                                "more than one hard link; left alone")
            continue
        entries.append((name, base, st))
    groups = {}
    for name, base, st in entries:
        prefix = base.split("-", 1)[0]
        groups.setdefault(prefix, []).append((name, base, st))
    for prefix, group in groups.items():
        group.sort(key=lambda e: (e[2].st_mtime, e[0]))
        keep = set(e[0] for e in group[-UNDO_KEEP:])
        for name, base, st in group:
            hrel = rel + "/" + name
            if name in keep or st.st_mtime > cutoff:
                continue
            cleaner.tally_top(hrel, st.st_size)
            cleaner.found("usertools_old", hrel, st.st_size,
                          lambda h=hrel: delete_old_file(cleaner, h))


def delete_old_file(cleaner, hrel):
    # type: (Cleaner, str) -> int
    """Delete one verified plugin file; returns bytes freed."""
    full = os.path.join(cleaner.home, hrel)
    try:
        st = os.lstat(full)
    except OSError as exc:
        raise pe.UsageError("lost race on %s: %s" % (hrel, exc))
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != cleaner.uid or st.st_nlink != 1 \
            or st.st_dev != cleaner.top_dev:
        raise pe.UsageError("%s changed during the run; left alone" % hrel)
    freed = st.st_size
    os.unlink(full)
    _add_capped(cleaner.summary, "deleted", {"path": hrel})
    return freed


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def run_scan(cleaner, home, prune_days):
    # type: (Cleaner, str, int) -> None
    """Full-home walk plus explicit roots; prune old trash batches first."""
    prune_trash(home, cleaner.summary, prune_days)
    fd = cleaner.open_dir(home, None, ".")
    if fd is None:
        return
    try:
        cleaner.walk_open(fd, ".", True, None)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    scan_php_logs(cleaner)
    scan_dev_caches(cleaner)
    scan_usertools_old(cleaner)


def run_restore(home, uid, summary, batch):
    # type: (str, int, dict, str) -> None
    """Put one trash batch back; conflicts reported, never overwritten."""
    root = os.path.join(trash_dir(home), batch)
    try:
        dst = os.lstat(root)
    except OSError:
        raise pe.UsageError("unknown trash batch: %s" % batch)
    if not stat.S_ISDIR(dst.st_mode) or stat.S_ISLNK(dst.st_mode):
        raise pe.UsageError("unknown trash batch: %s" % batch)
    if dst.st_uid != uid:
        raise pe.UsageError("trash batch is not yours; left alone")
    entries = read_manifest(root)
    restored = 0
    for ent in entries:
        hrel = ent["path"]
        try:
            if _restore_one(home, uid, summary, root, hrel):
                restored += 1
        except pe.UsageError as exc:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel, "reason": str(exc)})
        except OSError as exc:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel, "reason": "cannot restore: %s" % exc})
    summary["counts"]["restored_files"] = restored
    summary["counts"]["changed"] = restored
    try:
        os.rmdir(root)
    except OSError:
        pass


def _restore_one(home, uid, summary, root, hrel):
    # type: (str, int, dict, str, str) -> bool
    """Restore one manifest entry; True when the file came back."""
    src = os.path.join(root, hrel)
    dst_path = os.path.join(home, hrel)
    try:
        st = os.lstat(src)
    except OSError as exc:
        raise pe.UsageError("lost in trash: %s" % exc)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != uid or st.st_nlink != 1:
        raise pe.UsageError("trash copy changed; left in trash")
    if os.path.lexists(dst_path):
        summary["counts"]["restore_conflicts"] += 1
        _add_capped(summary, "errors",
                    {"path": hrel,
                     "reason": "already exists; left the trash copy in place"})
        return False
    _ensure_restore_parents(home, hrel)
    os.rename(src, dst_path)
    _add_capped(summary, "restored", {"path": hrel})
    return True


def run_empty(home, uid, summary, batch):
    # type: (str, int, dict, object) -> None
    """Delete one batch (or all batches); cannot be undone."""
    root = trash_dir(home)
    if batch is None:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            return
        targets = [n for n in names if BATCH_RE.match(n)]
    else:
        targets = [batch]
    emptied = 0
    for name in targets:
        full = os.path.join(root, name)
        try:
            dst = os.lstat(full)
        except OSError:
            continue
        if not stat.S_ISDIR(dst.st_mode) or stat.S_ISLNK(dst.st_mode):
            continue
        if dst.st_uid != uid:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": os.path.join(TRASH_DIRNAME, name),
                         "reason": "not yours; left alone"})
            continue
        try:
            safe_rmtree(full)
            emptied += 1
        except pe.UsageError as exc:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": os.path.join(TRASH_DIRNAME, name),
                         "reason": str(exc)})
    summary["counts"]["changed"] = emptied
# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_categories(values):
    # type: (object) -> object
    """Split repeatable/comma-separated --category flags; None when empty."""
    picked = []
    for value in values or []:
        for part in str(value).split(","):
            part = part.strip()
            if part:
                picked.append(part)
    if not picked:
        return None
    unknown = [c for c in picked if c not in CATEGORIES]
    if unknown:
        raise pe.UsageError(
            "unknown category %r (choose from: %s)" % (unknown[0], ", ".join(CATEGORIES)))
    seen = []
    for cid in picked:
        if cid not in seen:
            seen.append(cid)
    return seen


def build_parser():
    # type: () -> argparse.ArgumentParser
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--category", action="append", default=[],
                        help="category to include (repeatable; default: all)")
    parent.add_argument("--batch", default=None,
                        help="trash batch id (restore/empty one batch)")
    parent.add_argument("--all", dest="all_batches", action="store_true",
                        default=False, help="empty every trash batch")
    parent.add_argument("--json-progress", default=None, metavar="FILE",
                        help="write progress JSON here every N entries")
    parent.add_argument("--progress-every", type=int,
                        default=pe.DEFAULT_PROGRESS_EVERY,
                        help="progress write interval (default %d)"
                             % pe.DEFAULT_PROGRESS_EVERY)
    parent.add_argument("--policy", default=None,
                        help="policy file (default %s if present)"
                             % pe.DEFAULT_POLICY_PATH)
    parent.add_argument("--lock-dir", default=None,
                        help="lock directory (default ~/.cpanel/usertools)")
    parent.add_argument("--home", default=None,
                        help="home directory for confinement checks "
                             "(test hook only; requires USERTOOLS_TESTING=1 "
                             "in the environment; default: your real home)")
    parser = argparse.ArgumentParser(
        prog="space_cleaner.py",
        description="Unprivileged disk-space cleaner inside your home directory.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("clean-scan", parents=[parent],
                   help="report reclaimable clutter (never deletes)")
    sub.add_parser("clean-run", parents=[parent],
                   help="move to trash, truncate logs, delete old plugin files")
    sub.add_parser("trash-restore", parents=[parent],
                   help="put one trash batch back")
    sub.add_parser("trash-empty", parents=[parent],
                   help="delete trash batches (cannot be undone)")
    return parser


def main(argv=None):
    # type: (object) -> int
    pe.refuse_if_privileged()
    uid = os.getuid()

    try:
        signal.signal(signal.SIGTERM, pe._sigterm_handler)
    except (OSError, ValueError):
        pass  # no SIGTERM here; timeouts still bound the run

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.home is not None and \
            os.environ.get("USERTOOLS_TESTING") != "1":
        pe.eprint("error: --home is a test-only option")
        return pe.EXIT_USAGE

    try:
        home = pe.resolve_home(args.home)
        categories = parse_categories(args.category)
        if args.command == "clean-run" and not categories:
            raise pe.UsageError("clean-run needs at least one --category")
        if args.command == "trash-restore":
            batch = parse_batch_id(args.batch)
        elif args.command == "trash-empty":
            if args.all_batches and args.batch:
                raise pe.UsageError("trash-empty takes --batch or --all, not both")
            batch = parse_batch_id(args.batch) if args.batch else None
        else:
            batch = None
    except pe.UsageError as exc:
        pe.eprint("error: %s" % exc)
        return pe.EXIT_USAGE

    pe.apply_resource_limits()

    policy = pe.load_policy(args.policy)
    limit = pe.max_job_seconds(policy)
    log_min_mb = policy_int(policy, POLICY_LOG_MIN_MB, DEFAULT_LOG_MIN_MB,
                            *LOG_MIN_MB_RANGE)
    trash_days = policy_int(policy, POLICY_TRASH_DAYS, DEFAULT_TRASH_DAYS,
                            *TRASH_DAYS_RANGE)
    start = time.monotonic()
    deadline = start + limit  # limit is always positive (see max_job_seconds)

    lock_dir = args.lock_dir or os.path.join(home, ".cpanel", "usertools")
    lock = pe.JobLock(lock_dir)
    try:
        lock.acquire()
    except pe.BusyError as exc:
        pe.eprint("error: %s" % exc)
        return pe.EXIT_BUSY
    except pe.UsageError as exc:
        pe.eprint("error: %s" % exc)
        return pe.EXIT_USAGE

    acting = args.command != "clean-scan"
    dry_run = not acting
    summary = new_clean_summary(args.command, home, dry_run)

    progress_path = args.json_progress
    progress_every = args.progress_every if args.progress_every > 0 else 0

    def progress_cb(done, summ):
        # type: (int, dict) -> None
        if not progress_path:
            return
        pe.write_progress_file(progress_path, {
            "command": summ["command"],
            "scope": summ["scope"],
            "scanned": summ["counts"]["scanned"],
            "changed": summ["counts"]["changed"],
            "would_change": summ["counts"]["would_change"],
            "not_owned": summ["counts"]["not_owned"],
            "errors": summ["counts"]["errors"],
            "timed_out": summ["timed_out"],
            "interrupted": summ["interrupted"],
            "elapsed_seconds": round(time.monotonic() - start, 3),
        })

    def finish(code):
        # type: (int) -> int
        """Emit the JSON summary (partial on timeout/resource abort)."""
        totals = trash_size(home)
        summary["trash"] = {"bytes": totals[0], "batches": totals[1]}
        finalize_largest(summary)
        by_size = sorted(cleaner.top_stats.items(),
                         key=lambda kv: (-kv[1][0], kv[0]))
        by_inodes = sorted(cleaner.top_stats.items(),
                           key=lambda kv: (-kv[1][1], kv[0]))
        summary["top_dirs_size"] = [
            {"path": path, "bytes": vals[0]} for path, vals in by_size[:TOP_N]]
        summary["top_dirs_inodes"] = [
            {"path": path, "inodes": vals[1]} for path, vals in by_inodes[:TOP_N]]
        summary["elapsed_seconds"] = round(time.monotonic() - start, 3)
        if progress_path:
            progress_cb(summary["counts"]["scanned"], summary)
        sys.stdout.write(json.dumps(summary, ensure_ascii=True, default=str,
                                    indent=2) + "\n")
        sys.stdout.flush()
        return code

    try:
        top_st = os.stat(home)
    except OSError as exc:
        pe.eprint("error: cannot stat home: %s" % exc)
        return pe.EXIT_USAGE
    floors = {"log_min_bytes": log_min_mb * 1024 * 1024}
    cleaner = Cleaner(home, uid, summary, progress_cb, deadline,
                      progress_every, top_st.st_dev, categories, floors, acting)
    try:
        if args.command in ("clean-scan", "clean-run"):
            try:
                run_scan(cleaner, home, trash_days)
            except _WalkDone:
                pass
            if cleaner.trash_entries:
                write_manifest(os.path.join(trash_dir(home),
                                            cleaner.trash_batch),
                               cleaner.trash_entries)
        elif args.command == "trash-restore":
            run_restore(home, uid, summary, batch)
        elif args.command == "trash-empty":
            run_empty(home, uid, summary, batch)
        else:  # pragma: no cover - argparse required=True guards this
            raise pe.UsageError("unknown command: %r" % (args.command,))
    except pe.UsageError as exc:
        pe.eprint("error: %s" % exc)
        return finish(pe.EXIT_USAGE)
    except pe.ResourceLimitError as exc:
        summary["resource_limited"] = True
        pe.eprint("error: %s; run aborted, results are partial" % exc)
        return finish(pe.EXIT_RESOURCE)
    except _WalkDone:
        return finish(pe.EXIT_TIMEOUT)
    except Exception as exc:  # defensive: no partial-success confusion
        pe.eprint("error: run failed: %s" % exc)
        return finish(pe.EXIT_FAIL)
    if summary["timed_out"] or summary["interrupted"]:
        return finish(pe.EXIT_TIMEOUT)
    return finish(pe.EXIT_OK)


if __name__ == "__main__":
    sys.exit(main())

