#!/usr/bin/python3
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""perm_engine.py - unprivileged permission walker for UserTools for cPanel.

Runs ONLY as an unprivileged cPanel user. It checks, fixes (chmod) and
reports on file modes inside the caller's home directory. It never changes
ownership (no chown/chgrp anywhere) and refuses to run as root.

Security properties (each covered by tests/test_perm_engine.py):

  * Never follows symlinks. Directories are opened with O_NOFOLLOW and every
    stat/chmod uses dir_fd with follow_symlinks=False. Symlinks are skipped.
    Directory fds are held only along the current path (bounded by depth);
    EMFILE/ENFILE aborts with a non-zero exit, never a partial "success".
  * Stays on one filesystem: entries whose st_dev differs from the scope top
    are skipped.
  * Confined to the caller's home: the scope is canonicalised with realpath
    and must lie inside the caller's home directory. Exclude globs are
    validated (no absolute paths, no "..", max 20).
  * Refuses to run as root (euid == 0) or in a setuid context (euid != uid).
  * Only regular files and directories are processed; sockets, FIFOs and
    device nodes are skipped. Targets never include setuid/setgid bits, so
    bulk chmod clears them on files it changes.
  * Entries not owned by the caller are never touched; they are recorded as
    not_owned with the owner name (feeds the Ownership Report).
  * Engine-enforced protected paths (check/chmod only, no opt-out):
    top-level dotfiles/dotdirs and etc/mail/ssl/tmp/logs/access-logs are
    never processed or descended into; public_html/public_ftp are descended
    but their own mode is never changed (Fix Home owns it).

Usage:
  perm_engine.py {check,chmod,report,undo} [--scope PATH] [--exclude GLOB ...]
      [--dry-run] [--json-progress FILE] [options]

  check   - report what *would* change to the target modes (never changes).
  chmod   - change modes (unless --dry-run). Streams an undo journal of
            previous modes (unless --no-undo).
  report  - list entries not owned by the caller, grouped by owner.
  undo    - restore modes recorded in an undo journal (--journal, required).
  scan-apps - read-only Laravel app detection (max depth 4, never changes).

Undo journals (shared with the Fix Home UAPI module) are
gzip JSON lines at ~/.cpanel/usertools/undo/<tool>-<timestamp>.jsonl.gz:
a header line {"v":1,"tool":..,"home":..,"scope":..,"started":..} then one
{"path": home_relative, "from": "0600", "to": "0644"} line per change.
Only the newest 3 journals are kept. Undo never restores setuid/setgid/
sticky bits and skips entries that are now symlinks, unowned, changed since,
or outside the home.

Exit codes: 0 ok, 2 usage/validation/refusal, 3 another job running,
4 resource limit (EMFILE/ENFILE: partial run, summary still printed),
5 timed out or interrupted by SIGTERM (partial run, summary still printed),
1 unexpected failure.
"""

import argparse
import errno
import fnmatch
import gzip
import json
import os
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms (engine targets Linux)
    fcntl = None  # type: ignore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_FILE_MODE = 0o644
TARGET_DIR_MODE = 0o755

# --harden-sensitive targets (opt-in): exact basenames only.
HARDEN_MODES = {
    "wp-config.php": 0o640,
    ".env": 0o600,
}

EXEC_KEEP_SUFFIXES = (".cgi", ".pl", ".sh")
EXEC_KEEP_DIRNAMES = ("cgi-bin", "bin", ".bin")

# scan-apps: read-only Laravel app detection.
SCAN_MAX_DEPTH = 4
SCAN_COMPOSER_MAX_BYTES = 65536
SCAN_LOCK_MAX_BYTES = 1048576

# Engine-enforced protected paths.
# Relative to the caller's home; always active for check/chmod, no flag to
# disable; callers can only add excludes on top. `report` is exempt (read-only
# and must still see root/nobody-owned files under these paths).
# Rule 1: entries whose home-relative first component is a dotfile/dotdir or
# one of these names are never processed and never descended into.
PROTECTED_TOP_NAMES = frozenset(
    ["etc", "mail", "ssl", "tmp", "logs", "access-logs"]
)
# Rule 2: these home-relative directories are descended but their own mode is
# never changed (Fix Home owns their modes).
MODE_KEEP_TOP_DIRS = frozenset(["public_html", "public_ftp"])

MAX_EXCLUDES = 20
MAX_PATHS_PER_CATEGORY = 500

DEFAULT_MAX_JOB_SECONDS = 3600
DEFAULT_PROGRESS_EVERY = 500
DEFAULT_POLICY_PATH = "/etc/usertools.conf"
DEFAULT_LOCK_NAME = "perm_engine.lock"

UNDO_KEEP = 3
JOURNAL_VERSION = 1

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BUSY = 3
EXIT_RESOURCE = 4
EXIT_TIMEOUT = 5
EXIT_FAIL = 1


# Set by the SIGTERM handler installed in main(); run_walk and run_undo poll
# it so a terminated job stops cleanly with partial-summary semantics.
_stop_requested = False


def request_stop():
    # type: () -> None
    global _stop_requested
    _stop_requested = True


def stop_requested():
    # type: () -> bool
    return _stop_requested


def _sigterm_handler(signum, frame):
    # type: (Any, Any) -> None
    request_stop()


class UsageError(Exception):
    """Invalid CLI usage or failed validation (exit 2)."""


class BusyError(Exception):
    """Another job is already running for this user (exit 3)."""


class ResourceLimitError(Exception):
    """Out of file descriptors: abort, do not report partial success (exit 4)."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def eprint(msg):
    # type: (str) -> None
    sys.stderr.write(str(msg) + "\n")


def parse_mode(text):
    # type: (str) -> int
    """Parse an octal mode string (644, 0644, 0o644). Strips special bits."""
    t = text.strip().lower()
    if t.startswith("0o"):
        t = t[2:]
    try:
        mode = int(t, 8)
    except ValueError:
        raise UsageError("invalid mode: %r (use e.g. 644)" % text)
    if mode < 0 or mode > 0o7777:
        raise UsageError("mode out of range: %r (use e.g. 644)" % text)
    stripped = mode & ~0o7000  # never set setuid/setgid/sticky
    if stripped != mode:
        eprint("warning: special mode bits are never set; using %04o" % stripped)
    return stripped


def owner_name(uid):
    # type: (int) -> str
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def current_home():
    # type: () -> str
    return pwd.getpwuid(os.getuid()).pw_dir


# ---------------------------------------------------------------------------
# Startup guards
# ---------------------------------------------------------------------------

def refuse_if_privileged():
    # type: () -> None
    """Refuse to run as root or in a setuid/seteuid context."""
    if os.geteuid() == 0:
        eprint("refusing to run as root (uid 0)")
        raise SystemExit(EXIT_USAGE)
    if os.geteuid() != os.getuid():
        eprint("refusing to run with euid != uid (setuid context)")
        raise SystemExit(EXIT_USAGE)


def apply_resource_limits():
    # type: () -> None
    """nice(10) + ionice -c3 (best effort; failures only warn)."""
    try:
        os.nice(10)
    except OSError as exc:
        eprint("warning: nice(10) failed: %s" % exc)
    ionice = shutil.which("ionice")
    if ionice is None:
        return
    try:
        subprocess.run(
            [ionice, "-c3", "-p", str(os.getpid())],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except Exception as exc:  # missing binary, timeout, etc.
        eprint("warning: ionice failed: %s" % exc)


def load_policy(path):
    # type: (Optional[str]) -> Dict[str, str]
    """Read key=value pairs (with or without an INI section header)."""
    values = {}  # type: Dict[str, str]
    if path is None:
        path = DEFAULT_POLICY_PATH
        if not os.path.isfile(path):
            return values
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if line.startswith("["):
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.split(";")[0].split("#")[0].strip()
                if key:
                    values[key] = val
    except OSError as exc:
        eprint("warning: cannot read policy file %s: %s (using defaults)"
               % (path, exc))
    return values


def max_job_seconds(policy):
    # type: (Dict[str, str]) -> int
    """Seconds before a run times out. Missing/invalid/non-positive values
    fall back to the default (a non-positive limit would time out instantly,
    which is never what the admin meant)."""
    raw = policy.get("max_job_seconds")
    if raw is None:
        return DEFAULT_MAX_JOB_SECONDS
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value <= 0:
        eprint("warning: invalid max_job_seconds %r; using default %d"
               % (raw, DEFAULT_MAX_JOB_SECONDS))
        return DEFAULT_MAX_JOB_SECONDS
    return value


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_excludes(patterns):
    # type: (List[str]) -> List[str]
    """Reject dangerous exclude globs. Returns the cleaned list."""
    if len(patterns) > MAX_EXCLUDES:
        raise UsageError("too many --exclude patterns (max %d)"
                         % MAX_EXCLUDES)
    clean = []
    for pat in patterns:
        p = pat.strip()
        if not p:
            raise UsageError("empty --exclude pattern")
        if p.startswith("/"):
            raise UsageError("exclude must be relative, not absolute: %r"
                             % pat)
        parts = [seg for seg in p.replace("\\", "/").split("/") if seg not in ("", ".")]
        if ".." in parts:
            raise UsageError("exclude must not contain '..': %r" % pat)
        clean.append(p)
    return clean


def resolve_home(home_override):
    # type: (Optional[str]) -> str
    """Caller's home directory. The override is a test hook, honoured only
    with USERTOOLS_TESTING=1 in the environment (enforced in main); the UAPI
    layer must never pass it."""
    if home_override:
        home = os.path.realpath(home_override)
        if not os.path.isdir(home):
            raise UsageError("--home is not a directory: %r" % home_override)
        return home
    return os.path.realpath(current_home())


def home_relpath(path, home):
    # type: (str, str) -> str
    """home-relative path with '/' separators ('.' when equal to home)."""
    return os.path.relpath(path, home).replace(os.sep, "/")


def is_protected_entry(home_rel):
    # type: (str) -> bool
    """Rule-1 protected path: top-level dotfile/dotdir or one of
    PROTECTED_TOP_NAMES. `home_rel` is home-relative ('.' never matches)."""
    first = home_rel.split("/", 1)[0]
    return bool(first) and first != "." and (
        first.startswith(".") or first in PROTECTED_TOP_NAMES)


def is_mode_keep_dir(home_rel):
    # type: (str) -> bool
    """Rule-2 path: descended, but its own mode is never changed."""
    return home_rel in MODE_KEEP_TOP_DIRS


def resolve_scope(scope, home):
    # type: (str, str) -> str
    """Canonicalise scope; it must be a directory inside home and must not
    itself lie inside a rule-1 protected path."""
    real = os.path.realpath(scope)
    if real != home and os.path.commonpath([home, real]) != home:
        raise UsageError("scope %r is outside your home directory" % scope)
    if not os.path.isdir(real):
        raise UsageError("scope is not a directory: %r" % scope)
    if is_protected_entry(home_relpath(real, home)):
        raise UsageError("scope %r is inside a protected path and cannot "
                         "be processed" % scope)
    return real


def matches_exclude(relpath, patterns):
    # type: (str, List[str]) -> bool
    """Match a '/'-separated scope-relative path against exclude globs."""
    base = relpath.rsplit("/", 1)[-1]
    for pat in patterns:
        p = pat.replace("\\", "/")
        if "/" in p:
            if fnmatch.fnmatch(relpath, p):
                return True
        else:
            if fnmatch.fnmatch(base, p) or fnmatch.fnmatch(relpath, p):
                return True
    return False


# ---------------------------------------------------------------------------
# Mode decisions
# ---------------------------------------------------------------------------

def path_keep_exec(relpath):
    # type: (str) -> bool
    """Path-based keep-exec match: a bin-ish directory or script suffix."""
    parts = relpath.split("/")
    base = relpath.rsplit("/", 1)[-1]
    return (any(d in parts for d in EXEC_KEEP_DIRNAMES)
            or base.endswith(EXEC_KEEP_SUFFIXES))


def desired_mode(relpath, is_dir, current_mode, file_mode, dir_mode,
                 keep_exec, harden, exec_magic=False):
    # type: (str, bool, int, int, int, bool, bool, bool) -> int
    """Target mode for an entry (special bits never included).

    With keep_exec (default on), a file that already has an exec bit keeps
    0755 when it is under cgi-bin/bin/.bin, has a script suffix, or starts
    with shebang (#!) / ELF magic (exec_magic=True, read by the caller).
    """
    if is_dir:
        return dir_mode & ~0o7000
    base = relpath.rsplit("/", 1)[-1]
    if harden and base in HARDEN_MODES:
        return HARDEN_MODES[base]
    if keep_exec and current_mode & 0o111:
        if path_keep_exec(relpath):
            return 0o755
        if exec_magic:
            return 0o755
    return file_mode & ~0o7000


def read_magic(dir_fd, name):
    # type: (int, str) -> bytes
    """First 4 bytes of a regular file, via O_NOFOLLOW|O_NONBLOCK open
    relative to dir_fd. Returns b"" on any failure (symlink, race, etc.)."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=dir_fd)
    except OSError:
        return b""
    try:
        return os.read(fd, 4)
    except OSError:
        return b""
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def looks_executable(magic):
    # type: (bytes) -> bool
    """True for shebang scripts and ELF binaries (first-bytes sniff)."""
    return magic[:2] == b"#!" or magic[:4] == b"\x7fELF"


def read_capped(dir_fd, name, cap):
    # type: (int, str, int) -> Any
    """Bytes of a regular file via O_NOFOLLOW open, capped; None on failure."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=dir_fd)
    except OSError:
        return None
    try:
        chunks = []
        remaining = cap + 1
        while remaining > 0:
            try:
                data = os.read(fd, min(65536, remaining))
            except OSError:
                return None
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        blob = b"".join(chunks)
        if len(blob) > cap:
            return None  # over cap: treat as unreadable for our purposes
        return blob
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def check_app_dir(dir_fd, home_rel):
    # type: (int, str) -> Any
    """Laravel app probe: artisan file + vendor/autoload.php + composer.json
    requiring laravel/framework (all regular files, never following
    symlinks). Returns {path, framework_version} or None."""
    try:
        st = os.stat("artisan", dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            return None
        vst = os.stat("vendor", dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISDIR(vst.st_mode):
            return None
        vendor_fd = os.open("vendor", os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        try:
            ast = os.stat("autoload.php", dir_fd=vendor_fd,
                          follow_symlinks=False)
            if not stat.S_ISREG(ast.st_mode):
                return None
        except OSError:
            return None
    finally:
        try:
            os.close(vendor_fd)
        except OSError:
            pass
    blob = read_capped(dir_fd, "composer.json", SCAN_COMPOSER_MAX_BYTES)
    if blob is None:
        return None
    try:
        composer = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(composer, dict):
        return None
    require = composer.get("require")
    if not isinstance(require, dict) or "laravel/framework" not in require:
        return None
    version = ""
    lock_blob = read_capped(dir_fd, "composer.lock", SCAN_LOCK_MAX_BYTES)
    if lock_blob is not None:
        try:
            lock = json.loads(lock_blob.decode("utf-8"))
            packages = lock.get("packages", []) if isinstance(lock, dict) else []
            for pkg in packages:
                if isinstance(pkg, dict) and pkg.get("name") == "laravel/framework":
                    ver = pkg.get("version", "")
                    version = ver[1:] if ver.startswith("v") else ver
                    break
        except (ValueError, UnicodeDecodeError, AttributeError):
            pass
    return {"path": home_rel, "framework_version": version}


# ---------------------------------------------------------------------------
# Locking (one job per user)
# ---------------------------------------------------------------------------

class JobLock(object):
    """Exclusive non-blocking flock on <lock_dir>/perm_engine.lock."""

    def __init__(self, lock_dir):
        # type: (str) -> None
        self.lock_dir = lock_dir
        self.path = os.path.join(lock_dir, DEFAULT_LOCK_NAME)
        self._fh = None  # type: Any

    def acquire(self):
        # type: () -> None
        try:
            os.makedirs(self.lock_dir, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise UsageError("cannot create lock dir %r: %s"
                             % (self.lock_dir, exc))
        try:
            self._fh = open(self.path, "a+b")
        except OSError as exc:
            raise UsageError("cannot open lock file %r: %s" % (self.path, exc))
        if fcntl is None:
            eprint("warning: fcntl unavailable; single-job lock not enforced")
            return
        try:
            fcntl.flock(self._fh.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            self._fh.close()
            self._fh = None
            raise BusyError("another UserTools job is already running")

    def release(self):
        # type: () -> None
        try:
            if self._fh is not None and fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            if self._fh is not None:
                self._fh.close()
                self._fh = None


# ---------------------------------------------------------------------------
# Undo journals
# ---------------------------------------------------------------------------

def default_undo_dir(home):
    # type: (str) -> str
    return os.path.join(home, ".cpanel", "usertools", "undo")


def journal_timestamp():
    # type: () -> str
    now = time.time()
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime(now)) + "-%06d-%d" % (
        int((now % 1) * 1000000), os.getpid())


def validate_home_rel(rel):
    # type: (str) -> str
    """Clean a home-relative path or raise UsageError (no abs, no '..')."""
    if not rel or not isinstance(rel, str):
        raise UsageError("invalid journal path: %r" % (rel,))
    p = rel.replace("\\", "/").strip("/")
    parts = [seg for seg in p.split("/") if seg not in ("", ".")]
    if not parts or ".." in parts:
        raise UsageError("invalid journal path: %r" % (rel,))
    return "/".join(parts)


def parse_octal_mode(text):
    # type: (str) -> int
    try:
        mode = int(str(text).strip(), 8)
    except ValueError:
        raise UsageError("invalid mode in journal: %r" % (text,))
    if mode < 0 or mode > 0o7777:
        raise UsageError("mode out of range in journal: %r" % (text,))
    return mode


class UndoJournal(object):
    """Streaming gzip-jsonl writer of previous modes. Best effort: open
    failures warn and disable journaling for the run, never abort it."""

    def __init__(self, tmp_path, final_path, tool, home, scope):
        # type: (str, str, str, str, str) -> None
        self.tmp_path = tmp_path
        self.final_path = final_path
        self.fh = gzip.open(tmp_path, "wt", encoding="utf-8")
        self.fh.write(json.dumps({
            "v": JOURNAL_VERSION, "tool": tool, "home": home,
            "scope": scope, "started": time.time(),
        }, ensure_ascii=True) + "\n")

    def append(self, home_rel, frm, to):
        # type: (str, int, int) -> None
        self.fh.write(json.dumps({
            "path": home_rel,
            "from": "%04o" % (frm & 0o7777),
            "to": "%04o" % (to & 0o7777),
        }, ensure_ascii=True) + "\n")

    def close(self):
        # type: () -> str
        self.fh.close()
        os.replace(self.tmp_path, self.final_path)
        return self.final_path


def open_journal(undo_dir, tool, home, scope):
    # type: (str, str, str, str) -> Any
    """Create the undo dir and open a new journal; None (with warning) if the
    filesystem refuses."""
    try:
        os.makedirs(undo_dir, mode=0o700, exist_ok=True)
    except OSError as exc:
        eprint("warning: cannot create undo dir %s: %s (no undo journal)"
               % (undo_dir, exc))
        return None
    name = "%s-%s.jsonl.gz" % (tool, journal_timestamp())
    tmp_path = os.path.join(undo_dir, name + ".tmp")
    final_path = os.path.join(undo_dir, name)
    try:
        return UndoJournal(tmp_path, final_path, tool, home, scope)
    except OSError as exc:
        eprint("warning: cannot write undo journal %s: %s (no undo journal)"
               % (final_path, exc))
        return None


def prune_journals(undo_dir, keep=UNDO_KEEP, protect_name=None,
                   max_tmp_age=DEFAULT_MAX_JOB_SECONDS):
    # type: (str, int, Optional[str], int) -> None
    """Keep the newest `keep` journals PER TOOL PREFIX (sorted by the
    timestamp in the name); never prune `protect_name`; drop `.tmp` files
    only when older than `max_tmp_age` seconds so another running job's temp
    file is never deleted. Never fails a run (warns only)."""
    try:
        names = sorted(os.listdir(undo_dir))
    except OSError:
        return
    now = time.time()
    for name in names:
        if name.endswith(".tmp"):
            tpath = os.path.join(undo_dir, name)
            try:
                st = os.lstat(tpath)
                if now - st.st_mtime <= max_tmp_age:
                    continue
                os.unlink(tpath)
            except OSError:
                pass
    by_tool = {}  # type: Dict[str, List[str]]
    for name in names:
        if not name.endswith(".jsonl.gz") or "-" not in name:
            continue
        prefix = name.split("-", 1)[0]
        by_tool.setdefault(prefix, []).append(name)
    for prefix, group in by_tool.items():
        group.sort(key=lambda n: n.split("-", 1)[1])
        stale_list = [
            n for n in group[:max(0, len(group) - keep)]
            if n != protect_name
        ]
        for stale in stale_list:
            try:
                os.unlink(os.path.join(undo_dir, stale))
            except OSError as exc:
                eprint("warning: cannot prune old journal %s: %s" % (stale, exc))


def parse_journal(path):
    # type: (str) -> Any
    """Read a journal file; returns (header, records) or raises UsageError."""
    try:
        fh = gzip.open(path, "rt", encoding="utf-8")
    except OSError as exc:
        raise UsageError("cannot read journal %s: %s" % (path, exc))
    try:
        lines = fh.read().splitlines()
    except (OSError, EOFError) as exc:
        raise UsageError("cannot parse journal %s: %s" % (path, exc))
    finally:
        try:
            fh.close()
        except OSError:
            pass
    if not lines:
        raise UsageError("journal %s is empty" % path)
    try:
        header = json.loads(lines[0])
    except ValueError:
        raise UsageError("journal %s has a bad header" % path)
    if not isinstance(header, dict) or header.get("v") != JOURNAL_VERSION:
        raise UsageError("journal %s has an unsupported version" % path)
    records = []
    for i, line in enumerate(lines[1:], 1):
        try:
            rec = json.loads(line)
        except ValueError:
            raise UsageError("journal %s has a bad record on line %d"
                             % (path, i + 1))
        if not isinstance(rec, dict):
            raise UsageError("journal %s has a bad record on line %d"
                             % (path, i + 1))
        rel = validate_home_rel(rec.get("path", ""))
        frm = parse_octal_mode(rec.get("from", ""))
        to = parse_octal_mode(rec.get("to", ""))
        records.append({"path": rel, "from": frm, "to": to})
    return header, records


# ---------------------------------------------------------------------------
# Summary bookkeeping
# ---------------------------------------------------------------------------

def new_summary(command, scope, dry_run):
    # type: (str, str, bool) -> Dict[str, Any]
    return {
        "command": command,
        "scope": scope,
        "dry_run": dry_run,
        "counts": {
            "scanned": 0,
            "changed": 0,
            "would_change": 0,
            "apps": 0,
            "skipped_symlink": 0,
            "skipped_excluded": 0,
            "skipped_protected": 0,
            "skipped_xdev": 0,
            "skipped_special": 0,
            "skipped_changed_since": 0,
            "not_owned": 0,
            "errors": 0,
            "cleared_suid_sgid": 0,
            "stripped_suid_sgid": 0,
        },
        "not_owned_by": {},  # type: Dict[str, int]
        "paths": {
            "changed": [],
            "would_change": [],
            "apps": [],
            "not_owned": [],
            "errors": [],
            "skipped_symlink": [],
            "skipped_protected": [],
            "skipped_xdev": [],
            "skipped_special": [],
        },
        "omitted": {},  # type: Dict[str, int]
        "timed_out": False,
        "interrupted": False,
        "resource_limited": False,
        "undo_journal": None,
        "elapsed_seconds": 0.0,
    }


def add_path(summary, category, value):
    # type: (Dict[str, Any], str, Any) -> None
    lst = summary["paths"][category]
    if len(lst) < MAX_PATHS_PER_CATEGORY:
        lst.append(value)
    else:
        summary["omitted"][category] = summary["omitted"].get(category, 0) + 1


def bump(summary, counter):
    # type: (Dict[str, Any], str) -> None
    summary["counts"][counter] += 1


# ---------------------------------------------------------------------------
# The walk (fd-relative, never following symlinks)
# ---------------------------------------------------------------------------

def _is_resource_error(exc):
    # type: (BaseException) -> bool
    """True for EMFILE/ENFILE: out of file descriptors."""
    return isinstance(exc, OSError) and exc.errno in (errno.EMFILE,
                                                     errno.ENFILE)


def run_walk(top, home, uid, opts, summary, progress_cb):
    # type: (str, str, int, Dict[str, Any], Dict[str, Any], Any) -> None
    """Walk top with O_NOFOLLOW + dir_fd-relative stat/chmod.

    Only ONE directory fd is open at a time: each directory is opened,
    listed, processed (children are stat'ed/chmod'ed via its fd) and closed
    before descending. Subdirectories are reopened by absolute path with
    O_NOFOLLOW and verified against the (dev, ino) seen from the parent, so
    a swapped path is detected instead of followed. Memory aside, neither fd
    use (depth-independent) nor Python recursion limits tree depth.

    Why reopen-by-path is safe here: symlinks can never be opened
    (O_NOFOLLOW) or chmod'ed (skipped first), the reopened directory's
    identity is verified, and the ownership gate means an entry the caller
    does not own is recorded but never touched however the path resolved.

    opts keys: excludes, file_mode, dir_mode, keep_exec, harden,
    do_chmod, deadline (monotonic or None), progress_every, journal,
    scope_home_rel, max_depth (None = unlimited; scan-apps uses 4).
    progress_cb(entries_done, summary) is called periodically.

    Raises ResourceLimitError on EMFILE/ENFILE so the caller can abort with a
    non-zero exit instead of reporting a partial run as success.
    """
    excludes = opts["excludes"]
    deadline = opts.get("deadline")
    progress_every = opts.get("progress_every", DEFAULT_PROGRESS_EVERY)
    enforce_protected = summary["command"] != "report"
    is_scan = summary["command"] == "scan-apps"
    is_readonly = summary["command"] in ("report", "scan-apps")
    max_depth = opts.get("max_depth")

    top_home_rel = home_relpath(top, home)
    top_dev = None  # type: Optional[int]
    # Stack frames are (abs_path, scope_rel, home_rel, expected (dev, ino)).
    # Only the top frame has expected=None. The stack holds strings, so its
    # size never costs fds.
    stack = [(top, "", top_home_rel, None)]  # type: List[tuple]
    entries_done = 0

    def timed_out():
        # type: () -> bool
        return deadline is not None and time.monotonic() >= deadline

    def close_fd(fd):
        # type: (int) -> None
        try:
            os.close(fd)
        except OSError:
            pass

    def open_dir(abs_path, expect, rel_for_msg):
        # type: (str, Any, str) -> Any
        """Open a directory O_NOFOLLOW; verify (dev, ino) unless expect=None.

        Returns the fd, or None after recording an error. Raises
        ResourceLimitError on EMFILE/ENFILE.
        """
        try:
            fd = os.open(abs_path,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            if _is_resource_error(exc):
                raise ResourceLimitError(
                    "too many open files while opening %s: %s"
                    % (rel_for_msg, exc))
            bump(summary, "errors")
            add_path(summary, "errors",
                     {"path": rel_for_msg,
                      "reason": "cannot open directory: %s" % exc})
            return None
        if expect is not None:
            try:
                fst = os.fstat(fd)
            except OSError as exc:
                close_fd(fd)
                bump(summary, "errors")
                add_path(summary, "errors",
                         {"path": rel_for_msg,
                          "reason": "cannot stat directory: %s" % exc})
                return None
            if (fst.st_dev, fst.st_ino) != expect:
                close_fd(fd)
                bump(summary, "errors")
                add_path(summary, "errors",
                         {"path": rel_for_msg,
                          "reason": "directory changed during walk; skipped"})
                return None
        return fd

    def set_mode(dir_fd, name, child_rel, current, target):
        # type: (int, str, str, int, int) -> None
        if current == target:
            return  # already correct
        if not opts["do_chmod"]:
            bump(summary, "would_change")
            add_path(summary, "would_change",
                     {"path": child_rel,
                      "from": "%04o" % current,
                      "to": "%04o" % target})
            return
        try:
            os.chmod(name, target, dir_fd=dir_fd, follow_symlinks=False)
        except NotImplementedError:
            bump(summary, "errors")
            add_path(summary, "errors",
                     {"path": child_rel,
                      "reason": "chmod with follow_symlinks=False is not "
                                "supported on this platform "
                                "(wanted %04o)" % target})
            return
        except OSError as exc:
            bump(summary, "errors")
            add_path(summary, "errors",
                     {"path": child_rel,
                      "reason": "chmod failed: %s" % exc})
            return
        bump(summary, "changed")
        add_path(summary, "changed",
                 {"path": child_rel,
                  "from": "%04o" % current,
                  "to": "%04o" % target})
        if current & 0o6000:
            bump(summary, "cleared_suid_sgid")
        journal = opts.get("journal")
        if journal is not None:
            scope_home_rel = opts.get("scope_home_rel", ".")
            if scope_home_rel == ".":
                home_rel = child_rel
            else:
                home_rel = scope_home_rel + "/" + child_rel
            try:
                journal.append(home_rel, current, target)
            except OSError as exc:
                eprint("warning: undo journal write failed: %s "
                       "(run continues without undo)" % exc)
                opts["journal"] = None

    def record_app(dir_fd, app_hrel):
        # type: (int, str) -> None
        app = check_app_dir(dir_fd, app_hrel)
        if app is not None:
            bump(summary, "apps")
            add_path(summary, "apps", app)

    def handle_entry(fd, abs_path, name, child_rel, child_hrel, st, depth):
        # type: (int, str, str, str, str, Any, int) -> Any
        """Gates + mode eval for one listed entry. Returns a stack tuple to
        descend into (directories only, depth permitting) or None. The caller
        runs the progress check afterwards, so progress fires for every
        entry, skipped or not. `depth` is the entry's home-relative depth.
        """
        # 1. symlinks: never follow, never touch.
        if stat.S_ISLNK(st.st_mode):
            bump(summary, "skipped_symlink")
            add_path(summary, "skipped_symlink", child_rel)
            return None
        # 2. single filesystem.
        if top_dev is not None and st.st_dev != top_dev:
            bump(summary, "skipped_xdev")
            add_path(summary, "skipped_xdev", child_rel)
            return None
        # 3. engine-enforced protected paths (check/chmod only).
        if enforce_protected and is_protected_entry(child_hrel):
            bump(summary, "skipped_protected")
            add_path(summary, "skipped_protected", child_rel)
            return None
        # 4. caller excludes.
        if matches_exclude(child_rel, excludes):
            bump(summary, "skipped_excluded")
            return None
        # 5. only files and dirs.
        is_dir = stat.S_ISDIR(st.st_mode)
        is_reg = stat.S_ISREG(st.st_mode)
        if not is_dir and not is_reg:
            bump(summary, "skipped_special")
            add_path(summary, "skipped_special", child_rel)
            return None
        # 6. ownership: never touch what the caller does not own.
        if st.st_uid != uid:
            owner = owner_name(st.st_uid)
            bump(summary, "not_owned")
            summary["not_owned_by"][owner] = \
                summary["not_owned_by"].get(owner, 0) + 1
            add_path(summary, "not_owned",
                     {"path": child_rel, "owner": owner})
            return None

        if is_dir:
            if not is_readonly:
                current = stat.S_IMODE(st.st_mode)
                if enforce_protected and is_mode_keep_dir(child_hrel):
                    pass  # Fix Home owns this mode; descend only.
                else:
                    set_mode(fd, name, child_rel, current,
                             desired_mode(child_rel, True, current,
                                          opts["file_mode"], opts["dir_mode"],
                                          opts["keep_exec"], opts["harden"]))
            if is_scan:
                # Open now for the marker check (needed even at max depth,
                # where we do not descend). Errors already recorded.
                child_fd = open_dir(abs_path + "/" + name,
                                    (st.st_dev, st.st_ino), child_rel)
                if child_fd is not None:
                    try:
                        if depth <= SCAN_MAX_DEPTH:
                            record_app(child_fd, child_hrel)
                    finally:
                        close_fd(child_fd)
                if max_depth is not None and depth >= max_depth:
                    return None  # listed, not descended
            # Reopened later by absolute path + identity check
            # (see run_walk docstring); the stack holds strings.
            return (abs_path + "/" + name, child_rel, child_hrel,
                    (st.st_dev, st.st_ino))

        if is_readonly:
            return None  # read-only: ownership info already recorded

        current = stat.S_IMODE(st.st_mode)
        base = child_rel.rsplit("/", 1)[-1]
        exec_magic = (
            bool(opts["keep_exec"]) and bool(current & 0o111)
            and base not in HARDEN_MODES
            and not path_keep_exec(child_rel)
            and looks_executable(read_magic(fd, name)))
        set_mode(fd, name, child_rel, current,
                 desired_mode(child_rel, False, current,
                              opts["file_mode"], opts["dir_mode"],
                              opts["keep_exec"], opts["harden"], exec_magic))
        return None

    while stack:
        if timed_out():
            summary["timed_out"] = True
            break
        if stop_requested():
            summary["interrupted"] = True
            break
        abs_path, rel, hrel, expect = stack.pop()
        fd = open_dir(abs_path, expect, rel or ".")
        if fd is None:
            continue  # error already recorded (top failure empties the walk)
        try:
            if expect is None:
                # Top frame: establish the filesystem identity.
                try:
                    top_dev = os.fstat(fd).st_dev
                except OSError as exc:
                    bump(summary, "errors")
                    add_path(summary, "errors",
                             {"path": ".",
                              "reason": "cannot stat scope: %s" % exc})
                    continue
                bump(summary, "scanned")  # the scope top itself
                if is_scan:
                    top_depth = 0 if top_home_rel == "." else len(top_home_rel.split("/"))
                    if top_depth <= SCAN_MAX_DEPTH:
                        record_app(fd, top_home_rel)
            try:
                names = os.listdir(fd)
            except OSError as exc:
                if _is_resource_error(exc):
                    raise ResourceLimitError(
                        "too many open files while listing %s: %s"
                        % (rel or ".", exc))
                bump(summary, "errors")
                add_path(summary, "errors",
                         {"path": rel or ".",
                          "reason": "cannot list directory: %s" % exc})
                continue
            for name in sorted(names):
                if timed_out():
                    summary["timed_out"] = True
                    break
                if stop_requested():
                    summary["interrupted"] = True
                    break
                child_rel = name if not rel else rel + "/" + name
                if hrel == ".":
                    child_hrel = name
                else:
                    child_hrel = hrel + "/" + name
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError as exc:
                    if _is_resource_error(exc):
                        raise ResourceLimitError(
                            "too many open files while stating %s: %s"
                            % (child_rel, exc))
                    bump(summary, "errors")
                    add_path(summary, "errors",
                             {"path": child_rel,
                              "reason": "cannot stat: %s" % exc})
                    continue
                bump(summary, "scanned")
                entries_done += 1
                hdepth = 0 if hrel == "." else len(hrel.split("/"))
                sub = handle_entry(fd, abs_path, name, child_rel,
                                   child_hrel, st, hdepth + 1)
                if sub is not None:
                    stack.append(sub)
                if progress_every and entries_done % progress_every == 0:
                    progress_cb(entries_done, summary)
        finally:
            close_fd(fd)


def run_undo(journal_path, home, uid, opts, summary, progress_cb):
    # type: (str, str, int, Dict[str, Any], Dict[str, Any], Any) -> None
    """Restore modes recorded in an undo journal.

    Each record is re-validated at restore time through the same gates as
    the walk (no symlinks, same filesystem, owned by the caller, regular
    file/dir, inside the home) except the protected-path skip list: undo
    explicitly restores modes that an authorized earlier run changed, which
    for Fix Home journals are the protected tool-B paths themselves.
    Entries whose mode changed since the journal was written are left alone
    (skipped_changed_since). Restored modes never include setuid/setgid/
    sticky bits (stripped_suid_sgid).
    """
    deadline = opts.get("deadline")
    progress_every = opts.get("progress_every", DEFAULT_PROGRESS_EVERY)
    header, records = parse_journal(journal_path)
    summary["undo_journal"] = journal_path

    journal_scope = header.get("scope") or home
    try:
        scope = resolve_scope(journal_scope, home)
    except UsageError as exc:
        raise UsageError("journal %s: %s" % (journal_path, exc))
    scope_home_rel = home_relpath(scope, home)
    summary["scope"] = scope

    def timed_out():
        # type: () -> bool
        return deadline is not None and time.monotonic() >= deadline

    def stopped():
        # type: () -> Any
        if timed_out():
            summary["timed_out"] = True
            return True
        if stop_requested():
            summary["interrupted"] = True
            return True
        return False

    try:
        scope_fd = os.open(scope, os.O_RDONLY | os.O_DIRECTORY
                           | os.O_NOFOLLOW)
    except OSError as exc:
        if _is_resource_error(exc):
            raise ResourceLimitError("too many open files: %s" % exc)
        bump(summary, "errors")
        add_path(summary, "errors",
                 {"path": ".", "reason": "cannot open scope: %s" % exc})
        return
    try:
        top_dev = os.fstat(scope_fd).st_dev
    except OSError as exc:
        bump(summary, "errors")
        add_path(summary, "errors",
                 {"path": ".", "reason": "cannot stat scope: %s" % exc})
        try:
            os.close(scope_fd)
        except OSError:
            pass
        return

    done = 0
    try:
        for rec in records:
            if stopped():
                break
            rel = rec["path"]
            # Scope-relative portion of this home-relative record.
            if scope_home_rel == ".":
                scope_rel = rel
            elif rel == scope_home_rel or \
                    rel.startswith(scope_home_rel + "/"):
                scope_rel = rel[len(scope_home_rel):].strip("/")
            else:
                bump(summary, "errors")
                add_path(summary, "errors",
                         {"path": rel,
                          "reason": "outside the journal scope; skipped"})
                continue
            if not scope_rel:
                continue  # the scope itself is never chmod'ed
            bump(summary, "scanned")
            done += 1
            parts = scope_rel.split("/")
            # Open the parent dir by path, then operate via dir_fd.
            parent_rel = "/".join(parts[:-1])
            try:
                if parent_rel:
                    parent_fd = os.open(parent_rel, os.O_RDONLY
                                        | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=scope_fd)
                else:
                    parent_fd = os.dup(scope_fd)
            except OSError as exc:
                if _is_resource_error(exc):
                    raise ResourceLimitError(
                        "too many open files: %s" % exc)
                bump(summary, "errors")
                add_path(summary, "errors",
                         {"path": rel,
                          "reason": "cannot open parent: %s" % exc})
                continue
            try:
                try:
                    if os.fstat(parent_fd).st_dev != top_dev:
                        bump(summary, "skipped_xdev")
                        add_path(summary, "skipped_xdev", rel)
                        continue
                    st = os.stat(parts[-1], dir_fd=parent_fd,
                                 follow_symlinks=False)
                except OSError as exc:
                    if _is_resource_error(exc):
                        raise ResourceLimitError(
                            "too many open files: %s" % exc)
                    bump(summary, "errors")
                    add_path(summary, "errors",
                             {"path": rel,
                              "reason": "cannot stat: %s" % exc})
                    continue
                if stat.S_ISLNK(st.st_mode):
                    bump(summary, "skipped_symlink")
                    add_path(summary, "skipped_symlink", rel)
                    continue
                if st.st_dev != top_dev:
                    bump(summary, "skipped_xdev")
                    add_path(summary, "skipped_xdev", rel)
                    continue
                if not stat.S_ISREG(st.st_mode) and \
                        not stat.S_ISDIR(st.st_mode):
                    bump(summary, "skipped_special")
                    add_path(summary, "skipped_special", rel)
                    continue
                if st.st_uid != uid:
                    owner = owner_name(st.st_uid)
                    bump(summary, "not_owned")
                    summary["not_owned_by"][owner] = \
                        summary["not_owned_by"].get(owner, 0) + 1
                    add_path(summary, "not_owned",
                             {"path": rel, "owner": owner})
                    continue
                current = stat.S_IMODE(st.st_mode)
                if current != (rec["to"] & 0o7777):
                    bump(summary, "skipped_changed_since")
                    add_path(summary, "errors",
                             {"path": rel,
                              "reason": "mode changed since the journal was "
                                        "written; left alone"})
                    continue
                target = rec["from"] & 0o777
                if rec["from"] != target:
                    bump(summary, "stripped_suid_sgid")
                if current == target:
                    continue  # already at the restored mode
                if not opts.get("do_chmod", True):
                    bump(summary, "would_change")
                    add_path(summary, "would_change",
                             {"path": rel,
                              "from": "%04o" % current,
                              "to": "%04o" % target})
                    continue
                try:
                    os.chmod(parts[-1], target, dir_fd=parent_fd,
                             follow_symlinks=False)
                except NotImplementedError:
                    bump(summary, "errors")
                    add_path(summary, "errors",
                             {"path": rel,
                              "reason": "chmod with follow_symlinks=False is "
                                        "not supported on this platform"})
                    continue
                except OSError as exc:
                    bump(summary, "errors")
                    add_path(summary, "errors",
                             {"path": rel,
                              "reason": "chmod failed: %s" % exc})
                    continue
                bump(summary, "changed")
                add_path(summary, "changed",
                         {"path": rel,
                          "from": "%04o" % current,
                          "to": "%04o" % target})
            finally:
                try:
                    os.close(parent_fd)
                except OSError:
                    pass
            if progress_every and done % progress_every == 0:
                progress_cb(done, summary)
    finally:
        try:
            os.close(scope_fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    # type: () -> argparse.ArgumentParser
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--scope", default=None,
                        help="directory to process (default: your home)")
    parent.add_argument("--exclude", action="append", default=[],
                        help="relative glob to skip (repeatable, max %d)"
                             % MAX_EXCLUDES)
    parent.add_argument("--dry-run", action="store_true",
                        help="report only; change nothing "
                             "(check/report never change anything)")
    parent.add_argument("--json-progress", default=None, metavar="FILE",
                        help="write progress JSON here every N entries")
    parent.add_argument("--progress-every", type=int,
                        default=DEFAULT_PROGRESS_EVERY,
                        help="progress write interval (default %d)"
                             % DEFAULT_PROGRESS_EVERY)
    parent.add_argument("--file-mode", default="644",
                        help="octal target for files (default 644)")
    parent.add_argument("--dir-mode", default="755",
                        help="octal target for directories (default 755)")
    parent.add_argument("--keep-exec", dest="keep_exec", action="store_true",
                        default=True,
                        help="keep 755 on files that already have an exec bit "
                             "when in cgi-bin/bin/.bin, ending "
                             ".cgi/.pl/.sh, or starting with #!/ELF "
                             "(default on)")
    parent.add_argument("--no-keep-exec", dest="keep_exec",
                        action="store_false",
                        help="disable the exec-bit exception")
    parent.add_argument("--harden-sensitive", action="store_true",
                        default=False,
                        help="set wp-config.php to 0640 and .env to 0600")
    parent.add_argument("--policy", default=None,
                        help="policy file (default %s if present)"
                             % DEFAULT_POLICY_PATH)
    parent.add_argument("--lock-dir", default=None,
                        help="lock directory (default ~/.cpanel/usertools)")
    parent.add_argument("--home", default=None,
                        help="home directory for confinement checks "
                             "(test hook only; requires USERTOOLS_TESTING=1 "
                             "in the environment; default: your real home)")
    parent.add_argument("--undo-dir", default=None,
                        help="directory for undo journals "
                             "(default ~/.cpanel/usertools/undo)")
    parent.add_argument("--no-undo", dest="undo", action="store_false",
                        default=True,
                        help="do not write an undo journal for chmod")

    undo_parent = argparse.ArgumentParser(add_help=False)
    undo_parent.add_argument("--journal", default=None, required=True,
                             help="undo journal file to restore (required)")
    undo_parent.add_argument("--dry-run", action="store_true",
                             help="report what would be restored; "
                                  "change nothing")
    undo_parent.add_argument("--json-progress", default=None, metavar="FILE",
                             help="write progress JSON here every N entries")
    undo_parent.add_argument("--progress-every", type=int,
                             default=DEFAULT_PROGRESS_EVERY,
                             help="progress write interval (default %d)"
                                  % DEFAULT_PROGRESS_EVERY)
    undo_parent.add_argument("--policy", default=None,
                             help="policy file (default %s if present)"
                                  % DEFAULT_POLICY_PATH)
    undo_parent.add_argument("--lock-dir", default=None,
                             help="lock directory "
                                  "(default ~/.cpanel/usertools)")
    undo_parent.add_argument("--home", default=None,
                             help="home directory for confinement checks "
                                  "(test hook only; requires USERTOOLS_TESTING=1 "
                                  "in the environment; default: your real home)")

    parser = argparse.ArgumentParser(
        prog="perm_engine.py",
        description="Unprivileged permission check/chmod/report/undo inside "
                    "your home directory.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", parents=[parent],
                   help="show what would change (never changes anything)")
    sub.add_parser("chmod", parents=[parent],
                   help="set files to 644 and directories to 755 "
                        "(unless --dry-run)")
    sub.add_parser("report", parents=[parent],
                   help="list entries you do not own, grouped by owner")
    sub.add_parser("undo", parents=[undo_parent],
                   help="restore modes recorded in an undo journal")
    sub.add_parser("scan-apps", parents=[parent],
                   help="read-only Laravel app detection (max depth 4)")
    return parser


def write_progress_file(path, payload):
    # type: (str, Dict[str, Any]) -> None
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True, default=str)
            fh.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        eprint("warning: cannot write progress file %s: %s" % (path, exc))


def main(argv=None):
    # type: (Optional[List[str]]) -> int
    refuse_if_privileged()
    uid = os.getuid()

    try:
        signal.signal(signal.SIGTERM, _sigterm_handler)
    except (OSError, ValueError):
        pass  # no SIGTERM here; timeouts still bound the run

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.home is not None and \
            os.environ.get("USERTOOLS_TESTING") != "1":
        eprint("error: --home is a test-only option")
        return EXIT_USAGE

    is_undo = (args.command == "undo")
    try:
        home = resolve_home(args.home)
        if is_undo:
            excludes = []
            file_mode = TARGET_FILE_MODE
            dir_mode = TARGET_DIR_MODE
            scope = home  # placeholder; run_undo sets the real scope
        else:
            excludes = validate_excludes(args.exclude)
            file_mode = parse_mode(args.file_mode)
            dir_mode = parse_mode(args.dir_mode)
            scope = resolve_scope(args.scope or home, home)
    except UsageError as exc:
        eprint("error: %s" % exc)
        return EXIT_USAGE

    apply_resource_limits()

    policy = load_policy(args.policy)
    limit = max_job_seconds(policy)
    start = time.monotonic()
    deadline = start + limit  # limit is always positive (see max_job_seconds)

    lock_dir = args.lock_dir or os.path.join(home, ".cpanel", "usertools")
    lock = JobLock(lock_dir)
    try:
        lock.acquire()
    except BusyError as exc:
        eprint("error: %s" % exc)
        return EXIT_BUSY
    except UsageError as exc:
        eprint("error: %s" % exc)
        return EXIT_USAGE

    dry_run = bool(args.dry_run) or args.command in ("check", "scan-apps")
    do_chmod = (args.command in ("chmod", "undo") and not dry_run)
    summary = new_summary(args.command, scope, dry_run)

    progress_path = args.json_progress
    progress_every = args.progress_every if args.progress_every > 0 else 0

    def progress_cb(done, summ):
        # type: (int, Dict[str, Any]) -> None
        if not progress_path:
            return
        write_progress_file(progress_path, {
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
        summary["elapsed_seconds"] = round(time.monotonic() - start, 3)
        if progress_path:
            progress_cb(summary["counts"]["scanned"], summary)
        sys.stdout.write(json.dumps(summary, ensure_ascii=True, default=str,
                                    indent=2) + "\n")
        sys.stdout.flush()
        return code

    journal = None
    undo_dir = None
    if is_undo:
        opts = {
            "do_chmod": do_chmod,
            "deadline": deadline,
            "progress_every": progress_every,
        }
    else:
        if do_chmod and getattr(args, "undo", False):
            undo_dir = args.undo_dir or default_undo_dir(home)
            journal = open_journal(undo_dir, "bulk", home, scope)
            if journal is not None:
                summary["undo_journal"] = journal.final_path
        opts = {
            "excludes": excludes,
            "file_mode": file_mode,
            "dir_mode": dir_mode,
            "keep_exec": bool(args.keep_exec),
            "harden": bool(args.harden_sensitive),
            "do_chmod": do_chmod,
            "deadline": deadline,
            "progress_every": progress_every,
            "journal": journal,
            "scope_home_rel": home_relpath(scope, home),
            "max_depth": SCAN_MAX_DEPTH if args.command == "scan-apps" else None,
        }
    try:
        if is_undo:
            run_undo(args.journal, home, uid, opts, summary, progress_cb)
        else:
            run_walk(scope, home, uid, opts, summary, progress_cb)
    except UsageError as exc:
        # Journal/scope validation failed before anything changed.
        eprint("error: %s" % exc)
        code = EXIT_USAGE
    except ResourceLimitError as exc:
        summary["resource_limited"] = True
        eprint("error: %s; run aborted, results are partial" % exc)
        code = EXIT_RESOURCE
    except Exception as exc:  # defensive: no partial-success confusion
        eprint("error: walk failed: %s" % exc)
        code = EXIT_FAIL
    else:
        code = EXIT_OK
        if summary["timed_out"]:
            eprint("warning: time limit exceeded; results are partial")
            code = EXIT_TIMEOUT
        elif summary["interrupted"]:
            eprint("warning: interrupted by SIGTERM; results are partial")
            code = EXIT_TIMEOUT
    finally:
        lock.release()
        if journal is not None:
            try:
                journal.close()
            except OSError as exc:
                eprint("warning: cannot close undo journal: %s" % exc)
                summary["undo_journal"] = None
            jname = os.path.basename(journal.final_path) if summary["undo_journal"] else None
            prune_journals(undo_dir, protect_name=jname, max_tmp_age=limit)

    if code in (EXIT_FAIL, EXIT_USAGE):
        return code  # unexpected failure / bad input: no summary to trust
    return finish(code)


if __name__ == "__main__":
    sys.exit(main())
