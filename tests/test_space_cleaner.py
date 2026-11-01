# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""Tests for engine/space_cleaner.py.

Run on Linux:  python -m pytest tests/test_space_cleaner.py -q
"""
import json
import os
import stat
import subprocess
import sys
import time

import pytest

ENGINE_DIR = os.path.join(os.path.dirname(__file__), "..", "engine")
ENGINE = os.path.join(ENGINE_DIR, "space_cleaner.py")

sys.path.insert(0, os.path.abspath(ENGINE_DIR))
import space_cleaner as sc
import perm_engine as pe


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run_cleaner(*argv, home=None, policy=None):
    """Run the engine CLI; return (returncode, summary_or_None, stderr)."""
    cmd = [sys.executable, ENGINE] + list(argv)
    if home is not None:
        cmd += ["--home", str(home)]
    if policy is not None:
        cmd += ["--policy", str(policy)]
    env = dict(os.environ)
    env["USERTOOLS_TESTING"] = "1"
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                          env=env)
    summary = None
    if proc.stdout.strip():
        try:
            summary = json.loads(proc.stdout)
        except json.JSONDecodeError:
            summary = None
    return proc.returncode, summary, proc.stderr


def make_home(tmp_path):
    """Fake home tree: returns the home Path."""
    home = tmp_path / "home"
    (home / "public_html").mkdir(parents=True)
    (home / "public_html" / "index.html").write_text("hi")
    (home / "public_html" / "sub").mkdir(exist_ok=True)
    return home


def lockless(*argv, home, policy=None):
    """Run engine with an isolated lock dir (never touches ~/.cpanel)."""
    lockdir = os.path.join(str(home), "locks")
    full = [argv[0], "--lock-dir", lockdir] + list(argv[1:])
    if policy is not None:
        full += ["--policy", str(policy)]
    return run_cleaner(*full, home=home)


def write_policy(home, **items):
    """Write a policy file; return its path."""
    path = home / "test-policy.conf"
    with open(path, "w", encoding="utf-8") as fh:
        for key, value in items.items():
            fh.write("%s=%s\n" % (key, value))
    return str(path)


def sparse(path, size):
    """Create a sparse file of `size` bytes (st_size counts, no I/O cost)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path), "wb") as fh:
        fh.truncate(size)


def one_mb_policy(home):
    """Policy with a 1 MB log floor and 7-day trash."""
    return write_policy(home, cleaner_log_min_mb="1", cleaner_trash_days="7")


def scan(home, *cats, policy=None):
    """clean-scan with an isolated lock; return (rc, summary, stderr)."""
    args = ["clean-scan"]
    for cat in cats:
        args += ["--category", cat]
    if policy is None:
        policy = one_mb_policy(home)
    return lockless(*args, home=home, policy=policy)


def clean(home, *cats, policy=None):
    """clean-run with an isolated lock; return (rc, summary, stderr)."""
    args = ["clean-run"]
    for cat in cats:
        args += ["--category", cat]
    if policy is None:
        policy = one_mb_policy(home)
    return lockless(*args, home=home, policy=policy)


def seed_app(home, rel="myapp"):
    """Fake framework app with cache + compiled views; return app Path."""
    app = home / rel
    (app / "vendor").mkdir(parents=True)
    (app / "artisan").write_text("#!/usr/bin/env php\n")
    (app / "vendor" / "autoload.php").write_text("<?php\n")
    (app / "composer.json").write_text(
        '{"require": {"laravel/framework": "^10.0"}}')
    data = app / "storage" / "framework" / "cache" / "data"
    data.mkdir(parents=True)
    (data / "aaa").write_bytes(b"x" * 100)
    (data / "sub").mkdir()
    (data / "sub" / "bbb").write_bytes(b"y" * 200)
    views = app / "storage" / "framework" / "views"
    views.mkdir(parents=True)
    (views / "aaa.php").write_bytes(b"v" * 50)
    (views / "note.txt").write_text("keep me")
    return app


def seed_wp(home, rel="blog"):
    """Fake WordPress install with a cache dir; return blog Path."""
    blog = home / rel
    (blog / "wp-includes").mkdir(parents=True)
    (blog / "wp-config.php").write_text("<?php\n")
    (blog / "wp-includes" / "version.php").write_text("<?php\n")
    cache = blog / "wp-content" / "cache"
    cache.mkdir(parents=True)
    (cache / "one").write_bytes(b"x" * 70)
    (cache / "two").write_bytes(b"y" * 80)
    return blog


# ---------------------------------------------------------------------------
# error_logs (classic error_log files + per-domain PHP logs)
# ---------------------------------------------------------------------------

def test_error_log_scan_and_truncate(tmp_path):
    home = make_home(tmp_path)
    big = home / "public_html" / "error_log"
    sparse(big, 2 * 1024 * 1024)
    small = home / "public_html" / "sub" / "error_log"
    small.write_bytes(b"x" * 10)
    mode_before = stat.S_IMODE(os.stat(str(big)).st_mode)

    rc, summary, _ = scan(home, "error_logs")
    assert rc == 0
    cat = summary["categories"]["error_logs"]
    assert cat["files"] == 1
    assert cat["bytes"] == 2 * 1024 * 1024
    assert summary["counts"]["would_change"] == 1
    assert {e["path"] for e in cat["largest"]} == {"public_html/error_log"}

    rc, summary, _ = clean(home, "error_logs")
    assert rc == 0
    assert summary["counts"]["truncated_files"] == 1
    assert summary["counts"]["truncated_bytes"] == 2 * 1024 * 1024
    assert os.stat(str(big)).st_size == 0
    assert stat.S_IMODE(os.stat(str(big)).st_mode) == mode_before
    assert small.read_bytes() == b"x" * 10


def test_php_error_logs_only_pattern(tmp_path):
    home = make_home(tmp_path)
    logs = home / "logs"
    logs.mkdir()
    php_log = logs / "example_com.php.error.log"
    sparse(php_log, int(1.5 * 1024 * 1024))
    (logs / "access.log").write_bytes(b"a" * 50)
    (logs / "backup.sql.gz").write_bytes(b"b" * 50)

    rc, summary, _ = scan(home, "error_logs")
    assert rc == 0
    cat = summary["categories"]["error_logs"]
    assert cat["files"] == 1
    assert cat["largest"][0]["path"] == "logs/example_com.php.error.log"

    rc, summary, _ = clean(home, "error_logs")
    assert rc == 0
    assert os.stat(str(php_log)).st_size == 0
    assert (logs / "access.log").read_bytes() == b"a" * 50
    assert (logs / "backup.sql.gz").read_bytes() == b"b" * 50


def test_default_policy_floor_ignores_small_logs(tmp_path):
    home = make_home(tmp_path)
    sparse(home / "public_html" / "error_log", 2 * 1024 * 1024)
    policy = write_policy(home)  # no floors: 50 MB default
    rc, summary, _ = lockless("clean-scan", home=home, policy=policy)
    assert rc == 0
    assert summary["categories"]["error_logs"]["files"] == 0


def test_invalid_policy_falls_back(tmp_path):
    home = make_home(tmp_path)
    sparse(home / "public_html" / "error_log", 2 * 1024 * 1024)
    policy = write_policy(home, cleaner_log_min_mb="banana",
                          cleaner_trash_days="99999")
    rc, summary, err = lockless("clean-scan", home=home, policy=policy)
    assert rc == 0
    assert summary["categories"]["error_logs"]["files"] == 0
    assert "cleaner_log_min_mb" in err


def test_error_log_below_floor_untouched(tmp_path):
    home = make_home(tmp_path)
    small = home / "public_html" / "error_log"
    small.write_bytes(b"x" * 100)
    rc, summary, _ = clean(home, "error_logs")
    assert rc == 0
    assert summary["counts"]["truncated_files"] == 0
    assert small.read_bytes() == b"x" * 100


# ---------------------------------------------------------------------------
# core dumps
# ---------------------------------------------------------------------------

def test_core_dumps_trash(tmp_path):
    home = make_home(tmp_path)
    (home / "core").write_bytes(b"c" * 40)
    (home / "public_html" / "core.12345").write_bytes(b"d" * 60)
    (home / "public_html" / "core.txt").write_text("keep")
    (home / "mycore").write_text("keep")

    rc, summary, _ = scan(home, "core_dumps")
    assert rc == 0
    cat = summary["categories"]["core_dumps"]
    assert cat["files"] == 2
    assert cat["bytes"] == 100

    rc, summary, _ = clean(home, "core_dumps")
    assert rc == 0
    assert summary["counts"]["trashed_files"] == 2
    batch = summary["trash_batch"]
    assert batch is not None
    assert not os.path.lexists(str(home / "core"))
    assert (home / "public_html" / "core.txt").read_text() == "keep"
    assert (home / "mycore").read_text() == "keep"
    # trash keeps the home-relative layout
    assert os.path.isfile(os.path.join(
        str(home), ".usertools-trash", batch, "public_html", "core.12345"))


# ---------------------------------------------------------------------------
# framework + CMS caches
# ---------------------------------------------------------------------------

def test_app_cache_scan_clean_restore(tmp_path):
    home = make_home(tmp_path)
    app = seed_app(home)
    (app / "other.txt").write_text("keep")
    # a lookalike tree without app markers is never collected
    fake = home / "notapp"
    (fake / "storage" / "framework" / "cache" / "data").mkdir(parents=True)
    (fake / "storage" / "framework" / "cache" / "data" / "zzz").write_bytes(b"z")

    rc, summary, _ = scan(home, "app_cache")
    assert rc == 0
    cat = summary["categories"]["app_cache"]
    got = {e["path"] for e in cat["largest"]}
    assert "myapp/storage/framework/cache/data/aaa" in got
    assert "myapp/storage/framework/cache/data/sub/bbb" in got
    assert "myapp/storage/framework/views/aaa.php" in got
    assert not [p for p in got if p.startswith("notapp/")]
    assert cat["files"] == 3

    rc, summary, _ = clean(home, "app_cache")
    assert rc == 0
    assert summary["counts"]["trashed_files"] == 3
    batch = summary["trash_batch"]
    assert not os.path.lexists(str(app / "storage" / "framework" / "cache" / "data" / "aaa"))
    assert (app / "other.txt").read_text() == "keep"
    assert (app / "storage" / "framework" / "views" / "note.txt").read_text() == "keep me"
    assert (fake / "storage" / "framework" / "cache" / "data" / "zzz").read_bytes() == b"z"

    # restore round trip
    rc, summary, _ = lockless("trash-restore", "--batch", batch, home=home)
    assert rc == 0
    assert summary["counts"]["restored_files"] == 3
    assert (app / "storage" / "framework" / "cache" / "data" / "aaa").read_bytes() == b"x" * 100


def test_restore_conflict_keeps_trash_copy(tmp_path):
    home = make_home(tmp_path)
    seed_app(home)
    rc, summary, _ = clean(home, "app_cache")
    assert rc == 0
    batch = summary["trash_batch"]
    target = home / "myapp" / "storage" / "framework" / "views" / "aaa.php"
    target.write_bytes(b"recreated")
    rc, summary, _ = lockless("trash-restore", "--batch", batch, home=home)
    assert rc == 0
    assert summary["counts"]["restore_conflicts"] >= 1
    assert summary["counts"]["restored_files"] == 2
    assert target.read_bytes() == b"recreated"
    # the conflicting trash copy is still there
    assert os.path.isfile(os.path.join(
        str(home), ".usertools-trash", batch,
        "myapp", "storage", "framework", "views", "aaa.php"))


def test_wp_cache_scan_clean(tmp_path):
    home = make_home(tmp_path)
    blog = seed_wp(home)
    (blog / "index.php").write_text("keep")
    # missing version.php: not a WP install, cache left alone
    fake = home / "plain"
    fake.mkdir()
    (fake / "wp-config.php").write_text("<?php\n")
    (fake / "wp-content" / "cache").mkdir(parents=True)
    (fake / "wp-content" / "cache" / "q").write_bytes(b"q")

    rc, summary, _ = scan(home, "wp_cache")
    assert rc == 0
    assert summary["categories"]["wp_cache"]["files"] == 2

    rc, summary, _ = clean(home, "wp_cache")
    assert rc == 0
    assert summary["counts"]["trashed_files"] == 2
    assert (blog / "index.php").read_text() == "keep"
    assert (fake / "wp-content" / "cache" / "q").read_bytes() == b"q"


# ---------------------------------------------------------------------------
# developer caches
# ---------------------------------------------------------------------------

def test_dev_caches_trash(tmp_path):
    home = make_home(tmp_path)
    npm = home / ".npm" / "_cacache"
    (npm / "index-v5").mkdir(parents=True)
    (npm / "index-v5" / "a").write_bytes(b"1" * 30)
    comp = home / ".cache" / "composer"
    comp.mkdir(parents=True)
    (comp / "b").write_bytes(b"2" * 40)
    nodec = home / ".cache" / "usertools" / "node-compile-cache"
    nodec.mkdir(parents=True)
    (nodec / "c").write_bytes(b"3" * 50)

    rc, summary, _ = scan(home, "dev_caches")
    assert rc == 0
    assert summary["categories"]["dev_caches"]["files"] == 3
    assert summary["categories"]["dev_caches"]["bytes"] == 120

    rc, summary, _ = clean(home, "dev_caches")
    assert rc == 0
    assert summary["counts"]["trashed_files"] == 3
    assert not os.path.lexists(str(npm / "index-v5" / "a"))
    # the cache roots themselves stay (only contents move)
    assert os.path.isdir(str(npm))


# ---------------------------------------------------------------------------
# the plugin's own old files (delete, 30d+, never the newest 3 per tool)
# ---------------------------------------------------------------------------

def _old(path, days=40):
    stamp = time.time() - days * 86400
    os.utime(str(path), (stamp, stamp))


def seed_jobs_undo(home):
    jobs = home / ".cpanel" / "usertools" / "jobs"
    jobs.mkdir(parents=True)
    undo = home / ".cpanel" / "usertools" / "undo"
    undo.mkdir(parents=True)
    # five old bulk jobs: only the newest three survive
    for i in range(5):
        p = jobs / ("bulk-20200101T00000%d-1-1.result.json" % i)
        p.write_text("{}")
        _old(p)
    fresh = jobs / "bulk-20260101T000000-9-9.result.json"
    fresh.write_text("{}")
    # two old report jobs: fewer than three, both survive
    for i in range(2):
        p = jobs / ("report-20200101T00000%d-1-1.result.json" % i)
        p.write_text("{}")
        _old(p)
    # unknown suffix: never touched
    mystery = jobs / "bulk-20200101T000000-0-0.notes.txt"
    mystery.write_text("mystery")
    _old(mystery)
    # four old undo journals + one fresh: newest three survive
    for i in range(4):
        p = undo / ("app-20200101T00000%d.jsonl.gz" % i)
        p.write_bytes(b"old")
        _old(p)
    new_journal = undo / "app-20260101T000000-1-2.jsonl.gz"
    new_journal.write_bytes(b"new")
    return jobs, undo


def test_usertools_old_delete_rules(tmp_path):
    home = make_home(tmp_path)
    jobs, undo = seed_jobs_undo(home)

    rc, summary, _ = scan(home, "usertools_old")
    assert rc == 0
    cat = summary["categories"]["usertools_old"]
    # deletable: bulk-0..2 (old beyond newest 3 incl. the fresh job)
    # + app-0, app-1 (old beyond newest 3 incl. the fresh journal)
    assert cat["files"] == 5

    rc, summary, _ = clean(home, "usertools_old")
    assert rc == 0
    assert summary["counts"]["deleted_files"] == 5
    remaining_jobs = sorted(p.name for p in jobs.iterdir())
    assert "bulk-20200101T000003-1-1.result.json" in remaining_jobs
    assert "bulk-20200101T000004-1-1.result.json" in remaining_jobs
    assert "bulk-20260101T000000-9-9.result.json" in remaining_jobs
    assert "bulk-20200101T000000-1-1.result.json" not in remaining_jobs
    assert "bulk-20200101T000001-1-1.result.json" not in remaining_jobs
    assert "bulk-20200101T000002-1-1.result.json" not in remaining_jobs
    assert "report-20200101T000000-1-1.result.json" in remaining_jobs
    assert "report-20200101T000001-1-1.result.json" in remaining_jobs
    assert "bulk-20200101T000000-0-0.notes.txt" in remaining_jobs
    remaining_undo = sorted(p.name for p in undo.iterdir())
    assert "app-20200101T000000.jsonl.gz" not in remaining_undo
    assert "app-20200101T000001.jsonl.gz" not in remaining_undo
    assert "app-20200101T000002.jsonl.gz" in remaining_undo
    assert "app-20200101T000003.jsonl.gz" in remaining_undo
    assert "app-20260101T000000-1-2.jsonl.gz" in remaining_undo


# ---------------------------------------------------------------------------
# trash list/restore/empty/prune
# ---------------------------------------------------------------------------

def test_trash_empty_and_list(tmp_path):
    home = make_home(tmp_path)
    (home / "core.1").write_bytes(b"1" * 25)
    (home / "core.2").write_bytes(b"2" * 35)
    rc, summary, _ = clean(home, "core_dumps")
    assert rc == 0
    batch = summary["trash_batch"]
    # trash holds the two files plus the run's manifest
    assert summary["trash"]["bytes"] >= 60
    assert summary["trash"]["batches"] == 1

    rc, summary, _ = lockless("trash-empty", "--batch", batch, home=home)
    assert rc == 0
    assert not os.path.lexists(
        os.path.join(str(home), ".usertools-trash", batch))

    # emptying an already-gone batch is a clean no-op
    rc, summary, _ = lockless("trash-empty", "--batch", batch, home=home)
    assert rc == 0

    # --all across two batches
    (home / "core.3").write_bytes(b"3")
    clean(home, "core_dumps")
    (home / "core.4").write_bytes(b"4")
    clean(home, "core_dumps")
    rc, summary, _ = lockless("trash-empty", "--all", home=home)
    assert rc == 0
    assert os.listdir(os.path.join(str(home), ".usertools-trash")) == []


def test_trash_prune_by_age(tmp_path):
    home = make_home(tmp_path)
    trash = home / ".usertools-trash"
    old_batch = trash / "20200101T000000"
    (old_batch / "sub").mkdir(parents=True)
    (old_batch / "sub" / "f").write_bytes(b"old")
    _old(old_batch)
    (home / "core.9").write_bytes(b"9")
    # clean runs the same prune first, then trashes the fresh file
    rc, summary, _ = clean(home, "core_dumps")
    assert rc == 0
    assert summary["counts"]["trashed_files"] == 1
    assert not os.path.lexists(str(old_batch))
    assert summary["trash"]["batches"] == 1


def test_trash_batch_and_empty_shape_errors(tmp_path):
    home = make_home(tmp_path)
    # argument-stage refusals print no summary
    for argv in (["trash-restore", "--batch", "nope"],
                 ["trash-empty", "--batch", "xx", "--all"],
                 ["clean-run"],
                 ["clean-scan", "--category", "nope"],
                 ["clean-run", "--category", "error_logs,nope"]):
        rc, summary, _ = lockless(*argv, home=home)
        assert rc == 2, argv
        assert summary is None, argv
    # a well-formed but unknown batch fails with a reported summary
    rc, summary, _ = lockless("trash-restore", "--batch", "20200101T000000",
                              home=home)
    assert rc == 2
    assert summary is not None


def test_restore_blocked_by_symlink_parent(tmp_path):
    home = make_home(tmp_path)
    sub = home / "public_html" / "cacheme"
    sub.mkdir()
    (sub / "core.5").write_bytes(b"5" * 12)
    rc, summary, _ = clean(home, "core_dumps")
    assert rc == 0
    batch = summary["trash_batch"]
    # swap the real parent dir for a symlink after the clean
    import shutil
    shutil.rmtree(str(sub))
    os.symlink(str(home), str(sub))
    rc, summary, _ = lockless("trash-restore", "--batch", batch, home=home)
    assert rc == 0
    assert summary["counts"]["restored_files"] == 0
    assert summary["counts"]["errors"] >= 1
    assert os.path.islink(str(sub))


# ---------------------------------------------------------------------------
# refusals: symlinks, hard links, other owners, xdev, protected paths
# ---------------------------------------------------------------------------

def test_symlink_error_log_left_alone(tmp_path):
    home = make_home(tmp_path)
    outside = tmp_path / "outside-target"
    outside.write_bytes(b"secret" * 100)
    link = home / "public_html" / "error_log"
    os.symlink(str(outside), str(link))

    rc, summary, _ = scan(home, "error_logs")
    assert rc == 0
    assert summary["categories"]["error_logs"]["files"] == 0
    assert summary["counts"]["skipped_symlink"] >= 1

    rc, summary, _ = clean(home, "error_logs")
    assert rc == 0
    assert summary["counts"]["truncated_files"] == 0
    assert os.path.islink(str(link))
    assert outside.read_bytes() == b"secret" * 100


def test_hardlinked_log_left_alone(tmp_path):
    home = make_home(tmp_path)
    real = home / "public_html" / "real_log"
    sparse(real, 2 * 1024 * 1024)
    os.link(str(real), str(home / "public_html" / "error_log"))

    rc, summary, _ = scan(home, "error_logs")
    assert rc == 0
    assert summary["counts"]["skipped_hardlink"] == 2
    assert summary["categories"]["error_logs"]["files"] == 0

    rc, summary, _ = clean(home, "error_logs")
    assert rc == 0
    assert os.stat(str(real)).st_size == 2 * 1024 * 1024


class _FakeStat(object):
    """stat_result stand-in with an overridden owner (in-process tests)."""

    def __init__(self, real, uid):
        self._real = real
        self.st_uid = uid

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_other_owner_recorded_not_touched(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    victim = home / "public_html" / "error_log"
    sparse(victim, 2 * 1024 * 1024)
    real_stat = os.stat

    def fake_stat(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        name = path if isinstance(path, str) else ""
        if isinstance(name, str) and name.endswith("error_log"):
            return _FakeStat(st, 99)
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    summary = sc.new_clean_summary("clean-scan", str(home), True)
    top_dev = real_stat(str(home)).st_dev
    cleaner = sc.Cleaner(str(home), os.getuid(), summary,
                         lambda d, s: None, None, 0, top_dev, None,
                         {"log_min_bytes": 1024 * 1024}, False)
    fd = cleaner.open_dir(str(home), None, ".")
    assert fd is not None
    try:
        cleaner.walk_open(fd, ".", True, None)
    finally:
        os.close(fd)
    assert summary["counts"]["not_owned"] >= 1
    assert summary["categories"]["error_logs"]["files"] == 0
    assert os.stat(str(victim)).st_size == 2 * 1024 * 1024


def test_xdev_skipped(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    sub = home / "public_html" / "otherfs"
    sub.mkdir()
    (sub / "error_log").write_bytes(b"x" * 10)
    real_stat = os.stat

    class _FakeDev(object):
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            if name == "st_dev":
                return self._real.st_dev + 999999
            return getattr(self._real, name)

    def fake_stat(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        name = path if isinstance(path, str) else ""
        if isinstance(name, str) and "otherfs" in name:
            return _FakeDev(st)
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    summary = sc.new_clean_summary("clean-scan", str(home), True)
    top_dev = real_stat(str(home)).st_dev
    cleaner = sc.Cleaner(str(home), os.getuid(), summary,
                         lambda d, s: None, None, 0, top_dev, None,
                         {"log_min_bytes": 1}, False)
    fd = cleaner.open_dir(str(home), None, ".")
    assert fd is not None
    try:
        cleaner.walk_open(fd, ".", True, None)
    finally:
        os.close(fd)
    assert summary["counts"]["skipped_xdev"] >= 1


def test_protected_paths_untouched(tmp_path):
    home = make_home(tmp_path)
    for rel in ("mail/error_log", "etc/error_log", "ssl/error_log",
                "tmp/error_log", "logs/access.log", ".trash/error_log",
                "core.1"):
        p = home / rel
        if rel == "core.1":
            p.write_bytes(b"z" * 10)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"p" * 10)
    (home / ".ssh").mkdir()
    (home / ".ssh" / "error_log").write_bytes(b"s" * 10)

    rc, summary, _ = scan(home)
    assert rc == 0
    assert summary["categories"]["error_logs"]["files"] == 0
    # core.1 at the top level is fair game; protected ones are not
    assert summary["categories"]["core_dumps"]["files"] == 1
    assert summary["counts"]["skipped_protected"] >= 5
    for rel in ("mail/error_log", "etc/error_log", "logs/access.log",
                ".trash/error_log", ".ssh/error_log"):
        assert (home / rel).read_bytes() == b"p" * 10 or \
            (home / rel).read_bytes() == b"s" * 10


def test_backup_archives_never_touched(tmp_path):
    home = make_home(tmp_path)
    for name in ("backup.tar.gz", "site.zip", "dump.sql", "old.gz",
                 "core.tar", "error_log.1"):
        (home / name).write_bytes(b"b" * 20)
    # clean-run needs explicit categories; pass every one
    rc, summary, _ = clean(home, "error_logs", "core_dumps", "app_cache",
                           "wp_cache", "dev_caches", "usertools_old")
    assert rc == 0
    assert summary["counts"]["trashed_files"] == 0
    assert summary["counts"]["truncated_files"] == 0
    for name in ("backup.tar.gz", "site.zip", "dump.sql", "old.gz",
                 "core.tar", "error_log.1"):
        assert (home / name).read_bytes() == b"b" * 20


# ---------------------------------------------------------------------------
# misc: top dirs, filtering, busy, interrupt, usage errors
# ---------------------------------------------------------------------------

def test_top_dirs_and_largest(tmp_path):
    home = make_home(tmp_path)
    bigdir = home / "public_html" / "assets"
    bigdir.mkdir(parents=True)
    (bigdir / "a.bin").write_bytes(b"0" * 1000)
    (bigdir / "b.bin").write_bytes(b"1" * 2000)
    sparse(home / "public_html" / "error_log", 2 * 1024 * 1024)

    rc, summary, _ = scan(home, "error_logs")
    assert rc == 0
    by_size = {e["path"]: e["bytes"] for e in summary["top_dirs_size"]}
    assert by_size.get("public_html", 0) >= 2 * 1024 * 1024 + 3000
    assert summary["top_dirs_inodes"][0]["path"] == "public_html"
    largest = summary["categories"]["error_logs"]["largest"]
    assert len(largest) <= sc.LARGEST_N
    assert largest[0]["path"] == "public_html/error_log"


def test_category_filtering(tmp_path):
    home = make_home(tmp_path)
    (home / "core.7").write_bytes(b"7")
    sparse(home / "public_html" / "error_log", 2 * 1024 * 1024)
    rc, summary, _ = scan(home, "core_dumps")
    assert rc == 0
    assert summary["categories"]["core_dumps"]["files"] == 1
    assert summary["categories"]["error_logs"]["files"] == 0
    assert summary["counts"]["would_change"] == 1


def test_busy_when_locked(tmp_path):
    import fcntl
    home = make_home(tmp_path)
    lockdir = os.path.join(str(home), "locks")
    os.makedirs(lockdir, exist_ok=True)
    lockpath = os.path.join(lockdir, "perm_engine.lock")
    fh = open(lockpath, "a+b")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        cmd = [sys.executable, ENGINE, "clean-scan", "--home", str(home),
               "--lock-dir", lockdir]
        env = dict(os.environ)
        env["USERTOOLS_TESTING"] = "1"
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                              env=env)
        assert proc.returncode == 3
    finally:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()


def test_interrupted_run_reports_partial(tmp_path):
    home = make_home(tmp_path)
    bulk = home / "public_html" / "many"
    bulk.mkdir()
    for i in range(8000):
        (bulk / ("f%04d" % i)).write_bytes(b"x")
    policy = write_policy(home, cleaner_log_min_mb="1",
                          cleaner_trash_days="7")
    lockdir = os.path.join(str(home), "locks")
    progress = os.path.join(str(home), "prog.json")
    cmd = [sys.executable, ENGINE, "clean-scan", "--home", str(home),
           "--lock-dir", lockdir, "--policy", policy,
           "--json-progress", progress, "--progress-every", "1"]
    env = dict(os.environ)
    env["USERTOOLS_TESTING"] = "1"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env)
    try:
        # wait until the run is provably mid-flight, then stop it
        for _ in range(300):
            if proc.poll() is not None:
                break
            try:
                with open(progress, encoding="utf-8") as fh:
                    seen = json.load(fh).get("scanned", 0)
            except (OSError, ValueError):
                seen = 0
            if seen >= 300:
                break
            time.sleep(0.05)
        assert proc.poll() is None, "run finished before it could be stopped"
        proc.send_signal(15)  # SIGTERM
        out, _ = proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    assert proc.returncode == 5
    summary = json.loads(out)
    assert summary["interrupted"] or summary["timed_out"]
    assert summary["counts"]["scanned"] > 0


def test_summary_shape_for_uapi(tmp_path):
    """The status helper needs counts as a dict and progress fields."""
    home = make_home(tmp_path)
    rc, summary, _ = scan(home)
    assert rc == 0
    assert isinstance(summary["counts"], dict)
    for key in ("scanned", "changed", "would_change", "not_owned", "errors",
                "timed_out", "interrupted"):
        assert key in summary["counts"] or key in summary, key
    assert summary["command"] == "clean-scan"
    assert summary["scope"] == str(home)
    assert summary["trash"]["batches"] == 0


