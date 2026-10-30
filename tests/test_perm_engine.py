# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""Tests for engine/perm_engine.py.

Run on Linux:  python -m pytest tests/test_perm_engine.py -q
"""
import json
import os
import pwd
import stat
import subprocess
import sys
import time

import pytest

ENGINE_DIR = os.path.join(os.path.dirname(__file__), "..", "engine")
ENGINE = os.path.join(ENGINE_DIR, "perm_engine.py")

sys.path.insert(0, os.path.abspath(ENGINE_DIR))
import perm_engine as pe  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run_engine(*argv, home=None):
    """Run the engine CLI; return (returncode, summary_or_None, stderr)."""
    cmd = [sys.executable, ENGINE] + list(argv)
    if home is not None:
        cmd += ["--home", str(home)]
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
    (home / "public_html" / "sub").mkdir()
    (home / "public_html" / "sub" / "page.html").write_text("hi")
    return home


def lockless(*argv, home):
    """Run engine with an isolated lock dir (never touches ~/.cpanel)."""
    lockdir = os.path.join(str(home), "locks")
    return run_engine(argv[0], "--lock-dir", lockdir, *argv[1:], home=home)


# ---------------------------------------------------------------------------
# 5.3 confine to home / 5 exclude validation
# ---------------------------------------------------------------------------

def test_scope_outside_home_refused(tmp_path):
    home = make_home(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    rc, summary, err = lockless("check", "--scope", str(outside),
                                home=home)
    assert rc == 2
    assert summary is None
    assert "outside your home" in err


def test_scope_inside_home_ok(tmp_path):
    home = make_home(tmp_path)
    rc, summary, err = lockless("check", "--scope",
                                str(home / "public_html"), home=home)
    assert rc == 0, err
    assert summary["scope"].endswith("public_html")
    assert summary["counts"]["scanned"] >= 3  # top + file + subdir + file


def test_scope_traversal_trick_refused(tmp_path):
    home = make_home(tmp_path)
    tricky = os.path.join(str(home), "public_html", "..", "..", "etc")
    rc, summary, err = lockless("check", "--scope", tricky, home=home)
    assert rc == 2
    assert summary is None


def test_exclude_absolute_rejected(tmp_path):
    home = make_home(tmp_path)
    rc, summary, err = lockless("check", "--exclude", "/etc/passwd",
                                home=home)
    assert rc == 2
    assert summary is None


def test_exclude_dotdot_rejected(tmp_path):
    home = make_home(tmp_path)
    for bad in ("../secret", "a/../../b", ".."):
        rc, summary, err = lockless("check", "--exclude", bad, home=home)
        assert rc == 2, bad
        assert summary is None


def test_exclude_too_many_rejected(tmp_path):
    home = make_home(tmp_path)
    args = []
    for i in range(21):
        args += ["--exclude", "pat%d" % i]
    rc, summary, err = lockless("check", *args, home=home)
    assert rc == 2
    assert "max 20" in err


def test_excludes_honored(tmp_path):
    home = make_home(tmp_path)
    (home / "public_html" / "keepme.html").write_text("x")
    os.chmod(home / "public_html" / "keepme.html", 0o600)
    rc, summary, err = lockless("check", "--exclude", "keepme.html",
                                home=home)
    assert rc == 0, err
    paths = json.dumps(summary["paths"])
    assert "keepme.html" not in paths
    assert summary["counts"]["skipped_excluded"] >= 1


# ---------------------------------------------------------------------------
# check vs chmod vs dry-run
# ---------------------------------------------------------------------------

def test_check_reports_would_change_without_changing(tmp_path):
    home = make_home(tmp_path)
    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    rc, summary, err = lockless("check", home=home)
    assert rc == 0, err
    assert summary["counts"]["would_change"] >= 1
    assert summary["counts"]["changed"] == 0
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_chmod_applies_modes(tmp_path):
    home = make_home(tmp_path)
    f = home / "public_html" / "index.html"
    d = home / "public_html" / "sub"
    os.chmod(f, 0o600)
    os.chmod(d, 0o700)
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    assert summary["counts"]["changed"] >= 2
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o755


def test_chmod_dry_run_changes_nothing(tmp_path):
    home = make_home(tmp_path)
    f = home / "public_html" / "index.html"
    os.chmod(f, 0o600)
    rc, summary, err = lockless("chmod", "--dry-run", home=home)
    assert rc == 0, err
    assert summary["dry_run"] is True
    assert summary["counts"]["changed"] == 0
    assert summary["counts"]["would_change"] >= 1
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600


# ---------------------------------------------------------------------------
# 5.1 never follow symlinks
# ---------------------------------------------------------------------------

def test_symlink_file_never_followed(tmp_path):
    home = make_home(tmp_path)
    outside = home / "secret.txt"
    outside.write_text("secret")
    os.chmod(outside, 0o600)
    link = home / "public_html" / "evil-link"
    os.symlink(str(outside), str(link))
    rc, summary, err = lockless("chmod", "--scope",
                                str(home / "public_html"), home=home)
    assert rc == 0, err
    # outside file untouched, symlink itself untouched (still a link)
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o600
    assert os.path.islink(link)
    assert summary["counts"]["skipped_symlink"] >= 1
    joined = json.dumps(summary["paths"]["skipped_symlink"])
    assert "evil-link" in joined


def test_symlink_dir_not_descended(tmp_path):
    home = make_home(tmp_path)
    private = home / "private"
    private.mkdir()
    (private / "note.txt").write_text("x")
    os.chmod(private / "note.txt", 0o600)
    os.symlink(str(private), str(home / "public_html" / "dirlink"))
    rc, summary, err = lockless("chmod", "--scope",
                                str(home / "public_html"), home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(private / "note.txt").st_mode) == 0o600
    assert summary["counts"]["skipped_symlink"] >= 1


def test_scope_symlink_pointing_outside_refused(tmp_path):
    home = make_home(tmp_path)
    link = home / "escapelink"
    os.symlink("/etc", str(link))
    rc, summary, err = lockless("check", "--scope", str(link), home=home)
    assert rc == 2
    assert summary is None


# ---------------------------------------------------------------------------
# 5.2 stay on one filesystem
# ---------------------------------------------------------------------------

def test_cross_device_skipped_unit(tmp_path, monkeypatch):
    """Fake a subdir on another st_dev; it must be skipped, not descended."""
    home = make_home(tmp_path)
    xdev = home / "public_html" / "mnt"
    xdev.mkdir()
    (xdev / "inner.txt").write_text("x")

    real_stat = os.stat

    class FakeStat(object):
        def __init__(self, real):
            self._real = real
            for a in ("st_mode", "st_uid", "st_gid", "st_dev",
                      "st_ino", "st_nlink", "st_size"):
                setattr(self, a, getattr(real, a))

    def fake_stat(path, *a, **k):
        st = real_stat(path, *a, **k)
        if isinstance(path, str) and path == "mnt":
            other = FakeStat(st)
            other.st_dev = st.st_dev + 999999  # pretend another filesystem
            return other
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    summary = pe.new_summary("check", str(home), True)
    pe.run_walk(str(home), str(home), os.getuid(),
                {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                 "keep_exec": True, "harden": False, "do_chmod": False,
                 "deadline": None, "progress_every": 0},
                summary, lambda d, s: None)
    assert summary["counts"]["skipped_xdev"] >= 1
    assert "mnt" in json.dumps(summary["paths"]["skipped_xdev"])
    # inner.txt must not have been scanned (not descended)
    assert "inner.txt" not in json.dumps(summary)


# ---------------------------------------------------------------------------
# 5.4 refuse to run as root / setuid
# ---------------------------------------------------------------------------

def test_refuse_root_euid_zero(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit) as exc:
        pe.refuse_if_privileged()
    assert exc.value.code == 2


def test_refuse_setuid_context(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getuid", lambda: 1001)
    with pytest.raises(SystemExit) as exc:
        pe.refuse_if_privileged()
    assert exc.value.code == 2


def test_engine_allows_normal_user():
    pe.refuse_if_privileged()  # must not raise in the test process


# ---------------------------------------------------------------------------
# 5.5 only regular files and dirs; clear setuid/setgid
# ---------------------------------------------------------------------------

def test_special_files_skipped(tmp_path):
    home = make_home(tmp_path)
    fifo = home / "public_html" / "pipe"
    os.mkfifo(str(fifo))
    import socket
    sock = home / "public_html" / "sock"
    s = socket.socket(socket.AF_UNIX)
    try:
        s.bind(str(sock))
        rc, summary, err = lockless("chmod", "--scope",
                                    str(home / "public_html"), home=home)
        assert rc == 0, err
        assert summary["counts"]["skipped_special"] >= 2
    finally:
        s.close()


def test_suid_sgid_cleared_on_files(tmp_path):
    home = make_home(tmp_path)
    f = home / "public_html" / "runme"
    f.write_text("payload\n")
    os.chmod(f, 0o4755)  # setuid bit set by owner (allowed for own file)
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o4755
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o644
    assert summary["counts"]["cleared_suid_sgid"] >= 1


def test_cli_modes_never_add_special_bits(tmp_path):
    home = make_home(tmp_path)
    rc, summary, err = lockless("chmod", "--file-mode", "4755", home=home)
    assert rc == 0, err
    assert "special mode bits" in err


# ---------------------------------------------------------------------------
# 5.6 not owned -> record, never touch
# ---------------------------------------------------------------------------

def test_not_owned_recorded_not_touched(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    real_stat = os.stat

    def fake_stat(path, *a, **k):
        st = real_stat(path, *a, **k)
        if isinstance(path, str) and path.endswith("index.html"):
            class F(object):
                pass
            f = F()
            for attr in ("st_mode", "st_gid", "st_dev", "st_ino",
                         "st_nlink", "st_size"):
                setattr(f, attr, getattr(st, attr))
            f.st_uid = 0  # pretend root-owned
            return f
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(pe, "owner_name", lambda uid: "root" if uid == 0
                        else pwd.getpwuid(uid).pw_name)
    summary = pe.new_summary("chmod", str(home), False)
    pe.run_walk(str(home), str(home), os.getuid(),
                {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                 "keep_exec": True, "harden": False, "do_chmod": True,
                 "deadline": None, "progress_every": 0},
                summary, lambda d, s: None)
    assert summary["counts"]["not_owned"] >= 1
    assert summary["not_owned_by"].get("root", 0) >= 1
    entry = [e for e in summary["paths"]["not_owned"]
             if e["path"].endswith("index.html")][0]
    assert entry["owner"] == "root"


def test_report_groups_by_owner_unit(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    real_stat = os.stat

    def fake_stat(path, *a, **k):
        st = real_stat(path, *a, **k)
        if isinstance(path, str) and path.endswith(".html"):
            class F(object):
                pass
            f = F()
            for attr in ("st_mode", "st_gid", "st_dev", "st_ino",
                         "st_nlink", "st_size"):
                setattr(f, attr, getattr(st, attr))
            f.st_uid = 99
            return f
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(pe, "owner_name", lambda uid: "nobody" if uid == 99
                        else pwd.getpwuid(uid).pw_name)
    summary = pe.new_summary("report", str(home), True)
    pe.run_walk(str(home), str(home), os.getuid(),
                {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                 "keep_exec": True, "harden": False, "do_chmod": False,
                 "deadline": None, "progress_every": 0},
                summary, lambda d, s: None)
    assert summary["counts"]["changed"] == 0
    assert summary["not_owned_by"].get("nobody", 0) >= 2  # two .html files


# ---------------------------------------------------------------------------
# Helpers: keep-exec + harden
# ---------------------------------------------------------------------------

def test_keep_exec_on_cgi(tmp_path):
    home = make_home(tmp_path)
    cgi = home / "public_html" / "cgi-bin"
    cgi.mkdir()
    script = cgi / "run.cgi"
    script.write_text("#!/bin/sh\n")
    os.chmod(script, 0o755)
    plain = home / "public_html" / "plain.txt"
    plain.write_text("x")
    os.chmod(plain, 0o755)
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(script).st_mode) == 0o755  # kept
    assert stat.S_IMODE(os.stat(plain).st_mode) == 0o644  # stripped


def test_no_keep_exec_strips(tmp_path):
    home = make_home(tmp_path)
    script = home / "public_html" / "run.sh"
    script.write_text("#!/bin/sh\n")
    os.chmod(script, 0o755)
    rc, summary, err = lockless("chmod", "--no-keep-exec", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(script).st_mode) == 0o644


def test_harden_sensitive(tmp_path):
    home = make_home(tmp_path)
    wp = home / "public_html" / "wp-config.php"
    wp.write_text("x")
    os.chmod(wp, 0o644)
    env = home / "public_html" / ".env"
    env.write_text("x")
    os.chmod(env, 0o644)
    rc, summary, err = lockless("chmod", "--harden-sensitive", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(wp).st_mode) == 0o640
    assert stat.S_IMODE(os.stat(env).st_mode) == 0o600


def test_no_harden_by_default(tmp_path):
    home = make_home(tmp_path)
    wp = home / "public_html" / "wp-config.php"
    wp.write_text("x")
    os.chmod(wp, 0o644)
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(wp).st_mode) == 0o644


# ---------------------------------------------------------------------------
# 5.7 resource limits, lock, progress, max runtime
# ---------------------------------------------------------------------------

def test_nice_applied_and_ionice_tolerated(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    seen = {}

    def fake_nice(incr):
        seen["incr"] = incr
        return 10

    monkeypatch.setattr(os, "nice", fake_nice)
    monkeypatch.setattr(pe.shutil, "which", lambda name: None)  # no ionice
    pe.apply_resource_limits()
    assert seen.get("incr") == 10
    # full CLI run with no ionice on PATH must still succeed
    rc, summary, err = lockless("check", home=home)
    assert rc == 0, err


def test_lock_busy(tmp_path):
    home = make_home(tmp_path)
    lockdir = str(tmp_path / "locks")
    os.makedirs(lockdir, mode=0o700)
    import fcntl
    fh = open(os.path.join(lockdir, pe.DEFAULT_LOCK_NAME), "a+b")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        rc, summary, err = run_engine("check", "--lock-dir", lockdir,
                                      home=home)
        assert rc == 3
        assert "already running" in err
    finally:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()


def test_progress_fires_for_every_entry(tmp_path):
    """Progress fires for skipped/directory entries too, not just files."""
    home = make_home(tmp_path)
    calls = []
    summary = pe.new_summary("check", str(home), True)
    pe.run_walk(str(home), str(home), os.getuid(),
                {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                 "keep_exec": True, "harden": False, "do_chmod": False,
                 "deadline": None, "progress_every": 1},
                summary, lambda d, s: calls.append(d))
    total = summary["counts"]["scanned"] - 1  # top itself never triggers
    assert total > 2  # files + dirs present
    assert calls == list(range(1, total + 1))


def test_progress_json_written(tmp_path):
    home = make_home(tmp_path)
    prog = str(tmp_path / "progress.json")
    rc, summary, err = lockless("check", "--json-progress", prog,
                                "--progress-every", "1", home=home)
    assert rc == 0, err
    with open(prog) as fh:
        payload = json.load(fh)
    assert payload["scanned"] >= 1
    assert payload["command"] == "check"


def test_max_runtime_timeout_unit(tmp_path):
    """A deadline already in the past ends the walk with timed_out=True."""
    home = make_home(tmp_path)
    summary = pe.new_summary("check", str(home), True)
    pe.run_walk(str(home), str(home), os.getuid(),
                {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                 "keep_exec": True, "harden": False, "do_chmod": False,
                 "deadline": 0.0, "progress_every": 0},
                summary, lambda d, s: None)
    assert summary["timed_out"] is True


def test_timeout_exit_code_5(tmp_path, monkeypatch, capsys):
    """Timed-out CLI runs print the partial summary and exit 5 (not 0)."""
    home = make_home(tmp_path)
    lockdir = str(home / "locks")
    policy = tmp_path / "policy.conf"
    policy.write_text("max_job_seconds=10\n")
    calls = {"n": 0}

    def fake_mono():
        calls["n"] += 1
        return 1000.0 if calls["n"] == 1 else 2000.0

    monkeypatch.setattr(time, "monotonic", fake_mono)
    monkeypatch.setattr(os, "nice", lambda incr: 10)
    monkeypatch.setattr(pe.shutil, "which", lambda name: None)
    monkeypatch.setenv("USERTOOLS_TESTING", "1")
    rc = pe.main(["check", "--home", str(home), "--lock-dir", lockdir,
                  "--policy", str(policy)])
    assert rc == 5
    out, _ = capsys.readouterr()
    summary = json.loads(out)
    assert summary["timed_out"] is True


def test_policy_zero_or_bad_uses_default(tmp_path):
    """max_job_seconds<=0 or non-numeric warns and uses the default."""
    home = make_home(tmp_path)
    for content in ("max_job_seconds=0\n", "max_job_seconds=-5\n",
                    "max_job_seconds=many\n"):
        policy = tmp_path / "policy.conf"
        policy.write_text(content)
        rc, summary, err = lockless("check", "--policy", str(policy),
                                    home=home)
        assert rc == 0, err
        assert summary["timed_out"] is False
        assert "max_job_seconds" in err


# ---------------------------------------------------------------------------
# 5.8 output shape: counts, first-500 cap, reasons
# ---------------------------------------------------------------------------

def test_home_hook_gated(tmp_path, monkeypatch):
    """--home without USERTOOLS_TESTING=1 is refused (UAPI must not pass it)."""
    home = make_home(tmp_path)
    monkeypatch.delenv("USERTOOLS_TESTING", raising=False)
    rc = pe.main(["check", "--home", str(home), "--lock-dir",
                  str(home / "locks")])
    assert rc == 2


def test_exclude_equals_form_with_dash_value(tmp_path):
    """--exclude=<value> keeps a dash-leading pattern a value, not a flag."""
    home = make_home(tmp_path)
    target = home / "public_html" / "-dash.txt"
    target.write_text("x")
    os.chmod(target, 0o600)
    control = home / "public_html" / "index.html"
    os.chmod(control, 0o600)
    rc, summary, err = lockless("chmod", "--exclude=-dash*", home=home)
    assert rc == 0, err
    assert summary["counts"]["skipped_excluded"] >= 1
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(control).st_mode) == 0o644


def test_preview_matches_real_counts(tmp_path):
    """chmod --dry-run (UI preview) and the real run report the same counts."""
    home = make_home(tmp_path)
    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    os.chmod(home / "public_html" / "sub", 0o700)
    rc, preview, err = lockless("chmod", "--dry-run", "--no-undo", home=home)
    assert rc == 0, err
    rc, real, err = lockless("chmod", "--no-undo", home=home)
    assert rc == 0, err
    assert preview["counts"]["would_change"] == real["counts"]["changed"]
    assert preview["counts"]["would_change"] >= 2
    assert real["counts"]["changed"] >= 2


def test_output_shape_and_cap(tmp_path):
    home = make_home(tmp_path)
    big = home / "public_html" / "big"
    big.mkdir()
    for i in range(520):
        p = big / ("f%04d.txt" % i)
        p.write_text("x")
        os.chmod(p, 0o600)
    rc, summary, err = lockless("check", "--scope", str(big), home=home)
    assert rc == 0, err
    for key in ("scanned", "changed", "would_change", "apps",
                "skipped_symlink", "skipped_excluded", "skipped_protected",
                "skipped_xdev", "skipped_special", "skipped_changed_since",
                "not_owned", "errors", "cleared_suid_sgid",
                "stripped_suid_sgid"):
        assert key in summary["counts"], key
    assert len(summary["paths"]["would_change"]) == 500
    assert summary["omitted"]["would_change"] >= 20
    sample = summary["paths"]["would_change"][0]
    assert "path" in sample and "from" in sample and "to" in sample


# ---------------------------------------------------------------------------
# Undo journal + undo command + SIGTERM
# ---------------------------------------------------------------------------

def read_journal(path):
    import gzip as _gzip
    with _gzip.open(path, "rt", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    return json.loads(lines[0]), [json.loads(ln) for ln in lines[1:]]


def test_undo_journal_written(tmp_path):
    home = make_home(tmp_path)
    udir = str(tmp_path / "undo")
    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    rc, summary, err = lockless("chmod", "--undo-dir", udir, home=home)
    assert rc == 0, err
    assert summary["undo_journal"] is not None
    assert summary["undo_journal"].startswith(udir)
    header, records = read_journal(summary["undo_journal"])
    assert header["v"] == 1 and header["tool"] == "bulk"
    assert header["scope"].endswith("home")
    by_path = {r["path"]: r for r in records}
    assert by_path["public_html/index.html"]["from"] == "0600"
    assert by_path["public_html/index.html"]["to"] == "0644"


def test_no_undo_flag(tmp_path):
    home = make_home(tmp_path)
    udir = str(tmp_path / "undo")
    rc, summary, err = lockless("chmod", "--no-undo", "--undo-dir", udir,
                                home=home)
    assert rc == 0, err
    assert summary["undo_journal"] is None
    assert not os.path.isdir(udir)


def test_prune_keeps_three(tmp_path):
    import gzip as _gzip
    home = make_home(tmp_path)
    udir = tmp_path / "undo"
    udir.mkdir()
    for stamp in ("20000101T000000-000000-1", "20000102T000000-000000-1",
                  "20000103T000000-000000-1"):
        with _gzip.open(str(udir / ("bulk-%s.jsonl.gz" % stamp)), "wt") as fh:
            fh.write('{"v":1}\n')
    rc, summary, err = lockless("chmod", "--undo-dir", str(udir), home=home)
    assert rc == 0, err
    left = sorted(p.name for p in udir.iterdir() if p.suffixes[-2:] == [".jsonl", ".gz"] or p.name.endswith(".jsonl.gz"))
    assert len(left) == 3
    assert os.path.basename(summary["undo_journal"]) in left
    assert not (udir / "bulk-20000101T000000-000000-1.jsonl.gz").exists()


def test_prune_per_tool_and_tmp_age(tmp_path):
    """3 fixhome journals must not prune a fresh bulk journal; fresh .tmp
    files are kept while stale .tmp files (> max_job_seconds) are removed."""
    import gzip as _gzip
    home = make_home(tmp_path)
    udir = tmp_path / "undo"
    udir.mkdir()
    for stamp in ("20990101T000000-000000-1", "20990102T000000-000000-1",
                  "20990103T000000-000000-1"):
        with _gzip.open(str(udir / ("fixhome-%s.jsonl.gz" % stamp)), "wt") as fh:
            fh.write('{"v":1}\n')
    fresh_tmp = udir / "other-running.jsonl.gz.tmp"
    fresh_tmp.write_text("in-flight")
    stale_tmp = udir / "stale-job.jsonl.gz.tmp"
    stale_tmp.write_text("abandoned")
    old_time = time.time() - 7200
    os.utime(str(stale_tmp), (old_time, old_time))

    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    rc, summary, err = lockless("chmod", "--undo-dir", str(udir), home=home)
    assert rc == 0, err
    assert summary["undo_journal"] is not None
    assert os.path.exists(summary["undo_journal"]), "fresh bulk journal must survive 3 fixhome journals"
    assert fresh_tmp.exists(), "fresh .tmp must not be deleted"
    assert not stale_tmp.exists(), "stale .tmp older than max_job_seconds must be removed"
    rc2, usum, err2 = lockless("undo", "--journal", summary["undo_journal"], home=home)
    assert rc2 == 0, err2
    assert usum["counts"]["changed"] >= 1
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_undo_restores_modes(tmp_path):
    home = make_home(tmp_path)
    udir = str(tmp_path / "undo")
    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    rc, summary, err = lockless("chmod", "--undo-dir", udir, home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
    journal = summary["undo_journal"]
    rc, summary, err = lockless("undo", "--journal", journal, home=home)
    assert rc == 0, err
    assert summary["counts"]["changed"] >= 1
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_undo_dry_run(tmp_path):
    home = make_home(tmp_path)
    udir = str(tmp_path / "undo")
    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    rc, summary, err = lockless("chmod", "--undo-dir", udir, home=home)
    assert rc == 0, err
    rc, summary, err = lockless("undo", "--journal",
                                summary["undo_journal"], "--dry-run",
                                home=home)
    assert rc == 0, err
    assert summary["dry_run"] is True
    assert summary["counts"]["changed"] == 0
    assert summary["counts"]["would_change"] >= 1
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


def test_undo_skips_symlink_swap(tmp_path):
    home = make_home(tmp_path)
    udir = str(tmp_path / "undo")
    target = home / "public_html" / "index.html"
    other = home / "public_html" / "other.txt"
    other.write_text("x")
    os.chmod(other, 0o600)
    os.chmod(target, 0o600)
    rc, summary, err = lockless("chmod", "--undo-dir", udir, home=home)
    assert rc == 0, err
    journal = summary["undo_journal"]
    os.unlink(target)
    os.symlink(str(other), str(target))  # swap recorded file for a symlink
    rc, summary, err = lockless("undo", "--journal", journal, home=home)
    assert rc == 0, err
    assert summary["counts"]["skipped_symlink"] >= 1
    assert os.path.islink(target)
    # the untouched link target is still restored from its own record
    assert stat.S_IMODE(os.stat(other).st_mode) == 0o600


def test_undo_skips_changed_since(tmp_path):
    home = make_home(tmp_path)
    udir = str(tmp_path / "undo")
    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    rc, summary, err = lockless("chmod", "--undo-dir", udir, home=home)
    assert rc == 0, err
    os.chmod(target, 0o601)  # user changed it after the run
    rc, summary, err = lockless("undo", "--journal",
                                summary["undo_journal"], home=home)
    assert rc == 0, err
    assert summary["counts"]["skipped_changed_since"] >= 1
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o601


def test_undo_bad_journal(tmp_path):
    home = make_home(tmp_path)
    bad = tmp_path / "bad.jsonl.gz"
    bad.write_bytes(b"not gzip at all")
    rc, summary, err = lockless("undo", "--journal", str(bad), home=home)
    assert rc == 2
    assert summary is None


def test_undo_strips_suid_on_restore(tmp_path):
    home = make_home(tmp_path)
    udir = str(tmp_path / "undo")
    target = home / "public_html" / "runme"
    target.write_text("payload\n")
    os.chmod(target, 0o4755)
    rc, summary, err = lockless("chmod", "--undo-dir", udir, home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
    rc, summary, err = lockless("undo", "--journal",
                                summary["undo_journal"], home=home)
    assert rc == 0, err
    # previous 4755 restored WITHOUT the setuid bit
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o755
    assert summary["counts"]["stripped_suid_sgid"] >= 1


def test_stop_flag_aborts_walk(tmp_path, monkeypatch):
    """ stop_requested() mid-walk sets interrupted (no signal needed)."""
    home = make_home(tmp_path)
    calls = {"n": 0}

    def cb(done, summ):
        calls["n"] += 1
        if calls["n"] >= 1:
            pe.request_stop()

    summary = pe.new_summary("check", str(home), True)
    try:
        pe.run_walk(str(home), str(home), os.getuid(),
                    {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                     "keep_exec": True, "harden": False, "do_chmod": False,
                     "deadline": None, "progress_every": 1},
                    summary, cb)
    finally:
        pe._stop_requested = False
    assert summary["interrupted"] is True
    assert summary["counts"]["scanned"] < 10  # stopped early, not finished


def test_sigterm_subprocess(tmp_path):
    """SIGTERM mid-chmod -> exit 5 with partial JSON summary."""
    import signal as _signal
    home = tmp_path / "home"
    home.mkdir()
    big = home / "public_html"
    big.mkdir()
    for i in range(6000):
        p = big / ("f%05d.txt" % i)
        p.write_text("x")
        os.chmod(p, 0o600)
    lockdir = str(home / "locks")
    progfile = home / "prog.json"
    env = dict(os.environ)
    env["USERTOOLS_TESTING"] = "1"
    # --json-progress with --progress-every 1 writes prog.json on every single
    # scanned entry inside run_walk(), after the SIGTERM handler is installed,
    # and keeps the walk running for several seconds so SIGTERM always lands
    # mid-walk (never before handler installation and never after exit).
    cmd = [sys.executable, ENGINE, "chmod", "--lock-dir", lockdir,
           "--no-undo", "--home", str(home), "--scope", str(home),
           "--json-progress", str(progfile), "--progress-every", "1"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env)
    saw_work = False
    finished_early = False
    deadline = time.time() + 120
    while time.time() < deadline:
        if proc.poll() is not None:
            finished_early = True
            break
        if progfile.exists():
            saw_work = True
            break
        time.sleep(0.01)
    if finished_early:
        out, _ = proc.communicate()
        assert proc.returncode == 0
        assert json.loads(out)["counts"]["changed"] > 0
        return
    assert saw_work, "engine never started working"
    proc.send_signal(_signal.SIGTERM)
    out, err = proc.communicate(timeout=60)
    if proc.returncode == 0:
        # Rare edge case: finished the walk just as SIGTERM arrived.
        assert json.loads(out)["counts"]["changed"] > 0
        return
    assert proc.returncode == 5, err[-2000:]
    summary = json.loads(out)
    assert summary["interrupted"] is True


# ---------------------------------------------------------------------------
# scan-apps
# ---------------------------------------------------------------------------

def make_app(root, name="myapp", version="10.20.0", with_lock=True,
             composer_extra=None):
    import json as _json
    app = root / name
    (app / "vendor").mkdir(parents=True)
    (app / "artisan").write_text("#!/usr/bin/env php\n")
    (app / "vendor" / "autoload.php").write_text("<?php\n")
    require = {"php": ">=8.1", "laravel/framework": "^10.0"}
    if composer_extra:
        require.update(composer_extra)
    (app / "composer.json").write_text(
        _json.dumps({"name": "acme/app", "require": require}))
    if with_lock:
        (app / "composer.lock").write_text(_json.dumps({
            "packages": [{"name": "other/pkg", "version": "1.0.0"},
                         {"name": "laravel/framework", "version": "v" + version}],
        }))
    return app


def test_scan_finds_app_with_version(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    make_app(home / "public_html")
    rc, summary, err = lockless("scan-apps", home=home)
    assert rc == 0, err
    assert summary["command"] == "scan-apps"
    assert summary["counts"]["apps"] == 1
    assert summary["counts"]["changed"] == 0
    app = summary["paths"]["apps"][0]
    assert app["path"] == "public_html/myapp"
    assert app["framework_version"] == "10.20.0"


def test_scan_negatives(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    # missing artisan
    a = home / "noartisan"
    (a / "vendor").mkdir(parents=True)
    (a / "vendor" / "autoload.php").write_text("x")
    (a / "composer.json").write_text('{"require":{"laravel/framework":"^10.0"}}')
    # missing autoload
    b = home / "noautoload"
    b.mkdir()
    (b / "artisan").write_text("x")
    (b / "composer.json").write_text('{"require":{"laravel/framework":"^10.0"}}')
    # no framework package in require
    c = home / "noapp"
    (c / "vendor").mkdir(parents=True)
    (c / "artisan").write_text("x")
    (c / "vendor" / "autoload.php").write_text("x")
    (c / "composer.json").write_text('{"require":{"other/pkg":"^1.0"}}')
    # garbage composer.json
    d = home / "badjson"
    (d / "vendor").mkdir(parents=True)
    (d / "artisan").write_text("x")
    (d / "vendor" / "autoload.php").write_text("x")
    (d / "composer.json").write_text("not json{{{")
    # artisan is a directory
    e = home / "dirartisan"
    (e / "vendor").mkdir(parents=True)
    (e / "artisan").mkdir()
    (e / "vendor" / "autoload.php").write_text("x")
    (e / "composer.json").write_text('{"require":{"laravel/framework":"^10.0"}}')
    rc, summary, err = lockless("scan-apps", home=home)
    assert rc == 0, err
    assert summary["counts"]["apps"] == 0


def test_scan_missing_lock_gives_empty_version(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    make_app(home, "lonely", with_lock=False)
    rc, summary, err = lockless("scan-apps", home=home)
    assert rc == 0, err
    assert summary["counts"]["apps"] == 1
    assert summary["paths"]["apps"][0]["framework_version"] == ""


def test_scan_depth_limit(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    deep = home
    for i in range(3):
        deep = deep / ("l%d" % i)
    deep.mkdir(parents=True)  # home/l0/l1/l2: app below lands at depth 4
    make_app(deep, "app4")    # l0/l1/l2/app4, depth 4: found
    deeper = deep / "x"       # l0/l1/l2/x, depth 4: listed, not descended
    deeper.mkdir()
    make_app(deeper, "app5")  # depth 5: ignored
    rc, summary, err = lockless("scan-apps", home=home)
    assert rc == 0, err
    paths = [a["path"] for a in summary["paths"]["apps"]]
    assert "l0/l1/l2/app4" in paths
    assert not [p for p in paths if "app5" in p]


def test_scan_skips_protected_and_symlinks(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    sshapp = home / ".ssh" / "app"
    sshapp.mkdir(parents=True)
    (sshapp / "artisan").write_text("x")
    outside = tmp_path / "outside"
    make_app(outside, "real")
    os.symlink(str(outside / "real"), str(home / "linkedapp"))
    linkartisan = home / "linkartisan"
    linkartisan.write_text("x")
    app2 = home / "app2"
    (app2 / "vendor").mkdir(parents=True)
    os.symlink(str(linkartisan), str(app2 / "artisan"))
    (app2 / "vendor" / "autoload.php").write_text("x")
    (app2 / "composer.json").write_text('{"require":{"laravel/framework":"^10.0"}}')
    rc, summary, err = lockless("scan-apps", home=home)
    assert rc == 0, err
    assert summary["counts"]["apps"] == 0
    assert summary["counts"]["skipped_protected"] >= 1
    assert summary["counts"]["skipped_symlink"] >= 1


def test_error_entries_carry_reasons(tmp_path):
    home = make_home(tmp_path)
    locked = home / "public_html" / "lockeddir"
    locked.mkdir()
    (locked / "f.txt").write_text("x")
    os.chmod(locked, 0o000)  # owner cannot list -> error entry with reason
    try:
        rc, summary, err = lockless("check", home=home)
        assert rc == 0, err
        assert summary["counts"]["errors"] >= 1
        assert "reason" in summary["paths"]["errors"][0]
    finally:
        os.chmod(locked, 0o755)


# ---------------------------------------------------------------------------
# Fds bounded by depth, not directory count
# ---------------------------------------------------------------------------

def test_fd_bounded_under_low_rlimit(tmp_path):
    """2000 sibling dirs + a 100-deep chain with RLIMIT_NOFILE=64:
    0 errors, everything scanned, exit 0."""
    home = tmp_path / "home"
    home.mkdir()
    n_dirs = 2000
    for i in range(n_dirs):
        d = home / ("d%05d" % i)
        d.mkdir()
        f = d / "f.txt"
        f.write_text("x")
        os.chmod(f, 0o600)
    deep = home
    for i in range(100):
        deep = deep / ("level%03d" % i)
        deep.mkdir()
    (deep / "bottom.txt").write_text("x")
    os.chmod(deep / "bottom.txt", 0o600)

    def _lowfds():
        import resource as r
        r.setrlimit(r.RLIMIT_NOFILE, (64, 64))

    lockdir = str(home / "locks")
    cmd = [sys.executable, ENGINE, "chmod", "--lock-dir", lockdir,
           "--no-undo", "--home", str(home), "--scope", str(home)]
    env = dict(os.environ)
    env["USERTOOLS_TESTING"] = "1"
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                          preexec_fn=_lowfds, env=env)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "Too many open files" not in proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["counts"]["errors"] == 0
    # top + 2000 dirs + 2000 files + 100 chain dirs + bottom
    # + locks dir + lock file
    assert summary["counts"]["scanned"] == 1 + n_dirs * 2 + 101 + 2
    assert summary["resource_limited"] is False


# ---------------------------------------------------------------------------
# Engine-enforced protected paths
# ---------------------------------------------------------------------------

PROTECTED_DIRS = [".ssh", ".cpanel", ".gnupg", "etc", "mail", "ssl", "tmp",
                  "logs", "access-logs"]
PROTECTED_FILES = [".my.cnf", ".pgpass", ".bash_history"]


def test_protected_paths_untouched(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "public_html").mkdir()
    control = home / "public_html" / "index.html"
    control.write_text("x")
    os.chmod(control, 0o600)
    for name in PROTECTED_DIRS:
        d = home / name
        d.mkdir()
        os.chmod(d, 0o700)
        f = d / "secret.txt"
        f.write_text("x")
        os.chmod(f, 0o600)
    for name in PROTECTED_FILES:
        f = home / name
        f.write_text("x")
        os.chmod(f, 0o600)
    ak = home / ".ssh" / "authorized_keys"
    ak.write_text("k")
    os.chmod(ak, 0o600)
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    for name in PROTECTED_DIRS:
        assert stat.S_IMODE(os.stat(home / name).st_mode) == 0o700, name
        assert stat.S_IMODE(os.stat(home / name / "secret.txt").st_mode) \
            == 0o600, name
    for name in PROTECTED_FILES:
        assert stat.S_IMODE(os.stat(home / name).st_mode) == 0o600, name
    assert stat.S_IMODE(os.stat(ak).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(control).st_mode) == 0o644  # control changed
    assert summary["counts"]["skipped_protected"] == \
        len(PROTECTED_DIRS) + len(PROTECTED_FILES)


def test_public_html_and_ftp_mode_kept(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    for top in ("public_html", "public_ftp"):
        d = home / top
        d.mkdir()
        os.chmod(d, 0o750)
        f = d / "index.html"
        f.write_text("x")
        os.chmod(f, 0o600)
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    for top in ("public_html", "public_ftp"):
        assert stat.S_IMODE(os.stat(home / top).st_mode) == 0o750, top
        assert stat.S_IMODE(os.stat(home / top / "index.html").st_mode) \
            == 0o644, top


def test_scope_inside_protected_refused(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ssh").mkdir()
    deep = home / "etc" / "example.com"
    deep.mkdir(parents=True)
    for scope in (str(home / ".ssh"), str(deep)):
        rc, summary, err = lockless("check", "--scope", scope, home=home)
        assert rc == 2, scope
        assert summary is None
        assert "protected" in err
    # control: public_html scope is allowed (mode-keep, not refusal)
    (home / "public_html").mkdir()
    rc, summary, err = lockless("check", "--scope",
                                str(home / "public_html"), home=home)
    assert rc == 0, err


def test_report_exempt_from_protected(tmp_path, monkeypatch):
    """report still sees not-owned files under protected paths."""
    home = tmp_path / "home"
    home.mkdir()
    ssh = home / ".ssh"
    ssh.mkdir()
    ak = ssh / "authorized_keys"
    ak.write_text("k")
    real_stat = os.stat

    def fake_stat(path, *a, **k):
        st = real_stat(path, *a, **k)
        if isinstance(path, str) and path == "authorized_keys":
            class F(object):
                pass
            f = F()
            for attr in ("st_mode", "st_gid", "st_dev", "st_ino",
                         "st_nlink", "st_size"):
                setattr(f, attr, getattr(st, attr))
            f.st_uid = 0
            return f
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(pe, "owner_name", lambda uid: "root" if uid == 0
                        else pwd.getpwuid(uid).pw_name)
    summary = pe.new_summary("report", str(home), True)
    pe.run_walk(str(home), str(home), os.getuid(),
                {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                 "keep_exec": True, "harden": False, "do_chmod": False,
                 "deadline": None, "progress_every": 0},
                summary, lambda d, s: None)
    assert summary["counts"]["not_owned"] >= 1
    assert summary["counts"]["skipped_protected"] == 0


# ---------------------------------------------------------------------------
# Keep-exec: bin dirs, shebang, ELF magic
# ---------------------------------------------------------------------------

def test_keep_exec_bin_dir(tmp_path):
    home = make_home(tmp_path)
    bindir = home / "public_html" / "node_modules" / ".bin"
    bindir.mkdir(parents=True)
    tool = bindir / "tool"
    tool.write_text("binary\n")
    os.chmod(tool, 0o755)
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(tool).st_mode) == 0o755


def test_keep_exec_shebang_and_elf(tmp_path):
    home = make_home(tmp_path)
    script = home / "public_html" / "cronjob"
    script.write_text("#!/bin/sh\necho hi\n")
    os.chmod(script, 0o755)
    blob = home / "public_html" / "helper"
    blob.write_bytes(b"\x7fELF\x02\x01run")
    os.chmod(blob, 0o755)
    plain = home / "public_html" / "notes.txt"
    plain.write_text("x")
    os.chmod(plain, 0o755)
    rc, summary, err = lockless("chmod", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(script).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(blob).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(plain).st_mode) == 0o644


def test_no_keep_exec_strips_magic(tmp_path):
    home = make_home(tmp_path)
    script = home / "public_html" / "cronjob"
    script.write_text("#!/bin/sh\necho hi\n")
    os.chmod(script, 0o755)
    rc, summary, err = lockless("chmod", "--no-keep-exec", home=home)
    assert rc == 0, err
    assert stat.S_IMODE(os.stat(script).st_mode) == 0o644


def test_desired_mode_magic_unit():
    kw = {"file_mode": 0o644, "dir_mode": 0o755}
    assert pe.desired_mode("cron/run", False, 0o755, keep_exec=True,
                           harden=False, exec_magic=True, **kw) == 0o755
    assert pe.desired_mode("cron/run", False, 0o755, keep_exec=True,
                           harden=False, exec_magic=False, **kw) == 0o644
    assert pe.desired_mode("a/bin/tool", False, 0o755, keep_exec=True,
                           harden=False, exec_magic=False, **kw) == 0o755


# ---------------------------------------------------------------------------
# Chmod follow_symlinks=False unsupported -> recorded error, not exit 1
# ---------------------------------------------------------------------------

def test_chmod_notimplemented_recorded(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    target = home / "public_html" / "index.html"
    os.chmod(target, 0o600)
    real_chmod = os.chmod

    def fake_chmod(path, mode, *a, **k):
        if k.get("follow_symlinks") is False:
            raise NotImplementedError("fchmodat2 missing")
        return real_chmod(path, mode, *a, **k)

    monkeypatch.setattr(os, "chmod", fake_chmod)
    summary = pe.new_summary("chmod", str(home), False)
    pe.run_walk(str(home), str(home), os.getuid(),
                {"excludes": [], "file_mode": 0o644, "dir_mode": 0o755,
                 "keep_exec": True, "harden": False, "do_chmod": True,
                 "deadline": None, "progress_every": 0},
                summary, lambda d, s: None)  # must not raise
    assert summary["counts"]["errors"] >= 1
    assert "follow_symlinks" in json.dumps(summary["paths"]["errors"])
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600  # untouched
