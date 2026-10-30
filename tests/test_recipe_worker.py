# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for engine/recipe_worker.py. No server, no network."""
import json
import os
import random
import signal
import subprocess
import sys
import tempfile
import time

WORKER = os.path.join(os.path.dirname(__file__), "..", "engine", "recipe_worker.py")


def run_recipe(steps, extra=(), on_failure=None):
    tmp = tempfile.mkdtemp()
    paths = {k: os.path.join(tmp, k) for k in ("recipe", "progress", "result", "log")}
    recipe = {"steps": steps}
    if on_failure is not None:
        recipe["on_failure"] = on_failure
    with open(paths["recipe"], "w", encoding="utf-8") as fh:
        json.dump(recipe, fh)
    cmd = [
        sys.executable, WORKER, "--recipe", paths["recipe"],
        "--progress", paths["progress"], "--result", paths["result"],
        "--log", paths["log"],
    ] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    result = json.load(open(paths["result"]))
    log = open(paths["log"]).read() if os.path.exists(paths["log"]) else ""
    progress = json.load(open(paths["progress"]))
    return proc.returncode, result, log, progress


def step(name, *argv, **kw):
    return {
        "name": name,
        "argv": list(argv),
        "env": {"PATH": "/usr/bin:/bin"},
        "cwd": tempfile.gettempdir(),
        "timeout": kw.get("timeout", 30),
    }


def sleepers_left(marker):
    """No process still running the marker command."""
    proc = subprocess.run(
        ["pgrep", "-f", marker], capture_output=True, text=True
    )
    return proc.returncode == 0


def test_ok_run():
    rc, result, log, progress = run_recipe([step("hi", "/bin/echo", "hello")])
    assert rc == 0
    assert result["ok"] is True
    assert result["steps"][0]["exit"] == 0
    assert "hello" in log
    assert progress["state"] == "done"


def test_failing_step_stops():
    rc, result, log, _ = run_recipe(
        [step("bad", "/bin/false"), step("never", "/bin/echo", "x")]
    )
    assert rc == 1
    assert result["ok"] is False
    assert len(result["steps"]) == 1
    assert "never" not in log
    assert "cleanup" not in result


def test_failure_cleanup_runs_and_is_recorded(tmp_path):
    target = tmp_path / "node_modules"
    target.mkdir()
    (target / "marker.txt").write_text("x")
    cleanup = dict(step("rm-nm", "/bin/rm", "-rf", str(target)))
    cleanup["cwd"] = str(tmp_path)
    rc, result, log, _ = run_recipe(
        [step("bad", "/bin/false")], on_failure=cleanup
    )
    assert rc == 1
    assert result["ok"] is False
    assert result["cleanup"] == "removed"
    assert len(result["steps"]) == 2
    assert result["steps"][1].get("cleanup") is True
    assert not target.exists()


def test_failure_cleanup_skipped_on_success():
    rc, result, _, _ = run_recipe(
        [step("hi", "/bin/echo", "hello")],
        on_failure=step("never", "/bin/echo", "x"),
    )
    assert rc == 0
    assert result["ok"] is True
    assert "cleanup" not in result
    assert len(result["steps"]) == 1


def test_failure_cleanup_failure_recorded():
    rc, result, _, _ = run_recipe(
        [step("bad", "/bin/false")],
        on_failure=step("broken", "/nonexistent/binary"),
    )
    assert rc == 1
    assert result["cleanup"] == "cleanup-failed"
    assert result["steps"][-1].get("cleanup") is True


def test_failure_cleanup_invalid_spec_recorded():
    rc, result, _, _ = run_recipe(
        [step("bad", "/bin/false")], on_failure="not-a-step"
    )
    assert rc == 1
    assert result["cleanup"] == "cleanup-failed"
    assert result["steps"][-1].get("cleanup") is True


def test_timeout_kills_whole_group():
    # Repro: sh spawns two background sleeps and waits; the
    # timeout must leave none of them alive. The duration is random per run
    # so pgrep -f can never match the invoking shell itself.
    dur = str(random.randint(41, 59))
    rc, result, _, _ = run_recipe(
        [step("fan-out", "/bin/sh", "-c", "sleep %s & sleep %s & wait" % (dur, dur), timeout=2)]
    )
    assert result["ok"] is False
    assert result["steps"][0]["timed_out"] == 1
    deadline = time.time() + 15
    while time.time() < deadline and sleepers_left("sleep %s" % dur):
        time.sleep(0.2)
    assert not sleepers_left("sleep %s" % dur), "step grandchildren must be dead"


def test_cancel_kills_grandchildren():
    dur = str(random.randint(61, 79))
    tmp = tempfile.mkdtemp()
    paths = {k: os.path.join(tmp, k) for k in ("recipe", "progress", "result", "log")}
    with open(paths["recipe"], "w", encoding="utf-8") as fh:
        json.dump({"steps": [dict(step("long", "/bin/sh", "-c", "sleep %s & sleep %s & wait" % (dur, dur), timeout=120))]}, fh)
    proc = subprocess.Popen(
        [sys.executable, WORKER, "--recipe", paths["recipe"],
         "--progress", paths["progress"], "--result", paths["result"],
         "--log", paths["log"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        # Poll until the step and its sleep grandchildren are actually running
        # (no fixed sleep race against slow interpreter startup).
        deadline = time.time() + 30
        while time.time() < deadline:
            if os.path.exists(paths["progress"]) and sleepers_left("sleep %s" % dur):
                break
            time.sleep(0.1)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
    result = json.load(open(paths["result"]))
    assert result["ok"] is False
    assert result.get("cancelled") is True
    deadline = time.time() + 15
    while time.time() < deadline and sleepers_left("sleep %s" % dur):
        time.sleep(0.2)
    assert not sleepers_left("sleep %s" % dur), "cancel must reach grandchildren"


def test_overall_budget():
    dur = str(random.randint(81, 89))
    rc, result, _, _ = run_recipe(
        [step("slow", "/bin/sleep", dur, timeout=120)], extra=("--budget", "1")
    )
    assert rc == 4
    assert result["ok"] is False
    assert result.get("budget_exceeded") is True
    assert not sleepers_left("sleep %s" % dur), "budget kill must reap the step"


def test_big_output_stays_capped():
    rc, result, log, _ = run_recipe(
        [step("spam", "/bin/sh", "-c", "head -c 5000000 /dev/zero | tr '\\0' x")]
    )
    assert result["ok"] is True
    on_disk = log
    assert len(on_disk.encode("utf-8")) <= 300 * 1024, "log bounded by the cap"


def test_bad_recipe():
    tmp = tempfile.mkdtemp()
    bad = os.path.join(tmp, "recipe.json")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    proc = subprocess.run(
        [sys.executable, WORKER, "--recipe", bad,
         "--progress", os.path.join(tmp, "p"), "--result", os.path.join(tmp, "r"),
         "--log", os.path.join(tmp, "l")],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 2
    assert json.load(open(os.path.join(tmp, "r")))["ok"] is False


def test_no_shell_and_missing_binary():
    rc, result, _, _ = run_recipe([step("x", "/nonexistent/binary")])
    assert result["ok"] is False
    assert result["steps"][0]["exit"] == -1


def test_ansi_stripped_from_stored_log():
    # Composer-style colour output ("[39m[90m.") must not reach the stored log.
    rc, result, log, _ = run_recipe(
        [step("colour", "/bin/sh", "-c", "printf '\\033[1mInstalling\\033[0m\\n\\033[39m\\033[90m.\\033[0m\\n'")]
    )
    assert result["ok"] is True
    assert "\x1b" not in log, "no escape bytes in the stored log"
    assert "Installing\n.\n" in log, "stripped step output stored"
