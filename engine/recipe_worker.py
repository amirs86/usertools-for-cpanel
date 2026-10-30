#!/usr/bin/python3
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""Detached recipe runner for App Helper deploy jobs.

Runs a fixed argv recipe (composer install, npm ci/build) as the user with
progress/result/log files, mirroring the engine job conventions. Standard
library only. No shell: every step is an argv list with an explicit env
mapping, cwd and timeout.

Process hygiene: each step runs in its OWN process group
(start_new_session), output streams straight into the log file (never
buffered in worker memory; the cap is enforced by trimming), and timeouts,
cancel and the overall budget all kill the step's whole group (TERM, 5 s
grace, KILL, wait) so no child — hung npm, node workers, composer scripts —
keeps burning the account after the job ends.
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

TERM_GRACE = 5.0
POLL = 0.2

# Composer/npm/artisan paint their output with ANSI escapes (colour,
# progress). Logs are for reading, not terminals: strip every escape before
# the log is trimmed or stored.
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ \-/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-B]")


def clean_log(path):
    """Strip ANSI escapes from the stored log. Never raises."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return
    try:
        text = raw.decode("utf-8", errors="replace")
    except (UnicodeError, ValueError):
        return
    cleaned = ANSI_RE.sub("", text)
    if cleaned == text:
        return
    try:
        with open(path, "wb") as fh:
            fh.write(cleaned.encode("utf-8", errors="replace"))
    except OSError:
        return

_current_pgid = None
_cancel_requested = False


def write_json(path, obj):
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def trim_log(path, cap):
    # Clean first, then enforce the byte cap.
    clean_log(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size > 2 * cap:
        with open(path, "rb") as fh:
            fh.seek(max(0, size - cap))
            tail = fh.read()
        with open(path, "wb") as fh:
            fh.write(tail)


def _kill_group(pgid):
    """TERM, grace, KILL, wait. Never raises."""
    if pgid is None:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        return
    deadline = time.time() + TERM_GRACE
    while time.time() < deadline:
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError, OSError):
            return
        time.sleep(POLL)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        return
    deadline = time.time() + TERM_GRACE
    while time.time() < deadline:
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError, OSError):
            return
        time.sleep(POLL)


def _on_term(signum, frame):
    global _cancel_requested
    _cancel_requested = True
    _kill_group(_current_pgid)


def valid_step(step):
    if not isinstance(step, dict):
        return "bad step"
    argv = step.get("argv", [])
    if not argv or not all(isinstance(a, str) for a in argv):
        return "bad argv"
    env = step.get("env", {})
    if not isinstance(env, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in env.items()
    ):
        return "bad env"
    return None


def run_step(step, log_path, log_cap, deadline):
    """Run one step to completion. Returns a result record."""
    global _current_pgid
    name = step.get("name", "step")
    timeout = step.get("timeout", 3600)
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        return {"name": name, "exit": -1, "timed_out": 0, "error": "bad timeout"}
    cwd = step.get("cwd", ".")
    log_fd = open(log_path, "ab")
    try:
        log_fd.write(("$ %s\n" % " ".join(step["argv"])).encode("utf-8", errors="replace"))
        log_fd.flush()
        try:
            proc = subprocess.Popen(
                step["argv"],
                cwd=cwd,
                env=dict(step.get("env", {})),
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except FileNotFoundError:
            return {"name": name, "exit": -1, "timed_out": 0, "error": "binary not found"}
        except OSError as ex:
            return {"name": name, "exit": -1, "timed_out": 0, "error": str(ex)}
        try:
            _current_pgid = os.getpgid(proc.pid)
        except OSError:
            _current_pgid = None
        started = time.time()
        while True:
            if _cancel_requested:
                _kill_group(_current_pgid)
                try:
                    proc.wait(timeout=TERM_GRACE)
                except subprocess.TimeoutExpired:
                    pass
                return {"name": name, "exit": -1, "timed_out": 0, "cancelled": True}
            rc = proc.poll()
            if rc is not None:
                return {"name": name, "exit": rc, "timed_out": 0}
            now = time.time()
            if now - started > timeout:
                _kill_group(_current_pgid)
                try:
                    proc.wait(timeout=TERM_GRACE)
                except subprocess.TimeoutExpired:
                    pass
                return {"name": name, "exit": -1, "timed_out": 1}
            if deadline is not None and now > deadline:
                _kill_group(_current_pgid)
                try:
                    proc.wait(timeout=TERM_GRACE)
                except subprocess.TimeoutExpired:
                    pass
                return {"name": name, "exit": -1, "timed_out": 0, "budget_exceeded": True}
            time.sleep(POLL)
    finally:
        _current_pgid = None
        try:
            log_fd.close()
        except OSError:
            pass
        trim_log(log_path, log_cap)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipe", required=True)
    ap.add_argument("--progress", required=True)
    ap.add_argument("--result", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--log-cap", type=int, default=262144)
    ap.add_argument("--budget", type=int, default=3600)
    args = ap.parse_args(argv)

    # Own process group so cancel (kill -pid) reaches step children too.
    try:
        os.setsid()
    except OSError:
        pass
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)

    try:
        with open(args.recipe, encoding="utf-8") as fh:
            recipe = json.load(fh)
        steps = recipe.get("steps", [])
        if not isinstance(steps, list) or not steps:
            raise ValueError("no steps")
    except (OSError, ValueError) as ex:
        write_json(args.result, {"ok": False, "error": "bad recipe: %s" % ex, "steps": []})
        return 2

    budget = args.budget if args.budget and args.budget > 0 else None
    deadline = (time.time() + budget) if budget else None
    done = []
    for i, step in enumerate(steps):
        if _cancel_requested:
            break
        if deadline is not None and time.time() > deadline:
            done.append({"name": "recipe", "exit": -1, "timed_out": 0, "budget_exceeded": True})
            break
        write_json(
            args.progress,
            {
                "state": "running",
                "step": i + 1,
                "steps": len(steps),
                "name": step.get("name", "step") if isinstance(step, dict) else "step",
            },
        )
        problem = valid_step(step)
        if problem is not None:
            done.append({"name": "step", "exit": -1, "timed_out": 0, "error": problem})
            break
        rec = run_step(step, args.log, args.log_cap, deadline)
        done.append(rec)
        if rec.get("exit", -1) != 0:
            break

    cleanup = None
    failed = bool(done) and not all(r.get("exit", -1) == 0 for r in done)
    if failed and not _cancel_requested:
        # Optional failure cleanup (e.g. remove node_modules so a failed
        # build does not eat quota). Runs once, inside this same job; its
        # record is appended with cleanup=True and the outcome is reported
        # top-level. A missing/unusable spec or a failing cleanup is
        # recorded as cleanup-failed, never retried.
        spec = recipe.get("on_failure") if isinstance(recipe, dict) else None
        if spec is not None:
            problem = valid_step(spec)
            if problem is not None:
                done.append({"name": "cleanup", "exit": -1, "timed_out": 0,
                             "error": problem, "cleanup": True})
                cleanup = "cleanup-failed"
            else:
                rec = run_step(spec, args.log, args.log_cap, deadline)
                rec["cleanup"] = True
                done.append(rec)
                cleanup = "removed" if rec.get("exit", -1) == 0 else "cleanup-failed"

    if _cancel_requested or any(r.get("cancelled") for r in done):
        write_json(
            args.result,
            {"ok": False, "cancelled": True, "steps": done, "finished": int(time.time())},
        )
        write_json(args.progress, {"state": "cancelled", "step": len(done), "steps": len(steps)})
        return 3
    if any(r.get("budget_exceeded") for r in done):
        result = {"ok": False, "budget_exceeded": True, "steps": done,
                  "finished": int(time.time())}
        if cleanup is not None:
            result["cleanup"] = cleanup
        write_json(args.result, result)
        write_json(args.progress, {"state": "failed", "step": len(done), "steps": len(steps)})
        return 4
    ok = all(r.get("exit", -1) == 0 for r in done) and len(done) == len(steps)
    result = {"ok": bool(ok), "steps": done, "finished": int(time.time())}
    if cleanup is not None:
        result["cleanup"] = cleanup
    write_json(args.result, result)
    write_json(
        args.progress, {"state": "done" if ok else "failed", "step": len(done), "steps": len(steps)}
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
