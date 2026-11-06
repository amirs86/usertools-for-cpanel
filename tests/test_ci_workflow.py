# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Workflow pinning checks.
#
# The release workflow is in the install trust path, so these checks keep its
# runners, actions, permissions and signing identity fixed.
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RUNNER = re.compile(r"ubuntu-\d{2}\.\d{2}")
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"v\d+\.\d+\.\d+")


def _lines():
    return WORKFLOW.read_text(encoding="utf-8").splitlines()


def _jobs(lines):
    jobs = {}
    current = None
    in_jobs = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" "):
            in_jobs = stripped == "jobs:"
            current = None
            continue
        if not in_jobs:
            continue
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if match:
            current = match.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs


def _steps(job_lines):
    steps = []
    current = None
    for line in job_lines:
        if re.match(r"^ {6}- ", line):
            current = [line]
            steps.append(current)
        elif current is not None:
            current.append(line)
    return steps


def _mapping(lines, start):
    base = len(lines[start]) - len(lines[start].lstrip())
    values = {}
    for line in lines[start + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base:
            break
        match = re.fullmatch(r"\s*([A-Za-z0-9_-]+):\s*(\S+)\s*", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def test_runners_are_pinned():
    lines = _lines()
    assert "ubuntu-latest" not in "\n".join(lines)
    jobs = _jobs(lines)
    assert len(jobs) == 8
    runners = [
        match.group(1)
        for line in lines
        if (match := re.match(r"^\s*runs-on:\s*(\S+)\s*$", line))
    ]
    assert len(runners) == len(jobs)
    for value in runners:
        assert RUNNER.fullmatch(value), value


def test_actions_are_pinned_by_commit():
    uses = [
        line
        for line in _lines()
        if re.match(r"^\s*(?:-\s*)?uses:", line)
    ]
    assert uses
    for line in uses:
        match = re.fullmatch(
            r"\s*(?:-\s*)?uses:\s*(\S+)\s+#\s*(v\d+\.\d+\.\d+)\s*", line
        )
        assert match, line
        ref, version = match.groups()
        action, sha = ref.rsplit("@", 1)
        assert "/" in action, line
        assert COMMIT.fullmatch(sha), line
        assert VERSION.fullmatch(version), line


def test_permissions_are_least_privilege():
    lines = _lines()
    top = [index for index, line in enumerate(lines) if line == "permissions:"]
    assert len(top) == 1, "top-level permissions block is missing"
    assert _mapping(lines, top[0]) == {"contents": "read"}

    jobs = _jobs(lines)
    extra = {}
    for name, body in jobs.items():
        found = [
            index
            for index, line in enumerate(body)
            if re.fullmatch(r" {4}permissions:\s*", line)
        ]
        if found:
            assert len(found) == 1, name
            extra[name] = _mapping(body, found[0])
    assert set(extra) == {"release"}, extra
    assert extra["release"] == {"contents": "write", "id-token": "write"}


def test_checkouts_do_not_persist_credentials():
    jobs = _jobs(_lines())
    checkouts = []
    for body in jobs.values():
        for step in _steps(body):
            if any("uses: actions/checkout@" in line for line in step):
                checkouts.append(step)
    assert len(checkouts) == len(jobs) == 8
    for step in checkouts:
        assert any(
            re.fullmatch(r"\s*persist-credentials:\s*false\s*", line)
            for line in step
        ), step[0]


def test_cosign_release_is_pinned():
    text = "\n".join(_lines())
    assert re.search(r"^\s*cosign-release:\s*v2\.4\.1\s*$", text, re.MULTILINE)


def test_release_waits_for_every_job():
    jobs = _jobs(_lines())
    assert "release" in jobs
    needs = None
    body = jobs["release"]
    for index, line in enumerate(body):
        match = re.fullmatch(r" {4}needs:\s*(.*?)\s*", line)
        if not match:
            continue
        value = match.group(1)
        if value.startswith("[") and value.endswith("]"):
            needs = [item.strip() for item in value[1:-1].split(",") if item.strip()]
        elif value:
            needs = [value]
        else:
            needs = []
            for follow in body[index + 1:]:
                item = re.fullmatch(r"\s*-\s*(\S+)\s*", follow)
                if item:
                    needs.append(item.group(1))
                elif follow.strip() and not follow.lstrip().startswith("#"):
                    break
        break
    assert needs is not None
    assert len(needs) == len(set(needs)) == 7
    assert set(needs) == set(jobs) - {"release"}


def test_signature_identity_still_names_workflow():
    assert WORKFLOW.name == "ci.yml"
    assert WORKFLOW.is_file()
    for relative in ("bootstrap-install.sh", "bin/usertools-update"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert ".github/workflows/ci.yml@refs/tags/" in text, relative
