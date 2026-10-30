# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# SPDX header presence test.
#
# Every tracked source file must carry the copyright + SPDX header in its
# first lines. Docs (*.md), VERSION, LICENSE/NOTICE and plugin/install.json
# (JSON has no comments) are excluded by policy; binary images (*.png etc.)
# cannot carry text headers and are excluded too; everything else fails.
import pathlib
import subprocess


def _repo_root():
    out = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).strip()
    return pathlib.Path(out)


EXCLUDE_NAMES = {"LICENSE", "NOTICE", "VERSION"}
EXCLUDE_SUFFIXES = {".md", ".png", ".jpg", ".jpeg", ".gif", ".webp"}
EXCLUDE_PATHS = {"plugin/install.json"}


def _needs_header(rel):
    if rel in EXCLUDE_PATHS:
        return False
    name = rel.rsplit("/", 1)[-1]
    if name in EXCLUDE_NAMES:
        return False
    for suf in EXCLUDE_SUFFIXES:
        if name.endswith(suf):
            return False
    return True


def test_spdx_headers():
    root = _repo_root()
    files = subprocess.check_output(
        ["git", "ls-files"], cwd=str(root), text=True
    ).splitlines()
    missing = []
    for rel in files:
        if not _needs_header(rel):
            continue
        p = root / rel
        try:
            text = p.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            missing.append(rel + " (unreadable)")
            continue
        head = "\n".join(text.splitlines()[:10])
        if "Copyright 2026 Amir Sibaee" not in head:
            missing.append(rel + " (no copyright)")
        elif "SPDX-License-Identifier: Apache-2.0" not in head:
            missing.append(rel + " (no SPDX)")
    assert not missing, "source files missing SPDX header: " + ", ".join(missing)
