# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
# Bulk preview list regression — a finished dry run reports counts but
# the page left #ut-lists empty. Root cause: `paths.changed ||
# paths.would_change` in JS picks the empty `changed` array (empty arrays
# are truthy in JS), so the 246-item `would_change` list never rendered.
# The page now selects by mode (dry run -> would_change, apply -> changed).
import pathlib

BODY = pathlib.Path(__file__).resolve().parent.parent / "frontend" / "shared" / "bulk_permissions_body.tt"


def _text():
    return BODY.read_text(encoding="utf-8")


def test_buggy_array_fallback_gone():
    text = _text()
    assert "paths.changed || paths.would_change" not in text, (
        "buggy JS fallback still present (empty array is truthy, "
        "so dry runs render an empty list)"
    )


def test_mode_aware_selection_present():
    text = _text()
    assert "isDry ? (paths.would_change" in text, "dry-run branch missing"
    assert "(paths.changed || [])" in text, "apply branch missing"


def _select_change_list(paths, is_dry):
    # Mirrors the fixed JS: var changeList = isDry ? ... : ...;
    if is_dry:
        return paths.get("would_change") or []
    return paths.get("changed") or []


def _list_block_count(items, limit=50):
    # Mirrors listBlock: first 50 shown, remainder collapsed to "and N more".
    shown = items[:limit]
    extra = len(items) - len(shown)
    return len(shown), extra


def test_dry_run_renders_would_change():
    # Real-shaped bulk_permissions_status payload for a done dry run:
    # counts say 246, changed is empty, would_change holds 246 entries.
    would_change = [
        {"path": f"public_html/f{i}", "from": "0600", "to": "0644"}
        for i in range(246)
    ]
    summary = {
        "counts": {"would_change": 246, "changed": 0},
        "paths": {"changed": [], "would_change": would_change},
    }
    picked = _select_change_list(summary["paths"], True)
    assert len(picked) == 246, "dry run must render the would_change list"
    shown, extra = _list_block_count(picked)
    assert shown == 50
    assert extra == 196, "and 196 more"


def test_apply_renders_changed():
    changed = [{"path": "public_html/a", "from": "0600", "to": "0644"}]
    summary = {
        "counts": {"would_change": 0, "changed": 1},
        "paths": {"changed": changed, "would_change": []},
    }
    picked = _select_change_list(summary["paths"], False)
    assert picked == changed
