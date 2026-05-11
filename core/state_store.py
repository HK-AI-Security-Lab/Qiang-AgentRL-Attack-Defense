"""Persist each iteration's artifacts under reports/runs/<ts>/iter-NNN/."""

from __future__ import annotations

import datetime as dt
import difflib
import json
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "reports" / "runs"


def new_run_dir() -> Path:
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    d = RUNS_DIR / ts
    d.mkdir(parents=True, exist_ok=True)
    (d / "iters").mkdir(parents=True, exist_ok=True)
    return d


def iter_dir(run_dir: Path, it: int) -> Path:
    d = run_dir / "iters" / f"iter-{it:03d}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_iteration(
    it_dir: Path,
    policy_intent_yaml: str,
    probe_results: list[dict[str, Any]],
    score_dict: dict[str, Any],
    prev_intent_yaml: str | None,
) -> None:
    (it_dir / "policy_intent.yaml").write_text(policy_intent_yaml)
    (it_dir / "probe_results.json").write_text(
        json.dumps(probe_results, indent=2, ensure_ascii=False)
    )
    (it_dir / "score.json").write_text(
        json.dumps(score_dict, indent=2, ensure_ascii=False)
    )
    if prev_intent_yaml is not None:
        diff = "".join(
            difflib.unified_diff(
                prev_intent_yaml.splitlines(keepends=True),
                policy_intent_yaml.splitlines(keepends=True),
                fromfile="prev/policy_intent.yaml",
                tofile="curr/policy_intent.yaml",
            )
        )
        (it_dir / "diff.md").write_text("```diff\n" + diff + "\n```\n")


def finalize(run_dir: Path, latest_it_dir: Path) -> Path:
    final_dir = run_dir / "final"
    final_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "policy_intent.yaml",
        "probe_results.json",
        "score.json",
        "docker_run.sh",
        "waf_rules.json",
    ):
        src = latest_it_dir / name
        if src.exists():
            shutil.copy(src, final_dir / name)
    return final_dir
