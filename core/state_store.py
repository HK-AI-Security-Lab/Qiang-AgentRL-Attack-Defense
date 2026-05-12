"""Persist each iteration's artifacts under reports/runs/<ts>/iter-NNN/."""

from __future__ import annotations

import datetime as dt
import difflib
import json
import shutil
from pathlib import Path
from typing import Any

import yaml

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


def policy_diff(prev_yaml: str | None, curr_yaml: str) -> str:
    """Generate a human-readable policy diff showing what the agent learned.

    Output format:
      [category_name]
      - old_key: old_value
      + new_key: new_value
    """
    if prev_yaml is None:
        return "(baseline — no previous policy)"

    try:
        prev = yaml.safe_load(prev_yaml).get("policy_intent", {}).get("controls", {})
        curr = yaml.safe_load(curr_yaml).get("policy_intent", {}).get("controls", {})
    except Exception:
        return "(failed to parse YAML for diff)"

    lines: list[str] = []

    def _fmt(v: Any) -> str:
        if isinstance(v, list):
            if not v:
                return "[]"
            items = []
            for item in v:
                if isinstance(item, dict):
                    parts = [f"{k}: {iv}" for k, iv in item.items()]
                    items.append("{" + ", ".join(parts) + "}")
                else:
                    items.append(str(item))
            return "[" + ", ".join(items) + "]"
        if isinstance(v, bool):
            return str(v).lower()
        return str(v)

    def _diff_dict(path: str, a: dict, b: dict) -> None:
        all_keys = list(dict.fromkeys(list(a.keys()) + list(b.keys())))
        for k in all_keys:
            av, bv = a.get(k), b.get(k)
            if av == bv:
                continue
            if isinstance(av, dict) and isinstance(bv, dict):
                _diff_dict(f"{path}.{k}", av, bv)
            else:
                if av is not None:
                    lines.append(f"  - {k}: {_fmt(av)}")
                if bv is not None:
                    lines.append(f"  + {k}: {_fmt(bv)}")

    all_cats = list(dict.fromkeys(list(prev.keys()) + list(curr.keys())))
    for cat in all_cats:
        p, c = prev.get(cat, {}), curr.get(cat, {})
        if p == c:
            continue
        lines.append(f"[{cat}]")
        if isinstance(p, dict) and isinstance(c, dict):
            _diff_dict(cat, p, c)
        else:
            lines.append(f"  - {_fmt(p)}")
            lines.append(f"  + {_fmt(c)}")
        lines.append("")

    return "\n".join(lines).strip() if lines else "(no changes)"


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

    readable_diff = policy_diff(prev_intent_yaml, policy_intent_yaml)
    (it_dir / "policy_diff.txt").write_text(readable_diff + "\n")

    if prev_intent_yaml is not None:
        udiff = "".join(
            difflib.unified_diff(
                prev_intent_yaml.splitlines(keepends=True),
                policy_intent_yaml.splitlines(keepends=True),
                fromfile="prev/policy_intent.yaml",
                tofile="curr/policy_intent.yaml",
            )
        )
        (it_dir / "diff.md").write_text("```diff\n" + udiff + "\n```\n")


def finalize(run_dir: Path, latest_it_dir: Path) -> Path:
    final_dir = run_dir / "final"
    final_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "policy_intent.yaml",
        "probe_results.json",
        "score.json",
        "docker_run.sh",
        "waf_rules.json",
        "policy_diff.txt",
    ):
        src = latest_it_dir / name
        if src.exists():
            shutil.copy(src, final_dir / name)
    return final_dir
