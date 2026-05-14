"""Markdown reporter. Combines per-iteration artifacts into a single report.

Uses the LLM when available for the narrative; falls back to a deterministic
template so the demo always produces a report.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = ROOT / "agents" / "prompts" / "reporter.md"


def _client() -> Any:
    if OpenAI is None:
        return None
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key or api_key.startswith("sk-your-"):
        return None
    base_url = os.environ.get("OPENAI_BASE_URL", "https://yunwu.ai/v1")
    return OpenAI(api_key=api_key, base_url=base_url)


def _collect_trace(run_dir: Path) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    iters = sorted((run_dir / "iters").glob("iter-*"))
    for it in iters:
        entry: dict[str, Any] = {"iter": it.name}
        for fname in ("policy_intent.yaml", "probe_results.json", "score.json"):
            p = it / fname
            if p.exists():
                entry[fname] = p.read_text(encoding='utf-8')
        diff = it / "diff.md"
        if diff.exists():
            entry["diff.md"] = diff.read_text(encoding='utf-8')
        trace.append(entry)
    return trace


def _fallback(trace: list[dict[str, Any]]) -> str:
    lines = ["# AutoPatch-RL Run Report", ""]
    lines.append("## TL;DR")
    n = len(trace)
    if not n:
        return "# AutoPatch-RL Run Report\n\nNo iterations recorded.\n"
    last = trace[-1]
    last_score = json.loads(last.get("score.json", "{}")).get("total", "?")
    lines.append(
        f"Ran {n} iterations on a deliberately misconfigured Flask container "
        f"with a command-injection RCE. Final score = {last_score}. The final "
        f"policy is saved under `final/policy_intent.yaml`."
    )
    lines.append("")
    lines.append("## Iteration-by-iteration")
    for entry in trace:
        score_j = json.loads(entry.get("score.json", "{}"))
        results = json.loads(entry.get("probe_results.json", "[]"))
        allowed = [r["probe_id"] for r in results if r["actual"] == "allowed"]
        failed = [r["probe_id"] for r in results if r["actual"] == "fail"]
        lines.append(f"### {entry['iter']}")
        lines.append(f"- score: {score_j.get('total')}")
        lines.append(f"- allowed attack-surface probes: {allowed or '∅'}")
        lines.append(f"- failed regression probes: {failed or '∅'}")
        if "diff.md" in entry and entry["diff.md"].strip():
            lines.append(entry["diff.md"])
        lines.append("")
    lines.append("## Final policy")
    lines.append("")
    lines.append("```yaml")
    lines.append(last.get("policy_intent.yaml", "").strip())
    lines.append("```")
    lines.append("")
    lines.append("## Residual risk")
    lines.append(
        "- The app still contains the `os.popen(f\"ping {host}\")` bug; the WAF "
        "is a mitigation, not a fix. Phase 1 TODO: rewrite to argument list."
    )
    lines.append(
        "- AppArmor / vArmor are not exercised; Docker Desktop on macOS ships "
        "LinuxKit without AppArmor. Move to a real Linux VM for Phase 2."
    )
    return "\n".join(lines)


def write_report(run_dir: Path) -> Path:
    trace = _collect_trace(run_dir)
    cli = _client()
    out_path = run_dir / "report.md"

    if cli is None:
        out_path.write_text(_fallback(trace), encoding='utf-8')
        return out_path

    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    system = PROMPT_PATH.read_text(encoding='utf-8')
    user = json.dumps({"trace": trace}, ensure_ascii=False)

    try:
        resp = cli.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.3,
        )
        body = resp.choices[0].message.content or _fallback(trace)
    except Exception as e:
        print(f"[reporter] LLM call failed: {e}; using fallback")
        body = _fallback(trace)

    out_path.write_text(body, encoding='utf-8')
    return out_path
