"""LLM-driven red-team agent.

Given the current WAF config and previous probe results, generates novel
bypass payloads via an LLM call. Falls back to an empty payload list if
the LLM is unreachable.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = ROOT / "agents" / "prompts" / "red_agent.md"

_JSON_RE = re.compile(r"\{[\s\S]*\}", re.DOTALL)


def _client() -> Any:
    if OpenAI is None:
        return None
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key or api_key.startswith("sk-your-"):
        return None
    base_url = os.environ.get("OPENAI_BASE_URL", "https://yunwu.ai/v1")
    return OpenAI(api_key=api_key, base_url=base_url)


def _extract_json(text: str) -> dict | None:
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = re.sub(r"```", "", text)
    m = _JSON_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
        return None


def _validate_payloads(data: dict) -> list[dict[str, Any]]:
    payloads = data.get("payloads", [])
    valid = []
    required_keys = {"id", "endpoint", "method", "params", "detect_pattern", "technique"}
    for p in payloads:
        if not isinstance(p, dict):
            continue
        if required_keys - p.keys():
            continue
        if p["method"] not in ("GET", "POST"):
            continue
        if not isinstance(p["params"], dict):
            continue
        valid.append(p)
    return valid


def generate_payloads(
    waf_config: dict[str, Any],
    fixed_probe_results: list[dict[str, Any]],
    iteration: int,
    history: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], str, str]:
    """Return (payloads, rationale, source).

    source is 'llm' or 'empty' (no fallback heuristic for red agent).
    """
    cli = _client()
    if cli is None:
        return [], "LLM unavailable", "empty"

    model = os.environ.get("RED_MODEL") or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    system = PROMPT_PATH.read_text(encoding='utf-8')

    red_results = [r for r in fixed_probe_results if r["category"] == "red_team"]

    user = json.dumps(
        {
            "waf_config": waf_config,
            "fixed_probe_results": [
                {
                    "probe_id": r["probe_id"],
                    "actual": r["actual"],
                    "evidence": r.get("evidence", "")[:200],
                }
                for r in red_results
            ],
            "iteration": iteration,
            "instruction": (
                "Analyze the WAF config. Generate 3-8 novel bypass payloads "
                "targeting endpoints where the fixed probes were BLOCKED. "
                "Return ONLY the JSON object, no other text."
            ),
        },
        ensure_ascii=False,
    )

    try:
        resp = cli.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.7,
        )
        raw = resp.choices[0].message.content or ""
    except Exception as e:
        print(f"[red_agent] LLM call failed: {e}")
        return [], f"LLM error: {e}", "empty"

    data = _extract_json(raw)
    if data is None:
        print(f"[red_agent] failed to parse JSON from LLM output")
        return [], "JSON parse failed", "empty"

    payloads = _validate_payloads(data)
    rationale = data.get("rationale", "")
    return payloads, rationale, "llm"
