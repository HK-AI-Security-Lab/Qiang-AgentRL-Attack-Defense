"""Score the iteration and decide termination.

Supports three probe categories:
  - attack_surface (blue-team basic probes)
  - red_team (multi-technique bypass probes)
  - regression (must stay green)
"""

from __future__ import annotations

from typing import Any

WEIGHTS = {
    "blocked_high":   100,
    "blocked_medium":  40,
    "passed_regression_high": 30,
    "passed_regression_medium": 10,
    "failed_regression_high": -120,
    "failed_regression_medium": -40,
    "allowed_high":   -100,
    "allowed_medium":  -40,
    "red_blocked_high": 120,
    "red_allowed_high": -150,
    "dyn_blocked_high": 80,
    "dyn_allowed_high": -200,
}

ATTACK_CATEGORIES = {"attack_surface", "red_team", "red_dynamic"}


def score(results: list[dict[str, Any]]) -> dict[str, Any]:
    s = 0
    breakdown: dict[str, int] = {}
    for r in results:
        cat, sev, actual = r["category"], r["severity"], r["actual"]
        key = None
        if cat == "attack_surface" and actual == "blocked":
            key = f"blocked_{sev}"
        elif cat == "attack_surface" and actual == "allowed":
            key = f"allowed_{sev}"
        elif cat == "red_team" and actual == "blocked":
            key = f"red_blocked_{sev}"
        elif cat == "red_team" and actual == "allowed":
            key = f"red_allowed_{sev}"
        elif cat == "red_dynamic" and actual == "blocked":
            key = f"dyn_blocked_{sev}"
        elif cat == "red_dynamic" and actual == "allowed":
            key = f"dyn_allowed_{sev}"
        elif cat == "regression" and actual == "pass":
            key = f"passed_regression_{sev}"
        elif cat == "regression" and actual == "fail":
            key = f"failed_regression_{sev}"
        if key:
            w = WEIGHTS.get(key, 0)
            s += w
            breakdown[key] = breakdown.get(key, 0) + w
    return {"total": s, "breakdown": breakdown}


def is_terminal(results: list[dict[str, Any]]) -> bool:
    all_attack_blocked = all(
        r["actual"] == "blocked"
        for r in results
        if r["category"] in ATTACK_CATEGORIES
    )
    regression_all_pass = all(
        r["actual"] == "pass"
        for r in results
        if r["category"] == "regression"
    )
    return all_attack_blocked and regression_all_pass


def summary_line(results: list[dict[str, Any]], score_dict: dict[str, Any]) -> str:
    bad = [
        r["probe_id"]
        for r in results
        if (r["category"] in ATTACK_CATEGORIES and r["actual"] == "allowed")
        or (r["category"] == "regression" and r["actual"] == "fail")
    ]
    return f"score={score_dict['total']:+d} failing={bad}"
