"""Score the iteration and decide termination."""

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
}


def _matches(r: dict[str, Any], category: str, sev: str, actual: str) -> bool:
    return r["category"] == category and r["severity"] == sev and r["actual"] == actual


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
    high_attack_blocked = all(
        r["actual"] == "blocked"
        for r in results
        if r["category"] == "attack_surface" and r["severity"] == "high"
    )
    all_attack_blocked = all(
        r["actual"] == "blocked"
        for r in results
        if r["category"] == "attack_surface"
    )
    regression_all_pass = all(
        r["actual"] == "pass"
        for r in results
        if r["category"] == "regression"
    )
    return high_attack_blocked and all_attack_blocked and regression_all_pass


def summary_line(results: list[dict[str, Any]], score_dict: dict[str, Any]) -> str:
    bad = [
        r["probe_id"]
        for r in results
        if (r["category"] == "attack_surface" and r["actual"] == "allowed")
        or (r["category"] == "regression" and r["actual"] == "fail")
    ]
    return f"score={score_dict['total']:+d} failing={bad}"
