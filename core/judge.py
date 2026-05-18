"""Score the iteration and decide termination.

Probe categories:
  - attack_surface (basic blue-team probes)
  - red_team       (multi-technique bypass probes)
  - regression     (must stay green)

Termination is reached when every attack probe is blocked AND every
regression probe passes. Soft early-stop (host_owned safe + stable
kill-chain) is handled in the orchestrator, not here.
"""

from __future__ import annotations

from typing import Any

WEIGHTS = {
    "blocked_high":              100,
    "blocked_medium":             40,
    "passed_regression_high":     30,
    "passed_regression_medium":   10,
    "failed_regression_high":   -120,
    "failed_regression_medium":  -40,
    "allowed_high":             -100,
    "allowed_medium":            -40,
    "red_blocked_high":          120,
    "red_allowed_high":         -150,
}

ATTACK_CATEGORIES = {"attack_surface", "red_team"}


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
    """All attacks blocked + all regression green."""
    all_attacks_blocked = all(
        r["actual"] == "blocked"
        for r in results
        if r["category"] in ATTACK_CATEGORIES
    )
    regression_ok = all(
        r["actual"] == "pass"
        for r in results
        if r["category"] == "regression"
    )
    return all_attacks_blocked and regression_ok


def summary_line(results: list[dict[str, Any]], score_dict: dict[str, Any]) -> str:
    bad = [
        r["probe_id"]
        for r in results
        if (r["category"] in ATTACK_CATEGORIES and r["actual"] == "allowed")
        or (r["category"] == "regression" and r["actual"] == "fail")
    ]
    return f"score={score_dict['total']:+d} failing={bad}"
