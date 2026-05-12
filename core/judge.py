"""Score the iteration and decide termination.

Supports three probe categories:
  - attack_surface (blue-team basic probes)
  - red_team (multi-technique bypass probes)
  - regression (must stay green)

Win conditions:
  Blue Win  — all attacks blocked + regression green + Red fails to bypass
              for BLUE_WIN_STREAK consecutive rounds.
  Red Win   — Red has critical bypasses for RED_WIN_STREAK consecutive Blue
              repair rounds; OR Blue breaks regression for RED_WIN_STREAK
              consecutive rounds and fails to recover.
  Draw      — max rounds reached without satisfying either.
"""

from __future__ import annotations

import os
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

BLUE_WIN_STREAK = int(os.environ.get("BLUE_WIN_STREAK", "4"))
RED_WIN_STREAK = int(os.environ.get("RED_WIN_STREAK", "3"))


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


def classify_round(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify a single round's results into actionable signals."""
    all_attacks_blocked = all(
        r["actual"] == "blocked"
        for r in results
        if r["category"] in ATTACK_CATEGORIES
    )
    regression_all_pass = all(
        r["actual"] == "pass"
        for r in results
        if r["category"] == "regression"
    )
    regression_any_fail = any(
        r["actual"] == "fail"
        for r in results
        if r["category"] == "regression"
    )
    dyn_bypasses = [
        r for r in results
        if r["category"] == "red_dynamic" and r["actual"] == "allowed"
    ]
    any_critical_bypass = any(
        r["actual"] == "allowed"
        for r in results
        if r["category"] in ATTACK_CATEGORIES and r.get("severity") == "high"
    )
    return {
        "all_attacks_blocked": all_attacks_blocked,
        "regression_ok": regression_all_pass,
        "regression_fail": regression_any_fail,
        "dyn_bypass_count": len(dyn_bypasses),
        "any_critical_bypass": any_critical_bypass,
        "blue_clean": all_attacks_blocked and regression_all_pass and len(dyn_bypasses) == 0,
    }


class OutcomeTracker:
    """Track streaks across rounds to determine game outcome."""

    def __init__(self):
        self.blue_clean_streak = 0
        self.red_bypass_streak = 0
        self.regression_fail_streak = 0

    def update(self, round_class: dict[str, Any]) -> str | None:
        """Feed one round's classification. Returns outcome if game should end.

        Returns: "blue_win", "red_win", or None (continue).
        """
        if round_class["blue_clean"]:
            self.blue_clean_streak += 1
        else:
            self.blue_clean_streak = 0

        if round_class["any_critical_bypass"]:
            self.red_bypass_streak += 1
        else:
            self.red_bypass_streak = 0

        if round_class["regression_fail"]:
            self.regression_fail_streak += 1
        else:
            self.regression_fail_streak = 0

        if self.blue_clean_streak >= BLUE_WIN_STREAK:
            return "blue_win"

        if self.red_bypass_streak >= RED_WIN_STREAK:
            return "red_win"

        if self.regression_fail_streak >= RED_WIN_STREAK:
            return "red_win"

        return None


# Backward compat
def is_terminal(results: list[dict[str, Any]]) -> bool:
    c = classify_round(results)
    return c["blue_clean"]


def summary_line(results: list[dict[str, Any]], score_dict: dict[str, Any]) -> str:
    bad = [
        r["probe_id"]
        for r in results
        if (r["category"] in ATTACK_CATEGORIES and r["actual"] == "allowed")
        or (r["category"] == "regression" and r["actual"] == "fail")
    ]
    return f"score={score_dict['total']:+d} failing={bad}"
