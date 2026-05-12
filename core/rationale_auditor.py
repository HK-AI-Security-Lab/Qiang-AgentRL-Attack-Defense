"""Audit Blue agent rationale against actual probe results.

Compares what the policy YAML actually changed (via diff) against what
the probe results show. Flags claims that don't match reality.
"""

from __future__ import annotations

from typing import Any

import yaml

PROBE_TO_CONTROL = {
    "probe_host_mount":      "mounts",
    "probe_docker_sock":     "mounts",
    "probe_userns":          "seccomp",
    "probe_proc_kallsyms":   "seccomp",
    "probe_cmd_injection":   "app_waf",
    "red_cmd_injection":     "app_waf",
    "red_ssrf":              "app_waf",
    "red_path_traversal":    "app_waf",
    "red_sqli":              "app_waf",
    "red_ssti":              "app_waf",
    "red_deserialization":   "app_waf",
}


def _extract_controls(yaml_text: str) -> dict:
    try:
        data = yaml.safe_load(yaml_text)
        return data.get("policy_intent", {}).get("controls", {})
    except Exception:
        return {}


def _diff_controls(prev: dict, curr: dict) -> list[str]:
    """Return list of control categories that actually changed."""
    changed = []
    all_keys = set(prev.keys()) | set(curr.keys())
    for k in all_keys:
        if prev.get(k) != curr.get(k):
            changed.append(k)
    return changed


def audit(
    prev_yaml: str | None,
    curr_yaml: str,
    probe_results: list[dict[str, Any]],
    rationale: str,
) -> dict[str, Any]:
    """Audit a Blue move: compare claimed changes vs actual effect.

    Returns a dict with:
      - changed_categories: what actually changed in the YAML
      - claimed_fixes: probes the rationale mentions
      - actual_fixes: probes that went from allowed→blocked (or stayed blocked)
      - unfixed_claims: probes claimed as fixed but still allowed
      - verified: True if no unfixed claims
    """
    if prev_yaml is None:
        return {"verified": True, "reason": "baseline round", "changed_categories": [],
                "claimed_fixes": [], "actual_fixes": [], "unfixed_claims": []}

    prev_ctrl = _extract_controls(prev_yaml)
    curr_ctrl = _extract_controls(curr_yaml)
    changed_cats = _diff_controls(prev_ctrl, curr_ctrl)

    still_allowed = {
        r["probe_id"] for r in probe_results
        if r.get("actual") == "allowed" and r.get("category") != "regression"
    }
    blocked = {
        r["probe_id"] for r in probe_results
        if r.get("actual") == "blocked"
    }

    rationale_lower = rationale.lower()
    claimed_fixes = []
    for probe_id, cat in PROBE_TO_CONTROL.items():
        if probe_id.replace("_", " ") in rationale_lower or probe_id in rationale_lower:
            claimed_fixes.append(probe_id)
        elif cat in rationale_lower and cat in changed_cats:
            claimed_fixes.append(f"[category:{cat}]")

    unfixed = [p for p in claimed_fixes if p in still_allowed]

    return {
        "changed_categories": changed_cats,
        "claimed_fixes": claimed_fixes,
        "actual_fixes": sorted(blocked),
        "unfixed_claims": unfixed,
        "verified": len(unfixed) == 0,
    }
