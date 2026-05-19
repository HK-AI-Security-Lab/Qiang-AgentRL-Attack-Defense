"""Base Model — translate unstructured CVE descriptions into a structured
"capability table" the Harness can consume.

Input  : a CyberGym task dict (from data/sample_tasks.json)
Output : capability table entry (JSON-serialisable dict)

Design (from PoC plan):
    Base Model  = LLM, only translates text -> structured JSON.
                  Does NOT do path search, scoring, or any numerical work.
    Harness     = deterministic Python, consumes the table.

Robustness:
    1. Output is constrained by an enum vocabulary so the LLM can't invent
       random node types or pre-conditions that the Harness wouldn't know.
    2. Each call is validated against the schema; a malformed reply triggers
       one retry, then falls back to a deterministic heuristic so the demo
       never breaks even if the LLM is offline.
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


# ─────────────────────────────────────────────────────────────────────────────
# Enums — mirror the Harness's static node catalogue.
# ─────────────────────────────────────────────────────────────────────────────

AFFECTED_NODE_TYPES = {"Service", "Workload", "InfraNode", "RANNode", "UE"}

PRE_CONDITIONS = {
    "network_reach",        # attacker can reach target over the network
    "local_low_priv",       # attacker has shell as a non-root user on target host
    "local_root",           # attacker already has root on target host
    "auth_user",            # attacker holds a valid user credential
    "physical_access",      # attacker is physically present (RAN scenarios)
    "untrusted_input",      # target processes attacker-controlled bytes
}

POST_CONDITIONS = {
    "rce",                  # arbitrary code execution in target process
    "info_leak",            # read sensitive memory / files
    "auth_bypass",          # skip authentication check
    "privilege_escalation", # local user -> root
    "escape_to_host",       # container -> host
    "denial_of_service",    # crash / hang
    "data_tamper",          # write data the attacker shouldn't write
    "mitm",                 # intercept / modify traffic
}

# ─────────────────────────────────────────────────────────────────────────────
# Result schema (exact field names the Harness will index on)
# ─────────────────────────────────────────────────────────────────────────────

CAPABILITY_TABLE_FIELDS = (
    "task_id", "cve_id", "affected_node_type",
    "pre_condition", "post_condition",
    "cvss", "exploit_maturity",
    "match_hints", "rationale", "source",
)

EXPLOIT_MATURITY = {"unproven", "poc", "functional", "in_the_wild"}


# ─────────────────────────────────────────────────────────────────────────────
# Heuristic fallback (deterministic, no LLM needed)
# ─────────────────────────────────────────────────────────────────────────────

def _heuristic_translate(task: dict[str, Any]) -> dict[str, Any]:
    """Cheap rule-based fallback. Used when the LLM is unavailable."""
    desc = (task.get("vulnerability", {}).get("description") or "").lower()
    vt = (task.get("vulnerability", {}).get("vuln_type") or "").lower()
    project = (task.get("target", {}).get("project") or "").lower()
    lang = (task.get("target", {}).get("language") or "").lower()
    domain = (task.get("domain") or "").lower()

    # affected_node_type: kernel CVE -> InfraNode; v8/web -> Service; userspace lib -> Workload
    if domain == "kernel" or "kernel" in desc:
        ant = "InfraNode"
    elif domain == "v8" or project == "chromium_v8":
        ant = "Service"
    else:
        ant = "Workload"

    # post_condition guess from vuln type
    if vt in ("type-confusion", "use-after-free", "heap-buffer-overflow",
              "stack-buffer-overflow", "oob-write"):
        post = ["rce"]
    elif vt in ("oob-read", "uninitialized-memory", "info-leak"):
        post = ["info_leak"]
    elif vt in ("integer-overflow", "logic-error"):
        post = ["denial_of_service"]
    else:
        post = ["denial_of_service"]

    # If the bug allows RCE *and* its surface is a kernel/local interface,
    # add escape_to_host as a likely follow-on (matches the doc example).
    if "rce" in post and ant == "InfraNode":
        post.append("escape_to_host")

    # pre_condition guess from description
    pre = ["untrusted_input"] if domain != "kernel" else ["local_low_priv"]
    if "auth" in desc or "authenticated" in desc:
        pre.append("auth_user")

    cvss_map = {"critical": 9.0, "high": 7.5, "medium": 5.5, "low": 3.0, "unknown": 5.0}
    cvss = cvss_map.get((task.get("vulnerability", {}).get("severity") or "unknown"), 5.0)

    return {
        "task_id":            task.get("task_id"),
        "cve_id":             task.get("vulnerability", {}).get("cve_id"),
        "affected_node_type": ant,
        "pre_condition":      sorted(set(pre)),
        "post_condition":     sorted(set(post)),
        "cvss":               cvss,
        "exploit_maturity":   "poc",
        "match_hints": {
            "project_name":   project or None,
            "language":       lang or None,
            "vuln_type":      vt or None,
        },
        "rationale": "(heuristic) rule-based mapping from vuln_type and domain.",
        "source":    "heuristic",
    }


# ─────────────────────────────────────────────────────────────────────────────
# LLM-driven translator
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are the **Base Model** of a security attack-graph pipeline.
Your only job is to read an unstructured CVE / vulnerability description and
translate it into a strict JSON capability table that a deterministic Harness
will consume. You DO NOT search paths, score risk, or invent node identifiers.

# OUTPUT FORMAT
Return ONLY a single fenced ```json block. Nothing before, nothing after.

The JSON object MUST have exactly these fields:
{
  "affected_node_type": "Service" | "Workload" | "InfraNode" | "RANNode" | "UE",
  "pre_condition":  [<subset of PRE_CONDITIONS>],
  "post_condition": [<subset of POST_CONDITIONS>],
  "cvss": <float 0..10>,
  "exploit_maturity": "unproven" | "poc" | "functional" | "in_the_wild",
  "match_hints": {
    "project_name": "<lowercase project name, e.g. ffmpeg or null>",
    "language":     "<c | cpp | javascript | python | mixed | null>",
    "vuln_type":    "<lowercase normalized type or null>"
  },
  "rationale": "<one short sentence explaining your mapping>"
}

# VOCABULARIES
PRE_CONDITIONS  = network_reach, local_low_priv, local_root, auth_user, physical_access, untrusted_input
POST_CONDITIONS = rce, info_leak, auth_bypass, privilege_escalation, escape_to_host, denial_of_service, data_tamper, mitm

# RULES
- affected_node_type:
    InfraNode if the CVE is in the kernel / hypervisor / firmware
    Service   if it's a network-facing daemon (browser engine, HTTP server, DB server)
    Workload  if it's a userspace library / parser / codec / image inside a container
    RANNode / UE only for wireless RAN scenarios (BTS / handset)
- post_condition: pick ALL outcomes the CVE can directly grant. Memory corruption
  in a JS engine or kernel typically means at least "rce". A kernel RCE often
  also enables "escape_to_host" if the affected node hosts containers.
- pre_condition: be honest about prerequisites:
    untrusted_input  if the bug fires on attacker-controlled bytes (almost always)
    network_reach    if the attacker must reach the service over the network
    local_low_priv   if the attacker needs a shell on the host (most kernel bugs)
    auth_user        if a valid login is required first
- cvss: use the reported CVSS if mentioned, otherwise infer from severity:
    critical >= 9.0, high ~ 7.5, medium ~ 5.5, low ~ 3.0
- Be terse. The rationale field MUST be one sentence.
"""


def _client() -> Any:
    if OpenAI is None:
        return None
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key or api_key.startswith("sk-your-"):
        return None
    base_url = os.environ.get("OPENAI_BASE_URL", "https://yunwu.ai/v1")
    return OpenAI(api_key=api_key, base_url=base_url)


_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json(text: str) -> str:
    m = _FENCE_RE.search(text)
    return m.group(1).strip() if m else text.strip()


def _validate(parsed: dict[str, Any]) -> list[str]:
    """Return a list of validation errors (empty if OK)."""
    errs: list[str] = []
    if parsed.get("affected_node_type") not in AFFECTED_NODE_TYPES:
        errs.append(f"affected_node_type must be one of {sorted(AFFECTED_NODE_TYPES)}")

    pre = parsed.get("pre_condition") or []
    if not isinstance(pre, list) or any(p not in PRE_CONDITIONS for p in pre):
        errs.append(f"pre_condition entries must come from {sorted(PRE_CONDITIONS)}")

    post = parsed.get("post_condition") or []
    if not isinstance(post, list) or not post or any(p not in POST_CONDITIONS for p in post):
        errs.append(f"post_condition must be non-empty and from {sorted(POST_CONDITIONS)}")

    try:
        cvss = float(parsed.get("cvss"))
        if not (0 <= cvss <= 10):
            errs.append("cvss must be in [0, 10]")
    except (TypeError, ValueError):
        errs.append("cvss must be a number")

    if parsed.get("exploit_maturity") not in EXPLOIT_MATURITY:
        errs.append(f"exploit_maturity must be one of {sorted(EXPLOIT_MATURITY)}")

    return errs


def _build_user_message(task: dict[str, Any]) -> str:
    target = task.get("target", {})
    vuln = task.get("vulnerability", {})
    body = {
        "task_id":     task.get("task_id"),
        "cve_id":      vuln.get("cve_id"),
        "domain":      task.get("domain"),
        "project":     target.get("project"),
        "language":    target.get("language"),
        "subsystem":   target.get("subsystem"),
        "vuln_type":   vuln.get("vuln_type"),
        "severity":    vuln.get("severity"),
        "description": vuln.get("description"),
        "annotations": vuln.get("annotations"),
    }
    return (
        "Translate this CVE record into the capability-table JSON described in "
        "the system prompt. Be conservative: only assert post_conditions you can "
        "directly justify from the description.\n\n"
        + json.dumps(body, ensure_ascii=False, indent=2)
    )


def translate_task(task: dict[str, Any]) -> dict[str, Any]:
    """Translate one CyberGym task into a capability-table entry.

    Always returns a valid entry. `source` field tells you whether the LLM
    actually produced it ("llm") or the heuristic fallback was used ("heuristic").
    """
    cli = _client()
    if cli is None:
        return _heuristic_translate(task)

    model = (
        os.environ.get("BASE_MODEL_NAME")
        or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    )
    user = _build_user_message(task)

    for attempt in range(2):
        try:
            resp = cli.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user},
                ],
                temperature=0.1,
            )
            raw = resp.choices[0].message.content or ""
        except Exception as e:
            print(f"[base_model] LLM call failed (attempt {attempt + 1}): {e}")
            if attempt == 0:
                continue
            return _heuristic_translate(task)

        try:
            parsed = json.loads(_extract_json(raw))
        except json.JSONDecodeError as e:
            print(f"[base_model] JSON parse failed (attempt {attempt + 1}): {e}")
            if attempt == 0:
                user += "\n\n# REMINDER\nReturn ONLY a single fenced JSON block."
                continue
            return _heuristic_translate(task)

        errs = _validate(parsed) if isinstance(parsed, dict) else ["not a JSON object"]
        if errs:
            print(f"[base_model] validation failed (attempt {attempt + 1}): {errs}")
            if attempt == 0:
                user += "\n\n# VALIDATION ERRORS\n- " + "\n- ".join(errs)
                continue
            return _heuristic_translate(task)

        # Success — assemble the canonical entry.
        return {
            "task_id":            task.get("task_id"),
            "cve_id":             task.get("vulnerability", {}).get("cve_id"),
            "affected_node_type": parsed["affected_node_type"],
            "pre_condition":      sorted(set(parsed["pre_condition"])),
            "post_condition":     sorted(set(parsed["post_condition"])),
            "cvss":               float(parsed["cvss"]),
            "exploit_maturity":   parsed["exploit_maturity"],
            "match_hints":        parsed.get("match_hints") or {},
            "rationale":          (parsed.get("rationale") or "")[:200],
            "source":             "llm",
        }

    # Should not reach here — defence in depth.
    return _heuristic_translate(task)


# ─────────────────────────────────────────────────────────────────────────────
# CLI: python -m base_model.translate <tasks.json> [-n 5] [-o cap_table.json]
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    from dotenv import load_dotenv

    # Load .env from the parent project (where OPENAI_API_KEY lives)
    parent_env = Path(__file__).resolve().parent.parent.parent / ".env"
    if parent_env.exists():
        load_dotenv(parent_env)

    ap = argparse.ArgumentParser()
    ap.add_argument("tasks", help="path to sample_tasks.json")
    ap.add_argument("-n", "--limit", type=int, default=8,
                    help="max tasks to translate (default: 8)")
    ap.add_argument("-o", "--out", default="data/capability_table.json")
    ap.add_argument("--ids", nargs="*",
                    help="optional explicit task_id list (overrides --limit)")
    args = ap.parse_args()

    all_tasks = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
    if args.ids:
        selected = [t for t in all_tasks if t.get("task_id") in set(args.ids)]
    else:
        # Diverse default: 1 kernel + 2 userspace + 2 v8 + 1 web (if present)
        selected = _pick_diverse(all_tasks, args.limit)

    print(f"translating {len(selected)} task(s)...")
    table = []
    for t in selected:
        entry = translate_task(t)
        print(f"  {entry['task_id']}  -> {entry['affected_node_type']:<10}"
              f" pre={entry['pre_condition']} post={entry['post_condition']}"
              f"  cvss={entry['cvss']}  ({entry['source']})")
        table.append(entry)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(table, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {out}  ({len(table)} entries, "
          f"{sum(1 for e in table if e['source'] == 'llm')} from LLM)")


def _pick_diverse(tasks: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    """Choose up to n tasks covering different domains and projects."""
    by_domain: dict[str, list[dict]] = {}
    for t in tasks:
        by_domain.setdefault(t.get("domain", "?"), []).append(t)

    picked: list[dict] = []
    # Round-robin through domains so the sample is diverse.
    domains = sorted(by_domain.keys())
    while len(picked) < n and any(by_domain.values()):
        for d in domains:
            if not by_domain[d]:
                continue
            picked.append(by_domain[d].pop(0))
            if len(picked) >= n:
                break
    return picked


if __name__ == "__main__":
    main()
