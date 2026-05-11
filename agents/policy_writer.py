"""LLM-driven policy writer.

Calls an OpenAI-compatible endpoint (Yunwu by default) with the policy_writer
system prompt + a structured user message containing the current state and
probe results. Validates the LLM output against the JSON schema. Falls back
to a deterministic heuristic if the LLM is unreachable or malformed (so the
loop can still progress in CI / offline demos).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = ROOT / "agents" / "prompts" / "policy_writer.md"
SCHEMA_PATH = ROOT / "schemas" / "policy_intent.schema.json"

_FENCE_RE = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def _client() -> Any:
    if OpenAI is None:
        return None
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key or api_key.startswith("sk-your-"):
        return None
    base_url = os.environ.get("OPENAI_BASE_URL", "https://yunwu.ai/v1")
    return OpenAI(api_key=api_key, base_url=base_url)


def _extract_yaml(text: str) -> str:
    m = _FENCE_RE.search(text)
    if m:
        return m.group(1).strip()
    return text.strip()


def _validate(intent: dict[str, Any]) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text())
    return [
        f"{'/'.join(map(str, e.path))}: {e.message}"
        for e in Draft7Validator(schema).iter_errors(intent)
    ]


def propose_next(
    current_intent_yaml: str,
    probe_results: list[dict[str, Any]],
    history: list[dict[str, Any]],
) -> tuple[str, str]:
    """Return (new_intent_yaml, source) where source ∈ {'llm', 'heuristic'}."""
    cli = _client()
    if cli is None:
        return _heuristic_step(current_intent_yaml, probe_results), "heuristic"

    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    system = PROMPT_PATH.read_text()
    schema = SCHEMA_PATH.read_text()

    user = json.dumps(
        {
            "current_policy_intent_yaml": current_intent_yaml,
            "probe_results": probe_results,
            "history_brief": history[-6:],
            "schema": json.loads(schema),
            "instruction": "Return only the next policy_intent.yaml as a fenced YAML block.",
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
            temperature=0.2,
        )
        raw = resp.choices[0].message.content or ""
    except Exception as e:
        print(f"[policy_writer] LLM call failed: {e}; falling back to heuristic")
        return _heuristic_step(current_intent_yaml, probe_results), "heuristic"

    yaml_text = _extract_yaml(raw)
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        print(f"[policy_writer] YAML parse failed: {e}; falling back")
        return _heuristic_step(current_intent_yaml, probe_results), "heuristic"

    errors = _validate(parsed) if isinstance(parsed, dict) else ["not a mapping"]
    if errors:
        print(f"[policy_writer] schema validation failed: {errors}; falling back")
        return _heuristic_step(current_intent_yaml, probe_results), "heuristic"

    return yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True), "llm"


# ---------------------------------------------------------------------------
# Heuristic fallback — one fix per iteration (matches the LLM prompt constraint)
# ---------------------------------------------------------------------------

_HEURISTIC_STEPS = [
    "mounts",
    "capabilities",
    "seccomp",
    "container_security",
    "app_waf",
]


def _heuristic_step(
    current_yaml: str, probe_results: list[dict[str, Any]]
) -> str:
    data = yaml.safe_load(current_yaml)
    pi = data["policy_intent"]
    c = pi["controls"]
    waf = c["app_waf"]

    allowed = {r["probe_id"] for r in probe_results if r.get("actual") == "allowed"}
    failed_reg = {r["probe_id"] for r in probe_results if r.get("actual") == "fail"}

    note = ""

    # Step 1: mounts
    if "probe_host_mount" in allowed or "probe_docker_sock" in allowed:
        c["mounts"]["bind"] = [
            m for m in c["mounts"]["bind"]
            if m["host_path"] not in ("/", "/var/run/docker.sock")
        ]
        note = "removed dangerous bind mounts (/host, docker.sock)"
    # Step 2: capabilities
    elif "SYS_ADMIN" in c["capabilities"]["add"] or c["capabilities"]["drop"] == []:
        c["capabilities"]["add"] = [
            cap for cap in c["capabilities"]["add"] if cap != "SYS_ADMIN"
        ]
        c["capabilities"]["drop"] = ["ALL"]
        if "NET_RAW" not in c["capabilities"]["add"]:
            c["capabilities"]["add"].append("NET_RAW")
        note = "drop=ALL, add=[NET_RAW]; removed SYS_ADMIN"
    # Step 3: seccomp
    elif c["seccomp"]["profile"] == "Unconfined":
        c["seccomp"]["profile"] = "RuntimeDefault"
        note = "seccomp Unconfined -> RuntimeDefault"
    # Step 4: container_security
    elif not c["container_security"]["no_new_privileges"]:
        c["container_security"]["no_new_privileges"] = True
        c["container_security"]["allow_privilege_escalation"] = False
        note = "no_new_privileges=true, allow_privilege_escalation=false"
    # Step 5: WAF + cmd injection
    elif ("probe_cmd_injection" in allowed or "red_cmd_injection" in allowed) and not waf.get("enabled"):
        waf["enabled"] = True
        waf["block_patterns"] = ["[;&|`$()]", "\\$\\("]
        note = "WAF on, blocking shell metachar"
    # Step 6: path traversal
    elif "red_path_traversal" in allowed and not waf.get("path_traversal_block"):
        waf["path_traversal_block"] = True
        note = "path_traversal_block=true for /read"
    # Step 7: SQL injection
    elif "red_sqli" in allowed and not waf.get("sqli_parameterized"):
        waf["sqli_parameterized"] = True
        note = "sqli_parameterized=true for /search"
    # Step 8: SSTI
    elif "red_ssti" in allowed and not waf.get("ssti_sandbox"):
        waf["ssti_sandbox"] = True
        note = "ssti_sandbox=true for /render"
    # Step 9: SSRF
    elif "red_ssrf" in allowed:
        waf["ssrf_allowed_schemes"] = ["http", "https"]
        waf["ssrf_allowed_hosts"] = ["example.com"]
        note = "SSRF allowlist: http/https only, hosts=[example.com]"
    # Step 10: deserialization
    elif "red_deserialization" in allowed and not waf.get("pickle_disabled"):
        waf["pickle_disabled"] = True
        note = "pickle_disabled=true for /load"
    # Fix WAF false positive
    elif "regression_legit_ping" in failed_reg and waf.get("enabled"):
        waf["block_patterns"] = ["[;&|`$()]"]
        note = "narrowed WAF regex to fix false positive"
    else:
        note = "no further heuristic fix available"

    pi["rationale"] = f"(heuristic) {note}"
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
