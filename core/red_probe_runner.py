"""Execute LLM-generated red-team payloads against the target container."""

from __future__ import annotations

import os
import re
import time
from typing import Any
from urllib.parse import urlencode

import requests


def _target_base() -> str:
    host = os.environ.get("TARGET_HOST", "127.0.0.1")
    port = os.environ.get("TARGET_PORT", "18080")
    return f"http://{host}:{port}"


def run_payload(payload: dict[str, Any], iteration: int) -> dict[str, Any]:
    """Execute a single dynamic payload and return a probe-like result dict."""
    base = _target_base()
    endpoint = payload["endpoint"]
    method = payload["method"].upper()
    params = payload.get("params", {})
    detect = payload.get("detect_pattern", "")
    pid = payload.get("id", "dyn_unknown")

    url = f"{base}{endpoint}"
    t0 = time.time()
    resp_text = ""
    status_code = 0
    error = ""

    try:
        if method == "GET":
            r = requests.get(url, params=params, timeout=5)
        else:
            r = requests.post(url, data=params, timeout=5)
        resp_text = r.text[:4000]
        status_code = r.status_code
    except Exception as e:
        error = str(e)[:300]
        resp_text = error

    duration = round(time.time() - t0, 3)

    bypassed = False
    if detect and not error:
        try:
            bypassed = bool(re.search(detect, resp_text))
        except re.error:
            bypassed = detect in resp_text

    blocked_by_waf = "blocked_by_waf" in resp_text or "endpoint_disabled" in resp_text
    actual = "allowed" if bypassed else "blocked"

    evidence_parts = []
    if bypassed:
        evidence_parts.append(f"BYPASS via {payload.get('technique', '?')}")
        m = re.search(detect, resp_text) if detect else None
        if m:
            evidence_parts.append(f"match: {m.group()[:80]}")
    elif blocked_by_waf:
        evidence_parts.append("blocked by WAF")
    elif error:
        evidence_parts.append(f"error: {error[:100]}")
    else:
        evidence_parts.append(f"no match for detect_pattern (HTTP {status_code})")
    evidence = "; ".join(evidence_parts)

    return {
        "probe_id": pid,
        "category": "red_dynamic",
        "severity": "high",
        "expected": "blocked",
        "actual": actual,
        "evidence": evidence[:400],
        "raw_stdout": resp_text[:2000],
        "raw_stderr": "",
        "exit_code": 0 if bypassed else 1,
        "iteration": iteration,
        "duration_s": duration,
        "technique": payload.get("technique", ""),
        "endpoint": endpoint,
    }


def run_all(payloads: list[dict[str, Any]], iteration: int) -> list[dict[str, Any]]:
    return [run_payload(p, iteration) for p in payloads]
