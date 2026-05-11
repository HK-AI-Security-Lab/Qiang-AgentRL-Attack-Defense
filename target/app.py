"""
Vulnerable Flask app for AutoPatch-RL demo.

The /ping endpoint deliberately contains a command injection (OWASP A03 / CWE-78).
A regex-based WAF middleware is loaded from $WAF_RULES_PATH (JSON list of regex
patterns). When the env var is unset or the file does not exist, the WAF is OFF,
i.e. the baseline-vulnerable mode.

DO NOT EXPOSE THIS APP TO THE INTERNET.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from flask import Flask, jsonify, request

APP_VERSION = "0.1.0"
WAF_RULES_PATH = os.environ.get("WAF_RULES_PATH", "/etc/autopatch/waf_rules.json")

app = Flask(__name__)


def _load_waf_rules() -> list[re.Pattern[str]]:
    p = Path(WAF_RULES_PATH)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return [re.compile(pat) for pat in data.get("block_patterns", [])]
    except Exception as e:
        app.logger.warning("WAF rules load failed: %s", e)
        return []


@app.before_request
def _waf():
    rules = _load_waf_rules()
    if not rules:
        return None
    haystacks: list[str] = []
    if request.args:
        haystacks.append(request.query_string.decode("utf-8", "ignore"))
    if request.form:
        for k, v in request.form.items():
            haystacks.append(f"{k}={v}")
    if request.data:
        haystacks.append(request.data.decode("utf-8", "ignore"))
    for hay in haystacks:
        for r in rules:
            if r.search(hay):
                return (
                    jsonify(
                        {
                            "error": "blocked_by_waf",
                            "pattern": r.pattern,
                            "match": hay[:120],
                        }
                    ),
                    400,
                )
    return None


@app.get("/")
def home():
    return jsonify({"app": "vulnerable-pinger", "version": APP_VERSION})


@app.get("/healthz")
def health():
    return jsonify({"status": "ok"}), 200


@app.post("/ping")
def ping():
    """VULNERABLE: f-string into os shell. CWE-78."""
    host = request.form.get("host") or request.args.get("host") or "127.0.0.1"
    # ↓↓↓ The bug ↓↓↓
    cmd = f"ping -c 1 -W 1 {host}"
    try:
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=4
        )
        return out, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except subprocess.CalledProcessError as e:
        return e.output or b"", 200, {"Content-Type": "text/plain; charset=utf-8"}
    except subprocess.TimeoutExpired:
        return b"timeout", 504, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
