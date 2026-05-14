"""
Multi-vulnerability Flask app for AutoPatch-RL demo.

6 deliberate vulnerabilities across different OWASP categories:
  1. /ping   — Command Injection (CWE-78,  OWASP A03)
  2. /fetch  — SSRF             (CWE-918, OWASP A10)
  3. /read   — Path Traversal   (CWE-22,  OWASP A01)
  4. /search — SQL Injection     (CWE-89,  OWASP A03)
  5. /render — SSTI              (CWE-1336,OWASP A03)
  6. /load   — Insecure Deser.   (CWE-502, OWASP A08)

WAF middleware loaded from $WAF_RULES_PATH. When unset, WAF is OFF.
DO NOT EXPOSE THIS APP TO THE INTERNET.
"""

from __future__ import annotations

import base64
import json
import os
import pickle
import re
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, request, render_template_string

APP_VERSION = "0.5.0"
WAF_RULES_PATH = os.environ.get("WAF_RULES_PATH", "/etc/autopatch/waf_rules.json")
DB_PATH = os.environ.get("DB_PATH", "/tmp/demo.db")
NOTES_DIR = os.environ.get("NOTES_DIR", "/app/notes")

CANARY = {
    "cmd":   "CANARY_CMD_8f4a1b",
    "ssrf":  "CANARY_SSRF_3e7d2c",
    "path":  "CANARY_PATH_5c9e0a",
    "sqli":  "CANARY_SQLI_7f3a9c",
    "ssti":  "CANARY_SSTI_2b6d4e",
    "deser": "CANARY_DESER_9a1f7b",
}

app = Flask(__name__)


# ─── WAF middleware ─────────────────────────────────────────────────────────

def _load_waf_config() -> dict:
    p = Path(WAF_RULES_PATH)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception as e:
        app.logger.warning("WAF rules load failed: %s", e)
        return {}


_waf_cache: dict = {}


def _get_waf() -> dict:
    p = Path(WAF_RULES_PATH)
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return {}
    if _waf_cache.get("mtime") != mtime:
        _waf_cache["mtime"] = mtime
        _waf_cache["data"] = _load_waf_config()
    return _waf_cache.get("data", {})


@app.before_request
def _waf():
    cfg = _get_waf()
    if not cfg:
        return None

    disabled = cfg.get("disabled_endpoints", [])
    if request.path in disabled:
        return jsonify({"error": "endpoint_disabled", "path": request.path}), 404

    block_pats_raw = cfg.get("block_patterns", [])
    if not block_pats_raw:
        return None
    patterns = [re.compile(p) for p in block_pats_raw]

    haystacks: list[str] = []
    if request.args:
        haystacks.append(request.query_string.decode("utf-8", "ignore"))
    if request.form:
        for k, v in request.form.items():
            haystacks.append(f"{k}={v}")
    if request.data:
        haystacks.append(request.data.decode("utf-8", "ignore"))
    for hay in haystacks:
        if any(c in hay for c in "\n\r\x00"):
            return (
                jsonify({
                    "error": "blocked_by_waf",
                    "pattern": "control_char",
                    "match": repr(hay[:80]),
                }),
                400,
            )
        for r in patterns:
            if r.search(hay):
                return (
                    jsonify({
                        "error": "blocked_by_waf",
                        "pattern": r.pattern,
                        "match": hay[:120],
                    }),
                    400,
                )
    return None


# ─── DB init (SQLi target) ─────────────────────────────────────────────────

def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1,'admin','admin@demo.local','admin')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (2,'guest','guest@demo.local','user')"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets "
        "(id INTEGER PRIMARY KEY, flag TEXT)"
    )
    conn.execute(
        f"INSERT OR IGNORE INTO secrets VALUES (1,'{CANARY['sqli']}')"
    )
    conn.commit()
    conn.close()


with app.app_context():
    _init_db()


# ─── Notes dir init (path traversal target) ────────────────────────────────

Path(NOTES_DIR).mkdir(parents=True, exist_ok=True)
(Path(NOTES_DIR) / "welcome.txt").write_text("Welcome to the notes app!\n", encoding='utf-8')
(Path(NOTES_DIR) / "todo.txt").write_text("1. Fix vulnerabilities\n2. Ship\n", encoding='utf-8')
Path("/tmp/path_canary.txt").write_text(CANARY["path"] + "\n", encoding='utf-8')


# ─── Endpoints ──────────────────────────────────────────────────────────────

@app.get("/")
def home():
    return jsonify({
        "app": "vulnerable-multi",
        "version": APP_VERSION,
        "endpoints": [
            "/ping", "/fetch", "/read", "/search", "/render", "/load",
            "/healthz",
        ],
    })


@app.get("/healthz")
def health():
    return jsonify({"status": "ok", "canary": CANARY["ssrf"]}), 200


# ---- Vuln 1: Command Injection (CWE-78) ------------------------------------

@app.post("/ping")
def ping():
    host = request.form.get("host") or request.args.get("host") or "127.0.0.1"
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


# ---- Vuln 2: SSRF (CWE-918) ------------------------------------------------

@app.get("/fetch")
def fetch():
    """Fetch a URL. SSRF when unprotected."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "missing ?url="}), 400
    cfg = _get_waf()
    allowed_schemes = cfg.get("ssrf_allowed_schemes")
    allowed_hosts = cfg.get("ssrf_allowed_hosts")
    if allowed_schemes:
        from urllib.parse import urlparse
        import ipaddress
        parsed = urlparse(url)
        if parsed.scheme not in allowed_schemes:
            return jsonify({"error": "blocked_scheme", "scheme": parsed.scheme}), 400
        hostname = parsed.hostname or ""
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_loopback or addr.is_private or addr.is_link_local:
                return jsonify({"error": "blocked_private_ip", "host": hostname}), 400
        except ValueError:
            pass
        if hostname in ("localhost", "host.docker.internal", "metadata.google.internal"):
            return jsonify({"error": "blocked_host", "host": hostname}), 400
        if allowed_hosts and hostname not in allowed_hosts:
            return jsonify({"error": "blocked_host", "host": hostname}), 400
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            body = r.read(4096).decode("utf-8", "ignore")
        return jsonify({"url": url, "status": r.status, "body": body[:2000]})
    except Exception as e:
        return jsonify({"url": url, "error": str(e)[:300]}), 502


# ---- Vuln 3: Path Traversal (CWE-22) ---------------------------------------

@app.get("/read")
def read_note():
    """Read a note file. Path traversal when unprotected."""
    name = request.args.get("name", "welcome.txt")
    cfg = _get_waf()
    if cfg.get("path_traversal_block") and ".." in name:
        return jsonify({"error": "blocked_traversal", "name": name}), 400
    target = os.path.join(NOTES_DIR, name)
    try:
        content = open(target).read(4096)
        return jsonify({"file": name, "content": content})
    except Exception as e:
        return jsonify({"file": name, "error": str(e)[:300]}), 404


# ---- Vuln 4: SQL Injection (CWE-89) ----------------------------------------

@app.get("/search")
def search_users():
    """Search users by name. SQLi when unprotected."""
    q = request.args.get("q", "")
    if not q:
        return jsonify({"error": "missing ?q="}), 400
    cfg = _get_waf()
    conn = sqlite3.connect(DB_PATH)
    try:
        if cfg.get("sqli_parameterized"):
            rows = conn.execute(
                "SELECT id, name, email, role FROM users WHERE name LIKE ?",
                (f"%{q}%",),
            ).fetchall()
        else:
            sql = f"SELECT id, name, email, role FROM users WHERE name LIKE '%{q}%'"
            rows = conn.execute(sql).fetchall()
        return jsonify({
            "query": q,
            "results": [
                {"id": r[0], "name": r[1], "email": r[2], "role": r[3]}
                for r in rows
            ],
        })
    except Exception as e:
        return jsonify({"query": q, "error": str(e)[:300]}), 500
    finally:
        conn.close()


# ---- Vuln 5: SSTI (CWE-1336) -----------------------------------------------

@app.post("/render")
def render():
    """Render a user-supplied template. SSTI when unprotected."""
    template = request.form.get("template") or request.args.get("template", "")
    if not template:
        return jsonify({"error": "missing template"}), 400
    cfg = _get_waf()
    try:
        if cfg.get("ssti_sandbox"):
            from jinja2.sandbox import SandboxedEnvironment, is_internal_attribute
            class StrictSandbox(SandboxedEnvironment):
                def is_safe_attribute(self, obj, attr, value):
                    if attr.startswith("_"):
                        return False
                    return super().is_safe_attribute(obj, attr, value)
            env = StrictSandbox(autoescape=True)
            result = env.from_string(template).render()
        else:
            result = render_template_string(template, ssti_canary=CANARY["ssti"])
        return jsonify({"rendered": result})
    except Exception as e:
        return jsonify({"error": str(e)[:300]}), 500


# ---- Vuln 6: Insecure Deserialization (CWE-502) ----------------------------

@app.post("/load")
def load_obj():
    """Deserialise a base64-encoded pickle. RCE when unprotected."""
    cfg = _get_waf()
    if cfg.get("pickle_disabled"):
        return jsonify({"error": "endpoint_disabled", "reason": "pickle deserialization blocked by policy"}), 403
    data = request.form.get("data") or request.get_data(as_text=True)
    if not data:
        return jsonify({"error": "missing data (base64-encoded pickle)"}), 400
    try:
        raw = base64.b64decode(data)
        obj = pickle.loads(raw)
        return jsonify({"type": type(obj).__name__, "value": str(obj)[:500],
                        "canary": CANARY["deser"]})
    except Exception as e:
        return jsonify({"error": str(e)[:300]}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
