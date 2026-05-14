"""Build endpoint x technique bipartite attack graphs from probe results.

Per-iteration output: a graph with two node types
- endpoint  : /ping, /fetch, /read, /search, /render, /load
- technique : human-readable attack name (e.g. "semicolon injection",
              "decimal IP loopback bypass", "sandbox escape via __class__")

Edges go technique -> endpoint, labelled with status:
- bypassed : red payload made it through THIS round
- blocked  : red payload tried but defences caught it THIS round
- severed  : edge that was bypassed in some prior round but is now blocked
             (i.e. a defence the agent successfully installed)

The graph is the canonical state object the policy_writer agent should look
at. It is also the data source for attack_graph.html.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

# ---- Endpoint catalogue (single source of truth) ---------------------------

ENDPOINTS: list[dict[str, str]] = [
    {"path": "/ping",   "vuln": "Command Injection",   "cwe": "CWE-78"},
    {"path": "/fetch",  "vuln": "SSRF",                "cwe": "CWE-918"},
    {"path": "/read",   "vuln": "Path Traversal",      "cwe": "CWE-22"},
    {"path": "/search", "vuln": "SQL Injection",       "cwe": "CWE-89"},
    {"path": "/render", "vuln": "SSTI",                "cwe": "CWE-1336"},
    {"path": "/load",   "vuln": "Insecure Deser.",     "cwe": "CWE-502"},
]

# probe_id -> endpoint (covers static red_team probes)
_PROBE_ENDPOINT: dict[str, str] = {
    "red_cmd_injection":   "/ping",
    "red_ssrf":            "/fetch",
    "red_path_traversal":  "/read",
    "red_sqli":            "/search",
    "red_ssti":            "/render",
    "red_deserialization": "/load",
    "probe_cmd_injection": "/ping",  # blue-team basic probe also targets /ping
}

# ---- Technique extraction --------------------------------------------------

# red probe stdout pattern, e.g. "PAYLOAD[3] BYPASSED: 127.0.0.1; id"
# or "URL[5] SSRF_SUCCESS: http://2130706433:8080/healthz"
_LINE_RE = re.compile(
    r"^(?:PAYLOAD|URL)\[(\d+)\]\s+"
    r"(?P<status>BYPASSED|SSRF_SUCCESS|SQLI_SUCCESS|TRAVERSAL_SUCCESS|SSTI_CANARY|SSTI_MATH|SSTI_RCE|PICKLE_RCE|blocked(?:/failed)?)"
    r"[^:]*:\s*(?P<payload>.+?)\s*$",
    re.MULTILINE,
)

# Map a raw payload string to a short, stable technique name. Order matters:
# more specific patterns come first.
_TECHNIQUE_RULES: list[tuple[re.Pattern[str], str]] = [
    # cmd injection
    (re.compile(r"%3[bB]"),                "URL-encoded semicolon"),
    (re.compile(r"\$\(.+\)"),              "command substitution $()"),
    (re.compile(r"`[^`]+`"),               "command substitution backtick"),
    (re.compile(r";\{"),                   "IFS bracket trick"),
    (re.compile(r"\\n|\n"),                "newline injection"),
    (re.compile(r"\\t|\t"),                "tab injection"),
    (re.compile(r"\|\s*\w"),               "pipe operator"),
    (re.compile(r"&&\s*\w"),               "AND chain"),
    (re.compile(r";\s*\w"),                "semicolon injection"),
    # SSRF
    (re.compile(r"169\.254\.169\.254"),    "cloud metadata IP"),
    (re.compile(r"^file://", re.I),        "file:// scheme"),
    (re.compile(r"2130706433"),            "decimal IP loopback"),
    (re.compile(r"host\.docker\.internal"),"docker host bridge"),
    (re.compile(r"://localhost", re.I),    "localhost hostname"),
    (re.compile(r"://127\.0\.0\.1"),       "127.0.0.1 loopback"),
    (re.compile(r"://\[::1\]"),            "IPv6 loopback"),
    # path traversal
    (re.compile(r"%2[eE]%2[eE]"),          "URL-encoded dot-dot"),
    (re.compile(r"%2[fF]"),                "URL-encoded slash"),
    (re.compile(r"\.{4,}"),                "double-dot bypass"),
    (re.compile(r"^/tmp"),                 "absolute path"),
    (re.compile(r"\.\./"),                 "literal dot-dot"),
    # SQLi
    (re.compile(r"%27.*UNION", re.I),      "URL-encoded UNION"),
    (re.compile(r"UNION\s+SELECT", re.I),  "UNION SELECT"),
    (re.compile(r"OR\s+'1'='1"),           "OR 1=1 boolean"),
    (re.compile(r";\s*SELECT", re.I),      "stacked SELECT"),
    # SSTI
    (re.compile(r"__class__"),             "__class__ chain"),
    (re.compile(r"__mro__"),               "__mro__ traversal"),
    (re.compile(r"__builtins__"),          "__builtins__ access"),
    (re.compile(r"lipsum\.__globals"),     "lipsum globals trick"),
    (re.compile(r"\{\{config\}\}"),        "config leak"),
    (re.compile(r"\{\{7\*7\}\}"),          "math eval"),
    (re.compile(r"ssti_canary"),           "canary leak (sandbox off)"),
    # Evidence-string fallbacks (SSTI probe writes human strings, not payloads)
    (re.compile(r"canary leaked", re.I),   "canary leak (sandbox off)"),
    (re.compile(r"7\*7=49", re.I),         "math eval"),
    (re.compile(r"code execution", re.I),  "SSTI RCE"),
]


def _classify_technique(payload: str) -> str:
    for pat, name in _TECHNIQUE_RULES:
        if pat.search(payload):
            return name
    # Fall back to a truncated payload so unknown tricks remain visible.
    p = payload.strip()
    return f"raw: {p[:40]}" if p else "unknown"


def _extract_static_red_edges(probe: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull (technique, endpoint, status) tuples from a red_team probe row."""
    endpoint = _PROBE_ENDPOINT.get(probe["probe_id"])
    if not endpoint:
        return []
    raw = probe.get("raw_stdout", "") or ""
    edges: list[dict[str, Any]] = []
    for m in _LINE_RE.finditer(raw):
        status_raw = m.group("status")
        payload = m.group("payload")
        bypassed = status_raw not in ("blocked", "blocked/failed")
        edges.append({
            "endpoint": endpoint,
            "technique": _classify_technique(payload),
            "status": "bypassed" if bypassed else "blocked",
            "payload_preview": payload[:80],
            "source": probe["probe_id"],
        })
    # If the regex found nothing but the probe itself was allowed, still emit
    # a coarse edge so the graph is not empty.
    if not edges and probe.get("actual") == "allowed":
        edges.append({
            "endpoint": endpoint,
            "technique": "unparsed bypass",
            "status": "bypassed",
            "payload_preview": (probe.get("evidence") or "")[:80],
            "source": probe["probe_id"],
        })
    return edges


def _extract_dynamic_edges(dyn_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for r in dyn_results:
        ep = r.get("endpoint") or ""
        tech = r.get("technique") or "unknown dynamic"
        if not ep:
            continue
        edges.append({
            "endpoint": ep,
            "technique": tech.strip()[:80],
            "status": "bypassed" if r.get("actual") == "allowed" else "blocked",
            "payload_preview": (r.get("evidence") or "")[:80],
            "source": r.get("probe_id", "dyn"),
        })
    return edges


# ---- Public API ------------------------------------------------------------

def build_round_graph(
    iteration: int,
    probe_results: list[dict[str, Any]],
    red_dynamic_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Produce the per-round graph (no history merging)."""
    edges: list[dict[str, Any]] = []

    for p in probe_results:
        if p.get("category") == "red_team":
            edges.extend(_extract_static_red_edges(p))
        # blue-team static probes also map to /ping; surface their result
        elif p.get("category") == "attack_surface" and p.get("probe_id") in _PROBE_ENDPOINT:
            edges.append({
                "endpoint": _PROBE_ENDPOINT[p["probe_id"]],
                "technique": "basic probe: " + p["probe_id"],
                "status": "bypassed" if p.get("actual") == "allowed" else "blocked",
                "payload_preview": (p.get("evidence") or "")[:80],
                "source": p["probe_id"],
            })

    if red_dynamic_results:
        edges.extend(_extract_dynamic_edges(red_dynamic_results))

    # Deduplicate (endpoint, technique) keeping the worst status seen:
    # bypassed > blocked. (We want the graph to highlight any successful bypass.)
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for e in edges:
        k = (e["endpoint"], e["technique"])
        prev = by_key.get(k)
        if prev is None:
            by_key[k] = e
            continue
        # bypassed wins
        if prev["status"] == "blocked" and e["status"] == "bypassed":
            by_key[k] = e

    # Endpoint summary
    endpoint_status: dict[str, str] = {}
    for ep in ENDPOINTS:
        path = ep["path"]
        ep_edges = [e for e in by_key.values() if e["endpoint"] == path]
        if not ep_edges:
            endpoint_status[path] = "unknown"
        elif any(e["status"] == "bypassed" for e in ep_edges):
            endpoint_status[path] = "compromised"
        else:
            endpoint_status[path] = "defended"

    return {
        "iteration": iteration,
        "endpoints": ENDPOINTS,
        "edges": list(by_key.values()),
        "endpoint_status": endpoint_status,
        "stats": {
            "total_edges": len(by_key),
            "bypassed": sum(1 for e in by_key.values() if e["status"] == "bypassed"),
            "blocked": sum(1 for e in by_key.values() if e["status"] == "blocked"),
            "compromised_endpoints": sum(
                1 for s in endpoint_status.values() if s == "compromised"
            ),
        },
    }


def merge_history(
    current: dict[str, Any],
    prev_graphs: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Annotate the current round graph with cross-round provenance.

    Adds to each edge:
      - first_seen_iter : earliest iteration this (ep, tech) appeared
      - was_bypassed_before : True if any prior round had it bypassed
      - severed : True if was_bypassed_before AND current status == blocked
                  (i.e. agent successfully closed this attack path)
      - novel : True if first_seen_iter == current iteration
    """
    history: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for g in prev_graphs:
        it = g["iteration"]
        for e in g["edges"]:
            history.setdefault((e["endpoint"], e["technique"]), []).append(
                (it, e["status"])
            )

    cur_it = current["iteration"]
    for e in current["edges"]:
        key = (e["endpoint"], e["technique"])
        past = history.get(key, [])
        first_seen = min((p[0] for p in past), default=cur_it)
        was_bypassed = any(s == "bypassed" for _, s in past)
        e["first_seen_iter"] = first_seen
        e["was_bypassed_before"] = was_bypassed
        e["novel"] = first_seen == cur_it
        e["severed"] = was_bypassed and e["status"] == "blocked"
    return current


def write_graph(iter_dir: Path, graph: dict[str, Any]) -> Path:
    out = iter_dir / "attack_graph.json"
    out.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def load_run_graphs(run_dir: Path) -> list[dict[str, Any]]:
    """Load all per-round graphs in iteration order. Skips missing ones."""
    graphs: list[dict[str, Any]] = []
    iters = sorted((run_dir / "iters").glob("iter-*"))
    for d in iters:
        p = d / "attack_graph.json"
        if p.exists():
            graphs.append(json.loads(p.read_text(encoding="utf-8")))
    return graphs


def compact_for_prompt(graph: dict[str, Any], max_edges: int = 30) -> str:
    """Render the graph in a token-efficient form for LLM prompts.

    The format is a small markdown block: per-endpoint status + the most
    relevant edges, with novelty / severed annotations so the agent can
    reason about which paths to prioritize.
    """
    lines: list[str] = []
    lines.append(f"# Attack graph (iter {graph['iteration']})")
    lines.append("")
    lines.append("Endpoint status:")
    for ep in graph["endpoints"]:
        st = graph["endpoint_status"].get(ep["path"], "unknown")
        marker = {"compromised": "X", "defended": "OK", "unknown": "?"}.get(st, "?")
        lines.append(f"  [{marker}] {ep['path']:<8} {ep['vuln']}")

    # Sort edges: bypassed first, then severed (educational), then blocked.
    def rank(e: dict[str, Any]) -> tuple[int, int, str]:
        if e["status"] == "bypassed":
            return (0, -e.get("first_seen_iter", 0), e["endpoint"])
        if e.get("severed"):
            return (1, -e.get("first_seen_iter", 0), e["endpoint"])
        return (2, 0, e["endpoint"])

    edges = sorted(graph["edges"], key=rank)[:max_edges]
    if edges:
        lines.append("")
        lines.append("Active edges:")
        for e in edges:
            tags: list[str] = []
            if e.get("novel"):
                tags.append("NEW")
            if e.get("severed"):
                tags.append("SEVERED")
            if e["status"] == "bypassed":
                tags.append("ACTIVE-BYPASS")
            tag = (" [" + ",".join(tags) + "]") if tags else ""
            lines.append(
                f"  {e['endpoint']:<8} <- {e['technique']:<35} "
                f"[{e['status']}]{tag}"
            )
    return "\n".join(lines)


# ---- Self-protection guidance ---------------------------------------------

# Which WAF allowlist values would be self-defeating because the corresponding
# probe targets exactly that value. Surfaced into the prompt as "DO NOT ADD".
SELF_DEFEATING_ENTRIES: dict[str, list[str]] = {
    "ssrf_allowed_hosts": ["127.0.0.1", "localhost", "::1", "host.docker.internal"],
}


def policy_self_check(policy_intent: dict[str, Any]) -> list[str]:
    """Return human-readable warnings about policy choices that would let
    the corresponding red probe pass automatically. Used both as a sanity
    check and as prompt context for the agent."""
    warnings: list[str] = []
    waf = (policy_intent.get("controls") or {}).get("app_waf") or {}
    for field, bad_values in SELF_DEFEATING_ENTRIES.items():
        vals = waf.get(field) or []
        for v in vals:
            if v in bad_values:
                warnings.append(
                    f"app_waf.{field} contains {v!r} -- this is exactly what "
                    f"red_ssrf tests against. Including it makes that probe "
                    f"unblockable by allowlist alone."
                )
    return warnings
