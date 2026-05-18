"""5-layer kill chain attack graph (schema killchain.v1).

The graph is a STATIC catalogue of nodes + edges that describes every
known attack path from an L1 entry point all the way to L5 host
compromise. Each round we evaluate the catalogue against the current
policy_intent + probe results to produce a snapshot showing which
edges/nodes are reachable, severed, or empirically bypassed.

Layers
  L1  Initial Access         6 endpoints (where the attacker rings the doorbell)
  L2  Capability             what the attacker gets on success
  L3  Container Compromise   what they can do inside the container
  L4  Container Escape       how they get out of the container
  L5  Host Compromise        terminal state

Edge resolution per round
  1. If an edge has an `empirical` probe whose result we have, use that
     directly (probe says "blocked"/"bypassed" - authoritative).
  2. Else if the edge's `severance(policy_intent)` returns True, status
     is `severed`.
  3. Else the edge is `open` and its real status depends on whether the
     source node is reachable (propagated from L1 down).

Node reachability
  L1 nodes are always reachable (anyone can ring the doorbell).
  For higher layers, a node N is reachable iff there exists at least
  one incoming edge E such that:
    - E.source is reachable
    - all of E.requires are reachable (AND-precondition support)
    - E.status in {bypassed, reachable}
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Static node catalogue
# ---------------------------------------------------------------------------

NODES: list[dict[str, Any]] = [
    # L1 Initial Access
    {"id": "ia_ping",   "layer": 1, "label": "POST /ping",   "description": "Command Injection (CWE-78)"},
    {"id": "ia_fetch",  "layer": 1, "label": "GET /fetch",   "description": "SSRF (CWE-918)"},
    {"id": "ia_read",   "layer": 1, "label": "GET /read",    "description": "Path Traversal (CWE-22)"},
    {"id": "ia_search", "layer": 1, "label": "GET /search",  "description": "SQL Injection (CWE-89)"},
    {"id": "ia_render", "layer": 1, "label": "POST /render", "description": "SSTI (CWE-1336)"},
    {"id": "ia_load",   "layer": 1, "label": "POST /load",   "description": "Insecure Deserialization (CWE-502)"},
    # L2 Capability
    {"id": "cap_shell_exec",  "layer": 2, "label": "Shell exec (root)",  "description": "Arbitrary command execution as container root"},
    {"id": "cap_http_egress", "layer": 2, "label": "HTTP egress",        "description": "Server-side HTTP requests on attacker's behalf"},
    {"id": "cap_file_read",   "layer": 2, "label": "File read",          "description": "Arbitrary path read inside container"},
    {"id": "cap_db_read",     "layer": 2, "label": "DB read",            "description": "Read /tmp/demo.db (incl. secrets table)"},
    {"id": "cap_python_eval", "layer": 2, "label": "Python eval",        "description": "Code execution in Jinja2 / app context"},
    {"id": "cap_pickle_rce",  "layer": 2, "label": "Pickle RCE",         "description": "Deserialize attacker-controlled object"},
    # L3 Container Compromise
    {"id": "cc_read_shadow",   "layer": 3, "label": "Read /etc/shadow",   "description": "Sensitive file read; needs root"},
    {"id": "cc_read_kallsyms", "layer": 3, "label": "Leak kernel addrs",  "description": "Read /proc/kallsyms"},
    {"id": "cc_create_userns", "layer": 3, "label": "Create userns",      "description": "unshare -U"},
    {"id": "cc_read_host",     "layer": 3, "label": "Read /host root",   "description": "Host filesystem accessible via bind mount"},
    {"id": "cc_docker_sock",   "layer": 3, "label": "Talk docker.sock",  "description": "Reach Docker daemon API"},
    {"id": "cc_metadata_ssrf", "layer": 3, "label": "Cloud metadata",    "description": "Reach 169.254.169.254 / IMDS via SSRF"},
    # L4 Container Escape
    {"id": "esc_chroot_host",     "layer": 4, "label": "chroot to /host",   "description": "Run binaries from host root"},
    {"id": "esc_docker_sock_rce", "layer": 4, "label": "docker.sock RCE",   "description": "Spawn privileged container"},
    {"id": "esc_kernel_exploit",  "layer": 4, "label": "Kernel exploit",    "description": "kallsyms + userns -> kernel code exec"},
    {"id": "esc_sysadmin_escape", "layer": 4, "label": "SYS_ADMIN escape",  "description": "CAP_SYS_ADMIN allows mounting host fs"},
    # L5 Host
    {"id": "host_owned", "layer": 5, "label": "Host compromised", "description": "Attacker has shell on host / cluster"},
]

NODE_BY_ID: dict[str, dict[str, Any]] = {n["id"]: n for n in NODES}


# ---------------------------------------------------------------------------
# Severance predicates: given policy_intent, return True iff the edge is cut.
# Predicates are conservative: when uncertain, return False (assume reachable).
# ---------------------------------------------------------------------------

def _waf(p: dict) -> dict:
    return p.get("controls", {}).get("app_waf", {}) or {}


def _waf_blocks_shell_metachar(p: dict) -> bool:
    waf = _waf(p)
    if not waf.get("enabled"):
        return False
    for pat in waf.get("block_patterns") or []:
        if re.search(r"[;|`$()]", pat) or "&&" in pat or "\\|" in pat:
            return True
    return False


def _ssrf_blocks_loopback(p: dict) -> bool:
    waf = _waf(p)
    schemes = waf.get("ssrf_allowed_schemes")
    if not schemes:
        return False
    self_defeating = {"127.0.0.1", "localhost", "::1", "host.docker.internal"}
    hosts = waf.get("ssrf_allowed_hosts") or []
    if any(h in self_defeating for h in hosts):
        return False
    return True


def _ssrf_blocks_metadata(p: dict) -> bool:
    return bool(_waf(p).get("ssrf_allowed_schemes"))


def _path_block(p: dict) -> bool:
    return bool(_waf(p).get("path_traversal_block"))


def _sqli_param(p: dict) -> bool:
    return bool(_waf(p).get("sqli_parameterized"))


def _ssti_sandbox(p: dict) -> bool:
    return bool(_waf(p).get("ssti_sandbox"))


def _pickle_off(p: dict) -> bool:
    waf = _waf(p)
    if waf.get("pickle_disabled"):
        return True
    return "/load" in (waf.get("disabled_endpoints") or [])


def _has_sys_admin(p: dict) -> bool:
    caps = p.get("controls", {}).get("capabilities", {}) or {}
    if "ALL" in (caps.get("drop") or []):
        return False
    return "SYS_ADMIN" in (caps.get("add") or [])


def _has_host_mount(p: dict) -> bool:
    for m in (p.get("controls", {}).get("mounts", {}).get("bind") or []):
        hp = m.get("host_path") or m.get("source") or ""
        if hp in ("/", "/host"):
            return True
    return False


def _has_docker_sock(p: dict) -> bool:
    for m in (p.get("controls", {}).get("mounts", {}).get("bind") or []):
        hp = m.get("host_path") or m.get("source") or ""
        if "docker.sock" in hp:
            return True
    return False


def _seccomp_default(p: dict) -> bool:
    return p.get("controls", {}).get("seccomp", {}).get("profile") == "RuntimeDefault"


def _run_as_non_root(p: dict) -> bool:
    return bool(p.get("controls", {}).get("container_security", {}).get("run_as_non_root"))


# ---------------------------------------------------------------------------
# Static edge catalogue
# ---------------------------------------------------------------------------

_EDGE_SPECS: list[dict[str, Any]] = [
    # L1 -> L2 (empirical probes are authoritative)
    {"source": "ia_ping",   "target": "cap_shell_exec",  "label": "shell metachar injection",
     "severance": _waf_blocks_shell_metachar, "severance_label": "app_waf blocks shell metachars",
     "empirical": "red_cmd_injection"},
    {"source": "ia_fetch",  "target": "cap_http_egress", "label": "fetch attacker URL",
     "severance": _ssrf_blocks_loopback, "severance_label": "ssrf_allowed_hosts excludes loopback",
     "empirical": "red_ssrf"},
    {"source": "ia_read",   "target": "cap_file_read",   "label": "../ traversal",
     "severance": _path_block, "severance_label": "path_traversal_block: true",
     "empirical": "red_path_traversal"},
    {"source": "ia_search", "target": "cap_db_read",     "label": "UNION SELECT",
     "severance": _sqli_param, "severance_label": "sqli_parameterized: true",
     "empirical": "red_sqli"},
    {"source": "ia_render", "target": "cap_python_eval", "label": "__class__ chain",
     "severance": _ssti_sandbox, "severance_label": "ssti_sandbox: true",
     "empirical": "red_ssti"},
    {"source": "ia_load",   "target": "cap_pickle_rce",  "label": "pickle.loads",
     "severance": _pickle_off, "severance_label": "pickle_disabled / endpoint disabled",
     "empirical": "red_deserialization"},

    # L2 -> L3 (shell_exec is the main multiplier)
    {"source": "cap_shell_exec",  "target": "cc_read_shadow",   "label": "cat /etc/shadow",
     "severance": _run_as_non_root, "severance_label": "run_as_non_root: true"},
    {"source": "cap_shell_exec",  "target": "cc_read_kallsyms", "label": "cat /proc/kallsyms",
     "severance": _seccomp_default, "severance_label": "seccomp RuntimeDefault zeroes addrs",
     "empirical": "probe_proc_kallsyms"},
    {"source": "cap_shell_exec",  "target": "cc_create_userns", "label": "unshare -U",
     "severance": _seccomp_default, "severance_label": "seccomp RuntimeDefault blocks",
     "empirical": "probe_userns"},
    {"source": "cap_shell_exec",  "target": "cc_read_host",     "label": "ls /host",
     "severance": lambda p: not _has_host_mount(p),
     "severance_label": "no /host bind mount",
     "empirical": "probe_host_mount"},
    {"source": "cap_shell_exec",  "target": "cc_docker_sock",   "label": "curl --unix-socket docker.sock",
     "severance": lambda p: not _has_docker_sock(p),
     "severance_label": "no docker.sock bind mount",
     "empirical": "probe_docker_sock"},

    # Pickle RCE behaves like shell_exec
    {"source": "cap_pickle_rce", "target": "cc_read_shadow",   "label": "subprocess via gadget",
     "severance": _run_as_non_root, "severance_label": "run_as_non_root: true"},
    {"source": "cap_pickle_rce", "target": "cc_read_kallsyms", "label": "subprocess via gadget",
     "severance": _seccomp_default, "severance_label": "seccomp RuntimeDefault"},
    {"source": "cap_pickle_rce", "target": "cc_create_userns", "label": "subprocess via gadget",
     "severance": _seccomp_default, "severance_label": "seccomp RuntimeDefault"},

    # SSTI Python eval
    {"source": "cap_python_eval", "target": "cc_read_shadow", "label": "os.popen via __globals__",
     "severance": _run_as_non_root, "severance_label": "run_as_non_root: true"},

    # File read (no shell, just open())
    {"source": "cap_file_read", "target": "cc_read_shadow", "label": "read /etc/passwd",
     "severance": lambda p: False,
     "severance_label": "no policy lever (file_read = file_read)"},

    # Cloud metadata via egress
    {"source": "cap_http_egress", "target": "cc_metadata_ssrf", "label": "GET 169.254.169.254",
     "severance": _ssrf_blocks_metadata,
     "severance_label": "ssrf allowlist (excludes IMDS)"},

    # L3 -> L4
    {"source": "cc_read_host", "target": "esc_chroot_host", "label": "chroot /host /bin/bash",
     "severance": lambda p: False, "severance_label": "trivial once host fs visible"},
    {"source": "cc_docker_sock", "target": "esc_docker_sock_rce", "label": "POST /containers/create privileged=true",
     "severance": lambda p: False, "severance_label": "trivial once socket reachable"},
    # AND-edge: kernel exploit needs BOTH kallsyms AND userns
    {"source": "cc_read_kallsyms", "target": "esc_kernel_exploit",
     "requires": ["cc_create_userns"],
     "label": "kernel ROP gadget chain",
     "severance": lambda p: False, "severance_label": "kallsyms + userns suffice"},
    # SYS_ADMIN escape only needs shell + the cap
    {"source": "cap_shell_exec", "target": "esc_sysadmin_escape", "label": "mount -t proc / /mnt",
     "severance": lambda p: not _has_sys_admin(p),
     "severance_label": "SYS_ADMIN dropped"},

    # L4 -> L5
    {"source": "esc_chroot_host",     "target": "host_owned", "label": "host shell",
     "severance": lambda p: False, "severance_label": ""},
    {"source": "esc_docker_sock_rce", "target": "host_owned", "label": "host shell",
     "severance": lambda p: False, "severance_label": ""},
    {"source": "esc_kernel_exploit",  "target": "host_owned", "label": "host shell",
     "severance": lambda p: False, "severance_label": ""},
    {"source": "esc_sysadmin_escape", "target": "host_owned", "label": "host shell",
     "severance": lambda p: False, "severance_label": ""},
]


# ---------------------------------------------------------------------------
# Build / propagate
# ---------------------------------------------------------------------------

def _probe_status_table(probe_results: list[dict[str, Any]] | None) -> dict[str, str]:
    """Map probe_id -> 'bypassed' | 'blocked' from .actual."""
    out: dict[str, str] = {}
    if not probe_results:
        return out
    for p in probe_results:
        actual = p.get("actual")
        pid = p.get("probe_id")
        if not pid:
            continue
        if actual in ("allowed", "fail"):
            out[pid] = "bypassed"
        elif actual in ("blocked", "pass"):
            out[pid] = "blocked"
    return out


def _resolve_policy(policy_intent: dict | str | None) -> dict | None:
    """Accept dict, full YAML string, or already-unwrapped controls dict."""
    if policy_intent is None:
        return None
    if isinstance(policy_intent, dict):
        if "policy_intent" in policy_intent:
            return policy_intent["policy_intent"]
        return policy_intent
    if isinstance(policy_intent, str):
        try:
            import yaml
            data = yaml.safe_load(policy_intent)
            if isinstance(data, dict):
                return data.get("policy_intent", data)
        except Exception:
            return None
    return None


def build_round_graph(
    iteration: int,
    probe_results: list[dict[str, Any]] | None,
    red_dynamic_results: list[dict[str, Any]] | None = None,
    policy_intent: dict | str | None = None,
) -> dict[str, Any]:
    """Snapshot the kill chain for one iteration."""
    pi = _resolve_policy(policy_intent) or {}
    probe_status = _probe_status_table(probe_results)

    # Step 1: per-edge raw status (independent of source reachability)
    edges_out: list[dict[str, Any]] = []
    for spec in _EDGE_SPECS:
        emp = spec.get("empirical")
        if emp and emp in probe_status:
            raw_status = probe_status[emp]
            origin = "empirical"
        elif spec["severance"](pi):
            raw_status = "severed"
            origin = "policy"
        else:
            raw_status = "open"
            origin = "default"

        edges_out.append({
            "source": spec["source"],
            "target": spec["target"],
            "label": spec["label"],
            "severance_label": spec.get("severance_label", ""),
            "empirical": emp,
            "requires": list(spec.get("requires", [])),
            "_raw_status": raw_status,
            "origin": origin,
        })

    # Step 2: propagate node reachability from L1 to fixed point.
    node_reachable: dict[str, bool] = {n["id"]: (n["layer"] == 1) for n in NODES}
    for _ in range(len(NODES) + 1):
        changed = False
        for e in edges_out:
            if not node_reachable.get(e["source"]):
                continue
            if not all(node_reachable.get(r) for r in e["requires"]):
                continue
            if e["_raw_status"] in ("severed", "blocked"):
                continue
            if not node_reachable.get(e["target"]):
                node_reachable[e["target"]] = True
                changed = True
        if not changed:
            break

    # Step 3: finalize edge status with source-reachability awareness.
    for e in edges_out:
        raw = e.pop("_raw_status")
        src_ok = node_reachable.get(e["source"], False)
        if raw == "bypassed":
            status = "bypassed"
        elif raw == "blocked":
            status = "blocked"
        elif raw == "severed":
            status = "severed"
        elif src_ok:
            status = "reachable"
        else:
            status = "unreachable"
        e["status"] = status

    # Step 4: stats + paths
    bypassed = sum(1 for e in edges_out if e["status"] == "bypassed")
    severed  = sum(1 for e in edges_out if e["status"] == "severed")
    reachable = sum(1 for e in edges_out if e["status"] in ("bypassed", "reachable"))
    host_owned = node_reachable.get("host_owned", False)
    compromised_l2 = sum(
        1 for n in NODES
        if n["layer"] == 2 and node_reachable.get(n["id"])
    )
    paths = _enumerate_paths(edges_out, "host_owned") if host_owned else []

    return {
        "iteration": iteration,
        "schema_version": "killchain.v1",
        "nodes": NODES,
        "edges": edges_out,
        "node_reachable": node_reachable,
        "stats": {
            "bypassed_edges": bypassed,
            "severed_edges": severed,
            "reachable_edges": reachable,
            "host_owned": host_owned,
            "compromised_l2_capabilities": compromised_l2,
        },
        "kill_paths": paths,
    }


def _enumerate_paths(
    edges: list[dict[str, Any]],
    target: str,
    max_paths: int = 12,
    max_len: int = 7,
) -> list[list[str]]:
    """DFS enumerate live attack paths to `target` via bypassed/reachable edges."""
    adj: dict[str, list[tuple[str, list[str]]]] = {}
    for e in edges:
        if e["status"] not in ("bypassed", "reachable"):
            continue
        adj.setdefault(e["source"], []).append((e["target"], e["requires"]))

    l1 = [n["id"] for n in NODES if n["layer"] == 1]
    paths: list[list[str]] = []

    def dfs(cur: str, path: list[str], visited: set[str]) -> None:
        if len(paths) >= max_paths or len(path) > max_len:
            return
        if cur == target:
            paths.append(list(path))
            return
        for tgt, requires in adj.get(cur, []):
            if tgt in visited:
                continue
            visited.add(tgt)
            note = (" + needs " + ",".join(requires)) if requires else ""
            path.append(tgt + note)
            dfs(tgt, path, visited)
            path.pop()
            visited.remove(tgt)

    for start in l1:
        dfs(start, [start], {start})

    return paths


# ---------------------------------------------------------------------------
# History merge
# ---------------------------------------------------------------------------

def merge_history(
    current: dict[str, Any],
    prior_graphs: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Annotate each edge with cross-round provenance."""
    history: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for g in prior_graphs:
        if g["iteration"] >= current["iteration"]:
            continue
        for e in g["edges"]:
            key = (e["source"], e["target"])
            history.setdefault(key, []).append((g["iteration"], e["status"]))

    for e in current["edges"]:
        key = (e["source"], e["target"])
        past = history.get(key, [])
        was_bypassed = any(s == "bypassed" for _, s in past)
        was_severed  = any(s == "severed"  for _, s in past)
        e["was_bypassed_before"] = was_bypassed
        e["was_severed_before"]  = was_severed
        e["novel_severance"] = (e["status"] == "severed" and not was_severed)
        e["regressed"] = (e["status"] in ("bypassed", "reachable") and was_severed)
    return current


# ---------------------------------------------------------------------------
# Public utilities
# ---------------------------------------------------------------------------

def write_graph(iter_dir: Path, graph: dict[str, Any]) -> Path:
    out = iter_dir / "attack_graph.json"
    out.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def load_run_graphs(run_dir: Path) -> list[dict[str, Any]]:
    """Load all per-round graphs in iteration order."""
    graphs: list[dict[str, Any]] = []
    for d in sorted((run_dir / "iters").glob("iter-*")):
        p = d / "attack_graph.json"
        if not p.exists():
            continue
        try:
            graphs.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            continue
    return graphs


_LAYER_NAMES = {
    1: "L1 Initial Access",
    2: "L2 Capability",
    3: "L3 Container Compromise",
    4: "L4 Container Escape",
    5: "L5 Host",
}


def compact_for_prompt(graph: dict[str, Any], max_paths: int = 8, max_edges: int = 30) -> str:
    """Render the kill chain as token-efficient text for LLM prompts."""
    lines: list[str] = []
    lines.append(f"# Kill chain (iter {graph['iteration']})")
    lines.append("")
    stats = graph.get("stats", {})
    lines.append(
        f"stats: host_owned={stats.get('host_owned')} "
        f"reachable_edges={stats.get('reachable_edges')} "
        f"severed_edges={stats.get('severed_edges')} "
        f"bypassed_edges={stats.get('bypassed_edges')}"
    )
    lines.append("")

    nodes_by_layer: dict[int, list[dict[str, Any]]] = {}
    for n in graph["nodes"]:
        nodes_by_layer.setdefault(n["layer"], []).append(n)
    for layer in sorted(nodes_by_layer):
        lines.append(f"## {_LAYER_NAMES.get(layer, f'L{layer}')}")
        for n in nodes_by_layer[layer]:
            r = graph["node_reachable"].get(n["id"], False)
            marker = "X" if r else "."
            lines.append(f"  [{marker}] {n['id']:<22} {n['label']}")
        lines.append("")

    def rank(e: dict[str, Any]) -> tuple[int, str]:
        if e["status"] == "bypassed":     return (0, e["source"])
        if e.get("regressed"):            return (1, e["source"])
        if e.get("novel_severance"):      return (2, e["source"])
        if e["status"] == "reachable":    return (3, e["source"])
        if e["status"] == "severed":      return (4, e["source"])
        return (5, e["source"])

    interesting = [
        e for e in graph["edges"]
        if e["status"] in ("bypassed", "reachable")
        or e.get("regressed") or e.get("novel_severance")
    ]
    interesting.sort(key=rank)
    if interesting:
        lines.append("## Live and recently-changed edges")
        for e in interesting[:max_edges]:
            tags: list[str] = [e["status"].upper()]
            if e.get("regressed"):       tags.append("REGRESSED")
            if e.get("novel_severance"): tags.append("NEWLY-SEVERED")
            tag = "[" + ",".join(tags) + "]"
            req = (" + needs " + ",".join(e["requires"])) if e["requires"] else ""
            lines.append(f"  {e['source']} -> {e['target']:<22} {tag} via '{e['label']}'{req}")
        lines.append("")

    if graph.get("kill_paths"):
        n_show = min(max_paths, len(graph['kill_paths']))
        lines.append(f"## Live kill paths to host_owned (top {n_show})")
        for path in graph["kill_paths"][:max_paths]:
            lines.append("  " + " -> ".join(path))
        lines.append("")
    elif stats.get("host_owned") is False:
        lines.append("## Live kill paths to host_owned: NONE (host not reachable)")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-defeating policy detector
# ---------------------------------------------------------------------------

def policy_self_check(policy_intent: dict | str | None) -> list[str]:
    """Warnings about policy choices that defeat the corresponding red probe."""
    pi = _resolve_policy(policy_intent) or {}
    warnings: list[str] = []
    waf = (pi.get("controls") or {}).get("app_waf") or {}
    self_defeating = {"127.0.0.1", "localhost", "::1", "host.docker.internal"}
    for h in waf.get("ssrf_allowed_hosts") or []:
        if h in self_defeating:
            warnings.append(
                f"app_waf.ssrf_allowed_hosts contains {h!r} -- the red SSRF probe "
                f"targets exactly this. Including it makes red_ssrf permanently bypassed."
            )
    return warnings


# ---------------------------------------------------------------------------
# Backwards-compat shim (visualizer.py still imports ENDPOINTS)
# ---------------------------------------------------------------------------

ENDPOINTS = [
    {"path": "/ping",   "vuln": "Command Injection",   "cwe": "CWE-78"},
    {"path": "/fetch",  "vuln": "SSRF",                "cwe": "CWE-918"},
    {"path": "/read",   "vuln": "Path Traversal",      "cwe": "CWE-22"},
    {"path": "/search", "vuln": "SQL Injection",       "cwe": "CWE-89"},
    {"path": "/render", "vuln": "SSTI",                "cwe": "CWE-1336"},
    {"path": "/load",   "vuln": "Insecure Deser.",     "cwe": "CWE-502"},
]
