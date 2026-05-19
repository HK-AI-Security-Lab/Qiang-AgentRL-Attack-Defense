"""Path search over the merged static-baseline + VULN_EXPLOIT graph.

We compute a *search graph* (a plain DiGraph, edge keys collapsed) where:
  - reachability flows along NETWORK_REACH, IAM_BINDING, RUNS_AS, DEPENDS_ON,
    and VULN_EXPLOIT edges.
  - BELONGS_TO and DATA_FLOW are excluded from the search graph because
    BELONGS_TO is a labelling relation (svc -> product) and DATA_FLOW is
    informative-only (it doesn't grant the attacker a new node).

A "kill path" is any simple path from `internet` to a target whose criticality
is interesting (default: all P0/P1 services and any infra_node).
"""

from __future__ import annotations

from typing import Any, Iterable

import networkx as nx

from .graph import ENTRY_NODE_ID


# Edge types that propagate attacker reachability.
REACH_EDGE_TYPES = (
    "NETWORK_REACH",
    "IAM_BINDING",
    "RUNS_AS",
    "DEPENDS_ON",
    "VULN_EXPLOIT",
)


def to_search_graph(g: nx.MultiDiGraph) -> nx.DiGraph:
    """Collapse the MultiDiGraph into a plain DiGraph for search.

    Each (u, v) pair gets a single edge whose `types` is a list of all edge
    types between them. Self-loops (ghost VULN_EXPLOIT) are dropped.
    """
    sg = nx.DiGraph()
    for nid, attrs in g.nodes(data=True):
        sg.add_node(nid, **attrs)

    for u, v, attrs in g.edges(data=True):
        if u == v:
            continue
        et = attrs.get("type")
        if et not in REACH_EDGE_TYPES:
            continue
        if sg.has_edge(u, v):
            sg[u][v]["types"].add(et)
            # Track the highest CVSS observed across parallel vuln edges.
            cvss = attrs.get("cvss")
            if cvss is not None and (
                sg[u][v].get("max_cvss") is None or cvss > sg[u][v]["max_cvss"]
            ):
                sg[u][v]["max_cvss"] = cvss
        else:
            sg.add_edge(
                u, v,
                types={et},
                max_cvss=attrs.get("cvss") if et == "VULN_EXPLOIT" else None,
            )
    # Convert sets to sorted lists for stable JSON output.
    for _, _, ed in sg.edges(data=True):
        ed["types"] = sorted(ed["types"])
    return sg


# ─────────────────────────────────────────────────────────────────────────────
# Target selection
# ─────────────────────────────────────────────────────────────────────────────

def critical_assets(g: nx.MultiDiGraph) -> list[str]:
    """Default 'crown jewels' — anything we'd hate to see compromised.

    Heuristic: any service whose product has criticality P0 or P1, plus any
    infra_node (host pwn is always bad), plus any DB-shaped service.
    """
    targets: set[str] = set()
    products = {
        pid: attrs.get("criticality")
        for pid, attrs in g.nodes(data=True)
        if attrs.get("kind") == "product"
    }
    for nid, attrs in g.nodes(data=True):
        kind = attrs.get("kind")
        if kind == "service":
            crit = products.get(attrs.get("product"))
            if crit in ("P0", "P1") or "db" in nid or "redis" in nid or "postgres" in nid:
                targets.add(nid)
        elif kind == "infra_node":
            targets.add(nid)
    return sorted(targets)


# ─────────────────────────────────────────────────────────────────────────────
# Path enumeration + scoring
# ─────────────────────────────────────────────────────────────────────────────

def find_kill_paths(
    g: nx.MultiDiGraph,
    targets: Iterable[str] | None = None,
    *,
    source: str = ENTRY_NODE_ID,
    max_depth: int = 6,
    max_paths_per_target: int = 3,
) -> list[dict[str, Any]]:
    """Enumerate simple paths from `source` to each target, ranked by score.

    Returns a list of dicts:
      {
        "target": <node_id>,
        "path":   [n1, n2, ..., target],
        "edges":  [{"source","target","types","max_cvss"}, ...],
        "uses_vuln":   bool,
        "vuln_count":  int,
        "score":       float,   # higher = riskier
      }
    """
    sg = to_search_graph(g)
    if not sg.has_node(source):
        return []

    if targets is None:
        targets = critical_assets(g)

    out: list[dict[str, Any]] = []

    for tgt in targets:
        if not sg.has_node(tgt) or tgt == source:
            continue
        try:
            simple = nx.all_simple_paths(sg, source=source, target=tgt, cutoff=max_depth)
        except nx.NetworkXError:
            continue

        # Materialise but cap the number we keep per target.
        for path in simple:
            edges_meta = []
            uses_vuln = False
            vuln_count = 0
            max_cvss = 0.0
            for a, b in zip(path[:-1], path[1:]):
                ed = sg[a][b]
                types = ed["types"]
                if "VULN_EXPLOIT" in types:
                    uses_vuln = True
                    vuln_count += 1
                    if ed.get("max_cvss"):
                        max_cvss = max(max_cvss, ed["max_cvss"])
                edges_meta.append({
                    "source": a, "target": b,
                    "types":  types,
                    "max_cvss": ed.get("max_cvss"),
                })

            tgt_attrs = g.nodes[tgt]
            crit = _criticality_weight(g, tgt_attrs)
            score = max_cvss * crit * (1.5 if uses_vuln else 0.5) - 0.3 * (len(path) - 2)

            out.append({
                "target":     tgt,
                "path":       list(path),
                "edges":      edges_meta,
                "uses_vuln":  uses_vuln,
                "vuln_count": vuln_count,
                "max_cvss":   max_cvss,
                "depth":      len(path) - 1,
                "score":      round(score, 2),
            })

    # Per-target top-K then sort overall.
    by_target: dict[str, list[dict]] = {}
    for p in out:
        by_target.setdefault(p["target"], []).append(p)
    for tgt, lst in by_target.items():
        lst.sort(key=lambda x: -x["score"])
        del lst[max_paths_per_target:]

    flat = [p for lst in by_target.values() for p in lst]
    flat.sort(key=lambda x: -x["score"])
    return flat


def _criticality_weight(g: nx.MultiDiGraph, attrs: dict) -> float:
    """Map P0/P1/P2 (via product) to a numeric weight for scoring."""
    if attrs.get("kind") == "infra_node":
        return 1.5  # infra escape always bad
    if attrs.get("kind") == "service":
        prod = attrs.get("product")
        if prod and g.has_node(prod):
            crit = g.nodes[prod].get("criticality")
            return {"P0": 1.5, "P1": 1.0, "P2": 0.6}.get(crit, 0.6)
    return 0.5


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys

    from .graph import build_graph, load_inventory
    from .inject import inject_capabilities

    if len(sys.argv) < 3:
        print("usage: python -m harness.search <inventory.yaml> <capability_table.json>")
        sys.exit(1)

    g = build_graph(load_inventory(sys.argv[1]))
    table = json.loads(open(sys.argv[2], "r", encoding="utf-8").read())
    inject_capabilities(g, table)

    paths = find_kill_paths(g, max_depth=6, max_paths_per_target=2)
    print(f"found {len(paths)} kill paths\n")
    for p in paths[:15]:
        chain = " -> ".join(p["path"])
        marker = "[VULN]" if p["uses_vuln"] else "[no-vuln]"
        print(f"  score={p['score']:>6.2f}  cvss={p['max_cvss']:.1f}  depth={p['depth']}  "
              f"{marker} {p['target']:<14}")
        print(f"           {chain}")
