"""Find chokepoint nodes — the ones whose removal cuts the most kill paths.

We use two complementary signals:

  1. Path-cut count: for each candidate node, count how many kill paths in
     the current set traverse it. Removing the node eliminates all of them.
  2. Betweenness centrality on the search subgraph (paths whose target is
     a critical asset). This catches "bridges" even between paths we didn't
     enumerate up to depth 6.

The chokepoint score is a weighted blend of both, normalised to 0..1. The
top entries are the ones an SRE should patch first.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from .graph import ENTRY_NODE_ID
from .search import REACH_EDGE_TYPES, critical_assets, find_kill_paths, to_search_graph


def chokepoints(
    g: nx.MultiDiGraph,
    paths: list[dict[str, Any]] | None = None,
    *,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Return the top-K chokepoint nodes ranked by path-cut + betweenness.

    Excludes the synthetic `internet` node and the path endpoints themselves.
    """
    if paths is None:
        paths = find_kill_paths(g)

    # ── (1) path-cut count + score sum ──────────────────────────────────────
    cut_count: dict[str, int] = {}
    cut_score: dict[str, float] = {}
    for p in paths:
        # mid-path nodes only — internet and target don't count
        for n in p["path"][1:-1]:
            cut_count[n] = cut_count.get(n, 0) + 1
            cut_score[n] = cut_score.get(n, 0.0) + p["score"]

    # ── (2) betweenness centrality on the reach-subgraph ────────────────────
    sg = to_search_graph(g)
    # Drop self-loops to satisfy networkx assumptions
    sg.remove_edges_from(nx.selfloop_edges(sg))
    try:
        bc = nx.betweenness_centrality(sg, normalized=True, endpoints=False)
    except Exception:
        bc = {}

    # ── Blend ───────────────────────────────────────────────────────────────
    # Normalise path-cut count to 0..1 so the two signals share a scale.
    max_cuts = max(cut_count.values(), default=1) or 1
    candidates: dict[str, dict[str, Any]] = {}
    for n, c in cut_count.items():
        candidates[n] = {
            "node":          n,
            "paths_cut":     c,
            "score_sum":     round(cut_score.get(n, 0.0), 2),
            "betweenness":   round(bc.get(n, 0.0), 4),
            "path_norm":     c / max_cuts,
            "blend":         round(0.7 * (c / max_cuts) + 0.3 * bc.get(n, 0.0), 4),
            "kind":          g.nodes[n].get("kind"),
            "label":         g.nodes[n].get("label", n),
        }

    # Also include a few top-betweenness nodes that no path passes through —
    # they may bridge paths we haven't enumerated.
    if bc:
        bc_sorted = sorted(bc.items(), key=lambda kv: -kv[1])
        for n, score in bc_sorted[:5]:
            if n in (ENTRY_NODE_ID,) or n in candidates:
                continue
            attrs = g.nodes[n]
            if attrs.get("kind") == "product":  # skip purely organisational nodes
                continue
            candidates[n] = {
                "node":        n,
                "paths_cut":   0,
                "score_sum":   0.0,
                "betweenness": round(score, 4),
                "path_norm":   0.0,
                "blend":       round(0.3 * score, 4),
                "kind":        attrs.get("kind"),
                "label":       attrs.get("label", n),
            }

    ranked = sorted(candidates.values(), key=lambda d: -d["blend"])
    return ranked[:top_k]


def what_if_remove(
    g: nx.MultiDiGraph,
    node: str,
    paths: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """How many kill paths would removing `node` eliminate?"""
    if paths is None:
        paths = find_kill_paths(g)
    cut = [p for p in paths if node in set(p["path"][1:-1])]
    remaining = [p for p in paths if p not in cut]
    return {
        "node":          node,
        "kind":          g.nodes[node].get("kind"),
        "paths_total":   len(paths),
        "paths_cut":     len(cut),
        "paths_remain":  len(remaining),
        "score_cut":     round(sum(p["score"] for p in cut), 2),
        "score_remain":  round(sum(p["score"] for p in remaining), 2),
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys

    from .graph import build_graph, load_inventory
    from .inject import inject_capabilities

    if len(sys.argv) < 3:
        print("usage: python -m harness.cut <inventory.yaml> <capability_table.json>")
        sys.exit(1)

    g = build_graph(load_inventory(sys.argv[1]))
    table = json.loads(open(sys.argv[2], "r", encoding="utf-8").read())
    inject_capabilities(g, table)

    paths = find_kill_paths(g)
    print(f"{len(paths)} kill paths total\n")

    cps = chokepoints(g, paths, top_k=5)
    print("Top chokepoints (patch these first):")
    for cp in cps:
        sim = what_if_remove(g, cp["node"], paths)
        print(
            f"  {cp['node']:<20} ({cp['kind']:<10})  "
            f"cuts {sim['paths_cut']:>2}/{sim['paths_total']} paths  "
            f"score_cut={sim['score_cut']:>6.2f}  blend={cp['blend']}  "
            f"betweenness={cp['betweenness']}"
        )
