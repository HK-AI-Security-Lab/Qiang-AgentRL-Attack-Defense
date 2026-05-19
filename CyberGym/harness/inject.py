"""Inject VULN_EXPLOIT edges from a Base-Model capability table into the
static-baseline graph produced by harness.graph.

Per the design doc:

    capability_table[i] = {
       affected_node_type, pre_condition, post_condition, cvss, ...
    }

    For each entry, find every inventory node whose `kind` matches
    `affected_node_type`, then add a VULN_EXPLOIT edge whose semantics depend
    on post_condition:

      - if "escape_to_host" is in post_condition AND target is a Workload,
        the exploit yields control of its hosting InfraNode.
      - if target is an InfraNode, edges originate from every Workload running
        on that node and target the node itself ("local privesc").
      - if target is a Service, the edge originates from `internet` (or any
        upstream service that has NETWORK_REACH to it) and lands on the service.

Edges carry `pre_condition` so the path-search step can later filter paths
that don't satisfy them.

Matching is intentionally simple in the PoC:

    Service:   match by `project` keyword in service.label/workload.image
    Workload:  match by hint.project_name appearing in workload.packages or image
    InfraNode: match all infra_nodes (CVE applies to the kernel/hypervisor)

If no node matches we still emit a "ghost" placeholder edge anchored at the
synthetic `internet` node so the report doesn't silently drop unmatched CVEs.
"""

from __future__ import annotations

from typing import Any, Iterable

import networkx as nx

from .graph import (
    LAYER_INFRA, LAYER_SERVICE, LAYER_WORKLOAD,
    ENTRY_NODE_ID,
)


def _nodes_of_kind(g: nx.MultiDiGraph, kind: str) -> list[tuple[str, dict]]:
    return [(nid, attrs) for nid, attrs in g.nodes(data=True) if attrs.get("kind") == kind]


def _workload_packages(workload_attrs: dict) -> list[str]:
    pkgs = workload_attrs.get("packages") or []
    img  = workload_attrs.get("label") or ""
    return [str(p).lower() for p in pkgs] + [img.lower()]


def _project_matches_workload(workload_attrs: dict, project: str | None) -> bool:
    if not project:
        return False
    project = project.lower()
    haystack = " ".join(_workload_packages(workload_attrs))
    return project in haystack


def _services_using_workload(g: nx.MultiDiGraph, workload_id: str) -> list[str]:
    """All L2 services whose `workload` field points at this workload."""
    out = []
    for sid, attrs in g.nodes(data=True):
        if attrs.get("kind") == "service" and attrs.get("workload") == workload_id:
            out.append(sid)
    return out


def _infra_running_workload(g: nx.MultiDiGraph, workload_id: str) -> str | None:
    return g.nodes[workload_id].get("deployed_on")


def _resolve_targets(g: nx.MultiDiGraph, entry: dict) -> list[str]:
    """Pick inventory nodes that match this capability-table entry."""
    ant     = entry.get("affected_node_type")
    hints   = entry.get("match_hints") or {}
    project = (hints.get("project_name") or "").lower() or None

    matches: list[str] = []
    if ant == "InfraNode":
        # Kernel / hypervisor CVE — applies to every InfraNode unless we have
        # a more specific kernel-version hint (left as a future improvement).
        matches = [nid for nid, _ in _nodes_of_kind(g, "infra_node")]
    elif ant == "Workload":
        if project is None:
            # No project hint — fall back to GHOST rather than fan out across
            # every workload. This keeps the demo readable.
            matches = []
        else:
            for nid, attrs in _nodes_of_kind(g, "workload"):
                if _project_matches_workload(attrs, project):
                    matches.append(nid)
    elif ant == "Service":
        if project is None:
            matches = []
        else:
            for sid, attrs in _nodes_of_kind(g, "service"):
                wl = attrs.get("workload")
                if wl is None:
                    continue
                wl_attrs = g.nodes[wl]
                if _project_matches_workload(wl_attrs, project):
                    matches.append(sid)
    elif ant in ("RANNode", "UE"):
        # No RAN nodes in the toy inventory.
        matches = []
    return matches


def inject_capabilities(
    g: nx.MultiDiGraph,
    capability_table: Iterable[dict[str, Any]],
) -> nx.MultiDiGraph:
    """Mutate `g` by adding VULN_EXPLOIT edges. Returns `g` for chaining."""
    for entry in capability_table:
        targets = _resolve_targets(g, entry)
        post = set(entry.get("post_condition") or [])
        ant  = entry.get("affected_node_type")
        confidence = "low" if not (entry.get("match_hints") or {}).get("project_name") else "high"

        if not targets:
            # No inventory match — leave a single anchor edge at the internet
            # node so the report can still show the CVE exists.
            g.add_edge(
                ENTRY_NODE_ID, ENTRY_NODE_ID,   # self-loop on entry
                type="VULN_EXPLOIT",
                origin="declared",
                cve_id=entry.get("cve_id"),
                task_id=entry.get("task_id"),
                affected_node_type=ant,
                pre_condition=list(entry.get("pre_condition") or []),
                post_condition=sorted(post),
                cvss=entry.get("cvss"),
                exploit_maturity=entry.get("exploit_maturity"),
                rationale=entry.get("rationale", ""),
                ghost=True,
                confidence=confidence,
            )
            continue

        for target_id in targets:
            target_attrs = g.nodes[target_id]
            kind = target_attrs.get("kind")

            # Determine the edge SOURCE based on what the exploit needs.
            if kind == "service":
                # "Network attack" — anyone who has NETWORK_REACH to this
                # service is a potential origin. We add ONE edge from internet
                # (collapses all upstream entry points into one for clarity).
                edge_sources = [ENTRY_NODE_ID]
            elif kind == "workload":
                # Workload bug fires when its containing service processes
                # untrusted input. Source = the service running this workload.
                edge_sources = _services_using_workload(g, target_id) or [ENTRY_NODE_ID]
            elif kind == "infra_node":
                # Kernel / hypervisor escape. Source = any workload deployed on
                # this node (because attacker who already lands in a container
                # on that host can pivot down to the kernel).
                running_workloads = [
                    wid for wid, attrs in g.nodes(data=True)
                    if attrs.get("kind") == "workload" and attrs.get("deployed_on") == target_id
                ]
                edge_sources = running_workloads or [ENTRY_NODE_ID]
            else:
                edge_sources = [ENTRY_NODE_ID]

            for src in edge_sources:
                g.add_edge(
                    src, target_id,
                    type="VULN_EXPLOIT",
                    origin="declared",
                    cve_id=entry.get("cve_id"),
                    task_id=entry.get("task_id"),
                    affected_node_type=ant,
                    pre_condition=list(entry.get("pre_condition") or []),
                    post_condition=sorted(post),
                    cvss=entry.get("cvss"),
                    exploit_maturity=entry.get("exploit_maturity"),
                    rationale=entry.get("rationale", ""),
                    ghost=False,
                    confidence=confidence,
                )

            # If the exploit grants escape_to_host AND we landed on a workload,
            # also add a synthetic edge workload -> hosting infra_node so the
            # search step can chain into the kernel layer.
            if kind == "workload" and "escape_to_host" in post:
                infra = _infra_running_workload(g, target_id)
                if infra is not None:
                    g.add_edge(
                        target_id, infra,
                        type="VULN_EXPLOIT",
                        origin="implicit_escape",
                        cve_id=entry.get("cve_id"),
                        task_id=entry.get("task_id"),
                        affected_node_type="InfraNode",
                        pre_condition=["local_low_priv"],
                        post_condition=["escape_to_host"],
                        cvss=entry.get("cvss"),
                        exploit_maturity=entry.get("exploit_maturity"),
                        rationale=f"Implicit container escape from {entry.get('cve_id') or entry.get('task_id')}",
                        ghost=False,
                        confidence=confidence,
                    )
    return g


# ─────────────────────────────────────────────────────────────────────────────
# CLI: python -m harness.inject <inventory.yaml> <capability_table.json>
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys

    from .graph import build_graph, load_inventory, stats

    if len(sys.argv) < 3:
        print("usage: python -m harness.inject <inventory.yaml> <capability_table.json>")
        sys.exit(1)

    g = build_graph(load_inventory(sys.argv[1]))
    table = json.loads(open(sys.argv[2], "r", encoding="utf-8").read())
    inject_capabilities(g, table)

    s = stats(g)
    print(f"after injection: nodes={s['total_nodes']} edges={s['total_edges']}")
    print(f"  edges by type: {s['edge_counts']}")
    print()
    print("VULN_EXPLOIT edges:")
    for u, v, attrs in g.edges(data=True):
        if attrs.get("type") != "VULN_EXPLOIT":
            continue
        cve = attrs.get("cve_id") or attrs.get("task_id")
        print(f"  {u:<22} -> {v:<22}  {cve}  cvss={attrs.get('cvss')}"
              f"  post={attrs.get('post_condition')}  conf={attrs.get('confidence')}")
