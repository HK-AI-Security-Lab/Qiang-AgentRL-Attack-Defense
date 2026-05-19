"""Load a CyberGym inventory YAML into a networkx DiGraph.

Layers (matches Base-Model + Harness design doc):
    L0 entry      synthetic 'internet' / external-attacker node
    L1 Product    business unit
    L2 Service    networked service
    L3 Workload   container image / firmware
    L4 InfraNode  host / VM / hardware

Static edge types (loaded as-is from YAML `edges:` plus implicit edges):
    NETWORK_REACH   service -> service (or internet -> service)
    IAM_BINDING     service -> service
    DATA_FLOW       service -> service
    BELONGS_TO      service -> product           (implicit, from service.product)
    RUNS_AS         service -> workload          (implicit, from service.workload)
    DEPENDS_ON      workload -> infra_node       (implicit, from workload.deployed_on)

Node attributes carried forward intact from the YAML so callers (renderer,
vuln-injector, search) don't have to reload the source file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import networkx as nx
import yaml


# Layer constants — used by the renderer for the vertical-band layout.
LAYER_ENTRY    = 0
LAYER_PRODUCT  = 1
LAYER_SERVICE  = 2
LAYER_WORKLOAD = 3
LAYER_INFRA    = 4

LAYER_LABELS = {
    LAYER_ENTRY:    "L0 Entry",
    LAYER_PRODUCT:  "L1 Product",
    LAYER_SERVICE:  "L2 Service",
    LAYER_WORKLOAD: "L3 Workload",
    LAYER_INFRA:    "L4 InfraNode",
}

ENTRY_NODE_ID = "internet"


def load_inventory(path: str | Path) -> dict[str, Any]:
    """Read the YAML inventory file. Returns the raw dict."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def build_graph(inventory: dict[str, Any]) -> nx.MultiDiGraph:
    """Construct the static baseline graph (no vulnerability edges yet).

    Returns a MultiDiGraph because a single (source, target) pair often
    carries multiple edge types — e.g. order_svc -> user_db has
    NETWORK_REACH + IAM_BINDING + DATA_FLOW simultaneously.
    """
    g = nx.MultiDiGraph()
    g.graph["inventory_version"] = inventory.get("inventory_version", "?")
    g.graph["deployment"]        = inventory.get("deployment", "?")

    # ── Synthetic entry node ─────────────────────────────────────────────────
    g.add_node(
        ENTRY_NODE_ID,
        layer=LAYER_ENTRY,
        kind="entry",
        label="Internet / External Attacker",
        description="Untrusted public network. Source of all attack paths.",
    )

    # ── L1 Products ──────────────────────────────────────────────────────────
    for p in inventory.get("products") or []:
        g.add_node(
            p["id"],
            layer=LAYER_PRODUCT,
            kind="product",
            label=p.get("name", p["id"]),
            description=f"criticality={p.get('criticality', '?')}, owner={p.get('owner', '?')}",
            criticality=p.get("criticality"),
            owner=p.get("owner"),
        )

    # ── L2 Services ──────────────────────────────────────────────────────────
    for s in inventory.get("services") or []:
        g.add_node(
            s["id"],
            layer=LAYER_SERVICE,
            kind="service",
            label=s.get("name", s["id"]),
            description=f"port={s.get('expose_port')} auth={s.get('auth_method')}",
            product=s.get("product"),
            workload=s.get("workload"),
            expose_port=s.get("expose_port"),
            auth_method=s.get("auth_method"),
            ztn_policy=s.get("ztn_policy"),
            is_public=bool(s.get("is_public", False)),
        )
        # Implicit BELONGS_TO (service -> product)
        if s.get("product"):
            g.add_edge(
                s["id"], s["product"],
                type="BELONGS_TO", origin="implicit",
            )
        # Implicit RUNS_AS (service -> workload)
        if s.get("workload"):
            g.add_edge(
                s["id"], s["workload"],
                type="RUNS_AS", origin="implicit",
            )

    # ── L3 Workloads ─────────────────────────────────────────────────────────
    for w in inventory.get("workloads") or []:
        g.add_node(
            w["id"],
            layer=LAYER_WORKLOAD,
            kind="workload",
            label=w.get("image", w["id"]),
            description=f"runtime={w.get('runtime')}",
            packages=list(w.get("packages") or []),
            runtime=w.get("runtime"),
            deployed_on=w.get("deployed_on"),
        )
        # Implicit DEPENDS_ON (workload -> infra_node)
        if w.get("deployed_on"):
            g.add_edge(
                w["id"], w["deployed_on"],
                type="DEPENDS_ON", origin="implicit",
            )

    # ── L4 InfraNodes ────────────────────────────────────────────────────────
    for n in inventory.get("infra_nodes") or []:
        g.add_node(
            n["id"],
            layer=LAYER_INFRA,
            kind="infra_node",
            label=n["id"],
            description=(
                f"{n.get('os')} kernel={n.get('kernel_version')} "
                f"loc={n.get('location')}"
            ),
            os=n.get("os"),
            kernel_version=n.get("kernel_version"),
            hardware_model=n.get("hardware_model"),
            location=n.get("location"),
            is_public_exposed=bool(n.get("is_public_exposed", False)),
        )

    # ── Explicit edges from YAML ────────────────────────────────────────────
    for e in inventory.get("edges") or []:
        et = e["type"]
        src, dst = e["from"], e["to"]
        # auto-add the synthetic internet node as L0 if a YAML edge references it
        if src == ENTRY_NODE_ID and not g.has_node(src):
            g.add_node(src, layer=LAYER_ENTRY, kind="entry", label="Internet")
        if not (g.has_node(src) and g.has_node(dst)):
            # Skip silently rather than crash — better demo ergonomics
            continue
        g.add_edge(src, dst, type=et, origin="declared", notes=e.get("notes", ""))

    # ── Sanity: any L2 service marked is_public also gets internet -> svc ───
    # (so YAML authors can either declare the edge or just flip the flag)
    def _has_typed_edge(u: str, v: str, etype: str) -> bool:
        for _, _, attrs in g.out_edges(u, data=True):
            if _ == u and attrs.get("type") == etype:
                pass  # placeholder for clarity
        # MultiDiGraph: iterate keys
        if not g.has_edge(u, v):
            return False
        for k in g[u][v]:
            if g[u][v][k].get("type") == etype:
                return True
        return False

    for sid, attrs in g.nodes(data=True):
        if attrs.get("kind") == "service" and attrs.get("is_public"):
            if not _has_typed_edge(ENTRY_NODE_ID, sid, "NETWORK_REACH"):
                g.add_edge(
                    ENTRY_NODE_ID, sid,
                    type="NETWORK_REACH", origin="implicit",
                    notes="auto-added because service.is_public=true",
                )

    return g


# ─────────────────────────────────────────────────────────────────────────────
# Convenience helpers used by renderer / search / inject
# ─────────────────────────────────────────────────────────────────────────────

def nodes_by_layer(g: nx.MultiDiGraph) -> dict[int, list[str]]:
    """Return {layer_idx: [node_id, ...]} sorted by id within each layer."""
    out: dict[int, list[str]] = {}
    for nid, attrs in g.nodes(data=True):
        out.setdefault(attrs.get("layer", -1), []).append(nid)
    for layer, ids in out.items():
        ids.sort()
    return out


def edges_by_type(g: nx.MultiDiGraph, types: tuple[str, ...] | None = None) -> list[tuple[str, str, dict]]:
    """Filter edges by `type=` attribute. None means all edges."""
    out = []
    for u, v, attrs in g.edges(data=True):
        if types is None or attrs.get("type") in types:
            out.append((u, v, attrs))
    return out


def stats(g: nx.MultiDiGraph) -> dict[str, Any]:
    """Quick summary, useful for terminal output."""
    layer_counts = {LAYER_LABELS.get(layer, f"L?"): len(ids)
                    for layer, ids in sorted(nodes_by_layer(g).items())}
    edge_counts: dict[str, int] = {}
    for _, _, attrs in g.edges(data=True):
        t = attrs.get("type", "?")
        edge_counts[t] = edge_counts.get(t, 0) + 1
    return {
        "deployment":   g.graph.get("deployment"),
        "total_nodes":  g.number_of_nodes(),
        "total_edges":  g.number_of_edges(),
        "layer_counts": layer_counts,
        "edge_counts":  edge_counts,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI: python -m harness.graph CyberGym/inventory/sample.yaml
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m harness.graph <inventory.yaml>")
        sys.exit(1)

    inv = load_inventory(sys.argv[1])
    g   = build_graph(inv)
    s   = stats(g)
    print(f"deployment: {s['deployment']}")
    print(f"nodes={s['total_nodes']} edges={s['total_edges']}")
    print(f"  layers: {s['layer_counts']}")
    print(f"  edges:  {s['edge_counts']}")
