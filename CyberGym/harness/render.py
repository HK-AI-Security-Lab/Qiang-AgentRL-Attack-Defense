"""Render the static-baseline graph to a self-contained HTML.

Layout: 5 horizontal bands (L0 entry on top, L4 InfraNode on bottom).
SVG bezier edges colour-coded by type.

Output is a single .html file with everything inlined — open in any browser,
no CDN, no JS framework. (Same approach as core/attack_graph_html.py in the
parent AutoPatch-RL project.)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx

from .graph import (
    LAYER_LABELS,
    LAYER_ENTRY, LAYER_PRODUCT, LAYER_SERVICE, LAYER_WORKLOAD, LAYER_INFRA,
    nodes_by_layer,
)


# Edge colour palette — keep in sync with the CSS template below.
EDGE_STYLES = {
    "NETWORK_REACH": ("var(--reach)",  "solid"),
    "IAM_BINDING":   ("var(--iam)",    "dashed"),
    "DATA_FLOW":     ("var(--data)",   "dotted"),
    "DEPENDS_ON":    ("var(--depend)", "solid"),
    "RUNS_AS":       ("var(--depend)", "dashed"),
    "BELONGS_TO":    ("var(--belong)", "dashed"),
    "VULN_EXPLOIT":  ("var(--vuln)",   "solid"),  # used in Phase 3
}


def _serialise(g: nx.MultiDiGraph) -> dict[str, Any]:
    """Pack the graph into a JSON payload the HTML template can consume."""
    nodes = []
    for nid, attrs in g.nodes(data=True):
        nodes.append({
            "id":          nid,
            "layer":       attrs.get("layer"),
            "kind":        attrs.get("kind"),
            "label":       attrs.get("label", nid),
            "description": attrs.get("description", ""),
            # Bonus metadata used in the tooltip
            "criticality":   attrs.get("criticality"),
            "auth_method":   attrs.get("auth_method"),
            "ztn_policy":    attrs.get("ztn_policy"),
            "expose_port":   attrs.get("expose_port"),
            "kernel_version":attrs.get("kernel_version"),
            "os":            attrs.get("os"),
            "location":      attrs.get("location"),
            "packages":      attrs.get("packages"),
            "runtime":       attrs.get("runtime"),
            "is_public":     attrs.get("is_public"),
        })

    # Group parallel edges so the renderer can spread them into a small fan
    # (otherwise multiple types between the same node pair overlap pixel-by-pixel).
    pair_counts: dict[tuple[str, str], int] = {}
    edges = []
    for u, v, attrs in g.edges(data=True):
        if u == v:
            continue  # ghost self-loops shouldn't render as visible edges
        idx = pair_counts.get((u, v), 0)
        pair_counts[(u, v)] = idx + 1
        edges.append({
            "source": u,
            "target": v,
            "type":   attrs.get("type", "?"),
            "origin": attrs.get("origin", ""),
            "notes":  attrs.get("notes", ""),
            "cve_id": attrs.get("cve_id"),
            "task_id":attrs.get("task_id"),
            "cvss":   attrs.get("cvss"),
            "post_condition": attrs.get("post_condition"),
            "parallel_idx": idx,
        })
    for e in edges:
        e["parallel_total"] = pair_counts[(e["source"], e["target"])]

    return {
        "deployment": g.graph.get("deployment", "?"),
        "version":    g.graph.get("inventory_version", "?"),
        "nodes":      nodes,
        "edges":      edges,
    }


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberGym - Asset Topology</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --card2: #1c2128; --border: #30363d;
    --text: #c9d1d9; --text2: #8b949e; --text3: #6e7681;
    --reach:  #58a6ff;     /* NETWORK_REACH    blue */
    --iam:    #d29922;     /* IAM_BINDING      yellow */
    --data:   #a371f7;     /* DATA_FLOW        purple */
    --depend: #6e7681;     /* DEPENDS_ON / RUNS_AS  gray */
    --belong: #3fb950;     /* BELONGS_TO       green */
    --vuln:   #f85149;     /* VULN_EXPLOIT     red (Phase 3) */
    --critical: #f85149;
    --high:     #d29922;
    --font: 'SF Mono','JetBrains Mono','Cascadia Code',monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    min-height: 100vh; display: flex; flex-direction: column;
  }
  header {
    padding: 14px 22px; border-bottom: 1px solid var(--border);
    background: var(--card); display: flex; justify-content: space-between;
    align-items: center;
  }
  header h1 { margin: 0; font-size: 18px; font-weight: 600; }
  header .meta { color: var(--text2); font-family: var(--font); font-size: 13px; }
  .legend {
    padding: 10px 22px; background: var(--card2); border-bottom: 1px solid var(--border);
    display: flex; gap: 14px; flex-wrap: wrap; font-size: 12px; color: var(--text2);
  }
  .legend .chip {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 3px 10px; border-radius: 12px;
  }
  .legend .swatch { width: 18px; height: 4px; display: inline-block; border-radius: 2px; }
  .legend .swatch.dashed { background: repeating-linear-gradient(90deg, currentColor 0 6px, transparent 6px 10px); }
  .legend .swatch.dotted { background: repeating-linear-gradient(90deg, currentColor 0 2px, transparent 2px 6px); }

  main {
    flex: 1; display: grid; grid-template-columns: minmax(0,1fr) 340px;
    gap: 16px; padding: 16px 22px;
  }
  .graph {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px; min-height: 720px;
    position: relative; overflow: auto;
  }
  .graph svg { width: 100%; height: 100%; min-height: 700px; }
  .sidebar {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px;
    display: flex; flex-direction: column; gap: 14px;
    max-height: calc(100vh - 200px); overflow-y: auto;
  }
  .stat-row { display: grid; grid-template-columns: 1fr auto; gap: 4px; font-size: 13px; }
  .stat-row .v { font-family: var(--font); }
  .stat-row .v.bad  { color: var(--vuln); font-weight: 600; }
  .stat-row .v.good { color: var(--belong); font-weight: 600; }
  .stat-row .v.warn { color: var(--high); font-weight: 600; }

  .headline {
    background: linear-gradient(135deg, rgba(248,81,73,0.10), rgba(210,153,34,0.10));
    border: 1px solid var(--vuln);
    border-left: 4px solid var(--vuln);
    border-radius: 8px; padding: 10px 12px;
  }
  .headline-title {
    font-size: 11px; color: var(--vuln); font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 4px;
  }
  .headline-body {
    font-size: 13px; color: var(--text); line-height: 1.55;
  }
  .headline-body .num { color: var(--vuln); font-weight: 700; font-family: var(--font); }
  .headline-body code {
    background: var(--bg); padding: 1px 6px; border-radius: 3px;
    font-size: 12px; color: var(--high);
  }
  h2 { font-size: 13px; color: var(--text2); margin: 0 0 6px 0;
       text-transform: uppercase; letter-spacing: 0.5px; }
  .detail-pane {
    background: var(--card2); padding: 10px 12px; border-radius: 8px;
    font-size: 12px; line-height: 1.55; white-space: pre-wrap;
    border: 1px solid var(--border); max-height: 360px; overflow-y: auto;
    font-family: var(--font);
  }
  .layer-label {
    fill: var(--text3); font-family: var(--font); font-size: 11px;
    letter-spacing: 1px;
  }
  .layer-divider { stroke: var(--border); stroke-dasharray: 2 4; }

  .node-box rect { rx: 8; ry: 8; stroke-width: 2; transition: all 0.2s; }
  .node-box.product   rect { fill: rgba(63,185,80,0.10);  stroke: var(--belong); }
  .node-box.service   rect { fill: rgba(88,166,255,0.10); stroke: var(--reach); }
  .node-box.workload  rect { fill: rgba(110,118,129,0.15);stroke: var(--depend); }
  .node-box.infra_node rect{ fill: rgba(110,118,129,0.20);stroke: var(--text2); }
  .node-box.entry     rect { fill: rgba(248,81,73,0.15);  stroke: var(--vuln); }

  .node-box.public { stroke-dasharray: 0; }
  .node-box text { fill: var(--text); font-family: var(--font); font-size: 12px; }
  .node-box .desc { fill: var(--text2); font-size: 10px; }
  .node-box.selected rect { stroke-width: 3; filter: drop-shadow(0 0 6px currentColor); }
  .node-box { cursor: pointer; }

  .edge { fill: none; stroke-width: 1.5; opacity: 0.85; transition: opacity 0.15s; }
  .edge.NETWORK_REACH { stroke: var(--reach); }
  .edge.IAM_BINDING   { stroke: var(--iam);   stroke-dasharray: 6 4; }
  .edge.DATA_FLOW     { stroke: var(--data);  stroke-dasharray: 2 4; }
  .edge.DEPENDS_ON    { stroke: var(--depend); }
  .edge.RUNS_AS       { stroke: var(--depend); stroke-dasharray: 4 4; }
  .edge.BELONGS_TO    { stroke: var(--belong); stroke-dasharray: 4 4; }
  .edge.VULN_EXPLOIT  { stroke: var(--vuln);  stroke-width: 2.6; }
  .edge:hover { opacity: 1; stroke-width: 3.5; }
  .edge.dim { opacity: 0.12; }
  .edge.highlight { opacity: 1; stroke-width: 3; }
  .edge.kill { stroke: var(--vuln) !important; stroke-width: 3.6; opacity: 1; filter: drop-shadow(0 0 6px var(--vuln)); }
  .node-box.kill rect { stroke: var(--vuln); stroke-width: 3.5; filter: drop-shadow(0 0 6px var(--vuln)); }
  .node-box.choke rect { stroke: var(--high); stroke-width: 3.5; filter: drop-shadow(0 0 4px var(--high)); }

  .path-list { display: flex; flex-direction: column; gap: 4px; max-height: 280px; overflow-y: auto; }
  .path-item, .choke-item {
    font-family: var(--font); font-size: 11px; line-height: 1.45;
    padding: 6px 8px; border-radius: 6px;
    background: var(--card2); border: 1px solid var(--border);
    cursor: pointer; transition: all 0.15s;
  }
  .path-item:hover, .choke-item:hover { border-color: var(--vuln); }
  .path-item.active { border-color: var(--vuln); background: rgba(248,81,73,0.10); }
  .path-item .meta { color: var(--text2); font-size: 10px; margin-top: 2px; }
  .choke-item .label { color: var(--high); font-weight: 600; }
  .choke-item .num { color: var(--vuln); font-weight: 600; }

  .cap-item {
    font-family: var(--font); font-size: 11px; line-height: 1.45;
    padding: 6px 8px; border-radius: 6px;
    background: var(--card2); border: 1px solid var(--border);
    cursor: pointer; transition: all 0.15s;
  }
  .cap-item:hover { border-color: var(--vuln); }
  .cap-item.active { border-color: var(--vuln); background: rgba(248,81,73,0.10); }
  .cap-item .top { display: flex; justify-content: space-between; gap: 6px; }
  .cap-item .cve { color: var(--vuln); font-weight: 600; }
  .cap-item .ant {
    background: var(--bg); padding: 1px 6px; border-radius: 3px;
    font-size: 10px; color: var(--text2);
  }
  .cap-item .meta { color: var(--text2); font-size: 10px; margin-top: 3px; }
  .cap-item .ghost { opacity: 0.55; }
  .cap-item .ghost-tag {
    background: var(--gray); color: #fff; font-size: 9px;
    padding: 1px 5px; border-radius: 3px; margin-left: 4px;
  }

  footer { padding: 12px 22px; color: var(--text3); font-size: 11px;
           text-align: center; border-top: 1px solid var(--border); }
</style>
</head>
<body>

<header>
  <h1>CyberGym - Asset Topology</h1>
  <div class="meta">deployment: %%DEPLOYMENT%% &nbsp;.&nbsp; inventory: %%VERSION%%</div>
</header>

<div class="legend">
  <span class="chip"><span class="swatch" style="background:var(--reach)"></span>NETWORK_REACH</span>
  <span class="chip" style="color:var(--iam)"><span class="swatch dashed"></span>IAM_BINDING</span>
  <span class="chip" style="color:var(--data)"><span class="swatch dotted"></span>DATA_FLOW</span>
  <span class="chip"><span class="swatch" style="background:var(--depend)"></span>DEPENDS_ON / RUNS_AS</span>
  <span class="chip" style="color:var(--belong)"><span class="swatch dashed"></span>BELONGS_TO</span>
</div>

<main>
  <div class="graph">
    <svg id="svg" viewBox="0 0 1200 760" preserveAspectRatio="xMidYMid meet"></svg>
  </div>
  <aside class="sidebar">
    <div id="headline" class="headline" style="display:none">
      <div class="headline-title">Top Recommendation</div>
      <div class="headline-body" id="headlineBody">-</div>
    </div>
    <div>
      <h2>Inventory</h2>
      <div class="stat-row"><span>nodes</span><span class="v" id="sNodes">-</span></div>
      <div class="stat-row"><span>edges (static + vuln)</span><span class="v" id="sEdges">-</span></div>
      <div class="stat-row"><span>products</span><span class="v" id="sProd">-</span></div>
      <div class="stat-row"><span>services</span><span class="v" id="sSvc">-</span></div>
      <div class="stat-row"><span>workloads</span><span class="v" id="sWork">-</span></div>
      <div class="stat-row"><span>infra nodes</span><span class="v" id="sInfra">-</span></div>
    </div>
    <div>
      <h2>Threat Intel</h2>
      <div class="stat-row"><span>CVEs ingested</span><span class="v" id="sCaps">-</span></div>
      <div class="stat-row"><span>applicable to us</span><span class="v" id="sCapsApp">-</span></div>
      <div class="stat-row"><span>not applicable</span><span class="v" id="sCapsGhost">-</span></div>
      <div class="stat-row"><span>VULN_EXPLOIT edges</span><span class="v" id="sVuln">-</span></div>
      <div class="stat-row"><span>kill paths</span><span class="v bad" id="sPaths">-</span></div>
    </div>
    <div id="chokeBox" style="display:none">
      <h2>Top Chokepoints</h2>
      <div class="path-list" id="chokes"></div>
    </div>
    <div id="capBox" style="display:none">
      <h2>Capability Table (CVE intel)</h2>
      <div style="font-size:11px;color:var(--text2);margin-bottom:6px">
        Base Model output. Click a row to highlight every red edge it produced.
      </div>
      <div class="path-list" id="caps"></div>
    </div>
    <div id="pathBox" style="display:none">
      <h2>Kill Paths (click to highlight)</h2>
      <div class="path-list" id="paths"></div>
    </div>
    <div>
      <h2>Selected Node</h2>
      <div class="detail-pane" id="detail">click a node to inspect</div>
    </div>
  </aside>
</main>

<footer>Generated by CyberGym/harness/render.py</footer>

<script>
const PAYLOAD     = %%PAYLOAD%%;
const LAYER_LABELS= %%LAYER_LABELS%%;
const KILL_PATHS  = %%KILL_PATHS%%;
const CHOKEPOINTS = %%CHOKEPOINTS%%;
const CAPABILITIES= %%CAPABILITIES%%;

let selected      = null;
let activePathIdx = null;
let activeCapKey  = null;   // "<task_id>" — when set, highlights all VULN_EXPLOIT edges from this capability

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = (s == null ? '' : String(s));
  return d.innerHTML;
}

function buildLayout() {
  const W = 1200;
  const margin = { top: 36, bottom: 30, left: 90, right: 30 };
  const layerOrder = [0, 1, 2, 3, 4];
  const layerH = 140;
  const innerW = W - margin.left - margin.right;
  const H = margin.top + layerOrder.length * layerH + margin.bottom + 30;

  // Group nodes by layer.
  const byLayer = {0: [], 1: [], 2: [], 3: [], 4: []};
  for (const n of PAYLOAD.nodes) byLayer[n.layer].push(n);
  // Stable sort within each layer.
  for (const k of layerOrder) byLayer[k].sort((a,b) => a.id.localeCompare(b.id));

  const pos = {};
  for (const layer of layerOrder) {
    const arr = byLayer[layer];
    const n = arr.length || 1;
    const cy = margin.top + (layer + 0.5) * layerH;
    arr.forEach((node, i) => {
      const cx = margin.left + ((i + 0.5) * innerW) / n;
      const isWide = (node.kind === 'service' || node.kind === 'workload' || node.kind === 'entry');
      pos[node.id] = { cx, cy, w: isWide ? 170 : 140, h: 58 };
    });
  }
  return { W, H, layerH, margin, layerOrder, pos };
}

function drawSvg() {
  const svg = document.getElementById('svg');
  const { W, H, layerH, margin, layerOrder, pos } = buildLayout();
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  let inner = '';

  // Layer dividers + labels.
  for (const layer of layerOrder) {
    const yTop = margin.top + layer * layerH;
    if (layer > 0) {
      inner += `<line class="layer-divider" x1="${margin.left}" y1="${yTop}" x2="${W - margin.right}" y2="${yTop}"/>`;
    }
    const labelY = yTop + 16;
    inner += `<text class="layer-label" x="14" y="${labelY}">${escHtml(LAYER_LABELS[layer])}</text>`;
  }

  // Edges first.
  for (const e of PAYLOAD.edges) {
    const p1 = pos[e.source], p2 = pos[e.target];
    if (!p1 || !p2) continue;
    // Going down the layer order? bezier downward; otherwise upward.
    let y1, y2;
    if (p1.cy <= p2.cy) {
      y1 = p1.cy + p1.h/2;
      y2 = p2.cy - p2.h/2;
    } else {
      y1 = p1.cy - p1.h/2;
      y2 = p2.cy + p2.h/2;
    }
    // Fan parallel edges between the same node pair so they don't overlap.
    const total = e.parallel_total || 1;
    const idx   = e.parallel_idx   || 0;
    // offset in [-((total-1)/2)*step, +((total-1)/2)*step]
    const step  = 14;
    const offset = (idx - (total - 1) / 2) * step;
    const x1 = p1.cx + offset;
    const x2 = p2.cx + offset;
    const dy = (y2 - y1) / 2;
    const path = `M ${x1} ${y1} C ${x1} ${y1 + dy}, ${x2} ${y2 - dy}, ${x2} ${y2}`;
    const tooltip = `${e.source} -> ${e.target}\ntype: ${e.type}\norigin: ${e.origin}` + (e.notes ? `\nnotes: ${e.notes}` : '');
    inner += `<path class="edge ${e.type}" data-src="${e.source}" data-dst="${e.target}" d="${path}"><title>${escHtml(tooltip)}</title></path>`;
  }

  // Nodes.
  for (const n of PAYLOAD.nodes) {
    const p = pos[n.id];
    const cls = ['node-box', n.kind, n.is_public ? 'public' : ''].filter(x=>x).join(' ');
    const x = p.cx - p.w/2, y = p.cy - p.h/2;
    inner += `<g class="${cls}" data-id="${n.id}">
      <title>${escHtml(n.id + '\n' + (n.description || ''))}</title>
      <rect x="${x}" y="${y}" width="${p.w}" height="${p.h}"></rect>
      <text x="${p.cx}" y="${p.cy - 4}" text-anchor="middle" font-weight="600">${escHtml(n.label)}</text>
      <text class="desc" x="${p.cx}" y="${p.cy + 14}" text-anchor="middle">${escHtml((n.description || '').slice(0, 40))}</text>
    </g>`;
  }
  svg.innerHTML = inner;

  // Wire up click-to-inspect.
  svg.querySelectorAll('.node-box').forEach(g => {
    g.addEventListener('click', () => {
      selected = (selected === g.dataset.id) ? null : g.dataset.id;
      activePathIdx = null;
      activeCapKey  = null;
      document.querySelectorAll('.path-item').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.cap-item').forEach(el => el.classList.remove('active'));
      svgClassToggle();
      renderDetail();
    });
  });
}

function renderDetail() {
  const el = document.getElementById('detail');
  if (!selected) { el.textContent = 'click a node to inspect'; return; }
  const n = PAYLOAD.nodes.find(x => x.id === selected);
  if (!n) { el.textContent = '(unknown)'; return; }
  // Incoming + outgoing edges.
  const incoming = PAYLOAD.edges.filter(e => e.target === selected);
  const outgoing = PAYLOAD.edges.filter(e => e.source === selected);
  const fmtEdge = (e, dir) => `  ${dir === 'in' ? e.source + ' -> ' : '-> ' + e.target} [${e.type}]`;

  let lines = [];
  lines.push(`id:    ${n.id}`);
  lines.push(`kind:  ${n.kind}    (layer ${n.layer})`);
  lines.push(`label: ${n.label}`);
  if (n.description) lines.push(`desc:  ${n.description}`);
  for (const k of ['criticality','auth_method','ztn_policy','expose_port','kernel_version','os','location','runtime','is_public']) {
    if (n[k] !== null && n[k] !== undefined && n[k] !== '') lines.push(`${k}: ${n[k]}`);
  }
  if (n.packages && n.packages.length) {
    lines.push('packages:');
    for (const p of n.packages) lines.push('  - ' + p);
  }
  if (incoming.length) {
    lines.push('');
    lines.push(`incoming (${incoming.length}):`);
    incoming.forEach(e => lines.push(fmtEdge(e, 'in')));
  }
  if (outgoing.length) {
    lines.push('');
    lines.push(`outgoing (${outgoing.length}):`);
    outgoing.forEach(e => lines.push(fmtEdge(e, 'out')));
  }
  el.textContent = lines.join('\n');
}

function renderStats() {
  document.getElementById('sNodes').textContent = PAYLOAD.nodes.length;
  document.getElementById('sEdges').textContent = PAYLOAD.edges.length;
  const counts = {product:0, service:0, workload:0, infra_node:0};
  for (const n of PAYLOAD.nodes) if (counts[n.kind] !== undefined) counts[n.kind]++;
  document.getElementById('sProd').textContent  = counts.product;
  document.getElementById('sSvc').textContent   = counts.service;
  document.getElementById('sWork').textContent  = counts.workload;
  document.getElementById('sInfra').textContent = counts.infra_node;

  // Threat intel: how many CVEs actually landed on our inventory?
  const edgeCountByKey = capabilityEdgeCounts();
  let applicable = 0, ghost = 0;
  for (const cap of CAPABILITIES) {
    if ((edgeCountByKey[cap.task_id] || 0) > 0) applicable++;
    else ghost++;
  }
  const vulnEdges = PAYLOAD.edges.filter(e => e.type === 'VULN_EXPLOIT').length;

  document.getElementById('sVuln').textContent  = vulnEdges;
  document.getElementById('sCaps').textContent  = CAPABILITIES.length;
  // Format: "<applicable> / <total>"
  const capsAppEl = document.getElementById('sCapsApp');
  capsAppEl.textContent = applicable + ' / ' + CAPABILITIES.length;
  capsAppEl.className = 'v ' + (applicable > 0 ? 'bad' : 'good');
  document.getElementById('sCapsGhost').textContent = ghost;

  const pathsEl = document.getElementById('sPaths');
  pathsEl.textContent = KILL_PATHS.length;
  pathsEl.className = 'v ' + (KILL_PATHS.length > 0 ? 'bad' : 'good');
}

function capabilityEdgeCounts() {
  const out = {};
  for (const e of PAYLOAD.edges) {
    if (e.type !== 'VULN_EXPLOIT') continue;
    const k = e.task_id || e.cve_id;
    if (k) out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function renderHeadline() {
  const top = CHOKEPOINTS[0];
  if (!top || !KILL_PATHS.length) return;
  const total = KILL_PATHS.length;
  const cut   = top.paths_cut;
  const pct   = Math.round((cut / total) * 100);
  const body  = document.getElementById('headlineBody');
  body.innerHTML =
    'Patch <code>' + escHtml(top.label) + '</code> ' +
    '(' + escHtml(top.kind) + ') first &mdash; it sits on ' +
    '<span class="num">' + cut + ' / ' + total + '</span> live kill paths ' +
    '(<span class="num">' + pct + '%</span> attack-surface reduction).';
  document.getElementById('headline').style.display = '';
}

function renderCaps() {
  if (!CAPABILITIES.length) return;
  document.getElementById('capBox').style.display = '';
  const list = document.getElementById('caps');
  list.innerHTML = '';
  const edgeCount = capabilityEdgeCounts();
  CAPABILITIES.forEach(cap => {
    const key   = cap.task_id;
    const count = edgeCount[key] || 0;
    const ghost = count === 0;
    const cveLabel = cap.cve_id || cap.task_id.split(':').pop();
    const post = (cap.post_condition || []).join(', ');
    const item = document.createElement('div');
    item.className = 'cap-item' + (ghost ? ' ghost' : '');
    item.dataset.key = key;
    item.innerHTML =
      '<div class="top">' +
        '<span class="cve">' + escHtml(cveLabel) + '</span>' +
        '<span class="ant">' + escHtml(cap.affected_node_type) + '</span>' +
      '</div>' +
      '<div class="meta">' +
        'cvss=' + (cap.cvss != null ? cap.cvss.toFixed(1) : '?') + ' ' +
        '| post: ' + escHtml(post) + ' ' +
        '| edges injected: <b>' + count + '</b>' +
        (ghost ? '<span class="ghost-tag">no match</span>' : '') +
        ' (src=' + escHtml(cap.source || '?') + ')' +
      '</div>' +
      '<div class="meta" style="font-style:italic">' + escHtml(cap.rationale || '') + '</div>';
    if (!ghost) {
      item.addEventListener('click', () => { highlightCapability(key); });
    } else {
      item.style.cursor = 'default';
      item.title = 'No inventory node matched this capability — VULN_EXPLOIT edge was not injected.';
    }
    list.appendChild(item);
  });
}

function highlightCapability(key) {
  activeCapKey  = (activeCapKey === key) ? null : key;
  // Clear other selections so the highlight is unambiguous.
  activePathIdx = null;
  selected      = null;
  document.querySelectorAll('.path-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.cap-item').forEach(el => {
    el.classList.toggle('active', activeCapKey != null && el.dataset.key === activeCapKey);
  });
  svgClassToggle();
}

function renderPaths() {
  if (!KILL_PATHS.length) return;
  document.getElementById('pathBox').style.display = '';
  const list = document.getElementById('paths');
  list.innerHTML = '';
  KILL_PATHS.forEach((p, i) => {
    const item = document.createElement('div');
    item.className = 'path-item';
    item.dataset.idx = i;
    item.innerHTML =
      '<div>' + escHtml(p.path.join(' -> ')) + '</div>' +
      '<div class="meta">target=<b>' + escHtml(p.target) + '</b> ' +
      'score=' + p.score + ' cvss=' + (p.max_cvss || 0).toFixed(1) +
      ' depth=' + p.depth + (p.uses_vuln ? ' VULN' : '') + '</div>';
    item.addEventListener('click', () => { highlightPath(i); });
    list.appendChild(item);
  });
}

function renderChokes() {
  if (!CHOKEPOINTS.length) return;
  document.getElementById('chokeBox').style.display = '';
  const list = document.getElementById('chokes');
  list.innerHTML = '';
  CHOKEPOINTS.forEach(cp => {
    const item = document.createElement('div');
    item.className = 'choke-item';
    item.innerHTML =
      '<div><span class="label">' + escHtml(cp.label) + '</span> ' +
      '<span style="color:var(--text2)">(' + escHtml(cp.kind) + ')</span></div>' +
      '<div class="meta">cuts <span class="num">' + cp.paths_cut + '</span> paths, ' +
      'betweenness=' + cp.betweenness + ', blend=' + cp.blend + '</div>';
    item.addEventListener('click', () => {
      selected = cp.node;
      svgClassToggle();
      renderDetail();
    });
    list.appendChild(item);
  });
}

function highlightPath(idx) {
  activePathIdx = (activePathIdx === idx) ? null : idx;
  activeCapKey  = null;
  document.querySelectorAll('.cap-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.path-item').forEach(el => {
    el.classList.toggle('active', String(activePathIdx) === el.dataset.idx);
  });
  svgClassToggle();
}

function svgClassToggle() {
  const svg = document.getElementById('svg');
  // Reset
  svg.querySelectorAll('.node-box').forEach(g => {
    g.classList.remove('selected', 'kill', 'choke');
    g.classList.toggle('selected', selected !== null && g.dataset.id === selected);
  });
  svg.querySelectorAll('.edge').forEach(e => {
    e.classList.remove('kill', 'highlight', 'dim');
  });

  // Mark chokepoints
  for (const cp of CHOKEPOINTS) {
    const g = svg.querySelector('.node-box[data-id="' + cssEsc(cp.node) + '"]');
    if (g) g.classList.add('choke');
  }

  // (a) Capability highlight: mark every red edge produced by this capability.
  if (activeCapKey !== null) {
    const nodesTouched = new Set();
    svg.querySelectorAll('.edge').forEach(e => {
      // edge dataset doesn't carry task_id; we re-find the corresponding payload edge.
      const found = PAYLOAD.edges.find(pe =>
        pe.source === e.dataset.src && pe.target === e.dataset.dst &&
        pe.type === 'VULN_EXPLOIT' &&
        ((pe.task_id || pe.cve_id) === activeCapKey)
      );
      if (found) {
        e.classList.add('kill');
        nodesTouched.add(e.dataset.src);
        nodesTouched.add(e.dataset.dst);
      }
    });
    nodesTouched.forEach(nid => {
      const g = svg.querySelector('.node-box[data-id="' + cssEsc(nid) + '"]');
      if (g) g.classList.add('kill');
    });
    svg.querySelectorAll('.edge:not(.kill)').forEach(e => e.classList.add('dim'));
    return;
  }

  // (b) Highlight active kill path
  if (activePathIdx !== null && KILL_PATHS[activePathIdx]) {
    const p = KILL_PATHS[activePathIdx];
    for (const nid of p.path) {
      const g = svg.querySelector('.node-box[data-id="' + cssEsc(nid) + '"]');
      if (g) g.classList.add('kill');
    }
    for (let i = 0; i < p.path.length - 1; i++) {
      const a = p.path[i], b = p.path[i + 1];
      svg.querySelectorAll('.edge').forEach(e => {
        if (e.dataset.src === a && e.dataset.dst === b) e.classList.add('kill');
      });
    }
    svg.querySelectorAll('.edge:not(.kill)').forEach(e => e.classList.add('dim'));
    return;
  }

  // (c) Highlight neighbours of selected node
  if (selected) {
    svg.querySelectorAll('.edge').forEach(e => {
      const incident = (e.dataset.src === selected || e.dataset.dst === selected);
      e.classList.toggle('highlight', incident);
      e.classList.toggle('dim', !incident);
    });
  }
}

function cssEsc(s) {
  // Cheap CSS-attr escape; ids in this PoC are alnum + _- so this suffices.
  return String(s).replace(/"/g, '\\"');
}

drawSvg();
renderStats();
renderPaths();
renderChokes();
renderCaps();
renderHeadline();
svgClassToggle();
</script>
</body>
</html>
"""


def render_html(
    g: nx.MultiDiGraph,
    out_path: str | Path,
    *,
    kill_paths: list[dict[str, Any]] | None = None,
    chokepoints: list[dict[str, Any]] | None = None,
    capability_table: list[dict[str, Any]] | None = None,
) -> Path:
    """Write the graph to a self-contained HTML file.

    `kill_paths` and `chokepoints` are optional overlays produced by the
    Phase-3 search/cut steps. `capability_table` is the Base-Model output
    consumed at injection time; surfacing it lets the user see which CVEs
    the demo actually knew about.
    """
    payload = _serialise(g)
    html = _TEMPLATE
    html = html.replace("%%PAYLOAD%%",      json.dumps(payload, ensure_ascii=False))
    html = html.replace("%%LAYER_LABELS%%", json.dumps(LAYER_LABELS, ensure_ascii=False))
    html = html.replace("%%KILL_PATHS%%",   json.dumps(kill_paths or [],   ensure_ascii=False))
    html = html.replace("%%CHOKEPOINTS%%",  json.dumps(chokepoints or [],  ensure_ascii=False))
    html = html.replace("%%CAPABILITIES%%", json.dumps(capability_table or [], ensure_ascii=False))
    html = html.replace("%%DEPLOYMENT%%",   payload["deployment"])
    html = html.replace("%%VERSION%%",      payload["version"])
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# CLI: python -m harness.render <inventory.yaml> [<out.html>]
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    from .graph import load_inventory, build_graph

    if len(sys.argv) < 2:
        print("usage: python -m harness.render <inventory.yaml> [<out.html>]")
        sys.exit(1)
    inv_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "out/topology.html"
    g = build_graph(load_inventory(inv_path))
    out = render_html(g, out_path)
    print(f"wrote {out}  ({out.stat().st_size} bytes, {g.number_of_nodes()} nodes, {g.number_of_edges()} edges)")
