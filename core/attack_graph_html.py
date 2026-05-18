"""Render a 5-layer kill-chain HTML from per-iter attack_graph.json files.

Layout: nodes are stacked in 5 horizontal bands (L1 top, L5 bottom).
Edges are SVG bezier curves coloured by status. A round slider lets you
scrub between iterations and see which edges/nodes change colour.

Single self-contained HTML file, no external CDN dependency.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core import attack_graph


def _read_text(p: Path) -> str | None:
    if p.exists():
        try:
            return p.read_text(encoding="utf-8")
        except Exception:
            return None
    return None


def _read_json(p: Path) -> Any:
    txt = _read_text(p)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None


def _extract_rationale(policy_yaml: str) -> str:
    marker = "rationale:"
    idx = policy_yaml.find(marker)
    if idx < 0:
        return ""
    rationale = policy_yaml[idx + len(marker):].strip()
    if rationale.startswith(("|", ">")):
        rationale = rationale.split("\n", 1)[1] if "\n" in rationale else ""
    return rationale.strip().strip("'\"")[:1500]


def _collect_round_payloads(run_dir: Path) -> list[dict[str, Any]]:
    rounds: list[dict[str, Any]] = []
    iters = sorted((run_dir / "iters").glob("iter-*"))
    for it in iters:
        graph = _read_json(it / "attack_graph.json")
        if graph is None or graph.get("schema_version") != "killchain.v1":
            continue
        score = _read_json(it / "score.json") or {}
        policy_yaml = _read_text(it / "policy_intent.yaml") or ""
        rounds.append({
            "iteration": graph["iteration"],
            "nodes": graph["nodes"],
            "edges": graph["edges"],
            "node_reachable": graph["node_reachable"],
            "stats": graph["stats"],
            "kill_paths": graph.get("kill_paths", []),
            "score": score.get("total"),
            "rationale": _extract_rationale(policy_yaml),
        })
    return rounds


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AutoPatch-RL Kill Chain</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --card2: #1c2128; --border: #30363d;
    --red: #f85149; --red-bg: rgba(248,81,73,0.18);
    --green: #3fb950; --green-bg: rgba(63,185,80,0.18);
    --yellow: #d29922; --yellow-bg: rgba(210,153,34,0.18);
    --blue: #58a6ff; --blue-bg: rgba(88,166,255,0.18);
    --gray: #6e7681;
    --text: #c9d1d9; --text2: #8b949e; --text3: #6e7681;
    --font: 'SF Mono', 'JetBrains Mono', 'Cascadia Code', monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    min-height: 100vh; display: flex; flex-direction: column;
  }
  header {
    padding: 14px 22px; border-bottom: 1px solid var(--border);
    background: var(--card); display: flex; align-items: center;
    justify-content: space-between;
  }
  header h1 { margin: 0; font-size: 18px; font-weight: 600; }
  header .meta { color: var(--text2); font-size: 13px; font-family: var(--font); }
  .nav {
    padding: 12px 22px; background: var(--card2);
    border-bottom: 1px solid var(--border);
    display: flex; gap: 12px; align-items: center; flex-wrap: wrap;
  }
  .nav button {
    background: var(--card); color: var(--text); border: 1px solid var(--border);
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px;
  }
  .nav button:hover { background: var(--border); }
  .nav button:disabled { opacity: 0.4; cursor: not-allowed; }
  .round-label { font-family: var(--font); color: var(--text); min-width: 110px; }
  .slider-wrap { flex: 1; display: flex; align-items: center; gap: 12px; min-width: 200px; }
  input[type=range] { flex: 1; }
  .legend { display: flex; gap: 14px; font-size: 12px; color: var(--text2); flex-wrap: wrap; }
  .legend .chip { display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px; border-radius: 12px; }
  .legend .chip span.swatch {
    width: 18px; height: 4px; border-radius: 2px; display: inline-block;
  }
  main {
    flex: 1; display: grid; grid-template-columns: minmax(0,1fr) 360px;
    gap: 16px; padding: 16px 22px;
  }
  .graph {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px; min-height: 720px;
    position: relative; overflow: auto;
  }
  .graph svg { width: 100%; height: 100%; min-height: 700px; }
  .layer-label {
    position: absolute; left: 22px; color: var(--text3);
    font-family: var(--font); font-size: 11px; pointer-events: none;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .sidebar {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px;
    display: flex; flex-direction: column; gap: 14px;
    max-height: calc(100vh - 200px); overflow-y: auto;
  }
  .stat-row { display: grid; grid-template-columns: 1fr auto; gap: 4px; font-size: 13px; }
  .stat-row .v { font-family: var(--font); }
  .stat-row .v.bad  { color: var(--red); }
  .stat-row .v.good { color: var(--green); }
  h2 {
    font-size: 13px; color: var(--text2); margin: 0 0 6px 0;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .rationale {
    background: var(--card2); padding: 10px 12px; border-radius: 8px;
    font-size: 12px; line-height: 1.55; white-space: pre-wrap;
    border: 1px solid var(--border); max-height: 200px; overflow-y: auto;
  }
  .path-list { display: flex; flex-direction: column; gap: 6px; }
  .path {
    font-family: var(--font); font-size: 11px;
    padding: 6px 10px; border-radius: 6px;
    background: var(--red-bg); color: var(--text); border-left: 3px solid var(--red);
    word-break: break-word;
  }
  .edges-section h2 { margin-top: 8px; }
  .edge-list { display: flex; flex-direction: column; gap: 4px; max-height: 260px; overflow-y: auto; }
  .edge-item {
    font-size: 11px; font-family: var(--font);
    padding: 4px 8px; border-radius: 4px; border: 1px solid var(--border);
    background: var(--card2);
  }
  .edge-item.bypassed   { color: var(--red); border-left: 3px solid var(--red); }
  .edge-item.reachable  { color: var(--yellow); border-left: 3px solid var(--yellow); }
  .edge-item.severed    { color: var(--green); border-left: 3px solid var(--green); }
  .edge-item.blocked    { color: var(--text2); }

  /* SVG */
  .node-box rect { rx: 8; ry: 8; stroke-width: 2; transition: all 0.2s; }
  .node-box.compromised rect { fill: var(--red-bg); stroke: var(--red); }
  .node-box.safe         rect { fill: var(--card2);  stroke: var(--border); }
  .node-box text { fill: var(--text); font-family: var(--font); font-size: 12px; }
  .node-box .desc { fill: var(--text2); font-size: 10px; }

  .edge { fill: none; stroke-width: 1.6; opacity: 0.85; transition: opacity 0.2s; }
  .edge.bypassed   { stroke: var(--red);    stroke-width: 2.6; }
  .edge.reachable  { stroke: var(--yellow); stroke-width: 2; stroke-dasharray: 6 3; }
  .edge.severed    { stroke: var(--green);  stroke-width: 2; }
  .edge.blocked    { stroke: var(--gray);   stroke-width: 1; stroke-dasharray: 3 4; opacity: 0.35; }
  .edge.unreachable{ stroke: var(--gray);   stroke-width: 1; opacity: 0.18; }
  .edge.regressed       { filter: drop-shadow(0 0 4px var(--red));    }
  .edge.novel-severance { filter: drop-shadow(0 0 4px var(--green));  }
  .edge:hover { opacity: 1; stroke-width: 4; }
  .layer-divider { stroke: var(--border); stroke-dasharray: 2 4; }

  footer { padding: 12px 22px; color: var(--text3); font-size: 11px;
           text-align: center; border-top: 1px solid var(--border); }
</style>
</head>
<body>

<header>
  <h1>AutoPatch-RL · Kill Chain</h1>
  <div class="meta">run: %%RUN_NAME%% · rounds: %%NUM_ROUNDS%%</div>
</header>

<div class="nav">
  <button id="prevBtn">&larr; Prev</button>
  <div class="round-label" id="roundLabel">Round 0</div>
  <div class="slider-wrap">
    <input type="range" id="slider" min="0" max="0" value="0" step="1">
  </div>
  <button id="nextBtn">Next &rarr;</button>
  <div class="legend">
    <span class="chip"><span class="swatch" style="background:var(--red)"></span>bypassed (probe-confirmed)</span>
    <span class="chip"><span class="swatch" style="background:var(--yellow)"></span>reachable (no defence)</span>
    <span class="chip"><span class="swatch" style="background:var(--green)"></span>severed (cut by policy)</span>
    <span class="chip"><span class="swatch" style="background:var(--gray)"></span>blocked / unreachable</span>
  </div>
</div>

<main>
  <div class="graph">
    <svg id="svg" viewBox="0 0 1100 760" preserveAspectRatio="xMidYMid meet"></svg>
  </div>
  <aside class="sidebar">
    <div>
      <h2>Round Stats</h2>
      <div class="stat-row"><span>iteration</span><span class="v" id="sIter">-</span></div>
      <div class="stat-row"><span>score</span><span class="v" id="sScore">-</span></div>
      <div class="stat-row"><span>host owned</span><span class="v" id="sHost">-</span></div>
      <div class="stat-row"><span>bypassed edges</span><span class="v bad" id="sBypass">-</span></div>
      <div class="stat-row"><span>reachable edges</span><span class="v" id="sReach">-</span></div>
      <div class="stat-row"><span>severed edges</span><span class="v good" id="sSever">-</span></div>
      <div class="stat-row"><span>L2 caps reached</span><span class="v" id="sCaps">-</span></div>
    </div>
    <div>
      <h2>Live Kill Paths to Host</h2>
      <div class="path-list" id="paths"></div>
    </div>
    <div>
      <h2>Agent Rationale</h2>
      <div class="rationale" id="rationale">(no rationale)</div>
    </div>
    <div class="edges-section">
      <h2>Live Edges</h2>
      <div class="edge-list" id="edgeList"></div>
    </div>
  </aside>
</main>

<footer>Generated by AutoPatch-RL · attack_graph.html (kill-chain)</footer>

<script>
const ROUNDS = %%ROUNDS_JSON%%;

let cur = 0;

const LAYER_NAMES = {
  1: "L1 Initial Access",
  2: "L2 Capability",
  3: "L3 Container Compromise",
  4: "L4 Container Escape",
  5: "L5 Host"
};

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = (s == null ? '' : String(s));
  return d.innerHTML;
}

function renderGraph(round) {
  const svg = document.getElementById('svg');
  const W = 1100;
  const margin = { top: 30, bottom: 30, left: 70, right: 30 };

  // Group nodes by layer.
  const layers = {1: [], 2: [], 3: [], 4: [], 5: []};
  for (const n of round.nodes) layers[n.layer].push(n);

  // Vertical: each layer gets equal vertical band.
  const layerCount = 5;
  const innerW = W - margin.left - margin.right;
  // Tall enough to comfortably hold each layer; biggest layer is L2/L3 with ~6 nodes.
  const layerH = 130;
  const H = margin.top + layerCount * layerH + margin.bottom + 30;

  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  // Position lookup keyed by node id.
  const pos = {};
  for (let layer = 1; layer <= 5; layer++) {
    const arr = layers[layer];
    const n = arr.length;
    const cy = margin.top + (layer - 0.5) * layerH;
    arr.forEach((node, i) => {
      // Spread evenly across innerW.
      const cx = margin.left + ((i + 0.5) * innerW) / n;
      pos[node.id] = { cx, cy, w: 150, h: 56 };
    });
  }

  let svgInner = '';

  // Layer dividers + labels.
  for (let layer = 1; layer <= 5; layer++) {
    const y = margin.top + layer * layerH;
    if (layer < 5) {
      svgInner += `<line class="layer-divider" x1="${margin.left}" y1="${y}" x2="${W - margin.right}" y2="${y}"/>`;
    }
    const labelY = margin.top + (layer - 0.5) * layerH - layerH/2 + 14;
    svgInner += `<text x="14" y="${labelY}" fill="#6e7681" font-family="monospace" font-size="11" letter-spacing="1px">${escHtml(LAYER_NAMES[layer])}</text>`;
  }

  // Edges first (under nodes).
  for (const e of round.edges) {
    const p1 = pos[e.source];
    const p2 = pos[e.target];
    if (!p1 || !p2) continue;
    const cls = ['edge', e.status];
    if (e.regressed)       cls.push('regressed');
    if (e.novel_severance) cls.push('novel-severance');
    // Vertical bezier from bottom of source to top of target.
    const y1 = p1.cy + p1.h/2;
    const y2 = p2.cy - p2.h/2;
    const dy = (y2 - y1) / 2;
    const path = `M ${p1.cx} ${y1} C ${p1.cx} ${y1 + dy}, ${p2.cx} ${y2 - dy}, ${p2.cx} ${y2}`;
    const reqNote = (e.requires && e.requires.length) ? ` [+needs ${e.requires.join(',')}]` : '';
    const sev = e.severance_label ? `\nseverance: ${e.severance_label}` : '';
    const emp = e.empirical ? `\nempirical probe: ${e.empirical} (${e.origin})` : `\norigin: ${e.origin}`;
    const title = `${e.source} -> ${e.target}\nlabel: ${e.label}${reqNote}\nstatus: ${e.status}${emp}${sev}`;
    svgInner += `<path class="${cls.join(' ')}" d="${path}"><title>${escHtml(title)}</title></path>`;
  }

  // Nodes.
  for (const n of round.nodes) {
    const p = pos[n.id];
    const reachable = !!round.node_reachable[n.id];
    const cls = reachable ? 'compromised' : 'safe';
    const x = p.cx - p.w/2;
    const y = p.cy - p.h/2;
    const titleAttr = `${n.id}\n${n.description || ''}`;
    svgInner += `<g class="node-box ${cls}">
      <title>${escHtml(titleAttr)}</title>
      <rect x="${x}" y="${y}" width="${p.w}" height="${p.h}"></rect>
      <text x="${p.cx}" y="${p.cy - 4}" text-anchor="middle" font-weight="600">${escHtml(n.label)}</text>
      <text class="desc" x="${p.cx}" y="${p.cy + 14}" text-anchor="middle">${escHtml((n.description || '').slice(0, 32))}</text>
    </g>`;
  }

  svg.innerHTML = svgInner;
}

function renderSidebar(round) {
  document.getElementById('sIter').textContent = round.iteration;
  const sc = round.score == null ? '-' : (round.score >= 0 ? '+' : '') + round.score;
  document.getElementById('sScore').textContent = sc;
  const host = round.stats.host_owned;
  const sh = document.getElementById('sHost');
  sh.textContent = host ? 'YES' : 'no';
  sh.className = 'v ' + (host ? 'bad' : 'good');
  document.getElementById('sBypass').textContent = round.stats.bypassed_edges;
  document.getElementById('sReach').textContent = round.stats.reachable_edges;
  document.getElementById('sSever').textContent = round.stats.severed_edges;
  document.getElementById('sCaps').textContent = round.stats.compromised_l2_capabilities + ' / 6';
  document.getElementById('rationale').textContent = round.rationale || '(no rationale)';

  const paths = document.getElementById('paths');
  paths.innerHTML = '';
  if (!round.kill_paths || round.kill_paths.length === 0) {
    const div = document.createElement('div');
    div.style.color = 'var(--green)';
    div.style.fontSize = '12px';
    div.textContent = 'No live path to host_owned this round.';
    paths.appendChild(div);
  } else {
    for (const p of round.kill_paths) {
      const div = document.createElement('div');
      div.className = 'path';
      div.textContent = p.join(' -> ');
      paths.appendChild(div);
    }
  }

  const list = document.getElementById('edgeList');
  list.innerHTML = '';
  const interesting = round.edges.filter(e =>
    e.status === 'bypassed' || e.status === 'reachable' ||
    e.regressed || e.novel_severance
  );
  interesting.sort((a, b) => {
    const rank = e => (e.status === 'bypassed' ? 0 : (e.regressed ? 1 : (e.novel_severance ? 2 : (e.status === 'reachable' ? 3 : 4))));
    return rank(a) - rank(b);
  });
  for (const e of interesting) {
    const cls = ['edge-item', e.status];
    let tag = '';
    if (e.regressed) tag = ' [REGRESSED]';
    else if (e.novel_severance) tag = ' [NEWLY-SEVERED]';
    const div = document.createElement('div');
    div.className = cls.join(' ');
    div.textContent = `${e.source} -> ${e.target}${tag}`;
    div.title = `${e.label}\n${e.severance_label || ''}`;
    list.appendChild(div);
  }
}

function render() {
  const r = ROUNDS[cur];
  document.getElementById('roundLabel').textContent = `Round ${r.iteration}`;
  document.getElementById('slider').value = cur;
  renderGraph(r);
  renderSidebar(r);
  document.getElementById('prevBtn').disabled = cur === 0;
  document.getElementById('nextBtn').disabled = cur === ROUNDS.length - 1;
}

document.getElementById('slider').max = ROUNDS.length - 1;
document.getElementById('slider').addEventListener('input', e => {
  cur = parseInt(e.target.value, 10); render();
});
document.getElementById('prevBtn').onclick = () => { if (cur > 0) { cur--; render(); } };
document.getElementById('nextBtn').onclick = () => { if (cur < ROUNDS.length - 1) { cur++; render(); } };
document.addEventListener('keydown', e => {
  if (e.key === 'ArrowLeft' && cur > 0) { cur--; render(); }
  else if (e.key === 'ArrowRight' && cur < ROUNDS.length - 1) { cur++; render(); }
});

render();
</script>
</body>
</html>
"""


def generate_html(run_dir: Path) -> Path | None:
    rounds = _collect_round_payloads(run_dir)
    if not rounds:
        return None
    html = _TEMPLATE
    html = html.replace("%%ROUNDS_JSON%%", json.dumps(rounds, ensure_ascii=False))
    html = html.replace("%%RUN_NAME%%", run_dir.name)
    html = html.replace("%%NUM_ROUNDS%%", str(len(rounds)))
    out = run_dir / "attack_graph.html"
    out.write_text(html, encoding="utf-8")
    return out
