"""Render a per-run attack-graph HTML from iter-NNN/attack_graph.json files.

Output: <run_dir>/attack_graph.html — single self-contained file, no external
deps, openable offline. Layout is a vertical bipartite graph:

    [ endpoints (left) ]  ====edges====  [ techniques (right) ]

A round slider/buttons at the top swaps which round is shown. Edges are
coloured by status:

    bypassed (red)          this round, attack got through
    blocked  (gray)         this round, defence held
    severed  (green halo)   defence held this round but had been bypassed before
    novel    (yellow halo)  this technique appeared for the first time this round

Sidebar lists score, stats, and the agent's rationale for that round.
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


def _collect_round_payloads(run_dir: Path) -> list[dict[str, Any]]:
    """One blob per round with everything the HTML needs."""
    rounds: list[dict[str, Any]] = []
    iters = sorted((run_dir / "iters").glob("iter-*"))
    for it in iters:
        graph = _read_json(it / "attack_graph.json")
        if graph is None:
            continue
        score = _read_json(it / "score.json") or {}
        policy_yaml = _read_text(it / "policy_intent.yaml") or ""
        # Pull rationale out of YAML cheaply (avoid yaml dep here).
        rationale = ""
        marker = "rationale:"
        idx = policy_yaml.find(marker)
        if idx >= 0:
            rationale = policy_yaml[idx + len(marker):].strip()
            # strip leading | or > and any wrapping quotes
            if rationale.startswith(("|", ">")):
                rationale = rationale.split("\n", 1)[1] if "\n" in rationale else ""
            rationale = rationale.strip().strip("'\"")
        rounds.append({
            "iteration": graph["iteration"],
            "edges": graph["edges"],
            "endpoint_status": graph["endpoint_status"],
            "stats": graph["stats"],
            "score": score.get("total"),
            "rationale": rationale[:1200],
        })
    return rounds


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AutoPatch-RL · Attack Graph</title>
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
    display: flex; gap: 12px; align-items: center;
  }
  .nav button {
    background: var(--card); color: var(--text); border: 1px solid var(--border);
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px;
  }
  .nav button:hover { background: var(--border); }
  .nav button:disabled { opacity: 0.4; cursor: not-allowed; }
  .round-label { font-family: var(--font); color: var(--text); min-width: 110px; }
  .slider-wrap { flex: 1; display: flex; align-items: center; gap: 12px; }
  input[type=range] { flex: 1; }
  .legend { display: flex; gap: 14px; font-size: 12px; color: var(--text2); }
  .legend .chip {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 3px 8px; border-radius: 12px;
  }
  .legend .chip span.dot {
    width: 10px; height: 10px; border-radius: 50%; display: inline-block;
  }

  main {
    flex: 1; display: grid; grid-template-columns: minmax(0,1fr) 360px;
    gap: 16px; padding: 16px 22px;
  }
  .graph {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px; min-height: 600px;
    position: relative; overflow: auto;
  }
  .graph svg { width: 100%; height: 100%; min-height: 560px; }

  .sidebar {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px;
    display: flex; flex-direction: column; gap: 14px;
    max-height: calc(100vh - 200px); overflow-y: auto;
  }
  .stat-row { display: grid; grid-template-columns: 1fr auto; gap: 4px; font-size: 13px; }
  .stat-row .v { font-family: var(--font); }
  .score-positive { color: var(--green); }
  .score-negative { color: var(--red); }
  h2 {
    font-size: 13px; color: var(--text2); margin: 0 0 6px 0;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .rationale {
    background: var(--card2); padding: 10px 12px; border-radius: 8px;
    font-size: 12px; line-height: 1.55; white-space: pre-wrap;
    border: 1px solid var(--border); max-height: 220px; overflow-y: auto;
  }
  .edge-list {
    display: flex; flex-direction: column; gap: 4px;
    max-height: 360px; overflow-y: auto;
  }
  .edge-item {
    font-size: 11px; font-family: var(--font);
    padding: 4px 8px; border-radius: 4px; border: 1px solid var(--border);
    background: var(--card2);
  }
  .edge-item.bypassed { color: var(--red); border-left: 3px solid var(--red); }
  .edge-item.blocked  { color: var(--text2); }
  .edge-item.severed  { color: var(--green); border-left: 3px solid var(--green); }
  .edge-item.novel    { box-shadow: inset 0 0 0 1px var(--yellow); }

  /* SVG */
  .node-ep rect {
    fill: var(--card2); stroke: var(--border); stroke-width: 2;
    rx: 8; ry: 8; transition: all 0.2s;
  }
  .node-ep.compromised rect { fill: var(--red-bg); stroke: var(--red); }
  .node-ep.defended rect    { fill: var(--green-bg); stroke: var(--green); }
  .node-ep text { fill: var(--text); font-family: var(--font); font-size: 13px; }
  .node-ep .vuln { fill: var(--text2); font-size: 11px; }

  .node-tech rect {
    fill: var(--card2); stroke: var(--border); stroke-width: 1; rx: 6; ry: 6;
  }
  .node-tech text { fill: var(--text); font-family: var(--font); font-size: 11px; }

  .edge { fill: none; stroke-width: 1.5; opacity: 0.85; transition: opacity 0.2s; }
  .edge.bypassed { stroke: var(--red); stroke-width: 2.5; }
  .edge.blocked  { stroke: var(--gray); stroke-dasharray: 4 4; opacity: 0.4; }
  .edge.severed  { stroke: var(--green); stroke-width: 2; opacity: 0.7; }
  .edge.novel    { filter: drop-shadow(0 0 3px var(--yellow)); }
  .edge:hover { opacity: 1; stroke-width: 3.5; }

  footer { padding: 12px 22px; color: var(--text3); font-size: 11px;
           text-align: center; border-top: 1px solid var(--border); }
</style>
</head>
<body>

<header>
  <h1>AutoPatch-RL · Attack Graph</h1>
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
    <span class="chip"><span class="dot" style="background:var(--red)"></span>bypassed</span>
    <span class="chip"><span class="dot" style="background:var(--gray)"></span>blocked</span>
    <span class="chip"><span class="dot" style="background:var(--green)"></span>severed</span>
    <span class="chip"><span class="dot" style="background:var(--yellow)"></span>novel</span>
  </div>
</div>

<main>
  <div class="graph">
    <svg id="svg" viewBox="0 0 900 800" preserveAspectRatio="xMidYMid meet"></svg>
  </div>
  <aside class="sidebar">
    <div>
      <h2>Round Stats</h2>
      <div class="stat-row"><span>iteration</span><span class="v" id="sIter">-</span></div>
      <div class="stat-row"><span>score</span><span class="v" id="sScore">-</span></div>
      <div class="stat-row"><span>edges</span><span class="v" id="sEdges">-</span></div>
      <div class="stat-row"><span>bypassed</span><span class="v" id="sBypass">-</span></div>
      <div class="stat-row"><span>blocked</span><span class="v" id="sBlock">-</span></div>
      <div class="stat-row"><span>compromised endpoints</span><span class="v" id="sComp">-</span></div>
    </div>
    <div>
      <h2>Agent Rationale</h2>
      <div class="rationale" id="rationale">(no rationale)</div>
    </div>
    <div>
      <h2>Edges this round</h2>
      <div class="edge-list" id="edgeList"></div>
    </div>
  </aside>
</main>

<footer>Generated by AutoPatch-RL · attack_graph.html</footer>

<script>
const ROUNDS = %%ROUNDS_JSON%%;
const ENDPOINTS = %%ENDPOINTS_JSON%%;

let cur = 0;

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = (s == null ? '' : String(s));
  return d.innerHTML;
}

function renderGraph(round) {
  const svg = document.getElementById('svg');
  // Collect technique nodes from edges
  const techSet = new Map();   // technique -> {bypassed:bool, severed:bool, novel:bool}
  for (const e of round.edges) {
    let t = techSet.get(e.technique) || {bypassed:false, severed:false, novel:false};
    if (e.status === 'bypassed') t.bypassed = true;
    if (e.severed) t.severed = true;
    if (e.novel) t.novel = true;
    techSet.set(e.technique, t);
  }
  const techs = Array.from(techSet.keys()).sort((a,b) => {
    const ta = techSet.get(a), tb = techSet.get(b);
    if (ta.bypassed !== tb.bypassed) return ta.bypassed ? -1 : 1;
    return a.localeCompare(b);
  });

  const W = 900;
  const epH = 60, epGap = 18;
  const techH = 26, techGap = 6;

  const epX = 30, epW = 220;
  const techX = 600, techW = 280;

  const epStartY = 30;
  const techStartY = 30;

  const totalEpH = ENDPOINTS.length * (epH + epGap);
  const totalTechH = techs.length * (techH + techGap);
  const H = Math.max(800, totalEpH + 60, totalTechH + 60);

  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  // Position lookup
  const epPos = {};
  ENDPOINTS.forEach((ep, i) => {
    epPos[ep.path] = {
      x: epX, y: epStartY + i * (epH + epGap),
      w: epW, h: epH,
      cx: epX + epW, cy: epStartY + i * (epH + epGap) + epH/2,
    };
  });
  const techPos = {};
  techs.forEach((t, i) => {
    techPos[t] = {
      x: techX, y: techStartY + i * (techH + techGap),
      w: techW, h: techH,
      cx: techX, cy: techStartY + i * (techH + techGap) + techH/2,
    };
  });

  let svgInner = '';

  // Edges first so they sit under nodes
  for (const e of round.edges) {
    const p1 = epPos[e.endpoint];
    const p2 = techPos[e.technique];
    if (!p1 || !p2) continue;
    const cls = ['edge', e.status];
    if (e.severed) cls.push('severed');
    if (e.novel) cls.push('novel');
    const dx = (p2.cx - p1.cx) / 2;
    const path = `M ${p1.cx} ${p1.cy} C ${p1.cx + dx} ${p1.cy}, ${p2.cx - dx} ${p2.cy}, ${p2.cx} ${p2.cy}`;
    const title = `${e.endpoint} <- ${e.technique} [${e.status}]` +
      (e.severed ? ' (severed)' : '') + (e.novel ? ' (novel)' : '') +
      (e.payload_preview ? `\n${e.payload_preview}` : '');
    svgInner += `<path class="${cls.join(' ')}" d="${path}"><title>${escHtml(title)}</title></path>`;
  }

  // Endpoint nodes
  ENDPOINTS.forEach(ep => {
    const p = epPos[ep.path];
    const status = round.endpoint_status[ep.path] || 'unknown';
    svgInner += `<g class="node-ep ${status}">
      <rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}"></rect>
      <text x="${p.x + 14}" y="${p.y + 26}" font-weight="600">${escHtml(ep.path)}</text>
      <text class="vuln" x="${p.x + 14}" y="${p.y + 44}">${escHtml(ep.vuln)} (${ep.cwe})</text>
    </g>`;
  });

  // Technique nodes
  techs.forEach(t => {
    const p = techPos[t];
    const meta = techSet.get(t);
    let stroke = 'var(--border)';
    if (meta.bypassed) stroke = 'var(--red)';
    else if (meta.severed) stroke = 'var(--green)';
    if (meta.novel) stroke = 'var(--yellow)';
    const label = t.length > 38 ? t.slice(0, 36) + '...' : t;
    svgInner += `<g class="node-tech">
      <rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" style="stroke:${stroke}"></rect>
      <text x="${p.x + 8}" y="${p.y + 17}">${escHtml(label)}</text>
    </g>`;
  });

  svg.innerHTML = svgInner;
}

function renderSidebar(round) {
  document.getElementById('sIter').textContent = round.iteration;
  const sc = round.score == null ? '-' : (round.score >= 0 ? '+' : '') + round.score;
  const scEl = document.getElementById('sScore');
  scEl.textContent = sc;
  scEl.className = 'v ' + (round.score == null ? '' : (round.score >= 0 ? 'score-positive' : 'score-negative'));
  document.getElementById('sEdges').textContent = round.stats.total_edges;
  document.getElementById('sBypass').textContent = round.stats.bypassed;
  document.getElementById('sBlock').textContent = round.stats.blocked;
  document.getElementById('sComp').textContent = round.stats.compromised_endpoints + ' / ' + ENDPOINTS.length;
  document.getElementById('rationale').textContent = round.rationale || '(no rationale)';

  const list = document.getElementById('edgeList');
  list.innerHTML = '';
  // Sort: bypassed > severed > novel > blocked
  const sorted = round.edges.slice().sort((a,b) => {
    const rank = e => (e.status === 'bypassed' ? 0 : (e.severed ? 1 : (e.novel ? 2 : 3)));
    return rank(a) - rank(b);
  });
  sorted.forEach(e => {
    const cls = ['edge-item', e.status];
    if (e.severed) cls.push('severed');
    if (e.novel) cls.push('novel');
    const tag = e.severed ? ' [SEV]' : (e.novel ? ' [NEW]' : '');
    const div = document.createElement('div');
    div.className = cls.join(' ');
    div.textContent = `${e.endpoint} ← ${e.technique}${tag}`;
    if (e.payload_preview) div.title = e.payload_preview;
    list.appendChild(div);
  });
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
  cur = parseInt(e.target.value, 10);
  render();
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
    html = html.replace(
        "%%ENDPOINTS_JSON%%",
        json.dumps(attack_graph.ENDPOINTS, ensure_ascii=False),
    )
    html = html.replace("%%RUN_NAME%%", run_dir.name)
    html = html.replace("%%NUM_ROUNDS%%", str(len(rounds)))
    out = run_dir / "attack_graph.html"
    out.write_text(html, encoding="utf-8")
    return out
