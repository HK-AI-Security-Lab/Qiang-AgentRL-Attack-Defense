"""Generate an interactive HTML visualization of the Red vs Blue game.

The visualization shows 6 vulnerability endpoints as nodes, with a round
navigator. Clicking a round reveals what Red attacked, what Blue defended,
and how each endpoint's state changed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ENDPOINTS = [
    {"path": "/ping",   "vuln": "Command Injection",   "cwe": "CWE-78",   "icon": "&#128268;"},
    {"path": "/fetch",  "vuln": "SSRF",                "cwe": "CWE-918",  "icon": "&#127760;"},
    {"path": "/read",   "vuln": "Path Traversal",      "cwe": "CWE-22",   "icon": "&#128193;"},
    {"path": "/search", "vuln": "SQL Injection",       "cwe": "CWE-89",   "icon": "&#128202;"},
    {"path": "/render", "vuln": "SSTI",                "cwe": "CWE-1336", "icon": "&#128209;"},
    {"path": "/load",   "vuln": "Insecure Deser.",     "cwe": "CWE-502",  "icon": "&#128230;"},
]

# Map fixed red_team probe_id → endpoint
PROBE_TO_ENDPOINT = {
    "red_cmd_injection":   "/ping",
    "red_ssrf":            "/fetch",
    "red_path_traversal":  "/read",
    "red_sqli":            "/search",
    "red_ssti":            "/render",
    "red_deserialization": "/load",
}


def _read_json(p: Path) -> Any:
    if p.exists():
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            return None
    return None


def _policy_diff_brief(prev_yaml: str | None, curr_yaml: str | None) -> list[str]:
    """Return a list of human-readable policy change strings."""
    if not prev_yaml or not curr_yaml:
        return []
    try:
        import yaml as _yaml
        prev = _yaml.safe_load(prev_yaml).get("policy_intent", {}).get("controls", {})
        curr = _yaml.safe_load(curr_yaml).get("policy_intent", {}).get("controls", {})
    except Exception:
        return []
    changes: list[str] = []

    def diff_field(path: str, a: Any, b: Any):
        if a == b:
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for k in set(a.keys()) | set(b.keys()):
                diff_field(f"{path}.{k}", a.get(k), b.get(k))
        elif isinstance(a, list) and isinstance(b, list):
            added = [x for x in b if x not in a]
            removed = [x for x in a if x not in b]
            if added:
                changes.append(f"{path}: + {added}")
            if removed:
                changes.append(f"{path}: - {removed}")
        else:
            changes.append(f"{path}: {a!r} → {b!r}")

    diff_field("controls", prev, curr)
    return changes[:20]


def _enrich_game(run_dir: Path, game_log: list[dict]) -> list[dict]:
    """Inject per-endpoint state, payload-level results, and policy diffs."""
    enriched = []
    prev_policy_yaml: str | None = None
    persistent_state: dict[str, dict] = {ep["path"]: {"fixed": "unknown", "defenses": []} for ep in ENDPOINTS}

    for entry in game_log:
        rnd = entry["round"]
        it_dir = run_dir / "iters" / f"iter-{rnd:03d}"

        probe_results = _read_json(it_dir / "probe_results.json") or []
        red_payloads = _read_json(it_dir / "red_payloads.json") or []
        red_dyn = _read_json(it_dir / "red_dynamic_results.json") or []
        curr_policy_yaml = (it_dir / "policy_intent.yaml").read_text(encoding='utf-8') if (it_dir / "policy_intent.yaml").exists() else None

        # Per-endpoint state (fixed probe outcome)
        endpoint_state: dict[str, dict] = {}
        for ep in ENDPOINTS:
            endpoint_state[ep["path"]] = {
                "fixed": "unknown",     # blocked / allowed / disabled
                "dynamic": [],          # list of {technique, bypassed}
                "defenses_active": [],  # list of human-readable defense labels
            }

        for r in probe_results:
            if r["category"] != "red_team":
                continue
            ep = PROBE_TO_ENDPOINT.get(r["probe_id"])
            if not ep:
                continue
            endpoint_state[ep]["fixed"] = r["actual"]
            endpoint_state[ep]["evidence"] = r.get("evidence", "")[:200]

        # Match dynamic results to payloads
        dyn_by_id = {r["probe_id"]: r for r in red_dyn}
        for p in red_payloads:
            dyn = dyn_by_id.get(p["id"], {})
            ep = p.get("endpoint", "")
            if ep in endpoint_state:
                endpoint_state[ep]["dynamic"].append({
                    "technique": p.get("technique", ""),
                    "bypassed": dyn.get("actual") == "allowed",
                    "id": p["id"],
                    "params": p.get("params", {}),
                    "method": p.get("method", "GET"),
                    "evidence": dyn.get("evidence", "")[:200],
                })

        # Derive active defenses from WAF config
        waf = _read_json(it_dir / "waf_rules.json") or {}
        defenses: dict[str, list[str]] = {ep["path"]: [] for ep in ENDPOINTS}
        if waf.get("block_patterns"):
            defenses["/ping"].append(f"WAF regex: {len(waf['block_patterns'])} patterns")
        if waf.get("ssrf_allowed_schemes"):
            defenses["/fetch"].append(f"Scheme allowlist: {waf['ssrf_allowed_schemes']}")
        if waf.get("ssrf_allowed_hosts"):
            defenses["/fetch"].append(f"Host allowlist: {waf['ssrf_allowed_hosts']}")
        if waf.get("path_traversal_block"):
            defenses["/read"].append("Block `..` substring")
        if waf.get("sqli_parameterized"):
            defenses["/search"].append("Parameterized queries")
        if waf.get("ssti_sandbox"):
            defenses["/render"].append("Jinja2 SandboxedEnvironment")
        if waf.get("pickle_disabled"):
            defenses["/load"].append("Pickle disabled (403)")
        for ep_path in waf.get("disabled_endpoints", []):
            if ep_path in defenses:
                defenses[ep_path].append("Endpoint disabled (404)")
                endpoint_state[ep_path]["fixed"] = "disabled"

        for ep_path, defs in defenses.items():
            endpoint_state[ep_path]["defenses_active"] = defs

        entry["endpoint_state"] = endpoint_state
        entry["policy_changes"] = _policy_diff_brief(prev_policy_yaml, curr_policy_yaml)
        prev_policy_yaml = curr_policy_yaml
        enriched.append(entry)

    return enriched


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>AutoPatch-RL · Red vs Blue Replay</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --card2: #1c2128; --border: #30363d;
    --red: #f85149; --red-bg: rgba(248,81,73,0.12); --red-border: #da3633;
    --blue: #58a6ff; --blue-bg: rgba(88,166,255,0.12); --blue-border: #388bfd;
    --green: #3fb950; --green-bg: rgba(63,185,80,0.12);
    --gray: #6e7681; --gray-bg: rgba(110,118,129,0.15);
    --yellow: #d29922;
    --text: #c9d1d9; --text2: #8b949e; --text3: #6e7681;
    --font: 'SF Mono', 'JetBrains Mono', 'Cascadia Code', monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    min-height: 100vh; display: flex; flex-direction: column;
  }
  header {
    padding: 16px 24px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--card);
  }
  h1 { margin: 0; font-size: 20px; font-weight: 600; }
  h1 .red { color: var(--red); }
  h1 .blue { color: var(--blue); }
  .meta { color: var(--text2); font-size: 13px; }
  .meta b { color: var(--text); font-family: var(--font); }

  /* Navigator */
  .nav {
    padding: 12px 24px; background: var(--card2); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px;
  }
  .nav button {
    background: var(--card); color: var(--text); border: 1px solid var(--border);
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px;
    transition: all 0.15s;
  }
  .nav button:hover { background: var(--border); }
  .nav button:disabled { opacity: 0.4; cursor: not-allowed; }
  .nav .play-btn { background: var(--blue); color: white; border-color: var(--blue); }
  .nav .play-btn:hover { background: var(--blue-border); }
  .round-dots { display: flex; gap: 6px; flex: 1; justify-content: center; }
  .round-dot {
    width: 30px; height: 30px; border-radius: 50%;
    background: var(--card); border: 2px solid var(--border);
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; font-size: 11px; font-family: var(--font);
    color: var(--text2); transition: all 0.15s; position: relative;
  }
  .round-dot:hover { border-color: var(--blue); }
  .round-dot.active { border-color: var(--yellow); color: var(--yellow); transform: scale(1.15); }
  .round-dot.positive { background: var(--green-bg); color: var(--green); }
  .round-dot.negative { background: var(--red-bg); color: var(--red); }
  .round-dot.equilibrium::after {
    content: '★'; position: absolute; top: -10px; right: -6px;
    color: var(--green); font-size: 14px;
  }

  .score-display {
    font-family: var(--font); font-size: 14px; font-weight: 700;
    padding: 4px 12px; border-radius: 6px; min-width: 80px; text-align: center;
  }
  .score-display.positive { background: var(--green-bg); color: var(--green); }
  .score-display.negative { background: var(--red-bg); color: var(--red); }

  /* Main board */
  main {
    flex: 1; padding: 24px; display: grid;
    grid-template-columns: 1fr; gap: 20px; max-width: 1400px;
    margin: 0 auto; width: 100%;
  }
  .board {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 24px;
  }
  .board-title {
    font-size: 14px; color: var(--text2); margin-bottom: 16px;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .nodes {
    display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px;
  }
  .node {
    background: var(--card2); border: 2px solid var(--border);
    border-radius: 10px; padding: 14px; cursor: pointer;
    transition: all 0.2s; position: relative;
    min-height: 130px; display: flex; flex-direction: column;
  }
  .node:hover { transform: translateY(-2px); border-color: var(--blue); }
  .node.blocked { border-color: var(--green); background: var(--green-bg); }
  .node.allowed { border-color: var(--red); background: var(--red-bg); animation: pulse 1.2s infinite; }
  .node.disabled { border-color: var(--gray); background: var(--gray-bg); opacity: 0.6; }
  .node.bypass-attempt { border-color: var(--red); background: var(--red-bg); }
  .node.selected { outline: 2px solid var(--yellow); outline-offset: 2px; }

  @keyframes pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(248,81,73,0.4); }
    50% { box-shadow: 0 0 0 8px rgba(248,81,73,0); }
  }

  .node-icon { font-size: 24px; line-height: 1; margin-bottom: 6px; }
  .node-path {
    font-family: var(--font); font-size: 14px; font-weight: 600;
    color: var(--text); margin-bottom: 2px;
  }
  .node-vuln { font-size: 11px; color: var(--text2); margin-bottom: 4px; }
  .node-cwe { font-size: 10px; color: var(--text3); font-family: var(--font); }
  .node-status {
    margin-top: auto; font-size: 11px; font-weight: 600;
    padding: 2px 6px; border-radius: 4px; text-align: center;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .node.blocked .node-status { background: var(--green); color: #000; }
  .node.allowed .node-status { background: var(--red); color: #fff; }
  .node.disabled .node-status { background: var(--gray); color: #fff; }
  .node.unknown .node-status { background: var(--border); color: var(--text2); }

  .bypass-badge {
    position: absolute; top: -8px; right: -8px;
    background: var(--red); color: white; font-size: 10px;
    padding: 2px 6px; border-radius: 10px; font-weight: 700;
    font-family: var(--font);
  }

  /* Detail panels */
  .panels {
    display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
  }
  .panel {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px;
    max-height: 600px; overflow-y: auto;
  }
  .panel-red { border-left: 4px solid var(--red); }
  .panel-blue { border-left: 4px solid var(--blue); }
  .panel h2 {
    margin: 0 0 12px 0; font-size: 16px;
    display: flex; align-items: center; gap: 8px;
  }
  .panel-red h2 { color: var(--red); }
  .panel-blue h2 { color: var(--blue); }
  .panel .icon { font-size: 22px; }
  .section-label {
    color: var(--text2); font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px;
    margin: 14px 0 6px 0; font-weight: 600;
  }
  .rationale {
    background: var(--card2); padding: 10px 12px; border-radius: 8px;
    font-size: 13px; line-height: 1.55; color: var(--text);
    border: 1px solid var(--border);
  }
  .payload-item {
    background: var(--card2); border-left: 3px solid var(--gray);
    padding: 10px 12px; margin: 6px 0; border-radius: 6px;
    font-size: 12px;
  }
  .payload-item.bypassed { border-left-color: var(--red); }
  .payload-item.blocked  { border-left-color: var(--green); }
  .payload-item .technique { font-weight: 600; margin-bottom: 4px; }
  .payload-item .params {
    font-family: var(--font); font-size: 11px; color: var(--text2);
    background: var(--bg); padding: 4px 8px; border-radius: 4px;
    margin-top: 4px; word-break: break-all;
  }
  .payload-item .endpoint-tag {
    display: inline-block; font-family: var(--font);
    font-size: 10px; padding: 1px 6px; border-radius: 3px;
    background: var(--bg); margin-right: 6px;
  }
  .payload-item .result-tag {
    display: inline-block; font-size: 10px;
    padding: 1px 6px; border-radius: 3px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.3px;
  }
  .payload-item.bypassed .result-tag { background: var(--red); color: #fff; }
  .payload-item.blocked .result-tag  { background: var(--green); color: #000; }

  .policy-change {
    font-family: var(--font); font-size: 12px;
    padding: 6px 10px; border-radius: 4px; margin: 3px 0;
    background: var(--card2);
  }
  .policy-change .add { color: var(--green); }
  .policy-change .remove { color: var(--red); }

  .defenses-list { display: flex; flex-wrap: wrap; gap: 4px; }
  .defense-chip {
    background: var(--blue-bg); color: var(--blue);
    padding: 2px 8px; border-radius: 12px;
    font-size: 11px; border: 1px solid var(--blue-border);
  }

  /* Node detail modal */
  .node-detail {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px; margin-top: 16px;
    display: none;
  }
  .node-detail.show { display: block; }
  .node-detail h3 { margin: 0 0 8px 0; font-size: 16px; }
  .node-detail .close {
    float: right; background: none; border: none; color: var(--text2);
    cursor: pointer; font-size: 18px;
  }

  footer {
    padding: 16px 24px; border-top: 1px solid var(--border);
    text-align: center; color: var(--text3); font-size: 12px;
  }
  footer a { color: var(--blue); text-decoration: none; }
</style>
</head>
<body>

<header>
  <h1><span class="red">&#9876;</span> Red <span style="color:var(--text2)">vs</span> Blue <span class="blue">&#128737;</span> · AutoPatch-RL</h1>
  <div class="meta">%%MODEL%% · rounds: <b>%%NUM_ROUNDS%%</b> · <span style="color:%%OUTCOME_COLOR%%;font-weight:700">%%OUTCOME%%</span></div>
</header>

<div class="nav">
  <button id="prevBtn">&larr; Prev</button>
  <button id="playBtn" class="play-btn">&#9658; Play</button>
  <div class="round-dots" id="roundDots"></div>
  <div class="score-display" id="scoreDisplay">+0</div>
  <button id="nextBtn">Next &rarr;</button>
</div>

<main>
  <div class="board">
    <div class="board-title">
      <span id="roundTitle">Round 0</span> ·
      Endpoints — click a node for details
    </div>
    <div class="nodes" id="nodes"></div>
    <div class="node-detail" id="nodeDetail"></div>
  </div>

  <div class="panels">
    <div class="panel panel-red">
      <h2><span class="icon">&#9876;</span> Red Move</h2>
      <div id="redContent"></div>
    </div>
    <div class="panel panel-blue">
      <h2><span class="icon">&#128737;</span> Blue Move</h2>
      <div id="blueContent"></div>
    </div>
  </div>
</main>

<footer>
  Generated by AutoPatch-RL · run_dir: <a href="#">%%RUN_NAME%%</a>
</footer>

<script>
const GAME = %%GAME_JSON%%;
const ENDPOINTS = %%ENDPOINTS_JSON%%;

let current = 0;
let playTimer = null;
let selectedNodeIdx = null;

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = (s == null ? '' : String(s));
  return d.innerHTML;
}

function renderRoundDots() {
  const dots = document.getElementById('roundDots');
  dots.innerHTML = '';
  GAME.forEach((g, i) => {
    const d = document.createElement('div');
    d.className = 'round-dot';
    if (i === current) d.classList.add('active');
    if ((g.score || 0) > 0) d.classList.add('positive');
    else if ((g.score || 0) < 0) d.classList.add('negative');
    if (g.terminal) d.classList.add('equilibrium');
    d.textContent = 'R' + i;
    d.onclick = () => { current = i; render(); };
    d.title = `Round ${i}: score=${g.score}`;
    dots.appendChild(d);
  });
}

function renderNodes() {
  const c = document.getElementById('nodes');
  c.innerHTML = '';
  const g = GAME[current];
  const epState = g.endpoint_state || {};
  ENDPOINTS.forEach((ep, idx) => {
    const st = epState[ep.path] || {fixed: 'unknown', dynamic: [], defenses_active: []};
    const node = document.createElement('div');
    let cls = 'node';
    let status = 'UNKNOWN';
    if (st.fixed === 'blocked') { cls += ' blocked'; status = 'BLOCKED'; }
    else if (st.fixed === 'allowed') { cls += ' allowed'; status = 'BYPASSED'; }
    else if (st.fixed === 'disabled') { cls += ' disabled'; status = 'DISABLED'; }
    else { cls += ' unknown'; }
    if (selectedNodeIdx === idx) cls += ' selected';
    node.className = cls;

    const numBypass = (st.dynamic || []).filter(d => d.bypassed).length;
    const numDyn = (st.dynamic || []).length;
    const bypassBadge = numBypass > 0
      ? `<div class="bypass-badge">+${numBypass} dyn bypass</div>` : '';

    node.innerHTML = `
      ${bypassBadge}
      <div class="node-icon">${ep.icon}</div>
      <div class="node-path">${ep.path}</div>
      <div class="node-vuln">${ep.vuln}</div>
      <div class="node-cwe">${ep.cwe}</div>
      <div class="node-status">${status}</div>
    `;
    node.onclick = () => {
      selectedNodeIdx = (selectedNodeIdx === idx) ? null : idx;
      renderNodes();
      renderNodeDetail();
    };
    c.appendChild(node);
  });
}

function renderNodeDetail() {
  const d = document.getElementById('nodeDetail');
  if (selectedNodeIdx === null) { d.classList.remove('show'); return; }
  const ep = ENDPOINTS[selectedNodeIdx];
  const g = GAME[current];
  const st = (g.endpoint_state || {})[ep.path] || {};
  let html = `<button class="close" onclick="closeDetail()">&times;</button>`;
  html += `<h3>${ep.icon} ${ep.path} — ${ep.vuln} <span style="font-size:11px;color:var(--text2);font-family:var(--font)">${ep.cwe}</span></h3>`;
  html += `<div style="font-size:13px;color:var(--text2);margin-bottom:8px">Fixed probe: <b style="color:var(--${st.fixed==='blocked'?'green':st.fixed==='disabled'?'gray':'red'})">${(st.fixed||'unknown').toUpperCase()}</b></div>`;
  if (st.evidence) html += `<div class="rationale" style="margin-bottom:10px">${escHtml(st.evidence)}</div>`;

  if ((st.defenses_active || []).length) {
    html += `<div class="section-label">Active Defenses</div><div class="defenses-list">`;
    st.defenses_active.forEach(x => html += `<span class="defense-chip">${escHtml(x)}</span>`);
    html += `</div>`;
  }

  if ((st.dynamic || []).length) {
    html += `<div class="section-label">Red Dynamic Attempts (${st.dynamic.length})</div>`;
    st.dynamic.forEach(p => {
      const cls = p.bypassed ? 'bypassed' : 'blocked';
      const tag = p.bypassed ? 'BYPASS!' : 'blocked';
      const params = p.params ? JSON.stringify(p.params) : '';
      html += `<div class="payload-item ${cls}">
        <div><span class="result-tag">${tag}</span> <span class="technique">${escHtml(p.technique)}</span></div>
        ${params ? `<div class="params">${escHtml(params)}</div>` : ''}
      </div>`;
    });
  }
  d.innerHTML = html;
  d.classList.add('show');
}

function closeDetail() {
  selectedNodeIdx = null;
  renderNodes();
  renderNodeDetail();
}
window.closeDetail = closeDetail;

function renderRedPanel() {
  const g = GAME[current];
  const red = g.red_move || {};
  const c = document.getElementById('redContent');
  let html = '';
  html += `<div class="section-label">Rationale (round ${g.round})</div>`;
  html += `<div class="rationale">${escHtml(red.rationale || 'No rationale')}</div>`;
  html += `<div class="section-label">Stats</div>`;
  html += `<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:12px;">
    <span class="defense-chip" style="background:var(--gray-bg);border-color:var(--gray);color:var(--text)">Payloads: ${red.num_payloads || 0}</span>
    <span class="defense-chip" style="background:${(red.num_bypasses||0)>0?'var(--red-bg)':'var(--green-bg)'};border-color:${(red.num_bypasses||0)>0?'var(--red)':'var(--green)'};color:${(red.num_bypasses||0)>0?'var(--red)':'var(--green)'}">Bypasses: ${red.num_bypasses || 0}</span>
  </div>`;

  if ((red.payloads || []).length) {
    html += `<div class="section-label">Payloads Tried</div>`;
    const bypSet = new Set(red.bypass_techniques || []);
    red.payloads.forEach(p => {
      const isBypass = bypSet.has(p.technique);
      const cls = isBypass ? 'bypassed' : 'blocked';
      html += `<div class="payload-item ${cls}">
        <div>
          <span class="endpoint-tag">${p.endpoint}</span>
          <span class="result-tag">${isBypass ? 'BYPASS!' : 'blocked'}</span>
        </div>
        <div class="technique" style="margin-top:4px">${escHtml(p.technique)}</div>
      </div>`;
    });
  }

  c.innerHTML = html;
}

function renderBluePanel() {
  const g = GAME[current];
  const blue = g.blue_move || {};
  const c = document.getElementById('blueContent');
  let html = '';
  html += `<div class="section-label">Rationale (round ${g.round})</div>`;
  html += `<div class="rationale">${escHtml(blue.rationale || 'Baseline (no changes)')}</div>`;

  const fp = g.fixed_probes || {};
  html += `<div class="section-label">Fixed Probe Results</div>`;
  html += `<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:12px;">
    <span class="defense-chip" style="background:var(--green-bg);border-color:var(--green);color:var(--green)">Blocked: ${fp.blocked || 0}</span>
    <span class="defense-chip" style="background:${(fp.allowed||0)>0?'var(--red-bg)':'var(--gray-bg)'};border-color:${(fp.allowed||0)>0?'var(--red)':'var(--gray)'};color:${(fp.allowed||0)>0?'var(--red)':'var(--text)'}">Allowed: ${fp.allowed || 0}</span>
    <span class="defense-chip" style="background:var(--blue-bg);border-color:var(--blue);color:var(--blue)">Regression: ${fp.passed_reg || 0}/${(fp.passed_reg||0)+(fp.failed_reg||0)}</span>
  </div>`;

  if ((g.policy_changes || []).length) {
    html += `<div class="section-label">Policy Changes (vs previous round)</div>`;
    g.policy_changes.forEach(ch => {
      html += `<div class="policy-change">${escHtml(ch)}</div>`;
    });
  } else if (g.round > 0) {
    html += `<div class="section-label">Policy Changes</div><div class="rationale" style="color:var(--text2)">No structural changes</div>`;
  }

  c.innerHTML = html;
}

function renderScore() {
  const g = GAME[current];
  const sd = document.getElementById('scoreDisplay');
  const s = g.score || 0;
  sd.textContent = (s >= 0 ? '+' : '') + s;
  sd.className = 'score-display ' + (s >= 0 ? 'positive' : 'negative');
}

function renderTitle() {
  const g = GAME[current];
  const t = document.getElementById('roundTitle');
  let suffix = '';
  if (g.terminal) {
    const streaks = g.streaks || {};
    if (streaks.red_bypass >= 2 || streaks.reg_fail >= 2) suffix = ' <span style="color:var(--red)">&#9876; RED WIN</span>';
    else suffix = ' <span style="color:var(--green)">&#128737; BLUE WIN</span>';
  }
  t.innerHTML = `Round ${g.round}${suffix}`;
}

function render() {
  selectedNodeIdx = null;
  renderRoundDots();
  renderNodes();
  renderNodeDetail();
  renderRedPanel();
  renderBluePanel();
  renderScore();
  renderTitle();
  document.getElementById('prevBtn').disabled = current === 0;
  document.getElementById('nextBtn').disabled = current === GAME.length - 1;
}

document.getElementById('prevBtn').onclick = () => { if (current > 0) { current--; render(); } };
document.getElementById('nextBtn').onclick = () => { if (current < GAME.length-1) { current++; render(); } };

const playBtn = document.getElementById('playBtn');
playBtn.onclick = () => {
  if (playTimer) {
    clearInterval(playTimer); playTimer = null;
    playBtn.innerHTML = '&#9658; Play';
  } else {
    playBtn.innerHTML = '&#10074;&#10074; Pause';
    playTimer = setInterval(() => {
      if (current < GAME.length - 1) {
        current++; render();
      } else {
        clearInterval(playTimer); playTimer = null;
        playBtn.innerHTML = '&#8635; Replay';
      }
    }, 2500);
  }
};

document.addEventListener('keydown', e => {
  if (e.key === 'ArrowLeft' && current > 0) { current--; render(); }
  else if (e.key === 'ArrowRight' && current < GAME.length-1) { current++; render(); }
});

render();
</script>
</body>
</html>"""


def generate_html(run_dir: Path, game_log: list[dict[str, Any]] | dict[str, Any]) -> Path:
    """Generate HTML. game_log can be a list (legacy) or dict with 'rounds' key."""
    if isinstance(game_log, dict):
        rounds = game_log.get("rounds", [])
        gl_outcome = game_log.get("outcome", "draw")
        blue_m = game_log.get("blue_model", "?")
        red_m = game_log.get("red_model", "?")
    else:
        rounds = game_log
        gl_outcome = "draw"
        base = os.environ.get("OPENAI_MODEL", "unknown")
        blue_m = os.environ.get("BLUE_MODEL") or base
        red_m = os.environ.get("RED_MODEL") or base

    if blue_m == red_m:
        model_label = f"model: <b>{blue_m}</b>"
    else:
        model_label = (f"<span style='color:var(--blue)'>Blue=<b>{blue_m}</b></span> · "
                       f"<span style='color:var(--red)'>Red=<b>{red_m}</b></span>")

    outcome_labels = {"blue_win": "🛡️ BLUE WIN", "red_win": "⚔️ RED WIN", "draw": "🤝 DRAW"}
    outcome_label = outcome_labels.get(gl_outcome, gl_outcome.upper())
    outcome_color = {"blue_win": "var(--blue)", "red_win": "var(--red)", "draw": "var(--yellow)"}
    o_color = outcome_color.get(gl_outcome, "var(--text)")

    enriched = _enrich_game(run_dir, rounds)
    html = _TEMPLATE.replace("%%GAME_JSON%%", json.dumps(enriched, ensure_ascii=False))
    html = html.replace("%%ENDPOINTS_JSON%%", json.dumps(ENDPOINTS, ensure_ascii=False))
    html = html.replace("%%NUM_ROUNDS%%", str(len(rounds)))
    html = html.replace("%%MODEL%%", model_label)
    html = html.replace("%%RUN_NAME%%", run_dir.name)
    html = html.replace("%%OUTCOME%%", outcome_label)
    html = html.replace("%%OUTCOME_COLOR%%", o_color)
    out = run_dir / "battle.html"
    out.write_text(html, encoding='utf-8')
    return out
