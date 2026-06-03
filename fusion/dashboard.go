// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// fusion/dashboard.go: embedded HTML dashboard.
//
// Same slate-palette / sister-project style as the per-sniffer
// dashboard, but multi-station-aware. Each tab will grow over a few
// commits; this one ships the skeleton, the Sensors tab (add/remove
// via /api/sensors), and the Config tab (command fan-out via
// /api/fanout/*). Live/Activity/Topology are stubs that render
// placeholder text until their dedicated commits land.

package main

const dashboardHTML = `<!doctype html>
<html><head><meta charset="utf-8">
<title>meshtastic-fusion</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
/* Design tokens. Single source of truth for colors, type, spacing, radii.
 * Every rule below uses var(--token) instead of hardcoded values so the
 * dashboard has one place to retune visual language. Conventions:
 *
 *   Headings:
 *     h2 = section header inside a padded tab (e.g. Sensors "Add sensor")
 *     h3 = pane title in a grid pane (Live / Evidence)
 *     h4 = subsection inside a pane (Evidence detail)
 *
 *   Buttons:
 *     button.primary  -- safe affirmative actions (Add, Apply)
 *     button.danger   -- destructive (Remove)
 *     #tabs button    -- nav-style tab buttons (no chrome)
 *
 *   Status colors are reserved for actual status:
 *     --ok    green   converged / healthy
 *     --warn  amber   degraded / stale
 *     --err   red     not ready / rejected / placement bad
 *     --stale purple  previously converged, now too old
 *
 *   Monospace (--font-mono) is reserved for IDs, timestamps, and numeric
 *   tabular values -- not body text. */
:root {
  /* surfaces */
  --bg: #0f172a;
  --bg-panel: #1e293b;
  --bg-selected: #0c4a6e;
  --border: #334155;
  --border-soft: #1e293b;

  /* text (darkest to brightest) */
  --text-muted: #64748b;
  --text-3: #94a3b8;
  --text-2: #cbd5e1;
  --text: #e2e8f0;
  --text-bright: #f8fafc;

  /* accent (cyan family) */
  --accent: #38bdf8;
  --accent-deep: #0284c7;
  --accent-pale: #bae6fd;
  --accent-bg: #0c4a6e;
  --accent-hover: #075985;

  /* status */
  --ok: #22c55e;
  --ok-bright: #4ade80;
  --warn: #f59e0b;
  --warn-bright: #fbbf24;
  --warn-deep: #fb923c;
  --err: #ef4444;
  --err-bright: #f87171;
  --stale: #a78bfa;

  /* error surface (loud banners) */
  --err-bg: #7f1d1d;
  --err-border: #b91c1c;
  --err-text: #fecaca;
  --err-hover: #991b1b;

  /* type scale (ascending) */
  --text-xs: 10px;
  --text-sm: 11px;
  --text-base: 12px;
  --text-md: 13px;
  --text-body: 14px;  /* root <body> default; rarely set on individual rules */
  --text-lg: 15px;

  /* spacing */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;

  /* radius */
  --radius-sm: 2px;
  --radius: 3px;
  --radius-lg: 5px;

  /* fonts */
  --font-mono: 'SF Mono', Consolas, monospace;
}

*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);
  height:100vh;display:flex;flex-direction:column;font-size:var(--text-body)}
#bar{height:44px;flex-shrink:0;background:var(--bg-panel);display:flex;align-items:center;
  padding:0 var(--space-4);gap:var(--space-5);border-bottom:1px solid var(--border)}
#bar .title{font-weight:600;color:var(--text-bright);letter-spacing:0.5px}
#bar .stat{color:var(--text-3);font-size:var(--text-md)}
#bar .val{color:var(--accent);font-weight:600;font-variant-numeric:tabular-nums;margin-left:6px}
#bar #status{margin-left:auto;color:var(--text-muted);font-size:var(--text-base)}
#tabs{display:flex;align-items:center;background:var(--bg-panel);border-bottom:1px solid var(--border);
  flex-shrink:0}
#tabs button{background:none;color:var(--text-muted);border:none;padding:var(--space-2) var(--space-4);
  cursor:pointer;font:inherit;text-transform:uppercase;font-size:var(--text-base);letter-spacing:1px;
  font-weight:600;border-bottom:2px solid transparent}
#tabs button:hover{color:var(--text-3)}
#tabs button.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab{flex:1;display:none;overflow:auto;padding:var(--space-4)}
.tab.active{display:block}
#live.tab{padding:0}
#live.tab.active{display:flex}
#live-grid{display:grid;grid-template-columns:2fr 1fr;grid-template-rows:1fr 1fr 1fr;
  height:100%;width:100%;gap:1px;background:var(--border)}
#live-map-pane{grid-row:span 3;padding:0}
#live-map{width:100%;height:100%}
.leaflet-container{background:var(--bg)}
.live-pane{padding:var(--space-2) 10px;overflow:auto;background:var(--bg)}
.live-pane h3{font-size:var(--text-sm);color:var(--accent);text-transform:uppercase;letter-spacing:1px;
  margin-bottom:6px;border-bottom:1px solid var(--border);padding-bottom:var(--space-1)}
h2{font-size:var(--text-base);color:var(--accent);text-transform:uppercase;letter-spacing:1px;font-weight:600;
  border-bottom:1px solid var(--border);padding-bottom:5px;margin-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:var(--text-base);font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:5px var(--space-2);border-bottom:1px solid var(--border-soft)}
th{color:var(--text-muted);font-weight:600;font-size:var(--text-sm);text-transform:uppercase;letter-spacing:0.5px}
tr:hover td{background:var(--bg-panel)}
.muted{color:var(--text-muted)}
.status-ok{color:var(--ok-bright)}
.status-err{color:var(--err-bright)}
.status-stale{color:var(--warn-bright)}
.row{margin-bottom:14px;display:flex;gap:var(--space-2);flex-wrap:wrap;align-items:center}
input[type=text],textarea{background:var(--bg);color:var(--text);border:1px solid var(--border);
  border-radius:var(--radius);padding:6px 10px;font:inherit;font-size:var(--text-md);flex:1;min-width:200px}
input[type=text]:focus,textarea:focus{outline:none;border-color:var(--accent)}
textarea{font-family:var(--font-mono);min-height:80px}
button.primary{background:var(--accent-bg);color:var(--accent-pale);border:1px solid var(--accent-deep);
  border-radius:var(--radius);padding:6px 14px;cursor:pointer;font-size:var(--text-md);font-weight:500}
button.primary:hover{background:var(--accent-hover)}
button.danger{background:var(--err-bg);color:var(--err-text);border:1px solid var(--err-border);
  border-radius:var(--radius);padding:3px 9px;cursor:pointer;font-size:var(--text-sm)}
button.danger:hover{background:var(--err-hover)}
.hint{color:var(--text-muted);font-size:var(--text-sm);margin-top:var(--space-1);display:block}
.placeholder{color:var(--text-muted);font-style:italic;padding:30px 0;text-align:center}
#activity-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px}
.preset-card{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius-lg);
  padding:var(--space-3) 14px;display:flex;flex-direction:column;gap:6px}
.preset-card.hot{border-color:var(--accent)}
.preset-card.dead{opacity:0.55}
.preset-card .top{display:flex;align-items:baseline;gap:var(--space-2)}
.preset-card .nm{font-size:var(--text-lg);font-weight:600;color:var(--text-bright);flex:1}
.preset-card .meta{color:var(--text-3);font-size:var(--text-sm)}
.preset-card .row2{display:flex;gap:14px;font-size:var(--text-base);margin-top:2px}
.preset-card .lbl{color:var(--text-muted);font-size:var(--text-xs);text-transform:uppercase;
  letter-spacing:0.5px;display:block}
.preset-card .v{color:var(--accent);font-weight:600;font-size:var(--text-lg);font-variant-numeric:tabular-nums}
.preset-card .station-list{display:flex;flex-direction:column;gap:3px;margin-top:var(--space-1)}
.preset-card .station-row{display:flex;justify-content:space-between;font-size:var(--text-base);
  background:var(--bg);border-radius:var(--radius);padding:3px 7px;color:var(--text-2)}
.preset-card .station-row .dot{display:inline-block;width:var(--space-2);height:var(--space-2);
  border-radius:50%;margin-right:6px;vertical-align:middle}
#topology.tab.active{display:flex;flex-direction:column;position:relative;padding:0}
#topo-canvas{flex:1;display:block;width:100%;background:var(--bg);cursor:default}
#topo-canvas.hovering{cursor:pointer}
#topo-empty{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);
  pointer-events:none;z-index:5;max-width:480px;text-align:center}
#topo-legend{position:absolute;left:10px;top:10px;color:var(--text-muted);font-size:var(--text-sm);
  background:rgba(15,23,42,0.85);padding:7px 11px;border-radius:var(--radius);
  border:1px solid var(--border);z-index:4;pointer-events:none}
#topo-legend .l-station,#topo-legend .l-node{display:inline-block;width:var(--space-2);height:var(--space-2);
  border-radius:50%;vertical-align:middle;margin-right:3px}
#topo-legend .l-station{background:var(--warn-bright);border:1px solid var(--warn)}
#topo-legend .l-node{background:var(--accent)}
.fanout-result{font-family:var(--font-mono);font-size:var(--text-sm);color:var(--text-3);
  background:var(--bg-panel);border-radius:var(--radius);padding:var(--space-2) 10px;
  margin-top:6px;white-space:pre-wrap;max-height:200px;overflow:auto}

/* Evidence tab. Mirrors the Live tab's "map left, panes stacked right"
 * grid so the operator's eye lands on geography first and the timeline
 * + detail act as side panes. Top header holds the health strip and
 * persistent warnings full-width above the work area. */
#evidence.tab{padding:0;display:none;flex-direction:column}
#evidence.tab.active{display:flex}
#ev-header{flex:none;padding:10px 14px 6px;border-bottom:1px solid var(--border)}
#ev-health-strip{display:flex;gap:10px;flex-wrap:wrap}
.ev-card{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:6px 10px;min-width:108px}
.ev-card .ev-label{color:var(--text-muted);text-transform:uppercase;font-size:var(--text-xs);
  letter-spacing:0.06em;font-weight:600;margin-bottom:2px}
.ev-card .ev-value{font-size:var(--text-lg);font-variant-numeric:tabular-nums;font-weight:600;
  color:var(--text);line-height:1.2}
.ev-card .ev-sub{color:var(--text-3);font-size:var(--text-xs);margin-top:2px}
.ev-state-ready{color:var(--ok)}
.ev-state-degraded{color:var(--warn)}
.ev-state-not_ready,.ev-state-no_anchor{color:var(--err)}
.ev-state-stale{color:var(--stale)}
#ev-warnings{margin-top:6px}
#ev-persisted-banner{color:var(--text-3);font-size:var(--text-base);margin-top:6px}
.ev-warn{background:var(--err-bg);color:var(--err-text);border:1px solid var(--err-border);
  border-radius:var(--radius);padding:6px 10px;margin-top:var(--space-1);font-size:var(--text-sm);
  line-height:1.4}
.ev-warn b{color:#fff}
#evidence-grid{flex:1;display:grid;grid-template-columns:2fr 1fr;grid-template-rows:1fr 1fr;
  gap:1px;background:var(--border);min-height:0}
#ev-map-pane{grid-row:span 2;position:relative;background:var(--bg);min-width:0;min-height:0}
#ev-map{position:absolute;inset:0}
#ev-map-empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  color:var(--text-muted);font-size:var(--text-base);pointer-events:none;background:var(--bg);z-index:400;
  text-align:center;padding:20px}
.ev-pane{background:var(--bg);display:flex;flex-direction:column;overflow:hidden;min-width:0;min-height:0}
.ev-pane > h3{font-size:var(--text-sm);color:var(--accent);text-transform:uppercase;letter-spacing:1px;
  margin:0;padding:var(--space-2) var(--space-3) var(--space-1);border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:var(--space-2);flex:none;font-weight:600}
.ev-pane-controls{display:flex;align-items:center;gap:var(--space-2)}
.ev-pane-controls .zoom-buttons{display:inline-flex;background:var(--bg-panel);
  border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.ev-pane-controls .zoom-buttons button{background:transparent;color:var(--text-muted);border:none;
  padding:3px var(--space-2);font-size:var(--text-xs);cursor:pointer;border-right:1px solid var(--border);
  text-transform:none;letter-spacing:0;font-weight:400}
.ev-pane-controls .zoom-buttons button:last-child{border-right:none}
.ev-pane-controls .zoom-buttons button:hover{color:var(--text-3)}
.ev-pane-controls .zoom-buttons button.active{background:var(--bg);color:var(--accent)}
.ev-pane-controls .ev-readout{color:var(--text-muted);font-size:var(--text-xs);
  font-variant-numeric:tabular-nums;text-transform:none;letter-spacing:0;font-weight:400}
.ev-pane-controls .ev-refresh{background:transparent;border:1px solid var(--border);color:var(--text-3);
  padding:3px var(--space-2);border-radius:var(--radius);cursor:pointer;font-size:var(--text-xs);
  text-transform:none;letter-spacing:0;font-weight:400}
.ev-pane-controls .ev-refresh:hover{color:var(--text)}
#ev-timeline{flex:1;overflow-y:auto;padding:2px 0;min-height:0}
#ev-timeline .ev-empty{color:var(--text-muted);padding:20px 14px;text-align:center;
  font-size:var(--text-sm);line-height:1.5}
.ev-row{display:grid;grid-template-columns:72px auto auto 80px 1fr auto;gap:var(--space-2);
  padding:6px var(--space-3);border-bottom:1px solid var(--border-soft);cursor:pointer;
  font-size:var(--text-sm);align-items:center;line-height:1.3}
.ev-row .ev-action{background:transparent;border:1px solid var(--border);color:var(--text-3);
  padding:2px 7px;border-radius:var(--radius);font-size:var(--text-xs);cursor:pointer;
  font-family:inherit;text-transform:none;letter-spacing:0;font-weight:400;white-space:nowrap}
.ev-row .ev-action:hover{color:var(--accent);border-color:var(--accent)}
.ev-row .ev-action[disabled]{opacity:0.5;cursor:wait}
.ev-row .ev-action.replayed{color:var(--ok);border-color:var(--ok)}
.ev-row .ev-replay-tag{color:var(--ok);font-size:var(--text-xs);font-weight:600;
  text-transform:uppercase;letter-spacing:0.05em;margin-left:6px}
.ev-row:hover{background:var(--bg-panel)}
.ev-row.selected{background:var(--bg-selected);border-left:3px solid var(--accent);padding-left:9px}
.ev-row .ev-time{color:var(--text-3);font-variant-numeric:tabular-nums;font-size:var(--text-xs)}
.ev-row .ev-kind{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:0.05em;
  font-weight:600;padding:2px 5px;border-radius:var(--radius-sm);text-align:center;white-space:nowrap}
.ev-row .ev-kind-anchor{background:#1d4ed8;color:#dbeafe}
.ev-row .ev-kind-target{background:var(--bg-panel);color:var(--text-3);border:1px solid var(--border)}
.ev-row .ev-kind-solved{background:#166534;color:#dcfce7}
.ev-row .ev-kind-degraded{background:#854d0e;color:#fef3c7}
.ev-row .ev-from{color:var(--text);font-family:var(--font-mono);font-size:var(--text-xs);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ev-row .ev-trust{font-size:var(--text-xs);text-align:left;text-transform:uppercase;letter-spacing:0.04em;
  font-weight:600;white-space:nowrap}
.ev-row .ev-summary{color:var(--text-3);font-size:var(--text-xs);overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.ev-trust-sample{color:var(--ok)}
.ev-trust-sync{color:var(--accent)}
.ev-trust-software_lock{color:var(--warn)}
.ev-trust-frame{color:var(--warn-deep)}
.ev-trust-degraded{color:var(--err)}
#ev-detail{flex:1;overflow-y:auto;padding:10px var(--space-3);font-size:var(--text-sm);color:var(--text-2)}
#ev-detail .ev-empty{color:var(--text-muted);text-align:center;padding-top:30px;
  font-size:var(--text-sm);line-height:1.5}
#ev-detail h4{margin:10px 0 var(--space-1) 0;font-size:var(--text-xs);text-transform:uppercase;
  letter-spacing:0.06em;color:var(--text-muted);font-weight:600}
#ev-detail h4:first-child{margin-top:0}
#ev-detail .kv{display:flex;justify-content:space-between;padding:2px 0;
  border-bottom:1px dotted var(--border-soft);gap:var(--space-2)}
#ev-detail .kv .k{color:var(--text-muted);font-size:var(--text-xs);white-space:nowrap}
#ev-detail .kv .v{color:var(--text);font-size:var(--text-sm);font-variant-numeric:tabular-nums;
  font-family:var(--font-mono);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#ev-detail table.ev-stations{width:100%;border-collapse:collapse;margin-top:var(--space-1);
  font-size:var(--text-xs)}
#ev-detail table.ev-stations th{color:var(--text-muted);text-transform:uppercase;
  font-size:var(--text-xs);letter-spacing:0.05em;text-align:left;padding:3px 5px;
  border-bottom:1px solid var(--border)}
#ev-detail table.ev-stations td{color:var(--text-2);padding:3px 5px;
  border-bottom:1px dotted var(--border-soft);font-family:var(--font-mono);font-size:var(--text-xs)}
</style></head><body>
<div id="bar">
  <span class="title">meshtastic-fusion</span>
  <span class="stat">Sensors <span id="st-sensors" class="val">0</span></span>
  <span class="stat">Events <span id="st-events" class="val">0</span></span>
  <span class="stat">Transmissions <span id="st-tx" class="val">0</span></span>
  <span id="status">connecting...</span>
</div>
<div id="tabs">
  <button id="tab-live" class="active" onclick="showTab('live')">Live</button>
  <button id="tab-activity" onclick="showTab('activity')">Activity</button>
  <button id="tab-evidence" onclick="showTab('evidence')">Evidence</button>
  <button id="tab-topology" onclick="showTab('topology')">Topology</button>
  <button id="tab-sensors" onclick="showTab('sensors')">Sensors</button>
  <button id="tab-config" onclick="showTab('config')">Config</button>
</div>

<div id="live" class="tab active">
  <div id="live-grid">
    <div id="live-map-pane"><div id="live-map"></div></div>
    <div class="live-pane">
      <h3>Stations <span class="muted" id="station-count" style="font-weight:400;text-transform:none;letter-spacing:0">(0)</span></h3>
      <table id="stations-tbl"><thead><tr><th>Name</th><th>Frames</th><th>Last seen</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="live-pane">
      <h3>Nodes <span class="muted" id="node-count" style="font-weight:400;text-transform:none;letter-spacing:0">(0)</span></h3>
      <table id="nodes-tbl"><thead><tr><th>ID</th><th>Name</th><th>Heard by</th><th>Last</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="live-pane">
      <h3>Channels <span class="muted" id="channel-count" style="font-weight:400;text-transform:none;letter-spacing:0">(0)</span></h3>
      <table id="channels-tbl"><thead><tr><th>Hash</th><th>Name</th><th>Preset</th><th>Frames</th><th>Decrypt</th></tr></thead><tbody></tbody></table>
    </div>
  </div>
</div>

<div id="activity" class="tab">
  <div id="activity-grid"></div>
</div>

<div id="evidence" class="tab">
  <div id="ev-header">
    <div id="ev-health-strip">
      <div class="ev-card">
        <div class="ev-label">TDOA</div>
        <div class="ev-value" id="ev-tdoa-state">--</div>
        <div class="ev-sub" id="ev-tdoa-sub">checking</div>
      </div>
      <div class="ev-card">
        <div class="ev-label">Sensors</div>
        <div class="ev-value" id="ev-sensors-count">0</div>
        <div class="ev-sub" id="ev-sensors-sub">alive</div>
      </div>
      <div class="ev-card">
        <div class="ev-label">Anchors</div>
        <div class="ev-value" id="ev-anchors-count">0</div>
        <div class="ev-sub" id="ev-anchors-sub">declared</div>
      </div>
      <div class="ev-card">
        <div class="ev-label">Clock Pairs</div>
        <div class="ev-value" id="ev-pairs-count">0</div>
        <div class="ev-sub" id="ev-pairs-sub">converged</div>
      </div>
      <div class="ev-card">
        <div class="ev-label">DB Rows</div>
        <div class="ev-value" id="ev-db-clusters">0</div>
        <div class="ev-sub" id="ev-db-sub">clusters / 0 fixes</div>
      </div>
      <div class="ev-card">
        <div class="ev-label">Schema</div>
        <div class="ev-value" id="ev-schema">--</div>
        <div class="ev-sub" id="ev-schema-sub">replay disabled</div>
      </div>
    </div>
    <div id="ev-persisted-banner" style="display:none"></div>
    <div id="ev-warnings"></div>
  </div>
  <div id="evidence-grid">
    <div id="ev-map-pane">
      <div id="ev-map"></div>
      <div id="ev-map-empty">No solved fixes in this window.<br>Solved emitter positions plot here as TDOA solves arrive.</div>
    </div>
    <div class="ev-pane" id="ev-timeline-pane">
      <h3>
        <span>Timeline</span>
        <span class="ev-pane-controls">
          <div class="zoom-buttons" id="ev-zoom">
            <button data-zoom="15m">15m</button>
            <button data-zoom="1h" class="active">1h</button>
            <button data-zoom="6h">6h</button>
            <button data-zoom="24h">24h</button>
          </div>
          <span class="ev-readout" id="ev-range-readout">last 1h</span>
          <button class="ev-refresh" onclick="evidenceRefresh()">↻</button>
        </span>
      </h3>
      <div id="ev-timeline"><div class="ev-empty">Loading…</div></div>
    </div>
    <div class="ev-pane" id="ev-detail-pane">
      <h3>Detail</h3>
      <div id="ev-detail"><div class="ev-empty">Click a timeline row to see per-event detail: station participation, clock-sync snapshot, solve summary.</div></div>
    </div>
  </div>
</div>

<div id="topology" class="tab">
  <div id="topo-empty" class="placeholder">Waiting for the first frame... nodes appear as soon as any station hears them.</div>
  <div id="topo-legend">
    <span class=l-station></span> station &nbsp;|&nbsp;
    <span class=l-node></span> node, size = frames seen &nbsp;|&nbsp;
    edge color = SNR &nbsp;|&nbsp; dashed = pseudo "heard by station" edge
  </div>
  <canvas id="topo-canvas"></canvas>
</div>

<div id="sensors" class="tab">
  <h2>Add sensor</h2>
  <div class="row">
    <input id="s-name" type="text" placeholder="name (e.g. basement-rx)">
    <input id="s-zmq" type="text" placeholder="zmq endpoint (e.g. tcp://10.0.0.5:7008)">
  </div>
  <div class="row">
    <input id="s-api" type="text" placeholder="api endpoint (e.g. http://10.0.0.5:8888) -- optional but required for C2 fan-out">
    <input id="s-token" type="text" placeholder="api bearer token (optional, --api-token on the sensor)">
  </div>
  <div class="row">
    <button class="primary" onclick="addSensor()">Add</button>
    <span id="add-status" class="hint"></span>
  </div>
  <h2>Registered sensors</h2>
  <table id="sensors-tbl">
    <thead><tr><th>Name</th><th>Health</th><th>Frames</th><th>Decrypt</th><th>Msps</th><th>Last event</th><th>C2</th><th>ZMQ</th><th></th></tr></thead>
    <tbody></tbody>
  </table>
</div>

<div id="config" class="tab">
  <h2>Add key (fan-out to all sensors)</h2>
  <div class="row">
    <textarea id="key-input" placeholder="ChannelName=SPEC, one per line. SPEC is default | simpleN | hex:HHHH... | base64:..."></textarea>
  </div>
  <div class="row">
    <button class="primary" onclick="fanout('keys','key-input')">Add to all sensors</button>
    <span class="hint">Same wire format as a per-sensor /api/keys add. Each sensor reports back independently.</span>
  </div>
  <div id="key-result" class="fanout-result" style="display:none"></div>

  <h2>Channel-share URL (fan-out)</h2>
  <div class="row">
    <input id="share-input" type="text" placeholder="https://meshtastic.org/e/#...">
    <button class="primary" onclick="fanout('share-url','share-input')">Add channel</button>
  </div>
  <div id="share-result" class="fanout-result" style="display:none"></div>

  <h2>Add extra frequency (fan-out)</h2>
  <div class="row">
    <input id="freq-input" type="text" placeholder="HZ:bw=BW:sf=SF:cr=CR (e.g. 915183000:bw=125000:sf=12:cr=8)">
    <button class="primary" onclick="fanout('extra-freq','freq-input')">Add slot</button>
  </div>
  <div id="freq-result" class="fanout-result" style="display:none"></div>

  <h2>CoT multicast (fan-out)</h2>
  <div class="row">
    <input id="cot-input" type="text" placeholder="239.2.3.1:6969 (empty = disable on every sensor)">
    <button class="primary" onclick="fanout('cot-multicast','cot-input')">Apply</button>
  </div>
  <div id="cot-result" class="fanout-result" style="display:none"></div>
</div>

<script>
// Auth: pick up the bearer token from a one-shot ?token=... query
// param on first load, store it in sessionStorage, and use it on every
// /api/* fetch and the /events EventSource. Strip it from the URL bar
// once captured so it doesn't get bookmarked or screenshotted.
(function(){
  const url = new URL(window.location.href);
  const t = url.searchParams.get('token');
  if (t) {
    sessionStorage.setItem('fusionToken', t);
    url.searchParams.delete('token');
    history.replaceState({}, '', url.toString());
  }
})();
const FUSION_TOKEN = sessionStorage.getItem('fusionToken') || '';
function authHeaders(extra){
  const h = Object.assign({}, extra||{});
  if (FUSION_TOKEN) h['Authorization'] = 'Bearer ' + FUSION_TOKEN;
  return h;
}
function authUrl(path){
  if (!FUSION_TOKEN) return path;
  return path + (path.indexOf('?') >= 0 ? '&' : '?') + 'token=' + encodeURIComponent(FUSION_TOKEN);
}
function showTab(name){
  for(const t of ['live','activity','evidence','topology','sensors','config']){
    document.getElementById(t).classList.toggle('active',t===name);
    document.getElementById('tab-'+t).classList.toggle('active',t===name);
  }
  if(name==='sensors') refreshSensors();
  if(name==='evidence') {
    evidenceMapInit();
    setTimeout(()=>{ if (evidenceMap) evidenceMap.invalidateSize(); }, 60);
    evidenceRefresh();
  }
  if(name==='topology') topoStart(); else if (typeof topoStop==='function') topoStop();
  if(name==='live') setTimeout(()=>map.invalidateSize(),60);
}
function setStat(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}
let nEvents=0,nTx=0;

// Leaflet map.
const map = L.map('live-map').setView([39.5, -98.0], 4);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  {maxZoom:19, attribution:'(c) OSM (c) CARTO'}).addTo(map);

// Per-station color palette. Cyan for the first station, amber for the
// second, etc. -- distinct enough to read at a glance on a multi-station
// deployment.
const STATION_COLORS = ['#38bdf8','#fbbf24','#a78bfa','#f472b6','#4ade80','#fb923c','#60a5fa','#f87171'];
const stationIdx = {};   // name -> index into STATION_COLORS
function stationColor(name){
  if (!(name in stationIdx)) stationIdx[name] = Object.keys(stationIdx).length;
  return STATION_COLORS[stationIdx[name] % STATION_COLORS.length];
}

// stations[name] = { lat, lon, marker, frames, lastSeen }
const stations = {};
// nodes[id] = { name, lat, lon, marker, lastTs, heardBy: Set<station> }
const nodes = {};
// channels[hash] = { name, preset, frames, decrypted, lastTs }
// Hash key is the 1-byte channel byte from the frame header (0..255).
// 'name' starts unknown and latches to the first value we see from a
// successful decrypt -- so once any frame on this hash decrypts under
// any sensor's keyset, the channel becomes labeled across the dash.
const channels = {};
let mapAutoCentered = false;

function noteStation(name, lat, lon){
  let s = stations[name];
  if (!s) { s = stations[name] = { frames: 0, decrypted: 0, msps: 0, framesTotal: 0, decryptedTotal: 0, lastEventAt: 0 }; }
  s.frames++;
  s.lastSeen = Date.now()/1000;
  s.lastEventAt = s.lastSeen;
  if (typeof lat === 'number' && typeof lon === 'number') {
    s.lat = lat; s.lon = lon;
    const color = stationColor(name);
    if (!s.marker) {
      s.marker = L.circleMarker([lat, lon], {
        radius: 9, color: color, weight: 3, fillColor: color, fillOpacity: 0.45
      }).addTo(map).bindPopup('<b>'+name+'</b><br>RX station');
      if (!mapAutoCentered) { map.setView([lat, lon], 11); mapAutoCentered = true; }
    } else {
      s.marker.setLatLng([lat, lon]);
    }
  }
}

function noteChannel(p){
  if (p.channel_hash === undefined) return;
  let c = channels[p.channel_hash];
  if (!c) { c = channels[p.channel_hash] = { frames: 0, decrypted: 0, slots: new Set() }; }
  if (p.slot_id !== undefined && p.slot_id !== null && p.slot_id >= 0) c.slots.add(p.slot_id);
  c.frames++;
  c.lastTs = p.ts || Date.now()/1000;
  if (p.preset && !c.preset) c.preset = p.preset;
  if (p.channel_name) c.name = p.channel_name;
  if (p.decrypted !== false && p.port_name) c.decrypted++;
}
function noteNode(p){
  if (!p.from) return;
  let n = nodes[p.from];
  if (!n) { n = nodes[p.from] = { heardBy: new Set() }; }
  n.lastTs = p.ts || Date.now()/1000;
  if (p.station) n.heardBy.add(p.station);
  // long_name / short_name come from NODEINFO_APP decryption; if so, latch.
  if (p.long_name) n.name = p.long_name + (p.short_name ? ' ['+p.short_name+']' : '');
  // Position: from POSITION_APP decoded fields.
  if (p.lat !== undefined && p.lon !== undefined) {
    n.lat = p.lat; n.lon = p.lon;
    if (!n.marker) {
      n.marker = L.marker([p.lat, p.lon])
        .addTo(map)
        .bindPopup(()=>'<b>'+(n.name||p.from)+'</b><br>'+p.from+'<br>heard by: '+
          [...n.heardBy].join(', '));
      if (!mapAutoCentered) { map.setView([p.lat, p.lon], 11); mapAutoCentered = true; }
    } else {
      n.marker.setLatLng([p.lat, p.lon]);
    }
  }
}

// Multilateration: emitter positions estimated by the fusion mlat
// solver from >=3 timed observations across stations. Each emitter
// gets a magenta diamond marker plus a confidence circle whose radius
// equals the solver's reported uncertainty in meters. Updated in
// place each time a fresh GEOLOCATED event lands for the same node.
const geolocated = {}; // from -> { marker, circle, lastUpdate }
function noteGeolocated(p){
  const id = p.from;
  let g = geolocated[id];
  if (!g) {
    const marker = L.circleMarker([p.lat, p.lon], {
      radius: 6, color: '#e879f9', weight: 2, fillColor: '#a21caf', fillOpacity: 0.85,
    }).addTo(map).bindPopup(()=>{
      const u = p.uncertainty_m !== undefined ? p.uncertainty_m.toFixed(0)+' m' : '?';
      return '<b>mlat estimate</b><br>'+p.from+'<br>uncertainty: '+u+
             '<br>stations: '+(p.station_count||'?');
    });
    const circle = L.circle([p.lat, p.lon], {
      radius: Math.max(50, p.uncertainty_m || 100),
      color: '#a21caf', weight: 1, fillColor: '#a21caf', fillOpacity: 0.08,
    }).addTo(map);
    g = geolocated[id] = { marker, circle };
  } else {
    g.marker.setLatLng([p.lat, p.lon]);
    g.circle.setLatLng([p.lat, p.lon]);
    g.circle.setRadius(Math.max(50, p.uncertainty_m || 100));
  }
  g.lastUpdate = Date.now()/1000;
  if (!mapAutoCentered) { map.setView([p.lat, p.lon], 13); mapAutoCentered = true; }
}

let liveRafQueued = false;
function refreshLive(){
  if (liveRafQueued) return;
  liveRafQueued = true;
  requestAnimationFrame(()=>{ liveRafQueued = false; renderLiveTables(); });
}
function fmtAgo(ts){
  if (!ts) return '--';
  // ts is fractional epoch seconds; floor the delta to avoid rendering
  // float garbage like '14.936086893081665s'.
  const dt = Math.max(0, Math.floor(Date.now()/1000 - ts));
  if (dt < 60) return dt+'s';
  if (dt < 3600) return Math.floor(dt/60)+'m';
  return Math.floor(dt/3600)+'h';
}
function renderLiveTables(){
  const stb = document.querySelector('#stations-tbl tbody');
  const stationNames = Object.keys(stations).sort((a,b)=>stations[b].lastSeen-stations[a].lastSeen);
  setStat('station-count','('+stationNames.length+')');
  stb.innerHTML = '';
  for (const name of stationNames) {
    const s = stations[name];
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+
      stationColor(name)+';margin-right:6px;vertical-align:middle"></span>'+escHtml(name)+'</td>'+
      '<td>'+s.frames+'</td><td class=muted>'+fmtAgo(s.lastSeen)+'</td>';
    stb.appendChild(tr);
  }
  const ntb = document.querySelector('#nodes-tbl tbody');
  const nodeIds = Object.keys(nodes).sort((a,b)=>(nodes[b].lastTs||0)-(nodes[a].lastTs||0)).slice(0,200);
  setStat('node-count','('+Object.keys(nodes).length+')');
  ntb.innerHTML = '';
  for (const id of nodeIds) {
    const n = nodes[id];
    const heard = [...n.heardBy].map(name=>'<span class=muted>'+escHtml(name)+'</span>').join(', ') || '<span class=muted>--</span>';
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>'+escHtml(id)+'</td><td>'+escHtml(n.name||'')+'</td>'+
      '<td>'+heard+'</td><td class=muted>'+fmtAgo(n.lastTs)+'</td>';
    ntb.appendChild(tr);
  }
}
setInterval(refreshLive, 1000);

// Activity: per-preset cards, aggregated across all stations.
// Each card shows global counts (total/decrypt%/fpm/channels) plus a
// per-station row with that station's contribution to this preset.
const STANDARD_PRESETS = ['ShortTurbo','ShortFast','ShortSlow','MediumFast','MediumSlow','LongFast','LongMod','LongSlow','LongTurbo'];
// activity[preset] = { frames, decrypted, ts, channels: Set<hash>, slots: Set<slot_id>, perStation: {name:{frames,decrypted}}, sparkBuckets[60], bucketStart }
const activity = {};
function ensurePresetCard(p){
  if (activity[p]) return activity[p];
  return activity[p] = {
    frames: 0, decrypted: 0, ts: 0, channels: new Set(), slots: new Set(), perStation: {},
    sparkBuckets: new Array(60).fill(0), bucketStart: Math.floor(Date.now()/1000),
  };
}
for (const p of STANDARD_PRESETS) ensurePresetCard(p);

function noteActivityFrame(p){
  const preset = p.preset || '?';
  const a = ensurePresetCard(preset);
  const now = Math.floor(Date.now()/1000);
  const drift = now - a.bucketStart;
  if (drift > 0) {
    if (drift >= 60) a.sparkBuckets.fill(0);
    else { a.sparkBuckets.splice(0, drift); for (let i=0;i<drift;++i) a.sparkBuckets.push(0); }
    a.bucketStart = now;
  }
  a.frames++;
  a.sparkBuckets[59]++;
  a.ts = now;
  const wasDecrypted = p.decrypted !== false && p.port_name;
  if (wasDecrypted) a.decrypted++;
  if (p.channel_hash !== undefined) a.channels.add(p.channel_hash);
  if (p.slot_id !== undefined && p.slot_id !== null && p.slot_id >= 0) {
    if (!a.slots) a.slots = new Set();
    a.slots.add(p.slot_id);
  }
  const station = p.station || '(unnamed)';
  let s = a.perStation[station];
  if (!s) s = a.perStation[station] = { frames: 0, decrypted: 0 };
  s.frames++;
  if (wasDecrypted) s.decrypted++;
}

let activityRafQueued = false;
function refreshActivity(){
  if (activityRafQueued) return;
  activityRafQueued = true;
  requestAnimationFrame(()=>{ activityRafQueued = false; renderActivity(); });
}
function renderActivity(){
  const grid = document.getElementById('activity-grid');
  const presets = Object.keys(activity);
  presets.sort((x,y)=>{
    const ax=activity[x], ay=activity[y];
    const fx=ax.sparkBuckets.reduce((s,v)=>s+v,0);
    const fy=ay.sparkBuckets.reduce((s,v)=>s+v,0);
    if (fx!==fy) return fy-fx;
    return ay.ts - ax.ts;
  });
  const seen = {};
  for (const p of presets) {
    const a = activity[p];
    const id = 'preset-card-'+p;
    let card = document.getElementById(id);
    if (!card) {
      card = document.createElement('div'); card.id=id; card.className='preset-card';
      card.innerHTML = '<div class=top><span class=nm></span><span class=meta></span></div>'+
        '<div class=row2>'+
          '<div><span class=lbl>fpm</span><span class="v fpm">0</span></div>'+
          '<div><span class=lbl>Frames</span><span class="v frames">0</span></div>'+
          '<div><span class=lbl>Channels</span><span class="v chans">0</span></div>'+
          '<div><span class=lbl>Slots</span><span class="v slots">0</span></div>'+
        '</div>'+
        '<div class=station-list></div>';
      grid.appendChild(card);
    }
    seen[id] = true;
    const fpm = a.sparkBuckets.reduce((x,v)=>x+v,0);
    const decPct = a.frames>0 ? Math.round(100*a.decrypted/a.frames) : 0;
    card.querySelector('.nm').textContent = p;
    card.querySelector('.meta').textContent = a.frames>0 ? decPct+'% decrypted' : 'idle';
    card.querySelector('.fpm').textContent = fpm;
    card.querySelector('.frames').textContent = a.frames;
    card.querySelector('.chans').textContent = a.channels.size;
    card.querySelector('.slots').textContent = a.slots ? a.slots.size : 0;
    card.classList.toggle('hot', fpm>0);
    card.classList.toggle('dead', a.ts===0 || (Math.floor(Date.now()/1000)-a.ts)>120);
    const sl = card.querySelector('.station-list');
    const names = Object.keys(a.perStation).sort((x,y)=>a.perStation[y].frames - a.perStation[x].frames);
    if (names.length===0) {
      sl.innerHTML = '';
    } else {
      sl.innerHTML = names.map(name => {
        const ps = a.perStation[name];
        const dot = '<span class=dot style="background:'+stationColor(name)+'"></span>';
        return '<div class=station-row><span>'+dot+escHtml(name)+'</span>'+
          '<span class=muted>'+ps.frames+' frames'+(ps.decrypted>0?', '+ps.decrypted+' decrypted':'')+'</span></div>';
      }).join('');
    }
  }
  for (const c of Array.from(grid.children)) if (!seen[c.id]) c.remove();
}
setInterval(refreshActivity, 1000);

// Topology: force-directed graph. Same pattern as the per-sniffer
// dashboard's Topology, but each station is its own pinned node and
// each transmitting node has a faint dashed pseudo-edge to every
// station that has heard it (multi-station observation).
const topoCanvas = document.getElementById('topo-canvas');
const topoCtx = topoCanvas.getContext('2d');
const topoEmpty = document.getElementById('topo-empty');
const topoNodes = {}; // id -> {x,y,vx,vy,kind:'station'|'node',pinned}
const topoEdges = {}; // 'a|b' -> {a,b,snr,kind:'heard'|'convo'}
let topoActive = false, topoHover = null, topoLastTick = 0, topoRaf = 0;
const TOPO_NODE_MAX = 200;
function topoSize(){ topoCanvas.width = topoCanvas.clientWidth; topoCanvas.height = topoCanvas.clientHeight; }
function topoEnsureNode(id, kind){
  if (topoNodes[id]) return topoNodes[id];
  const rect = topoCanvas.getBoundingClientRect();
  const W = rect.width || 800, H = rect.height || 600;
  if (kind === 'station') {
    // Stations get pinned around the canvas in a soft ring so multiple
    // sensors don't all stack at center.
    const i = Object.values(topoNodes).filter(n=>n.kind==='station').length;
    const total = 8;
    const a = (i/total) * Math.PI*2;
    const r = Math.min(W,H) * 0.32;
    topoNodes[id] = {id, kind:'station', pinned:true,
      x: W/2 + Math.cos(a)*r, y: H/2 + Math.sin(a)*r, vx:0, vy:0};
  } else {
    const a = Math.random()*Math.PI*2, r = 50 + Math.random()*100;
    topoNodes[id] = {id, kind:'node', x: W/2 + Math.cos(a)*r, y: H/2 + Math.sin(a)*r, vx:0, vy:0};
  }
  if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';
  return topoNodes[id];
}
function topoNoteHeardBy(stationName, nodeId, snr){
  if (!stationName || !nodeId || nodeId === stationName) return;
  topoEnsureNode('station:'+stationName, 'station');
  topoEnsureNode(nodeId, 'node');
  const a = 'station:'+stationName, b = nodeId;
  const lo = a < b ? a : b, hi = a < b ? b : a;
  const k = lo+'|'+hi;
  let e = topoEdges[k];
  if (!e) e = topoEdges[k] = {a:lo, b:hi, snr:snr, kind:'heard', count:0};
  if (snr !== undefined && snr !== null) e.snr = snr;
  e.count++;
}
function topoSnrColor(snr, alpha){
  if (snr === undefined || snr === null) return 'rgba(148,163,184,'+(alpha||0.45)+')';
  const s = Math.max(-25, Math.min(10, snr));
  const t = (s + 25) / 35;
  const r = Math.round(255 * (1.0 - t));
  const g = Math.round(180 * t + 60);
  return 'rgba('+r+','+g+',80,'+(alpha||0.7)+')';
}
function topoNodeRadius(id){
  const n = nodes[id];
  const f = (n && n.heardBy) ? n.heardBy.size : 1;
  return Math.min(14, 5 + Math.log2(1 + f) * 1.5);
}
function topoTick(dt){
  const ids = Object.keys(topoNodes);
  if (!ids.length) return;
  const W = topoCanvas.width, H = topoCanvas.height, cx=W/2, cy=H/2;
  const K_REP=7000, K_ATT=0.04, REST=80, GRAV=0.012, DAMP=0.85, V_MAX=240;
  for (let i=0;i<ids.length;++i) {
    const a = topoNodes[ids[i]]; let fx=0, fy=0;
    for (let j=0;j<ids.length;++j) {
      if (i===j) continue;
      const b = topoNodes[ids[j]];
      let dx=a.x-b.x, dy=a.y-b.y, d2=dx*dx+dy*dy;
      if (d2 < 16) { dx=(Math.random()-0.5)*4; dy=(Math.random()-0.5)*4; d2=16; }
      const f = K_REP / d2, d = Math.sqrt(d2);
      fx += (dx/d)*f; fy += (dy/d)*f;
    }
    fx += (cx-a.x)*GRAV; fy += (cy-a.y)*GRAV;
    a._fx = fx; a._fy = fy;
  }
  for (const k in topoEdges) {
    const e = topoEdges[k]; const a=topoNodes[e.a], b=topoNodes[e.b];
    if (!a || !b) continue;
    const dx=b.x-a.x, dy=b.y-a.y, d=Math.sqrt(dx*dx+dy*dy)||0.001;
    const f = K_ATT * (d - REST);
    const fx=(dx/d)*f, fy=(dy/d)*f;
    a._fx += fx; a._fy += fy;
    b._fx -= fx; b._fy -= fy;
  }
  for (const id of ids) {
    const a = topoNodes[id];
    if (a.pinned) { a.vx=0; a.vy=0; continue; }
    a.vx = (a.vx + a._fx*dt) * DAMP;
    a.vy = (a.vy + a._fy*dt) * DAMP;
    if (a.vx>V_MAX) a.vx=V_MAX; else if (a.vx<-V_MAX) a.vx=-V_MAX;
    if (a.vy>V_MAX) a.vy=V_MAX; else if (a.vy<-V_MAX) a.vy=-V_MAX;
    a.x += a.vx*dt; a.y += a.vy*dt;
    const m = 24;
    if (a.x<m) {a.x=m;a.vx*=-0.4;} if (a.y<m) {a.y=m;a.vy*=-0.4;}
    if (a.x>W-m) {a.x=W-m;a.vx*=-0.4;} if (a.y>H-m) {a.y=H-m;a.vy*=-0.4;}
  }
}
function topoNodeAt(mx, my){
  for (const id of Object.keys(topoNodes)) {
    const a = topoNodes[id]; const r = a.kind==='station' ? 10 : topoNodeRadius(id.replace(/^station:/,''));
    const dx=a.x-mx, dy=a.y-my;
    if (dx*dx+dy*dy <= (r+3)*(r+3)) return id;
  }
  return null;
}
function topoRender(){
  const W=topoCanvas.width, H=topoCanvas.height;
  topoCtx.clearRect(0,0,W,H);
  for (const k in topoEdges) {
    const e = topoEdges[k]; const a=topoNodes[e.a], b=topoNodes[e.b];
    if (!a || !b) continue;
    const isH = topoHover && (e.a===topoHover || e.b===topoHover);
    topoCtx.strokeStyle = topoSnrColor(e.snr, isH ? 0.95 : 0.40);
    topoCtx.lineWidth = isH ? 2 : 1;
    topoCtx.setLineDash([4,3]);
    topoCtx.beginPath(); topoCtx.moveTo(a.x,a.y); topoCtx.lineTo(b.x,b.y); topoCtx.stroke();
  }
  topoCtx.setLineDash([]);
  topoCtx.font='12px system-ui'; topoCtx.textAlign='center'; topoCtx.textBaseline='top';
  for (const id of Object.keys(topoNodes)) {
    const a = topoNodes[id];
    const isH = id === topoHover;
    if (a.kind === 'station') {
      const name = id.slice('station:'.length);
      topoCtx.beginPath(); topoCtx.arc(a.x, a.y, 10, 0, Math.PI*2);
      topoCtx.fillStyle = stationColor(name);
      topoCtx.globalAlpha = 0.6; topoCtx.fill(); topoCtx.globalAlpha = 1;
      topoCtx.strokeStyle = stationColor(name); topoCtx.lineWidth = 2; topoCtx.stroke();
      topoCtx.fillStyle = '#e2e8f0';
      topoCtx.fillText(name, a.x, a.y + 13);
    } else {
      const r = topoNodeRadius(id);
      topoCtx.beginPath(); topoCtx.arc(a.x, a.y, r, 0, Math.PI*2);
      topoCtx.fillStyle = isH ? '#facc15' : '#38bdf8';
      topoCtx.fill();
      topoCtx.strokeStyle = '#0f172a'; topoCtx.lineWidth = 1.2; topoCtx.stroke();
      if (isH) {
        const n = nodes[id];
        const label = (n && n.name) ? n.name : id;
        topoCtx.fillStyle = '#e2e8f0';
        topoCtx.fillText(label, a.x, a.y + r + 3);
      }
    }
  }
}
function topoLoop(now){
  if (!topoActive) { topoRaf = 0; return; }
  const dt = topoLastTick ? Math.min(0.05, (now - topoLastTick) / 1000) : 0.016;
  topoLastTick = now;
  topoTick(dt);
  topoRender();
  topoRaf = requestAnimationFrame(topoLoop);
}
function topoStart(){
  topoSize();
  topoActive = true; topoLastTick = 0;
  if (Object.keys(topoNodes).length === 0) topoEmpty.style.display = 'block';
  if (!topoRaf) topoRaf = requestAnimationFrame(topoLoop);
}
function topoStop(){ topoActive = false; }
window.addEventListener('resize', ()=>{ if (topoActive) topoSize(); });
topoCanvas.addEventListener('mousemove', e=>{
  const rect = topoCanvas.getBoundingClientRect();
  const hit = topoNodeAt(e.clientX-rect.left, e.clientY-rect.top);
  topoHover = hit;
  topoCanvas.classList.toggle('hovering', !!hit);
});
topoCanvas.addEventListener('mouseleave', ()=>{ topoHover = null; topoCanvas.classList.remove('hovering'); });

const es=new EventSource(authUrl('/events'));
es.onopen=()=>{const s=document.getElementById('status');s.textContent='connected';s.style.color=''};
es.onerror=()=>{const s=document.getElementById('status');s.textContent='disconnected';s.style.color='#f87171'};
es.onmessage=(e)=>{
  let p; try{p=JSON.parse(e.data);}catch(_){return;}
  nEvents++; setStat('st-events',nEvents);
  if(p.event==='TX'){
    nTx++; setStat('st-tx',nTx);
    return;
  }
  if(p.event==='GEOLOCATED' && p.from && p.lat !== undefined && p.lon !== undefined){
    noteGeolocated(p);
    return;
  }
  // REPLAY_GEOLOCATED is the event-time re-solve result. Distinct from
  // live GEOLOCATED so the timeline keeps replay derivations separate
  // from real solves. Stash by source_event_id; the Evidence tab reads
  // evidenceReplays on every re-render.
  if(p.event==='REPLAY_GEOLOCATED' && p.source_event_id){
    evidenceReplays.set(p.source_event_id, p);
    // If the Evidence tab is currently showing, re-render so the
    // replayed row picks up the REPLAY badge and the detail pane
    // refreshes if this row is selected. evidenceRefresh would be
    // overkill (network round-trip); just re-render from cached data.
    if (document.getElementById('evidence').classList.contains('active')) {
      evidenceRenderTimeline();
      // Re-render detail if currently selected this row.
      if (evidenceSelected === p.source_event_id) {
        const sel = document.querySelector('#ev-timeline .ev-row.selected');
        if (sel) sel.click();
      }
    }
    return;
  }
  // STATS heartbeat from a sniffer: 5 s cadence per sensor with msps +
  // cumulative frames/decrypted. Use it to surface per-sensor health.
  if(p.event==='STATS' && p.station){
    const s = stations[p.station] || (stations[p.station]={frames:0,decrypted:0});
    s.msps = p.msps || 0;
    s.framesTotal = p.frames || 0;
    s.decryptedTotal = p.decrypted || 0;
    s.lastEventAt = Date.now()/1000;
    s.lastSeen = s.lastEventAt;
    return;
  }
  // Per-frame accounting: count decrypted frames per station for the
  // health dashboard.
  if(p.station){
    const s = stations[p.station] || (stations[p.station]={frames:0,decrypted:0});
    if(p.from){
      s.frames = (s.frames||0) + 1;
      if(p.decrypted !== false && p.port_name) s.decrypted = (s.decrypted||0) + 1;
    }
    s.lastEventAt = Date.now()/1000;
  }
  // Per-frame events. Track the originating station (with its GPS if any),
  // the transmitting node (with its position if NODEINFO/POSITION decoded),
  // and the per-preset activity counter.
  if (p.station) noteStation(p.station, p.station_lat, p.station_lon);
  if (p.from) noteNode(p);
  if (p.from) noteActivityFrame(p);
  if (p.from) noteChannel(p);
  if (p.from && p.station) topoNoteHeardBy(p.station, p.from, p.snr_db);
  refreshLive();
  refreshActivity();
};

// dealerStats[identity] = {heartbeats, last_seen_ago_sec, ...} -- updated
// alongside the sensor list refresh; rendered into the DEALER badge tooltip.
const dealerStats = {};
async function refreshSensors(){
  try{
    const [r1, r2] = await Promise.all([
      fetch('/api/sensors',{headers:authHeaders()}),
      fetch('/api/dealer-stats',{headers:authHeaders()}).catch(()=>null),
    ]);
    const list=await r1.json();
    setStat('st-sensors', list.length);
    if (r2 && r2.ok) {
      const j = await r2.json();
      // Reset so removed sessions disappear from the cache.
      for (const k of Object.keys(dealerStats)) delete dealerStats[k];
      for (const s of (j.sessions||[])) dealerStats[s.identity] = s;
    }
    renderSensorsTable(list);
  }catch(err){
    console.error('refreshSensors',err);
  }
}
let _sensorList = [];
function renderSensorsTable(list){
  if (list) _sensorList = list;
  const tb = document.querySelector('#sensors-tbl tbody');
  if (!tb) return;
  tb.innerHTML = '';
  const now = Date.now()/1000;
  for(const s of _sensorList){
    const live = stations[s.name] || {};
    const lastAge = live.lastEventAt ? Math.floor(now - live.lastEventAt) : null;
    let healthClass = 'muted', healthText = 'no data';
    if (lastAge !== null) {
      if (lastAge < 30)        { healthClass = 'status-ok';    healthText = 'live'; }
      else if (lastAge < 300)  { healthClass = 'status-stale'; healthText = 'idle '+lastAge+'s'; }
      else                     { healthClass = 'status-err';   healthText = 'stale '+Math.floor(lastAge/60)+'m'; }
    }
    const decTotal = live.decryptedTotal !== undefined ? live.decryptedTotal : (live.decrypted||0);
    const frameTotal = live.framesTotal !== undefined ? live.framesTotal : (live.frames||0);
    const decPct = frameTotal > 0 ? Math.round(100*decTotal/frameTotal) + '%' : '<span class=muted>--</span>';
    const msps = live.msps ? live.msps.toFixed(1) : '<span class=muted>--</span>';
    const lastSeen = lastAge !== null ? lastAge+'s' : '<span class=muted>--</span>';
    const dot = '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+
      stationColor(s.name)+';margin-right:6px;vertical-align:middle"></span>';
    const tr = document.createElement('tr');
    const ds = dealerStats[s.name];
    let dealerTip = 'DEALER session active; commands route via ZMQ';
    if (ds) {
      const hbAge = ds.last_seen_ago_sec ? ds.last_seen_ago_sec.toFixed(1)+'s ago' : 'fresh';
      dealerTip = 'DEALER session\n'+
        ds.heartbeats+' heartbeats (last '+hbAge+')\n'+
        ds.commands_sent+' cmds sent  '+ds.commands_replied+' replied  '+ds.commands_timed_out+' timeout\n'+
        'cmd latency: p50='+ds.cmd_latency_p50_ms+'ms  p95='+ds.cmd_latency_p95_ms+'ms';
    }
    const c2Badge = s.dealer
      ? '<span class="status-ok" title="'+escHtml(dealerTip)+'">DEALER</span>'
      : (s.api ? '<span class="muted" title="HTTP fan-out to '+escHtml(s.api)+'">HTTP</span>'
               : '<span class="status-err" title="no command transport configured">--</span>');
    tr.innerHTML = '<td>'+dot+escHtml(s.name)+'</td>'+
      '<td><span class="'+healthClass+'">'+healthText+'</span></td>'+
      '<td>'+frameTotal+'</td>'+
      '<td>'+decPct+'</td>'+
      '<td>'+msps+'</td>'+
      '<td class=muted>'+lastSeen+'</td>'+
      '<td>'+c2Badge+'</td>'+
      '<td><code>'+escHtml(s.zmq)+'</code></td>'+
      '<td><button class=danger onclick="removeSensor(\''+escHtml(s.name)+'\')">remove</button></td>';
    tb.appendChild(tr);
  }
  if(_sensorList.length===0){
    const tr=document.createElement('tr');
    tr.innerHTML='<td colspan=9 class="muted" style="text-align:center;padding:20px">no sensors registered. add one above, or pass tcp://... on the fusion command line.</td>';
    tb.appendChild(tr);
  }
}
// Re-render every second so health / msps / last-seen drift live.
setInterval(()=>{ if (document.getElementById('sensors').classList.contains('active')) renderSensorsTable(); }, 1000);
async function addSensor(){
  const name=document.getElementById('s-name').value.trim();
  const zmq =document.getElementById('s-zmq').value.trim();
  const api =document.getElementById('s-api').value.trim();
  const tok =document.getElementById('s-token').value.trim();
  if(!name || !zmq){
    setStatus('add-status','name and zmq endpoint are required',false);
    return;
  }
  const body={name:name,zmq:zmq};
  if(api) body.api=api;
  if(tok) body.api_token=tok;
  try{
    const r=await fetch('/api/sensors',{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify(body)});
    const j=await r.json();
    if(r.ok){
      setStatus('add-status','added '+j.added,true);
      document.getElementById('s-name').value='';
      document.getElementById('s-zmq').value='';
      document.getElementById('s-api').value='';
      document.getElementById('s-token').value='';
      refreshSensors();
    }else{
      setStatus('add-status',j.error||'error',false);
    }
  }catch(err){
    setStatus('add-status',String(err),false);
  }
}
async function removeSensor(name){
  try{
    const r=await fetch('/api/sensors/'+encodeURIComponent(name),{method:'DELETE',headers:authHeaders()});
    if(r.ok) refreshSensors();
  }catch(_){}
}
async function fanout(endpoint,inputId){
  const body=document.getElementById(inputId).value.trim().replace(/\n/g,',');
  const out=document.getElementById(inputId.replace('-input','-result'));
  out.style.display='block';
  out.textContent='sending...';
  try{
    const r=await fetch('/api/fanout/'+endpoint,{method:'POST',headers:authHeaders(),body:body});
    const j=await r.json();
    out.textContent=JSON.stringify(j,null,2);
  }catch(err){
    out.textContent='error: '+String(err);
  }
}
function setStatus(id,msg,ok){
  const el=document.getElementById(id);
  el.textContent=msg;
  el.className='hint '+(ok?'status-ok':'status-err');
}
function escHtml(s){return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

// ---- Evidence tab ----------------------------------------------------------
//
// Read-only view of persisted TDOA evidence: cluster_observations,
// pair_snapshots, solved_fixes, plus clock-sync warnings. No re-solve
// actions yet -- this is the trust/inspection surface; replay execution
// lands in a later commit.

let evidenceZoom = '1h';
let evidenceData = { summary: null, fixes: [], clusters: [], pairs: [], warnings: [] };
let evidenceSelected = null; // source_event_id of the currently-highlighted row

// evidenceReplays: ephemeral REPLAY_GEOLOCATED results, keyed by
// source_event_id. Not persisted -- replays are derivations the operator
// can re-run, so a page reload clears them. Stored only so the timeline
// + detail pane can show "yes, this event was just replayed" without a
// round trip.
const evidenceReplays = new Map();
function evidenceRowKey(from, pid, seq, eventTimeNs){
  return from + '|' + pid + '|' + (seq || 0) + '|' + eventTimeNs;
}

// Evidence map: dedicated Leaflet instance (NOT the Live map). The two
// maps have different jobs: Live is real-time situational awareness,
// Evidence is post-hoc investigation. Sharing the Leaflet helper is fine;
// sharing the map state is not.
let evidenceMap = null;
const evidenceMarkers = new Map(); // rowKey -> {marker, fix}
let evidenceMapAutoFit = false;

const ZOOM_NS = { '15m': 15*60*1e9, '1h': 60*60*1e9, '6h': 6*60*60*1e9, '24h': 24*60*60*1e9 };

function evidenceMapInit(){
  if (evidenceMap) return;
  evidenceMap = L.map('ev-map', { zoomControl: true }).setView([39.5, -98.0], 4);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    { maxZoom: 19, attribution: '(c) OSM (c) CARTO' }).addTo(evidenceMap);
}

document.querySelectorAll('#ev-zoom button').forEach(b=>{
  b.addEventListener('click', ()=>{
    evidenceZoom = b.getAttribute('data-zoom');
    document.querySelectorAll('#ev-zoom button').forEach(x=>x.classList.toggle('active', x===b));
    evidenceRefresh();
  });
});

async function evidenceFetch(path){
  try {
    const r = await fetch(authUrl(path), { headers: authHeaders() });
    if (!r.ok) return null;
    return await r.json();
  } catch(e) { return null; }
}

async function evidenceRefresh(){
  const tl = document.getElementById('ev-timeline');
  tl.innerHTML = '<div class="ev-empty">Loading...</div>';
  document.getElementById('ev-range-readout').textContent = 'last '+evidenceZoom;
  const endNs = Date.now() * 1e6; // ms -> ns
  const startNs = endNs - ZOOM_NS[evidenceZoom];
  const qs = '?start_ns='+Math.trunc(startNs)+'&end_ns='+Math.trunc(endNs);
  // Parallel fetch all surfaces.
  const [summary, fixes, clusters, pairs, warnings] = await Promise.all([
    evidenceFetch('/api/evidence/summary'),
    evidenceFetch('/api/evidence/fixes'+qs),
    evidenceFetch('/api/evidence/clusters'+qs),
    evidenceFetch('/api/evidence/pairs'+qs),
    evidenceFetch('/api/clock-sync/warnings'),
  ]);
  evidenceData = {
    summary: summary,
    fixes: (fixes && fixes.records) || [],
    clusters: (clusters && clusters.records) || [],
    pairs: (pairs && pairs.records) || [],
    warnings: (warnings && warnings.warnings) || [],
    clockSyncEnabled: warnings ? !!warnings.enabled : false,
  };
  evidenceRenderHealth();
  evidenceRenderWarnings();
  evidenceRenderMap();
  evidenceRenderTimeline();
}

// evidenceRenderMap repopulates the Evidence-tab map from the current
// fixes list. Pins are tinted by trust class (sync vs software_lock /
// frame); the currently-selected timeline row's pin is larger and
// styled in cyan. Auto-fits the map bounds on first render with
// content, then leaves the view alone so a user pan/zoom is not
// repeatedly reset by refreshes.
function evidenceRenderMap(){
  if (!evidenceMap) return;
  evidenceMarkers.forEach(m => m.marker.remove());
  evidenceMarkers.clear();
  const fixes = evidenceData.fixes || [];
  const emptyOverlay = document.getElementById('ev-map-empty');
  if (fixes.length === 0) {
    if (emptyOverlay) emptyOverlay.style.display = 'flex';
    return;
  }
  if (emptyOverlay) emptyOverlay.style.display = 'none';
  const TRUST_COLOR = {
    sample: '#22c55e',
    sync: '#38bdf8',
    software_lock: '#f59e0b',
    frame: '#fb923c',
  };
  const latlngs = [];
  for (const f of fixes) {
    if (typeof f.lat !== 'number' || typeof f.lon !== 'number') continue;
    if (f.lat === 0 && f.lon === 0) continue;
    const color = TRUST_COLOR[f.timestamp_class] || '#94a3b8';
    const m = L.circleMarker([f.lat, f.lon], {
      radius: 7, color: color, weight: 2, fillColor: color, fillOpacity: 0.45,
    }).addTo(evidenceMap);
    const lockStr = f.timestamp_class ? f.timestamp_class.toUpperCase() : '';
    m.bindPopup('<b>' + escHtml(f.from) + '</b>' +
      (f.emission_seq > 0 ? (' #'+f.emission_seq) : '') +
      '<br>±' + (f.uncertainty_m||0).toFixed(1) + ' m · ' + (f.station_count||0) + ' stations' +
      (lockStr ? ('<br><span style="color:'+color+'">'+escHtml(lockStr)+'</span>') : ''));
    const rowKey = f.from + '|' + f.packet_id + '|' + (f.emission_seq || 0);
    m.on('click', () => {
      evidenceSelected = rowKey;
      // Re-render timeline so the matching row highlights, then scroll to it.
      evidenceRenderTimeline();
      const sel = document.querySelector('#ev-timeline .ev-row.selected');
      if (sel) sel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
    evidenceMarkers.set(rowKey, { marker: m, fix: f });
    latlngs.push([f.lat, f.lon]);
  }
  // Auto-fit once. After the first non-empty render leave panning alone so
  // an operator who zoomed in to inspect a fix doesn't get yanked away on
  // the next refresh.
  if (!evidenceMapAutoFit && latlngs.length > 0) {
    evidenceMap.fitBounds(latlngs, { padding: [40, 40], maxZoom: 14 });
    evidenceMapAutoFit = true;
  }
}

// evidenceHighlightFix pans the Evidence map to a fix and pops its popup.
// Called when a timeline row is clicked.
function evidenceHighlightFix(rowKey){
  if (!evidenceMap) return;
  const entry = evidenceMarkers.get(rowKey);
  if (!entry) return;
  evidenceMap.panTo(entry.marker.getLatLng(), { animate: true });
  entry.marker.openPopup();
}

function evidenceRenderHealth(){
  const s = evidenceData.summary;
  const banner = document.getElementById('ev-persisted-banner');
  if (s && s.persisted) {
    document.getElementById('ev-db-clusters').textContent = (s.counts && s.counts.cluster_observations) || 0;
    document.getElementById('ev-db-sub').textContent =
      ((s.counts && s.counts.cluster_observations) || 0) + ' clusters / ' +
      ((s.counts && s.counts.solved_fixes) || 0) + ' fixes';
    document.getElementById('ev-schema').textContent = 'v' + (s.schema_version || 0);
    document.getElementById('ev-schema-sub').textContent =
      s.replay_available ? 'replay available' : 'replay disabled';
    banner.style.display = 'none';
  } else {
    document.getElementById('ev-db-clusters').textContent = '—';
    document.getElementById('ev-db-sub').textContent = 'no state-db attached';
    document.getElementById('ev-schema').textContent = '—';
    document.getElementById('ev-schema-sub').textContent = 'replay disabled';
    banner.innerHTML = '<b style="color:var(--warn-bright)">Running without --state-db.</b> ' +
      'The Evidence tab needs a persistent bbolt file to render historical events. ' +
      'Restart fusion with <code style="color:var(--text-2)">--state-db=/path/to/state.db</code> ' +
      'and the timeline will populate as anchor clusters and solves land.';
    banner.style.display = 'block';
  }
  // Sensors / anchors / pairs counts come from live state (stations[] and
  // /api/clock-sync/warnings.enabled). The TDOA state label is a simple
  // client-side rollup for v1; a backend /api/evidence/summary.tdoa_state
  // can replace it later if the rule grows complex.
  const sensorsAlive = Object.keys(stations).length;
  document.getElementById('ev-sensors-count').textContent = sensorsAlive;
  // Anchors + converged-pair counts aren't yet exposed by a public API; show
  // best-effort placeholders until /api/clock-sync/stats lands. Warnings still
  // indicate clock-sync state.
  const csOn = evidenceData.clockSyncEnabled;
  document.getElementById('ev-anchors-sub').textContent = csOn ? 'clock-sync on' : 'clock-sync off';
  document.getElementById('ev-pairs-sub').textContent = csOn ? 'see warnings' : 'n/a';
  // TDOA rollup, conservative v1 thresholds:
  //   NOT_READY if fewer than 3 sensors alive
  //   NO_ANCHOR if clock-sync disabled / no anchors
  //   DEGRADED if any anchor warning is active
  //   READY otherwise
  let state = 'not_ready', sub = 'sensors < 3';
  if (sensorsAlive >= 3) {
    if (!csOn) { state = 'no_anchor'; sub = 'no anchors configured'; }
    else if (evidenceData.warnings.length > 0) { state = 'degraded'; sub = evidenceData.warnings.length + ' warning(s)'; }
    else { state = 'ready'; sub = 'sensors + sync ok'; }
  }
  const el = document.getElementById('ev-tdoa-state');
  el.textContent = state.toUpperCase().replace('_',' ');
  el.className = 'ev-value ev-state-'+state;
  document.getElementById('ev-tdoa-sub').textContent = sub;
}

function evidenceRenderWarnings(){
  const host = document.getElementById('ev-warnings');
  host.innerHTML = '';
  for (const w of evidenceData.warnings) {
    const div = document.createElement('div');
    div.className = 'ev-warn';
    const code = w.code || 'warning';
    div.innerHTML = '<b>['+escHtml(code.toUpperCase())+']</b> ' + escHtml(w.message || '');
    host.appendChild(div);
  }
}

function evidenceRenderTimeline(){
  const tl = document.getElementById('ev-timeline');
  tl.innerHTML = '';
  // Interleave fixes + clusters into one timeline. Fixes have
  // event_time_ns; clusters have cluster_time_ns. Anchor-cluster vs
  // target-cluster is distinguished from the fact that solved_fixes
  // suppress anchors (live event loop suppresses GEOLOCATED for declared
  // anchors), so any cluster whose (from, pid) matches a solved fix is a
  // target; the rest are either anchors or insufficient-station targets.
  const fixByKey = new Map();
  for (const f of evidenceData.fixes) {
    fixByKey.set(f.from + '|' + f.packet_id + '|' + (f.emission_seq || 0), f);
  }
  const rows = [];
  for (const c of evidenceData.clusters) {
    const k = c.from + '|' + c.packet_id + '|' + (c.emission_seq || 0);
    const fix = fixByKey.get(k);
    const obsCount = (c.observations || []).length;
    rows.push({
      timeNs: c.cluster_time_ns,
      kind: fix ? 'solved' : (c.low_trust ? 'degraded' : 'target'),
      from: c.from,
      packetId: c.packet_id,
      emissionSeq: c.emission_seq || 0,
      stationCount: obsCount,
      summary: obsCount + ' station' + (obsCount === 1 ? '' : 's') +
        (c.preset ? (' · ' + c.preset) : '') +
        (c.low_trust ? ' · low-trust' : '') +
        ((c.station_dupes_suppressed||0) > 0 ? (' · dupes=' + c.station_dupes_suppressed) : ''),
      trust: fix ? fix.timestamp_class : (c.low_trust ? 'degraded' : ''),
      cluster: c,
      fix: fix || null,
    });
    if (fix) fixByKey.delete(k);
  }
  // Any unmatched fix (anchor cluster wasn't retained, or fix lacks a
  // cluster row) still shows up so the timeline doesn't lie about solves.
  for (const fix of fixByKey.values()) {
    rows.push({
      timeNs: fix.event_time_ns,
      kind: 'solved',
      from: fix.from,
      packetId: fix.packet_id,
      emissionSeq: fix.emission_seq || 0,
      stationCount: fix.station_count || 0,
      summary: 'solved · ' + (fix.station_count||0) + ' stations · ±' +
        Math.round(fix.uncertainty_m||0) + ' m',
      trust: fix.timestamp_class,
      cluster: null,
      fix: fix,
    });
  }
  rows.sort((a,b) => Number(b.timeNs) - Number(a.timeNs)); // newest first
  if (rows.length === 0) {
    const persisted = evidenceData.summary && evidenceData.summary.persisted;
    const total = persisted ?
      ((evidenceData.summary.counts && evidenceData.summary.counts.cluster_observations) || 0) : 0;
    if (!persisted) {
      tl.innerHTML = '<div class="ev-empty">Evidence persistence is off. See the banner above.</div>';
    } else if (total === 0) {
      tl.innerHTML = '<div class="ev-empty">' +
        'Waiting for station feeds and anchor observations.<br><br>' +
        'New events appear here in real time once sniffers connect and ' +
        'clock-sync is converging. Operator-declared anchors train the clock ' +
        'graph; everything else becomes a target.' +
        '</div>';
    } else {
      tl.innerHTML = '<div class="ev-empty">' +
        'No events in the last ' + evidenceZoom + '. ' + total + ' total in the DB — ' +
        'try a larger zoom.</div>';
    }
    return;
  }
  for (const r of rows) {
    const row = document.createElement('div');
    row.className = 'ev-row';
    const trustClass = r.trust ? 'ev-trust ev-trust-'+r.trust : 'ev-trust';
    const trustText = r.trust ? r.trust.toUpperCase() : '';
    const tstr = (new Date(Number(r.timeNs)/1e6)).toLocaleTimeString([], {hour12:false});
    const rowKey = evidenceRowKey(r.from, r.packetId, r.emissionSeq, r.timeNs);
    const replay = evidenceReplays.get(rowKey);
    // Re-solve button is only meaningful when we have persisted cluster
    // observations with enough stations for the solver. A bare fix row
    // (no cluster) can't be re-solved because the raw observations are
    // missing from the bucket.
    const canReplay = r.cluster && (r.stationCount || 0) >= 3;
    const replayedTag = replay
      ? ' <span class="ev-replay-tag">REPLAY</span>'
      : '';
    const actionHtml = canReplay
      ? '<button class="ev-action'+(replay?' replayed':'')+'" data-event-id="'+
          escHtml(rowKey)+'">Replay</button>'
      : '<span></span>';
    row.innerHTML =
      '<div class="ev-time">'+escHtml(tstr)+'</div>' +
      '<div class="ev-kind ev-kind-'+r.kind+'">'+escHtml(r.kind)+'</div>' +
      '<div class="ev-from">'+escHtml(r.from)+(r.emissionSeq>0?(':#'+r.emissionSeq):'')+'</div>' +
      '<div class="'+trustClass+'">'+escHtml(trustText)+replayedTag+'</div>' +
      '<div class="ev-summary">'+escHtml(r.summary)+'</div>' +
      actionHtml;
    row.addEventListener('click', () => evidenceShowDetail(r, row));
    const btn = row.querySelector('.ev-action');
    if (btn) {
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        evidenceReplay(r, btn);
      });
    }
    if (evidenceSelected === rowKey) row.classList.add('selected');
    tl.appendChild(row);
  }
}

// evidenceReplay POSTs /api/resolve for the given row. The result lands
// asynchronously via the REPLAY_GEOLOCATED SSE event; this fn only fires
// the request and gives the operator instant feedback that the action is
// in flight. The button is intentionally not disabled forever -- if
// nothing comes back within a few seconds, the operator can retry.
async function evidenceReplay(r, btn){
  btn.disabled = true;
  const wasText = btn.textContent;
  btn.textContent = 'Replaying...';
  try {
    const resp = await fetch(authUrl('/api/resolve'), {
      method: 'POST',
      headers: authHeaders({'Content-Type':'application/json'}),
      body: JSON.stringify({
        from: r.from,
        packet_id: r.packetId,
        emission_seq: r.emissionSeq,
        event_time_ns: Number(r.timeNs),
        mode: 'event_time',
      }),
    });
    if (!resp.ok) {
      const errText = (await resp.text()).slice(0, 200);
      btn.textContent = 'Replay failed';
      btn.title = errText;
      setTimeout(() => { btn.textContent = wasText; btn.disabled = false; btn.title = ''; }, 3000);
      return;
    }
    // Success ack: the REPLAY_GEOLOCATED SSE event will re-enable the
    // button + update the row when it arrives. If the SSE arrives before
    // we get here (rare), evidenceRenderTimeline will have already
    // re-rendered with the replayed state.
    setTimeout(() => { btn.disabled = false; btn.textContent = wasText; }, 1500);
  } catch (e) {
    btn.textContent = 'Replay error';
    setTimeout(() => { btn.textContent = wasText; btn.disabled = false; }, 3000);
  }
}

function evidenceShowDetail(r, rowEl){
  // Highlight selected row.
  document.querySelectorAll('#ev-timeline .ev-row').forEach(x=>x.classList.remove('selected'));
  rowEl.classList.add('selected');
  evidenceSelected = evidenceRowKey(r.from, r.packetId, r.emissionSeq, r.timeNs);
  // Pan + open popup for the matching map marker. No-op when the row is
  // an unsolved cluster (no fix -> no marker on the map).
  evidenceHighlightFix(r.from + '|' + r.packetId + '|' + r.emissionSeq);
  const host = document.getElementById('ev-detail');
  let html = '';
  html += '<h4>Event</h4>';
  html += kv('time', new Date(Number(r.timeNs)/1e6).toISOString());
  html += kv('from', r.from);
  html += kv('packet_id', String(r.packetId));
  if (r.emissionSeq > 0) html += kv('emission_seq', String(r.emissionSeq));
  html += kv('kind', r.kind);

  if (r.fix) {
    html += '<h4>Solved Fix</h4>';
    html += kv('lat / lon', r.fix.lat.toFixed(6) + ', ' + r.fix.lon.toFixed(6));
    html += kv('uncertainty', '±' + (r.fix.uncertainty_m || 0).toFixed(1) + ' m');
    html += kv('station_count', String(r.fix.station_count || 0));
    html += kv('iterations', String(r.fix.iterations || 0));
    html += kv('timestamp_class', (r.fix.timestamp_class || '') +
      (r.fix.timestamp_class_degraded ? ' (degraded)' : ''));
    if (r.fix.clock_sync_pair_count > 0) {
      html += kv('clock_sync_pairs', String(r.fix.clock_sync_pair_count));
      html += kv('clock_sync_residual', (r.fix.clock_sync_residual_ns||0).toFixed(0) + ' ns');
      html += kv('clock_sync_anchors', String(r.fix.clock_sync_anchor_count || 0));
      html += kv('clock_sync_reference', r.fix.clock_sync_reference || '—');
    }
    if (r.fix.pair_snapshot_keys_used && r.fix.pair_snapshot_keys_used.length) {
      html += '<h4>Pair Snapshots Used</h4>';
      for (const k of r.fix.pair_snapshot_keys_used) {
        html += '<div class="kv"><span class="k">pair</span><span class="v">'+escHtml(k)+'</span></div>';
      }
    }
  }

  if (r.cluster && r.cluster.observations && r.cluster.observations.length) {
    html += '<h4>Stations</h4>';
    html += '<table class="ev-stations"><thead><tr><th>Station</th><th>Lock</th><th>SNR</th></tr></thead><tbody>';
    for (const o of r.cluster.observations) {
      const lockNs = o.preamble_lock_t_ns || 0;
      const lockStr = lockNs > 0 ? new Date(lockNs/1e6).toLocaleTimeString([], {hour12:false}) + '.' + (lockNs % 1000000).toString().padStart(6,'0').slice(0,3) : '—';
      html += '<tr><td>'+escHtml(o.station||'')+'</td><td>'+escHtml(lockStr)+'</td><td>'+(o.snr_db?o.snr_db.toFixed(1)+' dB':'—')+'</td></tr>';
    }
    html += '</tbody></table>';
    if (r.cluster.station_dupes_suppressed > 0) {
      html += '<div class="kv" style="margin-top:6px"><span class="k">dupes suppressed</span><span class="v">'+r.cluster.station_dupes_suppressed+'</span></div>';
    }
    if (r.cluster.low_trust) {
      html += '<div class="kv"><span class="k">trust</span><span class="v" style="color:var(--err)">LOW (lock missing for one or more obs)</span></div>';
    }
  }

  if (!r.fix && !(r.cluster && r.cluster.observations && r.cluster.observations.length)) {
    html += '<div class="ev-empty" style="padding-top:20px">No persisted detail for this event yet.</div>';
  }

  const replay = evidenceReplays.get(evidenceRowKey(r.from, r.packetId, r.emissionSeq, r.timeNs));
  if (replay) {
    html += '<h4>Replay (event-time)</h4>';
    html += kv('replay_mode', replay.replay_mode || '');
    html += kv('clock_model_time_ns', String(replay.clock_model_time_ns || ''));
    html += kv('lat / lon', (replay.lat||0).toFixed(6) + ', ' + (replay.lon||0).toFixed(6));
    html += kv('uncertainty', '±' + (replay.uncertainty_m || 0).toFixed(1) + ' m');
    html += kv('station_count', String(replay.station_count || 0));
    html += kv('iterations', String(replay.iterations || 0));
    html += kv('timestamp_class', (replay.timestamp_class || '') +
      (replay.timestamp_class_degraded ? ' (degraded)' : ''));
    if (replay.clock_sync_reference) {
      html += kv('clock_sync_reference', replay.clock_sync_reference);
    }
    if (replay.pair_snapshot_keys_used && replay.pair_snapshot_keys_used.length) {
      for (const k of replay.pair_snapshot_keys_used) {
        html += '<div class="kv"><span class="k">pair_snapshot</span><span class="v">'+escHtml(k)+'</span></div>';
      }
    }
  }

  host.innerHTML = html;
}

function kv(k,v){
  return '<div class="kv"><span class="k">'+escHtml(k)+'</span><span class="v">'+escHtml(String(v))+'</span></div>';
}

// Initial state
refreshSensors();
</script>
</body></html>`
