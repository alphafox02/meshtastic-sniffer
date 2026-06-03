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
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;
  height:100vh;display:flex;flex-direction:column;font-size:14px}
#bar{height:44px;flex-shrink:0;background:#1e293b;display:flex;align-items:center;
  padding:0 16px;gap:20px;border-bottom:1px solid #334155}
#bar .title{font-weight:600;color:#f8fafc;letter-spacing:0.5px}
#bar .stat{color:#94a3b8;font-size:13px}
#bar .val{color:#38bdf8;font-weight:600;font-variant-numeric:tabular-nums;margin-left:6px}
#bar #status{margin-left:auto;color:#64748b;font-size:12px}
#tabs{display:flex;align-items:center;background:#1e293b;border-bottom:1px solid #334155;
  flex-shrink:0}
#tabs button{background:none;color:#64748b;border:none;padding:8px 16px;cursor:pointer;
  font:inherit;text-transform:uppercase;font-size:12px;letter-spacing:1px;font-weight:600;
  border-bottom:2px solid transparent}
#tabs button:hover{color:#94a3b8}
#tabs button.active{color:#38bdf8;border-bottom-color:#38bdf8}
.tab{flex:1;display:none;overflow:auto;padding:18px}
.tab.active{display:block}
#live.tab{padding:0}
#live.tab.active{display:flex}
#live-grid{display:grid;grid-template-columns:2fr 1fr;grid-template-rows:1fr 1fr 1fr;
  height:100%;width:100%;gap:1px;background:#334155}
#live-map-pane{grid-row:span 3;padding:0}
#live-map{width:100%;height:100%}
.leaflet-container{background:#0f172a}
.live-pane{padding:8px 10px;overflow:auto;background:#0f172a}
.live-pane h3{font-size:11px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;
  margin-bottom:6px;border-bottom:1px solid #334155;padding-bottom:4px}
h2{font-size:12px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;
  border-bottom:1px solid #334155;padding-bottom:5px;margin-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:12px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #1e293b}
th{color:#64748b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}
tr:hover td{background:#1e293b}
.muted{color:#64748b}
.status-ok{color:#4ade80}
.status-err{color:#f87171}
.status-stale{color:#fbbf24}
.row{margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input[type=text],textarea{background:#0f172a;color:#e2e8f0;border:1px solid #334155;
  border-radius:3px;padding:6px 10px;font:inherit;font-size:13px;flex:1;min-width:200px}
input[type=text]:focus,textarea:focus{outline:none;border-color:#38bdf8}
textarea{font-family:'SF Mono',Consolas,monospace;min-height:80px}
button.primary{background:#0c4a6e;color:#bae6fd;border:1px solid #0284c7;border-radius:3px;
  padding:6px 14px;cursor:pointer;font-size:13px;font-weight:500}
button.primary:hover{background:#075985}
button.danger{background:#7f1d1d;color:#fecaca;border:1px solid #b91c1c;border-radius:3px;
  padding:3px 9px;cursor:pointer;font-size:11px}
button.danger:hover{background:#991b1b}
.hint{color:#64748b;font-size:11px;margin-top:4px;display:block}
.placeholder{color:#64748b;font-style:italic;padding:30px 0;text-align:center}
#activity-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px}
.preset-card{background:#1e293b;border:1px solid #334155;border-radius:5px;padding:12px 14px;
  display:flex;flex-direction:column;gap:6px}
.preset-card.hot{border-color:#38bdf8}
.preset-card.dead{opacity:0.55}
.preset-card .top{display:flex;align-items:baseline;gap:8px}
.preset-card .nm{font-size:15px;font-weight:600;color:#f8fafc;flex:1}
.preset-card .meta{color:#94a3b8;font-size:11px}
.preset-card .row2{display:flex;gap:14px;font-size:12px;margin-top:2px}
.preset-card .lbl{color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;display:block}
.preset-card .v{color:#38bdf8;font-weight:600;font-size:15px;font-variant-numeric:tabular-nums}
.preset-card .station-list{display:flex;flex-direction:column;gap:3px;margin-top:4px}
.preset-card .station-row{display:flex;justify-content:space-between;font-size:12px;
  background:#0f172a;border-radius:3px;padding:3px 7px;color:#cbd5e1}
.preset-card .station-row .dot{display:inline-block;width:8px;height:8px;border-radius:50%;
  margin-right:6px;vertical-align:middle}
#topology.tab.active{display:flex;flex-direction:column;position:relative;padding:0}
#topo-canvas{flex:1;display:block;width:100%;background:#0f172a;cursor:default}
#topo-canvas.hovering{cursor:pointer}
#topo-empty{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);
  pointer-events:none;z-index:5;max-width:480px;text-align:center}
#topo-legend{position:absolute;left:10px;top:10px;color:#64748b;font-size:11px;
  background:rgba(15,23,42,0.85);padding:7px 11px;border-radius:3px;border:1px solid #334155;z-index:4;pointer-events:none}
#topo-legend .l-station,#topo-legend .l-node{display:inline-block;width:8px;height:8px;
  border-radius:50%;vertical-align:middle;margin-right:3px}
#topo-legend .l-station{background:#fbbf24;border:1px solid #f59e0b}
#topo-legend .l-node{background:#38bdf8}
.fanout-result{font-family:'SF Mono',Consolas,monospace;font-size:11px;color:#94a3b8;
  background:#1e293b;border-radius:3px;padding:8px 10px;margin-top:6px;white-space:pre-wrap;
  max-height:200px;overflow:auto}

/* Evidence tab. Mirrors the Live tab's "map left, panes stacked right"
 * grid so the operator's eye lands on geography first and
 * the timeline + detail act as side cards. Top header holds the health
 * strip and persistent warnings full-width above the work area. */
#evidence.tab{padding:0;display:none;flex-direction:column}
#evidence.tab.active{display:flex}
#ev-header{flex:none;padding:10px 14px 6px;border-bottom:1px solid #334155}
#ev-health-strip{display:flex;gap:10px;flex-wrap:wrap}
.ev-card{background:#1e293b;border:1px solid #334155;border-radius:4px;padding:6px 10px;
  min-width:108px}
.ev-card .ev-label{color:#64748b;text-transform:uppercase;font-size:10px;letter-spacing:0.06em;
  font-weight:600;margin-bottom:2px}
.ev-card .ev-value{font-size:15px;font-variant-numeric:tabular-nums;font-weight:600;color:#e2e8f0;
  line-height:1.2}
.ev-card .ev-sub{color:#94a3b8;font-size:10px;margin-top:2px}
.ev-state-ready{color:#22c55e}
.ev-state-degraded{color:#f59e0b}
.ev-state-not_ready,.ev-state-no_anchor{color:#ef4444}
.ev-state-stale{color:#a78bfa}
#ev-warnings{margin-top:6px}
#ev-persisted-banner{color:#94a3b8;font-size:12px;margin-top:6px}
.ev-warn{background:#7f1d1d;color:#fecaca;border:1px solid #b91c1c;border-radius:3px;
  padding:6px 10px;margin-top:4px;font-size:11px;line-height:1.4}
.ev-warn b{color:#fff}
#evidence-grid{flex:1;display:grid;grid-template-columns:2fr 1fr;grid-template-rows:1fr 1fr;
  gap:1px;background:#334155;min-height:0}
#ev-map-pane{grid-row:span 2;position:relative;background:#0f172a;min-width:0;min-height:0}
#ev-map{position:absolute;inset:0}
#ev-map-empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  color:#64748b;font-size:12px;pointer-events:none;background:#0f172a;z-index:400;
  text-align:center;padding:20px}
.leaflet-container{background:#0f172a}
.ev-pane{background:#0f172a;display:flex;flex-direction:column;overflow:hidden;min-width:0;
  min-height:0}
.ev-pane > h3{font-size:11px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;
  margin:0;padding:8px 12px 4px;border-bottom:1px solid #334155;display:flex;align-items:center;
  justify-content:space-between;gap:8px;flex:none;font-weight:600}
.ev-pane-controls{display:flex;align-items:center;gap:8px}
.ev-pane-controls .zoom-buttons{display:inline-flex;background:#1e293b;border:1px solid #334155;
  border-radius:3px;overflow:hidden}
.ev-pane-controls .zoom-buttons button{background:transparent;color:#64748b;border:none;
  padding:3px 8px;font-size:10px;cursor:pointer;border-right:1px solid #334155;
  text-transform:none;letter-spacing:0;font-weight:400}
.ev-pane-controls .zoom-buttons button:last-child{border-right:none}
.ev-pane-controls .zoom-buttons button:hover{color:#94a3b8}
.ev-pane-controls .zoom-buttons button.active{background:#0f172a;color:#38bdf8}
.ev-pane-controls .ev-readout{color:#64748b;font-size:10px;font-variant-numeric:tabular-nums;
  text-transform:none;letter-spacing:0;font-weight:400}
.ev-pane-controls .ev-refresh{background:transparent;border:1px solid #334155;color:#94a3b8;
  padding:3px 8px;border-radius:3px;cursor:pointer;font-size:10px;
  text-transform:none;letter-spacing:0;font-weight:400}
.ev-pane-controls .ev-refresh:hover{color:#e2e8f0}
#ev-timeline{flex:1;overflow-y:auto;padding:2px 0;min-height:0}
#ev-timeline .ev-empty{color:#64748b;padding:20px 14px;text-align:center;font-size:11px;
  line-height:1.5}
.ev-row{display:grid;grid-template-columns:72px auto auto 80px 1fr;gap:8px;
  padding:6px 12px;border-bottom:1px solid #1e293b;cursor:pointer;font-size:11px;
  align-items:center;line-height:1.3}
.ev-row:hover{background:#1e293b}
.ev-row.selected{background:#0c4a6e;border-left:3px solid #38bdf8;padding-left:9px}
.ev-row .ev-time{color:#94a3b8;font-variant-numeric:tabular-nums;font-size:10px}
.ev-row .ev-kind{font-size:9px;text-transform:uppercase;letter-spacing:0.05em;font-weight:600;
  padding:2px 5px;border-radius:2px;text-align:center;white-space:nowrap}
.ev-row .ev-kind-anchor{background:#1d4ed8;color:#dbeafe}
.ev-row .ev-kind-target{background:#1e293b;color:#94a3b8;border:1px solid #334155}
.ev-row .ev-kind-solved{background:#166534;color:#dcfce7}
.ev-row .ev-kind-degraded{background:#854d0e;color:#fef3c7}
.ev-row .ev-from{color:#e2e8f0;font-family:'SF Mono',Consolas,monospace;font-size:10px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ev-row .ev-trust{font-size:9px;text-align:left;text-transform:uppercase;letter-spacing:0.04em;
  font-weight:600;white-space:nowrap}
.ev-row .ev-summary{color:#94a3b8;font-size:10px;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.ev-trust-sample{color:#22c55e}
.ev-trust-sync{color:#38bdf8}
.ev-trust-software_lock{color:#f59e0b}
.ev-trust-frame{color:#fb923c}
.ev-trust-degraded{color:#ef4444}
#ev-detail{flex:1;overflow-y:auto;padding:10px 12px;font-size:11px;color:#cbd5e1}
#ev-detail .ev-empty{color:#64748b;text-align:center;padding-top:30px;font-size:11px;line-height:1.5}
#ev-detail h4{margin:10px 0 4px 0;font-size:10px;text-transform:uppercase;letter-spacing:0.06em;
  color:#64748b;font-weight:600}
#ev-detail h4:first-child{margin-top:0}
#ev-detail .kv{display:flex;justify-content:space-between;padding:2px 0;border-bottom:1px dotted #1e293b;
  gap:8px}
#ev-detail .kv .k{color:#64748b;font-size:10px;white-space:nowrap}
#ev-detail .kv .v{color:#e2e8f0;font-size:11px;font-variant-numeric:tabular-nums;
  font-family:'SF Mono',Consolas,monospace;text-align:right;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#ev-detail table.ev-stations{width:100%;border-collapse:collapse;margin-top:4px;font-size:10px}
#ev-detail table.ev-stations th{color:#64748b;text-transform:uppercase;font-size:9px;
  letter-spacing:0.05em;text-align:left;padding:3px 5px;border-bottom:1px solid #334155}
#ev-detail table.ev-stations td{color:#cbd5e1;padding:3px 5px;border-bottom:1px dotted #1e293b;
  font-family:'SF Mono',Consolas,monospace;font-size:10px}
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
let evidenceSelected = null; // {kind, id} of the currently-highlighted row

// Evidence map: dedicated Leaflet instance (NOT the Live map).
// the two maps have different jobs -- Live is real-time situational
// awareness, Evidence is post-hoc investigation. Sharing the Leaflet helper
// is fine; sharing the map state is not.
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
    banner.innerHTML = '<b style="color:#fbbf24">Running without --state-db.</b> ' +
      'The Evidence tab needs a persistent bbolt file to render historical events. ' +
      'Restart fusion with <code style="color:#cbd5e1">--state-db=/path/to/state.db</code> ' +
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
    rows.push({
      timeNs: c.cluster_time_ns,
      kind: fix ? 'solved' : (c.low_trust ? 'degraded' : 'target'),
      from: c.from,
      packetId: c.packet_id,
      emissionSeq: c.emission_seq || 0,
      summary: ((c.observations||[]).length) + ' station' +
        (((c.observations||[]).length === 1) ? '' : 's') +
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
    row.innerHTML =
      '<div class="ev-time">'+escHtml(tstr)+'</div>' +
      '<div class="ev-kind ev-kind-'+r.kind+'">'+escHtml(r.kind)+'</div>' +
      '<div class="ev-from">'+escHtml(r.from)+(r.emissionSeq>0?(':#'+r.emissionSeq):'')+'</div>' +
      '<div class="'+trustClass+'">'+escHtml(trustText)+'</div>' +
      '<div class="ev-summary">'+escHtml(r.summary)+'</div>';
    const rowKey = r.from + '|' + r.packetId + '|' + r.emissionSeq;
    row.addEventListener('click', () => evidenceShowDetail(r, row));
    if (evidenceSelected === rowKey) row.classList.add('selected');
    tl.appendChild(row);
  }
}

function evidenceShowDetail(r, rowEl){
  // Highlight selected row.
  document.querySelectorAll('#ev-timeline .ev-row').forEach(x=>x.classList.remove('selected'));
  rowEl.classList.add('selected');
  evidenceSelected = r.from + '|' + r.packetId + '|' + r.emissionSeq;
  // Pan + open popup for the matching map marker. No-op when the row is
  // an unsolved cluster (no fix -> no marker on the map).
  evidenceHighlightFix(evidenceSelected);
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
      html += '<div class="kv"><span class="k">trust</span><span class="v" style="color:#ef4444">LOW (lock missing for one or more obs)</span></div>';
    }
  }

  if (!r.fix && !(r.cluster && r.cluster.observations && r.cluster.observations.length)) {
    html += '<div class="ev-empty" style="padding-top:20px">No persisted detail for this event yet.</div>';
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
