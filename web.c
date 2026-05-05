/*
 * meshtastic-sniffer: built-in web dashboard.
 *
 * Single-threaded TCP listener that accepts HTTP/1.1 connections.
 * GET /events upgrades to SSE; the socket is kept and registered in
 * a small client list. web_publish_line() iterates the list and
 * writes non-blocking; broken sockets are reaped.
 *
 * The dashboard HTML is a single embedded string -- Leaflet map +
 * node table + message log + discoveries panel, all wired to the
 * /events SSE stream.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE
#include "web.h"
#include "cot.h"
#include "keyset.h"
#include "options.h"

extern keyset_t *app_get_keyset(void);
extern int       app_add_runtime_extra_freq(uint64_t f_hz, int bw_hz, int sf, int cr);

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_SSE_CLIENTS 8

static int  g_listen_fd = -1;
static int  g_sse_fds[MAX_SSE_CLIENTS];
static int  g_sse_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_thread;
static volatile int g_thread_running = 0;

static const char DASHBOARD_HTML[] =
"<!doctype html>\n"
"<html><head><meta charset=\"utf-8\">\n"
"<title>meshtastic-sniffer</title>\n"
"<link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\">\n"
"<script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\"></script>\n"
"<style>\n"
"body{margin:0;font-family:system-ui,sans-serif;background:#181818;color:#eee;height:100vh;display:flex;flex-direction:column;}\n"
"#tabs{display:flex;background:#222;border-bottom:1px solid #444;}\n"
"#tabs button{background:none;color:#aaa;border:none;padding:8px 14px;cursor:pointer;font:inherit;}\n"
"#tabs button.active{color:#9bf;border-bottom:2px solid #9bf;}\n"
".tab{flex:1;display:none;overflow:hidden;}\n"
".tab.active{display:flex;}\n"
".grid{display:grid;grid-template-columns:2fr 1fr;grid-template-rows:1fr 1fr 1fr 1fr;height:100%;width:100%;gap:1px;background:#000;}\n"
".pane{padding:6px;overflow:auto;}\n"
"#map{height:100%;width:100%;}\n"
"h2{margin:0 0 6px 0;font-size:13px;color:#9bf;border-bottom:1px solid #444;padding-bottom:4px;}\n"
"table{width:100%;border-collapse:collapse;font-size:11px;}\n"
"th,td{text-align:left;padding:2px 6px;border-bottom:1px solid #333;}\n"
"th{color:#9bf;font-weight:600;}\n"
".text{color:#cfc;font-style:italic;}\n"
".disc{color:#fc9;}\n"
".atak{color:#f9c;}\n"
".muted{color:#888;font-size:10px;}\n"
".log-item{padding:2px 0;border-bottom:1px dotted #2c2c2c;font-size:11px;}\n"
".log-item .ts{color:#666;font-size:10px;margin-right:6px;}\n"
"#config{padding:18px;overflow:auto;width:100%;}\n"
"#config h3{color:#9bf;margin:18px 0 6px 0;}\n"
"#config{padding:14px 18px;overflow:auto;max-width:780px;}\n"
"#config h3{margin:14px 0 6px 0;font-size:14px;color:#9bf;border-bottom:1px solid #333;padding-bottom:3px;}\n"
"#config textarea,#config input[type=text]{width:100%;box-sizing:border-box;background:#0d0d0d;color:#eee;border:1px solid #444;padding:6px;font-family:monospace;font-size:12px;}\n"
"#config button{background:#225;color:#cef;border:1px solid #58c;padding:6px 14px;cursor:pointer;margin-top:6px;margin-right:8px;}\n"
"#config .hint{color:#888;font-size:11px;margin-top:4px;display:block;}\n"
"#config .row{margin-bottom:14px;}\n"
"#config .row span{color:#888;font-size:11px;}\n"
".status-ok{color:#9f9;}.status-err{color:#f99;}\n"
"</style></head><body>\n"
"<div id=\"tabs\">\n"
"  <button id=\"tab-live\" class=\"active\" onclick=\"showTab('live')\">Live</button>\n"
"  <button id=\"tab-spectrum\" onclick=\"showTab('spectrum')\">Spectrum</button>\n"
"  <button id=\"tab-config\" onclick=\"showTab('config')\">Config</button>\n"
"</div>\n"
"<div id=\"live\" class=\"tab active\">\n"
"  <div class=\"grid\">\n"
"    <div class=\"pane\" style=\"grid-row:span 4;padding:0;\"><div id=\"map\"></div></div>\n"
"    <div class=\"pane\"><h2>Nodes <button onclick=\"exportCsv()\" style=\"float:right;background:#225;color:#cef;border:1px solid #58c;padding:1px 8px;font-size:10px;cursor:pointer;\">CSV</button></h2><table id=\"nodes\"><thead><tr><th>ID</th><th>Name</th><th>SNR</th><th>Last seen</th></tr></thead><tbody></tbody></table></div>\n"
"    <div class=\"pane\"><h2>Channels <span class=muted>(by hash)</span></h2><table id=\"channels\"><thead><tr><th>Hash</th><th>Name</th><th>Preset</th><th>Frames</th><th>Decrypt</th><th>Last</th></tr></thead><tbody></tbody></table></div>\n"
"    <div class=\"pane\"><h2>Messages</h2><div id=\"msgs\"></div></div>\n"
"    <div class=\"pane\"><h2>Discoveries &amp; ATAK</h2><div id=\"disc\"></div></div>\n"
"  </div>\n"
"</div>\n"
"<div id=\"spectrum\" class=\"tab\" style=\"flex-direction:column;background:#000;\">\n"
"  <canvas id=\"waterfall\" style=\"flex:1;width:100%;display:block;background:#000;\"></canvas>\n"
"  <div id=\"spec-axis\" style=\"height:18px;color:#9bf;font-size:10px;font-family:monospace;padding:2px 0;\"></div>\n"
"</div>\n"
"<div id=\"config\" class=\"tab\">\n"
"  <h3>Add keys</h3>\n"
"  <div class=\"row\">\n"
"    <textarea id=\"keys-input\" rows=\"4\" placeholder=\"LongFast=default&#10;Ops=hex:00112233445566778899aabbccddeeff&#10;Crew=base64:AQ==\"></textarea>\n"
"    <button onclick=\"postKeys()\">Add</button>\n"
"    <span id=\"keys-status\" class=\"hint\"></span>\n"
"    <div class=\"hint\">One spec per line. ChannelName=SPEC (recommended) or bare SPEC. SPEC: default | simple0..10 | hex:&hellip; | base64:&hellip;</div>\n"
"  </div>\n"
"  <h3>Channel-share URL</h3>\n"
"  <div class=\"row\">\n"
"    <input id=\"share-input\" type=\"text\" placeholder=\"https://meshtastic.org/e/#&hellip;\">\n"
"    <button onclick=\"postShare()\">Add channel from URL</button>\n"
"    <span id=\"share-status\" class=\"hint\"></span>\n"
"    <div class=\"hint\">Paste the meshtastic.org/e/ link from a channel-share QR code. Decoded protobuf is added to the keyset.</div>\n"
"  </div>\n"
"  <h3>Add extra frequency</h3>\n"
"  <div class=\"row\">\n"
"    <input id=\"freq-input\" type=\"text\" placeholder=\"915183000:bw=250000:sf=11:cr=5\">\n"
"    <button onclick=\"postFreq()\">Add</button>\n"
"    <span id=\"freq-status\" class=\"hint\"></span>\n"
"    <div class=\"hint\">HZ:bw=BW:sf=SF:cr=CR -- promote an off-grid sighting or any custom freq to a real decoder slot.</div>\n"
"  </div>\n"
"  <h3>CoT multicast</h3>\n"
"  <div class=\"row\">\n"
"    <input id=\"cot-input\" type=\"text\" placeholder=\"239.2.3.1:6969 (empty to disable)\">\n"
"    <button onclick=\"postCot()\">Apply</button>\n"
"    <span id=\"cot-status\" class=\"hint\"></span>\n"
"    <div class=\"hint\">Republish positioned nodes (POSITION + ATAK PLI) as CoT XML to a multicast group. ATAK-CIV / WinTAK / iTAK on the same LAN pick them up automatically.</div>\n"
"  </div>\n"
"</div>\n"
"<script>\n"
"function showTab(name){for(const t of ['live','spectrum','config']){document.getElementById(t).classList.toggle('active',t===name);document.getElementById('tab-'+t).classList.toggle('active',t===name);}if(name==='live')setTimeout(()=>map.invalidateSize(),60);if(name==='spectrum')resizeWaterfall();}\n"
"// Hide the Spectrum tab unless the server has --web-spectrum enabled.\n"
"// SSE 'SPECTRUM' events only flow when that flag is set; without it, the\n"
"// tab would just show a blank black canvas.\n"
"fetch('/api/info').then(r=>r.json()).then(info=>{if(!info.spectrum){const b=document.getElementById('tab-spectrum');if(b)b.style.display='none';}}).catch(()=>{});\n"
"const map = L.map('map').setView([39.5, -98.0], 4);\n"
"L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom:19, attribution:'&copy; OSM'}).addTo(map);\n"
"const markers = {}, trails = {}, nodes = {}, edges = {}, channels = {};\n"
"const msgsEl = document.getElementById('msgs'); const discEl = document.getElementById('disc'); const tbody = document.querySelector('#nodes tbody');\n"
"const chTbody = document.querySelector('#channels tbody');\n"
"function fmtTime(t){return new Date(t*1000).toLocaleTimeString();}\n"
"function refreshNodes(){\n"
"  const ids = Object.keys(nodes).sort((a,b)=>nodes[b].ts-nodes[a].ts);\n"
"  tbody.innerHTML = '';\n"
"  for (const id of ids){const n=nodes[id]; const tr=document.createElement('tr');\n"
"    const snr = n.snr_db !== undefined ? n.snr_db.toFixed(1) + ' dB' : '<span class=muted>-</span>';\n"
"    const name = n.name || `<span class=muted>${n.frames||1}\\u00d7</span>`;\n"
"    tr.innerHTML=`<td>${id}</td><td>${name}</td><td>${snr}</td><td>${fmtTime(n.ts)}</td>`;\n"
"    tbody.appendChild(tr);}\n"
"}\n"
"function refreshChannels(){\n"
"  const hashes = Object.keys(channels).sort((a,b)=>channels[b].ts-channels[a].ts);\n"
"  chTbody.innerHTML = '';\n"
"  for (const h of hashes){const c=channels[h]; const tr=document.createElement('tr');\n"
"    const hashHex = '0x'+(parseInt(h)&0xff).toString(16).padStart(2,'0');\n"
"    const name = c.name || '<span class=muted>?</span>';\n"
"    const preset = c.preset || '<span class=muted>?</span>';\n"
"    const dec = c.total ? Math.round(100*c.decrypted/c.total) : 0;\n"
"    const decCell = c.decrypted>0 ? `${c.decrypted}/${c.total} (${dec}%)` : `<span class=muted>0/${c.total}</span>`;\n"
"    tr.innerHTML=`<td>${hashHex}</td><td>${name}</td><td>${preset}</td><td>${c.total}</td><td>${decCell}</td><td>${fmtTime(c.ts)}</td>`;\n"
"    chTbody.appendChild(tr);}\n"
"}\n"
"function exportCsv(){\n"
"  const rows = [['node_id','name','lat','lon','last_snr_db','last_seen']];\n"
"  for (const id of Object.keys(nodes)){const n=nodes[id];\n"
"    const ll = (markers[id] && markers[id].getLatLng) ? markers[id].getLatLng() : null;\n"
"    rows.push([id, (n.name||'').replace(/,/g,';'), ll?ll.lat.toFixed(7):'', ll?ll.lng.toFixed(7):'', n.snr_db!==undefined?n.snr_db.toFixed(1):'', new Date(n.ts*1000).toISOString()]);\n"
"  }\n"
"  const csv = rows.map(r=>r.join(',')).join('\\n');\n"
"  const blob = new Blob([csv], {type:'text/csv'}); const url = URL.createObjectURL(blob);\n"
"  const a = document.createElement('a'); a.href = url;\n"
"  a.download = `meshtastic-nodes-${new Date().toISOString().replace(/[:.]/g,'-')}.csv`;\n"
"  a.click(); setTimeout(()=>URL.revokeObjectURL(url), 1000);\n"
"}\n"
"function pushTo(el, html, ts){\n"
"  const div = document.createElement('div'); div.className='log-item';\n"
"  div.innerHTML = `<span class=ts>${fmtTime(ts||Date.now()/1000)}</span>${html}`;\n"
"  el.insertBefore(div, el.firstChild);\n"
"  while (el.children.length>40) el.removeChild(el.lastChild);\n"
"}\n"
"function updateTrail(id, ll){\n"
"  if (!trails[id]) trails[id] = {pts:[], line:null};\n"
"  trails[id].pts.push(ll);\n"
"  if (trails[id].pts.length > 8) trails[id].pts.shift();\n"
"  if (trails[id].line) map.removeLayer(trails[id].line);\n"
"  if (trails[id].pts.length > 1)\n"
"    trails[id].line = L.polyline(trails[id].pts, {color:'#9bf',weight:2,opacity:0.6}).addTo(map);\n"
"}\n"
"// Mesh edge: draw a line from src node to dst node when both are positioned.\n"
"// Used for relay_node hints and NEIGHBORINFO entries. SNR scales opacity.\n"
"function noteEdge(srcId, dstId, snr){\n"
"  if (!srcId || !dstId || srcId===dstId) return;\n"
"  if (!markers[srcId] || !markers[dstId]) return;\n"
"  const k = srcId<dstId ? srcId+'|'+dstId : dstId+'|'+srcId;\n"
"  const a = markers[srcId].getLatLng(), b = markers[dstId].getLatLng();\n"
"  // 0 dB -> 1.0 opacity, -20 dB -> 0.2 opacity, clamp.\n"
"  const op = Math.max(0.2, Math.min(1.0, 1.0 + (snr||0)/30.0));\n"
"  if (edges[k]) map.removeLayer(edges[k]);\n"
"  edges[k] = L.polyline([a,b], {color:'#fc6',weight:1,opacity:op,dashArray:'3,4'}).addTo(map);\n"
"}\n"
"const wfCanvas = document.getElementById('waterfall'); const wfCtx = wfCanvas.getContext('2d');\n"
"let wfImg = null, wfRow = 0, wfMeta = null;\n"
"function resizeWaterfall(){\n"
"  const r = wfCanvas.parentElement.getBoundingClientRect();\n"
"  wfCanvas.width = Math.max(256, r.width|0); wfCanvas.height = Math.max(256, (r.height-22)|0);\n"
"  wfImg = wfCtx.createImageData(wfCanvas.width, wfCanvas.height);\n"
"  for (let i=0;i<wfImg.data.length;i+=4){wfImg.data[i+3]=255;}\n"
"  wfRow = 0; if (wfMeta) updateAxis(wfMeta);\n"
"}\n"
"window.addEventListener('resize', resizeWaterfall);\n"
"function dbToColor(db){\n"
"  // -120 dB = black, -40 dB = red, in a typical heatmap.\n"
"  let t = (db + 120) / 80; if (t<0) t=0; if (t>1) t=1;\n"
"  const r = Math.min(255, Math.floor(255*Math.max(0, t-0.33)*1.5));\n"
"  const g = Math.min(255, Math.floor(255*Math.max(0, t-0.66)*3));\n"
"  const b = Math.min(255, Math.floor(255*Math.min(t,0.5)*2));\n"
"  return [r,g,b];\n"
"}\n"
"function updateAxis(m){\n"
"  const lo = (m.f_center - m.samp_rate/2)/1e6;\n"
"  const hi = (m.f_center + m.samp_rate/2)/1e6;\n"
"  document.getElementById('spec-axis').textContent = `${lo.toFixed(2)} MHz \\u2014 ${m.f_center/1e6.toFixed(2)} MHz \\u2014 ${hi.toFixed(2)} MHz   (\\u0394 ${(m.samp_rate/1e6).toFixed(1)} MHz)`;\n"
"}\n"
"function drawSpectrumRow(bins, m){\n"
"  if (!wfImg) resizeWaterfall();\n"
"  wfMeta = m; updateAxis(m);\n"
"  const W = wfCanvas.width, H = wfCanvas.height;\n"
"  // shift everything up one row, write new row at bottom\n"
"  wfImg.data.copyWithin(0, W*4, wfImg.data.length);\n"
"  const yOffset = (H-1)*W*4;\n"
"  for (let x = 0; x < W; ++x){\n"
"    const b = bins[Math.floor(x * bins.length / W)];\n"
"    const c = dbToColor(b);\n"
"    const i = yOffset + x*4;\n"
"    wfImg.data[i]=c[0]; wfImg.data[i+1]=c[1]; wfImg.data[i+2]=c[2]; wfImg.data[i+3]=255;\n"
"  }\n"
"  wfCtx.putImageData(wfImg, 0, 0);\n"
"}\n"
"const es = new EventSource('/events');\n"
"es.onmessage = (e) => {\n"
"  let p; try { p = JSON.parse(e.data); } catch(_){ return; }\n"
"  if (p.event === 'OFF_GRID_LORA') {\n"
"    pushTo(discEl, `<span class=disc>off-grid: ${(p.f_hz/1e6).toFixed(3)} MHz, SNR ${p.snr_db.toFixed(1)} dB</span>`, p.ts);\n"
"    return;\n"
"  }\n"
"  if (p.event === 'SPECTRUM') { drawSpectrumRow(p.bins, p); return; }\n"
"  if (!p.from) return;\n"
"  // Per-channel stats: bucket by channel_hash so unknown networks are visible too.\n"
"  if (p.channel !== undefined){\n"
"    const h = p.channel;\n"
"    if (!channels[h]) channels[h] = {total:0, decrypted:0, ts:0};\n"
"    const c = channels[h]; c.total++; c.ts = p.ts;\n"
"    if (p.channel_name) c.name = p.channel_name;\n"
"    if (p.preset) c.preset = p.preset;\n"
"    // 'decrypted' is only emitted when false; presence of port_name/portnum implies success.\n"
"    if (p.decrypted !== false && p.port_name) c.decrypted++;\n"
"    refreshChannels();\n"
"  }\n"
"  const id = p.from;\n"
"  if (!nodes[id]) nodes[id] = {ts:0, frames:0};\n"
"  const n = nodes[id]; n.ts = p.ts; n.frames = (n.frames||0) + 1;\n"
"  if (p.snr_db !== undefined) n.snr_db = p.snr_db;\n"
"  if (p.long_name) n.name = p.long_name + (p.short_name ? ' ['+p.short_name+']' : '');\n"
"  else if (p.atak_callsign) n.name = p.atak_callsign + ' ['+p.atak_team+']';\n"
"  if (p.lat !== undefined && p.lon !== undefined) {\n"
"    const ll = [p.lat, p.lon];\n"
"    if (markers[id]) markers[id].setLatLng(ll);\n"
"    else markers[id] = L.marker(ll).addTo(map).bindPopup(`<b>${id}</b><br>${n.name||''}`);\n"
"    updateTrail(id, ll);\n"
"    if (Object.keys(markers).length === 1) map.setView(ll, 10);\n"
"  }\n"
"  // Relay-hop hint: header.relay_node is the upper byte of the relayer's node id.\n"
"  // Useful enough to draw an approximate edge between any two known nodes whose\n"
"  // ids share that upper byte and are both positioned.\n"
"  // (Real edges come from NEIGHBORINFO_APP packets.)\n"
"  if (p.neighbors && Array.isArray(p.neighbors)){\n"
"    for (const nb of p.neighbors) noteEdge(id, nb.id, nb.snr_db);\n"
"  }\n"
"  if (p.text) pushTo(msgsEl, `<b>${n.name||id}</b> <span class=muted>${p.channel_name||''}</span>: <span class=text>${p.text}</span>`, p.ts);\n"
"  if (p.atak_callsign) pushTo(discEl, `<span class=atak>ATAK ${p.atak_callsign} (${p.atak_team}/${p.atak_role})${p.atak_chat?' chat: '+p.atak_chat:''}</span>`, p.ts);\n"
"  refreshNodes();\n"
"};\n"
"async function postBody(path, body){\n"
"  const r = await fetch(path, {method:'POST', body});\n"
"  return r.ok ? await r.json() : {error:'HTTP '+r.status};\n"
"}\n"
"function setStatus(id, txt, ok){const el=document.getElementById(id); el.textContent=txt; el.className='hint '+(ok?'status-ok':'status-err');}\n"
"async function postKeys(){\n"
"  const body = document.getElementById('keys-input').value.replace(/\\n/g,',');\n"
"  const r = await postBody('/api/keys', body);\n"
"  if (r.error) setStatus('keys-status', r.error, false);\n"
"  else { setStatus('keys-status', 'added '+r.added, true); document.getElementById('keys-input').value=''; }\n"
"}\n"
"async function postShare(){\n"
"  const body = document.getElementById('share-input').value;\n"
"  const r = await postBody('/api/share-url', body);\n"
"  if (r.error) setStatus('share-status', r.error, false);\n"
"  else { setStatus('share-status', 'added '+r.added+' channel(s)', true); document.getElementById('share-input').value=''; }\n"
"}\n"
"async function postFreq(){\n"
"  const body = document.getElementById('freq-input').value;\n"
"  const r = await postBody('/api/extra-freq', body);\n"
"  if (r.error) setStatus('freq-status', r.error, false);\n"
"  else { setStatus('freq-status', 'channel '+r.channel_id, true); document.getElementById('freq-input').value=''; }\n"
"}\n"
"async function postCot(){\n"
"  const body = document.getElementById('cot-input').value;\n"
"  const r = await postBody('/api/cot-multicast', body);\n"
"  if (r.error) setStatus('cot-status', r.error, false);\n"
"  else if (r.enabled === false) setStatus('cot-status', 'disabled', true);\n"
"  else setStatus('cot-status', r.host+':'+r.port, true);\n"
"}\n"
"</script></body></html>\n";

static int set_nonblock(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    return f < 0 ? -1 : fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static void send_all(int fd, const char *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (r <= 0) {
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            return;
        }
        sent += (size_t)r;
    }
}

static void serve_index(int fd) {
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", sizeof(DASHBOARD_HTML) - 1);
    send_all(fd, hdr, (size_t)n);
    send_all(fd, DASHBOARD_HTML, sizeof(DASHBOARD_HTML) - 1);
    close(fd);
}

static void serve_404(int fd) {
    const char *r =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 9\r\nConnection: close\r\n\r\nnot found";
    send_all(fd, r, strlen(r));
    close(fd);
}

static void send_response(int fd, int code, const char *body)
{
    char hdr[256];
    size_t blen = body ? strlen(body) : 0;
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        code, code == 200 ? "OK" : (code == 400 ? "Bad Request" : "Server Error"),
        blen);
    send_all(fd, hdr, (size_t)n);
    if (body) send_all(fd, body, blen);
    close(fd);
}

/* Find the body in an HTTP request that's already been recv'd. */
static const char *find_body(const char *buf)
{
    const char *p = strstr(buf, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

/* URL-decode in place. Returns new length. */
static size_t url_decode_inplace(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%' && r[1] && r[2]) {
            char h[3] = {r[1], r[2], 0};
            *w++ = (char)strtol(h, NULL, 16);
            r += 3;
        } else if (*r == '+') {
            *w++ = ' '; ++r;
        } else {
            *w++ = *r++;
        }
    }
    *w = 0;
    return (size_t)(w - s);
}

/* Tiny base64 lookup of one char, copied from keyset.c. */
static int b64v(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

/* meshtastic.org/e/ URLs are of the form:
 *   meshtastic.org/e/?#CgUYAyIBAQ           (single-channel base64-url)
 *   meshtastic.org/e/?#CHANNELSET=BASE64URL (also seen)
 * The base64-url payload is a protobuf ChannelSet { Channel channels = 1 }
 * where each Channel has a settings { name, psk } sub-message.
 *
 * For each channel found, calls keyset_add(name, psk_bytes, psk_len).
 * Returns the number of channels added, or -1 on parse error. */
/* Public wrapper so main.c can use the same decoder for --share-url. */
int web_decode_share_url(keyset_t *ks, const char *url) { extern int decode_channel_share(keyset_t *, const char *); return decode_channel_share(ks, url); }

int decode_channel_share(keyset_t *ks, const char *url_or_b64)
{
    if (!ks || !url_or_b64) return -1;
    /* Locate the base64 portion: after '#' or after '=' or whole string. */
    const char *p = url_or_b64;
    const char *hash = strchr(p, '#');
    if (hash) p = hash + 1;
    const char *eq = strchr(p, '=');
    if (eq) p = eq + 1;

    /* base64-url decode (with no required padding) */
    uint8_t buf[256]; size_t out = 0;
    uint32_t accum = 0; int bits = 0;
    for (; *p && out < sizeof(buf); ++p) {
        if (*p == '=' || *p == '&' || *p == ' ' || *p == '\r' || *p == '\n') break;
        int v = b64v(*p);
        if (v < 0) return -1;
        accum = (accum << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buf[out++] = (uint8_t)((accum >> bits) & 0xff);
        }
    }
    if (out == 0) return -1;

    /* Parse ChannelSet protobuf:
     *   field 1: repeated Channel { settings (1) { psk (1, bytes), name (2, string), ... } }
     *   field 1 alt: also some firmware emits Channel directly.
     * Walk top-level fields; for each length-delimited field 1, parse
     * inner Channel; for inner field 1, parse Settings; pull psk + name. */
    int added = 0;
    const uint8_t *bp = buf, *bend = buf + out;
    while (bp < bend) {
        /* read tag */
        uint64_t tag = 0; int shift = 0;
        while (bp < bend) {
            uint8_t b = *bp++;
            tag |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        uint32_t fld = (uint32_t)(tag >> 3);
        uint32_t wt  = (uint32_t)(tag & 0x7);
        if (wt == 2) {
            /* length-delimited */
            uint64_t l = 0; shift = 0;
            while (bp < bend) {
                uint8_t b = *bp++;
                l |= (uint64_t)(b & 0x7f) << shift;
                if (!(b & 0x80)) break;
                shift += 7;
            }
            if ((uint64_t)(bend - bp) < l) break;
            const uint8_t *cp = bp; const uint8_t *cend = bp + l;
            bp += l;

            if (fld != 1) continue;  /* not a Channel */

            /* Parse Channel: look for field 1 (settings) submessage. */
            uint8_t  psk[32]; size_t psk_len = 0;
            char     name[32]; name[0] = 0;
            while (cp < cend) {
                uint64_t t2 = 0; int s2 = 0;
                while (cp < cend) {
                    uint8_t b = *cp++;
                    t2 |= (uint64_t)(b & 0x7f) << s2;
                    if (!(b & 0x80)) break;
                    s2 += 7;
                }
                uint32_t f2 = (uint32_t)(t2 >> 3);
                uint32_t w2 = (uint32_t)(t2 & 0x7);
                if (w2 != 2) continue;
                uint64_t l2 = 0; s2 = 0;
                while (cp < cend) {
                    uint8_t b = *cp++;
                    l2 |= (uint64_t)(b & 0x7f) << s2;
                    if (!(b & 0x80)) break;
                    s2 += 7;
                }
                if ((uint64_t)(cend - cp) < l2) break;
                const uint8_t *sp = cp; const uint8_t *send = cp + l2; cp += l2;
                if (f2 != 1) continue;     /* not the settings sub-message */

                /* Parse ChannelSettings: field 1 = psk (bytes), field 2 = name (string). */
                while (sp < send) {
                    uint64_t t3 = 0; int s3 = 0;
                    while (sp < send) {
                        uint8_t b = *sp++;
                        t3 |= (uint64_t)(b & 0x7f) << s3;
                        if (!(b & 0x80)) break;
                        s3 += 7;
                    }
                    uint32_t f3 = (uint32_t)(t3 >> 3);
                    uint32_t w3 = (uint32_t)(t3 & 0x7);
                    if (w3 != 2) continue;
                    uint64_t l3 = 0; s3 = 0;
                    while (sp < send) {
                        uint8_t b = *sp++;
                        l3 |= (uint64_t)(b & 0x7f) << s3;
                        if (!(b & 0x80)) break;
                        s3 += 7;
                    }
                    if ((uint64_t)(send - sp) < l3) break;
                    if (f3 == 1 && l3 <= sizeof(psk)) {   /* psk */
                        memcpy(psk, sp, l3); psk_len = (size_t)l3;
                    } else if (f3 == 2 && l3 < sizeof(name)) {
                        memcpy(name, sp, l3); name[l3] = 0;
                    }
                    sp += l3;
                }
            }

            if (psk_len > 0) {
                /* simpleN expansion: a one-byte psk N means simpleN. */
                if (psk_len == 1) {
                    extern const uint8_t MESH_DEFAULT_PSK[16];
                    uint8_t expanded[16];
                    memcpy(expanded, MESH_DEFAULT_PSK, 16);
                    expanded[15] = psk[0];
                    if (keyset_add(ks, name[0] ? name : NULL, expanded, 16) == 0) ++added;
                } else if (psk_len == 16 || psk_len == 32) {
                    if (keyset_add(ks, name[0] ? name : NULL, psk, psk_len) == 0) ++added;
                }
            }
        } else {
            /* skip non-length fields cheaply */
            if (wt == 0) { while (bp < bend && (*bp++ & 0x80)) {} }
            else if (wt == 1) bp += 8;
            else if (wt == 5) bp += 4;
        }
    }
    return added;
}

static void promote_to_sse(int fd) {
    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n"
        "retry: 2000\n\n";
    send_all(fd, hdr, strlen(hdr));
    set_nonblock(fd);

    pthread_mutex_lock(&g_lock);
    if (g_sse_count < MAX_SSE_CLIENTS) {
        g_sse_fds[g_sse_count++] = fd;
        if (verbose) fprintf(stderr, "web: SSE client connected (%d total)\n", g_sse_count);
    } else {
        close(fd);
    }
    pthread_mutex_unlock(&g_lock);
}

/* Read an HTTP request fully: headers + (Content-Length-bound) body.
 * Returns total bytes in buf (NUL-terminated), or 0 on error. */
static size_t recv_full_request(int fd, char *buf, size_t cap)
{
    size_t got = 0;
    /* Read until we have headers ("\r\n\r\n"). */
    while (got < cap - 1) {
        ssize_t n = recv(fd, buf + got, cap - 1 - got, 0);
        if (n <= 0) return 0;
        got += (size_t)n;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    /* Parse Content-Length to know how much body we still need. */
    const char *cl = strstr(buf, "Content-Length:");
    if (!cl) cl = strstr(buf, "content-length:");
    if (cl) {
        cl = strchr(cl, ':');
        if (cl) {
            size_t need = (size_t)strtoul(cl + 1, NULL, 10);
            const char *body = strstr(buf, "\r\n\r\n");
            size_t header_len = body ? (size_t)((body + 4) - buf) : got;
            size_t have = got > header_len ? got - header_len : 0;
            while (have < need && got < cap - 1) {
                ssize_t n = recv(fd, buf + got, cap - 1 - got, 0);
                if (n <= 0) break;
                got += (size_t)n;
                have += (size_t)n;
                buf[got] = 0;
            }
        }
    }
    return got;
}

static void *web_thread(void *arg)
{
    (void)arg;
    while (g_thread_running) {
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        int fd = accept(g_listen_fd, (struct sockaddr *)&peer, &peerlen);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }

        /* 16 KB request buffer -- enough for hundreds of keys or a long share URL. */
        static __thread char buf[16384];
        size_t got = recv_full_request(fd, buf, sizeof(buf));
        if (!got) { close(fd); continue; }

        if (strncmp(buf, "GET / ",        6) == 0 ||
            strncmp(buf, "GET /\r",       6) == 0 ||
            strncmp(buf, "GET /index",   10) == 0) serve_index(fd);
        else if (strncmp(buf, "GET /events", 11) == 0) promote_to_sse(fd);
        else if (strncmp(buf, "GET /api/info", 13) == 0) {
            extern bool opt_web_spectrum;
            char resp[128];
            snprintf(resp, sizeof(resp), "{\"spectrum\":%s}",
                     opt_web_spectrum ? "true" : "false");
            send_response(fd, 200, resp);
        }
        else if (strncmp(buf, "POST /api/keys", 14) == 0) {
            const char *body = find_body(buf);
            keyset_t *ks = app_get_keyset();
            if (!body || !ks) { send_response(fd, 400, "{\"error\":\"no body or no keyset\"}"); continue; }
            int added = keyset_parse_csv(ks, body);
            char resp[64]; snprintf(resp, sizeof(resp), "{\"added\":%d}", added);
            send_response(fd, 200, resp);
        }
        else if (strncmp(buf, "POST /api/share-url", 19) == 0) {
            const char *body = find_body(buf);
            keyset_t *ks = app_get_keyset();
            if (!body || !ks) { send_response(fd, 400, "{\"error\":\"no body or no keyset\"}"); continue; }
            char dec[1024]; size_t bl = strlen(body);
            if (bl >= sizeof(dec)) bl = sizeof(dec) - 1;
            memcpy(dec, body, bl); dec[bl] = 0;
            url_decode_inplace(dec);
            int added = decode_channel_share(ks, dec);
            char resp[64];
            if (added < 0) { send_response(fd, 400, "{\"error\":\"could not parse share URL\"}"); continue; }
            snprintf(resp, sizeof(resp), "{\"added\":%d}", added);
            send_response(fd, 200, resp);
        }
        else if (strncmp(buf, "POST /api/extra-freq", 20) == 0) {
            const char *body = find_body(buf);
            if (!body) { send_response(fd, 400, "{\"error\":\"no body\"}"); continue; }
            /* Format: "HZ:bw=BW:sf=SF:cr=CR" -- match CLI parser. */
            uint64_t f = strtoull(body, NULL, 10);
            int bw = 250000, sf = 11, cr = 5;
            const char *p = body;
            while ((p = strchr(p, ':')) != NULL) {
                ++p;
                if (!strncmp(p, "bw=", 3)) bw = atoi(p + 3);
                else if (!strncmp(p, "sf=", 3)) sf = atoi(p + 3);
                else if (!strncmp(p, "cr=", 3)) cr = atoi(p + 3);
            }
            int id = (f && bw) ? app_add_runtime_extra_freq(f, bw, sf, cr) : -1;
            char resp[64];
            if (id < 0) { send_response(fd, 400, "{\"error\":\"add failed\"}"); continue; }
            snprintf(resp, sizeof(resp), "{\"channel_id\":%d}", id);
            send_response(fd, 200, resp);
        }
        else if (strncmp(buf, "POST /api/cot-multicast", 23) == 0) {
            const char *body = find_body(buf);
            if (!body) { send_response(fd, 400, "{\"error\":\"no body\"}"); continue; }
            /* Body: "HOST:PORT" or empty to disable. */
            char host[64]; int port = 6969;
            const char *colon = strchr(body, ':');
            if (!colon || !*body) {
                cot_set_endpoint(NULL, 0);
                send_response(fd, 200, "{\"enabled\":false}");
                continue;
            }
            size_t hl = (size_t)(colon - body);
            if (hl >= sizeof(host)) hl = sizeof(host) - 1;
            memcpy(host, body, hl); host[hl] = 0;
            port = atoi(colon + 1);
            int rc = cot_set_endpoint(host, port);
            char resp[128];
            if (rc < 0) { send_response(fd, 400, "{\"error\":\"could not bind multicast\"}"); continue; }
            snprintf(resp, sizeof(resp), "{\"enabled\":true,\"host\":\"%s\",\"port\":%d}", host, port);
            send_response(fd, 200, resp);
        }
        else serve_404(fd);
    }
    return NULL;
}

void web_init(int port)
{
    if (port <= 0) return;

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) { perror("web: socket"); return; }
    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("web: bind"); close(g_listen_fd); g_listen_fd = -1; return;
    }
    if (listen(g_listen_fd, 16) < 0) {
        perror("web: listen"); close(g_listen_fd); g_listen_fd = -1; return;
    }

    g_thread_running = 1;
    if (pthread_create(&g_thread, NULL, web_thread, NULL) != 0) {
        close(g_listen_fd); g_listen_fd = -1; g_thread_running = 0; return;
    }
    pthread_setname_np(g_thread, "web");
    fprintf(stderr, "web: listening on port %d\n", port);
}

void web_publish_line(const char *json, size_t len)
{
    if (!json || len == 0) return;
    /* Wrap as SSE: "data: <json>\n\n" */
    char  hdr[8] = "data: ";
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_sse_count; ) {
        int fd = g_sse_fds[i];
        ssize_t r1 = send(fd, hdr,  6,    MSG_NOSIGNAL | MSG_DONTWAIT);
        ssize_t r2 = send(fd, json, len,  MSG_NOSIGNAL | MSG_DONTWAIT);
        ssize_t r3 = send(fd, "\n", 1,    MSG_NOSIGNAL | MSG_DONTWAIT);
        if (r1 < 0 || r2 < 0 || r3 < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                close(fd);
                g_sse_fds[i] = g_sse_fds[--g_sse_count];
                continue;
            }
        }
        ++i;
    }
    pthread_mutex_unlock(&g_lock);
}

void web_shutdown(void)
{
    if (g_thread_running) {
        g_thread_running = 0;
        if (g_listen_fd >= 0) shutdown(g_listen_fd, SHUT_RDWR);
        pthread_join(g_thread, NULL);
    }
    if (g_listen_fd >= 0) { close(g_listen_fd); g_listen_fd = -1; }
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_sse_count; ++i) close(g_sse_fds[i]);
    g_sse_count = 0;
    pthread_mutex_unlock(&g_lock);
}
