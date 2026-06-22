/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
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
 */

#define _GNU_SOURCE
#include "web.h"
#include "c2.h"
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

#define MAX_SSE_CLIENTS    8
#define HISTORY_RING_SIZE  1024  /* recent events replayed to new SSE clients */

static int  g_listen_fd = -1;
static int  g_sse_fds[MAX_SSE_CLIENTS];
static int  g_sse_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_thread;
static volatile int g_thread_running = 0;

/* Ring buffer of recently-published JSON lines. New SSE clients (browser
 * refresh, multi-tab) get the buffer's contents replayed to them so the
 * dashboard reconstructs its node / channel / activity / topology state
 * without having to wait for new traffic. Bounded memory: average event
 * is ~200 bytes -> <250 KB at full capacity. Cleared on sniffer restart;
 * the long-term archive feature is a separate, opt-in concern. */
typedef struct {
    char  *buf;
    size_t len;
} history_entry_t;
static history_entry_t g_history[HISTORY_RING_SIZE];
static int g_history_head  = 0;  /* index of next slot to write */
static int g_history_count = 0;  /* total entries currently stored, capped */

static const char DASHBOARD_HTML[] =
"<!doctype html>\n"
"<html><head><meta charset=\"utf-8\">\n"
"<title>meshtastic-sniffer</title>\n"
"<link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\">\n"
"<script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\"></script>\n"
"<style>\n"
/* Slate palette mirroring inmarsat-sniffer: same family of tools.    */
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;height:100vh;display:flex;flex-direction:column;font-size:14px}\n"
/* Persistent stats header (always visible across tabs).               */
"#bar{height:44px;flex-shrink:0;background:#1e293b;display:flex;align-items:center;padding:0 16px;gap:20px;border-bottom:1px solid #334155}\n"
"#bar .title{font-weight:600;color:#f8fafc;letter-spacing:0.5px}\n"
"#bar .stat{color:#94a3b8;font-size:13px}\n"
"#bar .val{color:#38bdf8;font-weight:600;font-variant-numeric:tabular-nums;margin-left:6px}\n"
"#bar #status{margin-left:auto;color:#64748b;font-size:12px}\n"
"#theme-toggle{background:transparent;color:inherit;border:1px solid currentColor;border-radius:4px;padding:0 8px;cursor:pointer;font-size:14px;line-height:22px;height:24px;opacity:0.55}\n"
"#theme-toggle:hover{opacity:1}\n"
/* Tab strip below the bar.                                           */
"#tabs{display:flex;align-items:center;background:#1e293b;border-bottom:1px solid #334155;flex-shrink:0}\n"
"#tabs button{background:none;color:#64748b;border:none;padding:8px 16px;cursor:pointer;font:inherit;text-transform:uppercase;font-size:12px;letter-spacing:1px;font-weight:600;border-bottom:2px solid transparent}\n"
"#tabs button:hover{color:#94a3b8}\n"
"#tabs button.active{color:#38bdf8;border-bottom-color:#38bdf8}\n"
".tab{flex:1;display:none;overflow:hidden}\n"
".tab.active{display:flex}\n"
/* Live tab: 2-col grid, map left, side panels right.                 */
".grid{display:grid;grid-template-columns:2fr 1fr;grid-template-rows:1fr 1fr 1fr 1fr;height:100%;width:100%;gap:1px;background:#334155}\n"
".pane{padding:8px 10px;overflow:auto;background:#0f172a}\n"
"#map{height:100%;width:100%}\n"
".leaflet-container{background:#0f172a}\n"
"h2{margin:0 0 6px 0;font-size:12px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;border-bottom:1px solid #334155;padding-bottom:5px;display:flex;align-items:center;gap:8px}\n"
"h2 .muted{font-weight:400;text-transform:none;letter-spacing:0;color:#64748b;font-size:11px;flex:1}\n"
"h2 button{background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:3px;padding:3px 9px;cursor:pointer;font-size:11px}\n"
"h2 button:hover{background:#334155;color:#e2e8f0}\n"
"table{width:100%;border-collapse:collapse;font-size:12px;font-variant-numeric:tabular-nums}\n"
"th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #1e293b}\n"
"th{color:#64748b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}\n"
"tr:hover td{background:#1e293b}\n"
".text{color:#4ade80}\n"
".disc{color:#fb923c}\n"
"button.promote{background:#0c4a6e;color:#bae6fd;border:1px solid #0284c7;border-radius:3px;padding:1px 8px;cursor:pointer;font-size:10px;margin-left:6px}\n"
"button.promote:hover{background:#075985;color:#e0f2fe}\n"
"button.promote:disabled{opacity:0.6;cursor:default}\n"
"html.light button.promote{background:#e0f2fe;color:#0c4a6e;border-color:#0284c7}\n"
"html.light button.promote:hover{background:#bae6fd}\n"
".atak{color:#f472b6}\n"
".muted{color:#64748b}\n"
".log-item{padding:5px 0;border-bottom:1px dotted #1e293b;font-size:12px;line-height:1.5;word-wrap:break-word}\n"
".log-item .ts{color:#64748b;font-size:11px;margin-right:6px}\n"
".log-item b{color:#38bdf8}\n"
".port{color:#a78bfa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;background:#1e1b2e;padding:1px 5px;border-radius:3px;margin:0 4px}\n"
".snr-arrow{margin-left:3px;font-size:12px;line-height:1}\n"
".snr-up   {color:#4ade80}\n"
".snr-down {color:#f87171}\n"
".snr-flat {color:#64748b}\n"
/* Config + Activity tabs are plain block content -- override the
 * .tab.active{display:flex} that's right for Live.
 * Topology tab uses a flex column so the canvas can fill the pane. */
"#config.tab.active,#activity.tab.active{display:block}\n"
"#topology.tab.active{display:flex;flex-direction:column}\n"
"#topology{position:relative;overflow:hidden}\n"
"#topo-canvas{flex:1;display:block;width:100%;background:#0f172a;cursor:default}\n"
"#topo-canvas.hovering{cursor:pointer}\n"
"#topo-empty{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);max-width:480px;text-align:center;pointer-events:none;z-index:5}\n"
"#topo-legend{position:absolute;left:10px;top:10px;color:#64748b;font-size:11px;background:rgba(15,23,42,0.85);padding:7px 11px;border-radius:3px;border:1px solid #334155;z-index:4;pointer-events:none}\n"
"#topo-legend .l-node{display:inline-block;width:8px;height:8px;border-radius:50%;background:#38bdf8;vertical-align:middle;margin-right:3px}\n"
"#topo-legend .l-edge{display:inline-block;width:14px;height:1px;background:#94a3b8;vertical-align:middle;margin-right:3px}\n"
"html.light #topo-canvas{background:#ffffff}\n"
"html.light #topo-legend{background:rgba(255,255,255,0.92);color:#475569;border-color:#cbd5e1}\n"
/* Activity tab: per-channel cards in a responsive grid.              */
"#activity{padding:14px;overflow:auto}\n"
"#activity-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}\n"
".empty-hint{color:#64748b;font-size:13px;padding:24px 4px;text-align:center;font-style:italic}\n"
".chan-card{background:#1e293b;border:1px solid #334155;border-radius:5px;padding:12px 14px;display:flex;flex-direction:column;gap:7px;transition:border-color 0.2s}\n"
".chan-card.hot{border-color:#38bdf8}\n"
".chan-card.dead{opacity:0.55}\n"
".chan-card .top{display:flex;align-items:baseline;gap:6px;flex-wrap:wrap}\n"
".chan-card .nm{font-size:15px;font-weight:600;color:#f8fafc;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n"
".chan-card .ph{color:#64748b;font-size:11px;font-family:'SF Mono',Consolas,monospace}\n"
".chan-card .preset{color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}\n"
".chan-card .row2{display:flex;gap:16px;font-size:12px}\n"
".chan-card .row2 .lbl{color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;display:block}\n"
".chan-card .row2 .v{color:#38bdf8;font-weight:600;font-variant-numeric:tabular-nums;font-size:15px}\n"
".chan-card canvas{display:block;width:100%;height:36px;background:#0f172a;border-radius:3px}\n"
".chan-card .last{color:#64748b;font-size:11px}\n"
".chan-card .ch-list{margin-top:2px;display:flex;flex-direction:column;gap:3px}\n"
".chan-card .ch-row{display:flex;justify-content:space-between;font-size:12px;color:#cbd5e1;padding:3px 6px;border-radius:3px;background:#0f172a}\n"
".chan-card .ch-row .ch-nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-right:8px}\n"
".chan-card .ch-row .ch-stats{color:#64748b;font-variant-numeric:tabular-nums;font-size:11px;white-space:nowrap}\n"
".chan-card .ch-row.locked{color:#fb923c}\n"
"html.light .chan-card .ch-row{background:#f8fafc;color:#475569}\n"
"html.light .chan-card .ch-row.locked{color:#c2410c}\n"
"html.light .chan-card{background:#ffffff;border-color:#e2e8f0}\n"
"html.light .chan-card.hot{border-color:#0284c7}\n"
"html.light .chan-card .nm{color:#0f172a}\n"
"html.light .chan-card .ph{color:#94a3b8}\n"
"html.light .chan-card .preset{color:#64748b}\n"
"html.light .chan-card .row2 .lbl{color:#94a3b8}\n"
"html.light .chan-card .row2 .v{color:#0284c7}\n"
"html.light .chan-card canvas{background:#f1f5f9}\n"
"html.light .chan-card .last{color:#94a3b8}\n"
"html.light .empty-hint{color:#94a3b8}\n"
"#config{padding:18px;overflow:auto;max-width:820px;width:100%}\n"
"#config h3{margin:18px 0 6px 0;font-size:12px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;border-bottom:1px solid #334155;padding-bottom:4px}\n"
"#config h3:first-child{margin-top:0}\n"
"#config textarea,#config input[type=text]{width:100%;box-sizing:border-box;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:3px;padding:8px 10px;font-family:'SF Mono',Consolas,monospace;font-size:13px}\n"
"#config textarea:focus,#config input[type=text]:focus{outline:none;border-color:#38bdf8}\n"
"#config button{background:#0c4a6e;color:#bae6fd;border:1px solid #0284c7;border-radius:3px;padding:7px 16px;cursor:pointer;margin-top:6px;margin-right:8px;font-size:13px;font-weight:500}\n"
"#config button:hover{background:#075985;color:#e0f2fe}\n"
"#config .hint{color:#64748b;font-size:12px;margin-top:4px;display:block}\n"
"#config .row{margin-bottom:14px}\n"
".status-ok{color:#4ade80}\n"
".status-err{color:#f87171}\n"
/* Light theme overrides (dark stays default; toggled via html.light). */
"html.light body{background:#f8fafc;color:#1e293b}\n"
"html.light #bar{background:#ffffff;border-bottom-color:#cbd5e1}\n"
"html.light #bar .title{color:#0f172a}\n"
"html.light #bar .stat{color:#475569}\n"
"html.light #bar .val{color:#0284c7}\n"
"html.light #bar #status{color:#94a3b8}\n"
"html.light #tabs{background:#ffffff;border-bottom-color:#cbd5e1}\n"
"html.light #tabs button{color:#94a3b8}\n"
"html.light #tabs button:hover{color:#475569}\n"
"html.light #tabs button.active{color:#0284c7;border-bottom-color:#0284c7}\n"
"html.light .pane{background:#ffffff}\n"
"html.light h2{color:#0284c7;border-bottom-color:#e2e8f0}\n"
"html.light h2 .muted{color:#94a3b8}\n"
"html.light h2 button{background:#f1f5f9;color:#475569;border-color:#cbd5e1}\n"
"html.light h2 button:hover{background:#e2e8f0;color:#1e293b}\n"
"html.light th{color:#94a3b8}\n"
"html.light th,html.light td{border-bottom-color:#f1f5f9}\n"
"html.light tr:hover td{background:#f8fafc}\n"
"html.light .text{color:#15803d}\n"
"html.light .disc{color:#c2410c}\n"
"html.light .atak{color:#a21caf}\n"
"html.light .muted{color:#94a3b8}\n"
"html.light .log-item{border-bottom-color:#e2e8f0}\n"
"html.light .log-item .ts{color:#94a3b8}\n"
"html.light .log-item b{color:#0284c7}\n"
"html.light .grid{background:#cbd5e1}\n"
"html.light .leaflet-container{background:#f8fafc}\n"
"html.light #config h3{color:#0284c7;border-bottom-color:#e2e8f0}\n"
"html.light #config textarea,html.light #config input[type=text]{background:#ffffff;color:#1e293b;border-color:#cbd5e1}\n"
"html.light #config textarea:focus,html.light #config input[type=text]:focus{border-color:#0284c7}\n"
"html.light #config button{background:#e0f2fe;color:#0c4a6e;border-color:#0284c7}\n"
"html.light #config button:hover{background:#bae6fd}\n"
"html.light #config .hint{color:#64748b}\n"
/* Nodes table: search input + sortable headers + clickable rows.       */
".tbl-tools{display:flex;align-items:center;gap:6px;margin:0 0 5px 0}\n"
".tbl-tools input{flex:1;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:3px;padding:4px 8px;font-size:12px;font-family:inherit}\n"
".tbl-tools input:focus{outline:none;border-color:#38bdf8}\n"
".tbl-tools .count{color:#64748b;font-size:11px;white-space:nowrap}\n"
"th.sortable{cursor:pointer;user-select:none}\n"
"th.sortable:hover{color:#38bdf8}\n"
"th.sortable .arr{display:inline-block;width:10px;color:#38bdf8;font-size:10px}\n"
"tr.node-row{cursor:pointer}\n"
"tr.node-row.selected td{background:#1e3a5f}\n"
"html.light .tbl-tools input{background:#ffffff;color:#1e293b;border-color:#cbd5e1}\n"
"html.light .tbl-tools input:focus{border-color:#0284c7}\n"
"html.light .tbl-tools .count{color:#94a3b8}\n"
"html.light th.sortable:hover{color:#0284c7}\n"
"html.light th.sortable .arr{color:#0284c7}\n"
"html.light tr.node-row.selected td{background:#dbeafe}\n"
/* Drawer: slide-in detail panel from the right. Overlays the live grid */
/* but doesn't fully cover the map -- 380px wide is intentional.        */
"#drawer{position:fixed;top:44px;bottom:0;right:0;width:380px;max-width:90vw;background:#0f172a;border-left:1px solid #334155;box-shadow:-4px 0 16px rgba(0,0,0,0.4);transform:translateX(100%);transition:transform 0.18s ease;z-index:600;display:flex;flex-direction:column;overflow:hidden}\n"
"#drawer.open{transform:translateX(0)}\n"
"#drawer-head{padding:12px 14px;border-bottom:1px solid #334155;display:flex;align-items:flex-start;gap:8px}\n"
"#drawer-head .grow{flex:1;min-width:0}\n"
"#drawer-head .nm{font-size:15px;font-weight:600;color:#f8fafc;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n"
"#drawer-head .id{font-size:12px;color:#64748b;font-family:'SF Mono',Consolas,monospace;margin-top:2px}\n"
"#drawer-head .close{background:transparent;color:#64748b;border:none;font-size:20px;cursor:pointer;padding:0 6px;line-height:1}\n"
"#drawer-head .close:hover{color:#e2e8f0}\n"
"#drawer-body{flex:1;overflow-y:auto;padding:8px 14px}\n"
"#drawer-body section{margin:14px 0}\n"
"#drawer-body section:first-child{margin-top:6px}\n"
"#drawer-body h3{font-size:11px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;margin-bottom:6px}\n"
".metric-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px}\n"
".metric{background:#1e293b;border-radius:3px;padding:7px 9px}\n"
".metric .lbl{color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:0.5px}\n"
".metric .v{color:#38bdf8;font-size:15px;font-weight:600;font-variant-numeric:tabular-nums}\n"
"#drawer-spark{display:block;width:100%;height:54px;background:#1e293b;border-radius:3px}\n"
"#drawer-msgs,#drawer-pos{font-size:12px;line-height:1.5;max-height:160px;overflow-y:auto}\n"
"#drawer-msgs .item{padding:4px 0;border-bottom:1px dotted #1e293b}\n"
"#drawer-pos td{padding:3px 6px;border:none;font-size:11px;font-family:'SF Mono',Consolas,monospace}\n"
"html.light #drawer{background:#ffffff;border-left-color:#cbd5e1;box-shadow:-4px 0 16px rgba(15,23,42,0.08)}\n"
"html.light #drawer-head{border-bottom-color:#e2e8f0}\n"
"html.light #drawer-head .nm{color:#0f172a}\n"
"html.light #drawer-head .id{color:#94a3b8}\n"
"html.light #drawer-body h3{color:#0284c7}\n"
"html.light .metric{background:#f1f5f9}\n"
"html.light .metric .lbl{color:#94a3b8}\n"
"html.light .metric .v{color:#0284c7}\n"
"html.light #drawer-spark{background:#f1f5f9}\n"
"html.light #drawer-msgs .item{border-bottom-color:#e2e8f0}\n"
"</style></head><body>\n"
"<div id=\"bar\">\n"
"  <span class=\"title\">meshtastic-sniffer</span>\n"
"  <span class=\"stat\">Rate <span id=\"st-msps\" class=\"val\">--</span> Msps</span>\n"
"  <span class=\"stat\">Frames <span id=\"st-frames\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">Decrypted <span id=\"st-decrypted\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\" id=\"st-offgrid-wrap\" style=\"display:none\">Off-grid <span id=\"st-offgrid\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\" id=\"st-focus-wrap\" style=\"display:none\" title=\"Focused pool: workers / promotions / dropped / below-snr / cumulative focus-decoded frames\">Focus <span id=\"st-focus\" class=\"val\">--</span></span>\n"
"  <span class=\"stat\" id=\"st-clock-wrap\" style=\"display:none\" title=\"Self-reported clock-discipline class (--station-t-acc-ns). Affects TDOA accuracy when 3+ stations correlate.\">Clock <span id=\"st-clock\" class=\"val\">--</span></span>\n"
"  <span id=\"status\">connecting...</span>\n"
"  <button id=\"theme-toggle\" onclick=\"toggleTheme()\" title=\"Toggle light/dark theme\">dark</button>\n"
"</div>\n"
"<div id=\"tabs\">\n"
"  <button id=\"tab-live\" class=\"active\" onclick=\"showTab('live')\">Live</button>\n"
"  <button id=\"tab-activity\" onclick=\"showTab('activity')\">Activity</button>\n"
"  <button id=\"tab-topology\" onclick=\"showTab('topology')\">Topology</button>\n"
"  <button id=\"tab-config\" onclick=\"showTab('config')\">Config</button>\n"
"</div>\n"
"<div id=\"live\" class=\"tab active\">\n"
"  <div class=\"grid\">\n"
"    <div class=\"pane\" style=\"grid-row:span 4;padding:0;\"><div id=\"map\"></div></div>\n"
"    <div class=\"pane\"><h2>Nodes <span class=muted id=\"nodes-count\"></span><button onclick=\"exportCsv()\" style=\"background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:3px;padding:2px 8px;cursor:pointer;font-size:10px;\">CSV</button></h2>\n"
"      <div class=\"tbl-tools\"><input id=\"nodes-search\" type=\"text\" placeholder=\"Search id, name...\" autocomplete=\"off\"></div>\n"
"      <table id=\"nodes\">\n"
"        <thead><tr>\n"
"          <th class=\"sortable\" data-sort=\"id\">ID<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"name\">Name<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"snr\">SNR<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"frames\">Frames<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"ts\">Last seen<span class=arr></span></th>\n"
"        </tr></thead>\n"
"        <tbody></tbody>\n"
"      </table>\n"
"    </div>\n"
"    <div class=\"pane\"><h2>Channels <span class=muted>(by hash)</span></h2><table id=\"channels\"><thead><tr><th>Hash</th><th>Name</th><th>Preset</th><th>Frames</th><th>Decrypt</th><th>Slots</th><th>SNR (1h)</th><th>Last</th></tr></thead><tbody></tbody></table></div>\n"
"    <div class=\"pane\"><h2>Messages</h2><div id=\"msgs\"></div></div>\n"
"    <div class=\"pane\"><h2>Discoveries &amp; ATAK</h2><div id=\"disc\"></div></div>\n"
"  </div>\n"
"</div>\n"
"<div id=\"activity\" class=\"tab\">\n"
"  <div id=\"activity-empty\" class=\"empty-hint\">Waiting for packets... channels light up as frames arrive.</div>\n"
"  <div id=\"activity-grid\"></div>\n"
"</div>\n"
"<div id=\"topology\" class=\"tab\">\n"
"  <div id=\"topo-empty\" class=\"empty-hint\">Waiting for the first frame... nodes appear as soon as the sniffer hears them, and link up via NEIGHBORINFO and relay-hop hints.</div>\n"
"  <div id=\"topo-legend\"><span class=l-node></span> node, size = frames seen &nbsp;|&nbsp; <span class=l-edge></span> edge = observed RX, color = SNR &nbsp;|&nbsp; click a node to inspect</div>\n"
"  <canvas id=\"topo-canvas\"></canvas>\n"
"</div>\n"
"<div id=\"config\" class=\"tab\">\n"
"  <h3>Add keys</h3>\n"
"  <div class=\"row\">\n"
"    <textarea id=\"keys-input\" rows=\"4\" placeholder=\"LongFast=default&#10;Ops=hex:00112233445566778899aabbccddeeff&#10;Crew=base64:AQ==\"></textarea>\n"
"    <button onclick=\"postKeys()\">Add</button>\n"
"    <span id=\"keys-status\" class=\"hint\"></span>\n"
"    <div class=\"hint\">One spec per line. ChannelName=SPEC (recommended) or bare SPEC. SPEC: default | simple0..10 | hex:... | base64:...</div>\n"
"  </div>\n"
"  <h3>Channel-share URL</h3>\n"
"  <div class=\"row\">\n"
"    <input id=\"share-input\" type=\"text\" placeholder=\"https://meshtastic.org/e/#...\">\n"
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
"  <h3>View options</h3>\n"
"  <div class=\"row\">\n"
"    <label><input type=\"checkbox\" id=\"showUntrusted\"> Show untrusted frames (CRC-fail or no-decrypt) in map / nodes / channels</label>\n"
"    <div class=\"hint\">Off by default. Frames without verified bytes (e.g. cross-slot phantoms of a real TX, or noise patterns that passed the 5-bit header checksum by chance) decode to corrupted from/to/packet_id fields. Surfacing them invents nodes that don't exist. Turn this on for diagnostic inspection of what the demod produced before trust filtering.</div>\n"
"  </div>\n"
"</div>\n"
"<aside id=\"drawer\" aria-hidden=\"true\">\n"
"  <div id=\"drawer-head\">\n"
"    <div class=\"grow\"><div class=\"nm\" id=\"d-name\">--</div><div class=\"id\" id=\"d-id\">--</div></div>\n"
"    <button class=\"close\" onclick=\"closeDrawer()\" title=\"Close\">&times;</button>\n"
"  </div>\n"
"  <div id=\"drawer-body\">\n"
"    <section><div class=\"metric-grid\">\n"
"      <div class=\"metric\"><div class=\"lbl\">Frames</div><div class=\"v\" id=\"d-frames\">0</div></div>\n"
"      <div class=\"metric\"><div class=\"lbl\">Avg SNR</div><div class=\"v\" id=\"d-snr\">--</div></div>\n"
"      <div class=\"metric\"><div class=\"lbl\">Last seen</div><div class=\"v\" id=\"d-last\">--</div></div>\n"
"    </div></section>\n"
"    <section><h3>SNR (last 60)</h3><canvas id=\"drawer-spark\" width=\"360\" height=\"50\"></canvas></section>\n"
"    <section><h3>Recent messages</h3><div id=\"drawer-msgs\"></div></section>\n"
"    <section><h3>Recent positions</h3><div id=\"drawer-pos\"></div></section>\n"
"    <section><h3>Channels seen on</h3><div id=\"drawer-channels\"></div></section>\n"
"  </div>\n"
"</aside>\n"
"<script>\n"
"function showTab(name){\n"
"  for(const t of ['live','activity','topology','config']){\n"
"    document.getElementById(t).classList.toggle('active',t===name);\n"
"    document.getElementById('tab-'+t).classList.toggle('active',t===name);\n"
"  }\n"
"  /* Drawer slides over the tab content; if it stays open after a tab\n"
"   * switch it covers the new tab and looks broken. Close on every\n"
"   * switch -- user re-opens by clicking a row in the new tab. */\n"
"  if (drawerNodeId) closeDrawer();\n"
"  if (name==='live') setTimeout(()=>map.invalidateSize(),60);\n"
"  if (name==='activity') renderActivity();\n"
"  if (name==='topology') topoStart(); else topoStop();\n"
"}\n"
"// Theme toggle: dark is default, light persists in localStorage. Map\n"
"// tile layer swaps between Carto dark/light to match. Same pattern as\n"
"// inmarsat-sniffer / iridium-sniffer.\n"
"let tileLayer=null;\n"
"function setTheme(name){const html=document.documentElement;if(name==='light')html.classList.add('light');else html.classList.remove('light');try{localStorage.setItem('theme',name);}catch(e){}if(tileLayer)map.removeLayer(tileLayer);const url=(name==='light')?'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png':'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';tileLayer=L.tileLayer(url,{maxZoom:19,attribution:'(c) OSM (c) CARTO'}).addTo(map);const btn=document.getElementById('theme-toggle');if(btn)btn.textContent=(name==='light')?'light':'dark';}\n"
"function toggleTheme(){setTheme(document.documentElement.classList.contains('light')?'dark':'light');}\n"
"const map = L.map('map').setView([39.5, -98.0], 4);\n"
"// Apply persisted theme (also adds the matching tile layer to the map).\n"
"setTheme((function(){try{return localStorage.getItem('theme')||'dark';}catch(e){return 'dark';}})());\n"
"const markers = {}, trails = {}, nodes = {}, edges = {}, channels = {};\n"
"const msgsEl = document.getElementById('msgs'); const discEl = document.getElementById('disc'); const tbody = document.querySelector('#nodes tbody');\n"
"// Delegated click handler: 'promote' button on an OFF_GRID_LORA row\n"
"// POSTs the discovered freq + sensible (BW, SF, CR) to /api/extra-freq.\n"
"// On success the button text changes to '\\u2713 added' and disables; on\n"
"// error the row's button shows the failure inline.\n"
"discEl.addEventListener('click', async (e) => {\n"
"  const btn = e.target.closest('button.promote');\n"
"  if (!btn) return;\n"
"  const f  = btn.dataset.f, bw = btn.dataset.bw, sf = btn.dataset.sf, cr = btn.dataset.cr;\n"
"  btn.disabled = true; btn.textContent = '...';\n"
"  try {\n"
"    const r = await fetch('/api/extra-freq', { method: 'POST', body: `${f}:bw=${bw}:sf=${sf}:cr=${cr}` });\n"
"    const j = await r.json();\n"
"    if (r.ok && j.channel_id !== undefined) { btn.textContent = '\\u2713 added (ch '+j.channel_id+')'; }\n"
"    else { btn.textContent = 'failed'; btn.disabled = false; }\n"
"  } catch (err) { btn.textContent = 'error'; btn.disabled = false; }\n"
"});\n"
"const chTbody = document.querySelector('#channels tbody');\n"
/* Per-slot rolling SNR history, keyed by physical slot id. Filled from
 * CHAN_SNR SSE events; renderChannels() averages buckets across the
 * slots that map to each channel hash. */
"const chanSnr = {};\n"
"const nodesCount = document.getElementById('nodes-count');\n"
"const nodesSearch = document.getElementById('nodes-search');\n"
"// LRU cap on the nodes map. Busy environments produce hundreds of\n"
"// distinct ids; we keep the 1000 most-recently-seen and drop older ones\n"
"// (and their map markers/trails) so memory + paint cost stays bounded.\n"
"const NODES_MAX = 1000;\n"
"function evictNodes(){\n"
"  const ids = Object.keys(nodes);\n"
"  if (ids.length <= NODES_MAX) return;\n"
"  ids.sort((a,b)=>nodes[a].ts-nodes[b].ts);\n"
"  const drop = ids.length - NODES_MAX;\n"
"  for (let i=0;i<drop;++i){\n"
"    const id = ids[i];\n"
"    if (markers[id]) { map.removeLayer(markers[id]); delete markers[id]; }\n"
"    if (trails[id]) { if (trails[id].line) map.removeLayer(trails[id].line); delete trails[id]; }\n"
"    delete nodes[id];\n"
"  }\n"
"  if (drawerNodeId && !nodes[drawerNodeId]) closeDrawer();\n"
"}\n"
"function fmtTime(t){return new Date(t*1000).toLocaleTimeString();}\n"
"// Sortable + searchable Nodes table. State + RAF-coalesced renders so\n"
"// burst traffic doesn't trigger a full DOM rebuild per frame.\n"
"let nodesSortKey = 'ts', nodesSortDir = -1, nodesQuery = '';\n"
"function nodesValue(n, id, key){\n"
"  if (key==='id') return id;\n"
"  if (key==='name') return (n.name||'').toLowerCase();\n"
"  if (key==='snr') return n.snr_db===undefined ? -999 : n.snr_db;\n"
"  if (key==='frames') return n.frames||0;\n"
"  return n.ts||0;\n"
"}\n"
"function nodesCmp(aId, bId){\n"
"  const a = nodesValue(nodes[aId], aId, nodesSortKey);\n"
"  const b = nodesValue(nodes[bId], bId, nodesSortKey);\n"
"  if (a < b) return -1*nodesSortDir;\n"
"  if (a > b) return  1*nodesSortDir;\n"
"  return 0;\n"
"}\n"
"function nodesMatches(id, n){\n"
"  if (!nodesQuery) return true;\n"
"  if (id.toLowerCase().includes(nodesQuery)) return true;\n"
"  if (n.name && n.name.toLowerCase().includes(nodesQuery)) return true;\n"
"  return false;\n"
"}\n"
"let nodesRafQueued = false;\n"
"function refreshNodes(){\n"
"  if (nodesRafQueued) return;\n"
"  nodesRafQueued = true;\n"
"  requestAnimationFrame(()=>{ nodesRafQueued = false; renderNodes(); });\n"
"}\n"
"function renderNodes(){\n"
"  const all = Object.keys(nodes);\n"
"  const matched = nodesQuery ? all.filter(id=>nodesMatches(id, nodes[id])) : all;\n"
"  matched.sort(nodesCmp);\n"
"  // Cap rendered rows -- the table pane scrolls but rendering 5000 rows\n"
"  // costs us nothing useful. 200 is more than fits on screen.\n"
"  const TOPN = 200;\n"
"  const rows = matched.slice(0, TOPN);\n"
"  const frag = document.createDocumentFragment();\n"
"  for (const id of rows){\n"
"    const n = nodes[id];\n"
"    const tr = document.createElement('tr');\n"
"    tr.className = 'node-row' + (id===drawerNodeId ? ' selected' : '');\n"
"    tr.dataset.id = id;\n"
"    const snr = n.snr_db !== undefined ? n.snr_db.toFixed(1) + ' dB' : '<span class=muted>-</span>';\n"
"    // Name fallback: NODEINFO_APP isn't seen until a node broadcasts it\n"
"    // (15-30 min cadence), so unknown names are normal early on. Show\n"
"    // the last 4 hex digits of the id (matches what the device's own\n"
"    // LCD shows) plus a state hint: 'await' = decrypting OK but no\n"
"    // NODEINFO yet, 'enc' = at least one frame failed to decrypt.\n"
"    let name;\n"
"    if (n.name) {\n"
"      name = n.name;\n"
"    } else {\n"
"      const tail = id.length >= 5 ? id.slice(-4) : id;\n"
"      const state = n.has_encrypted ? 'enc' : 'await';\n"
"      name = `${tail} <span class=muted>(${state})</span>`;\n"
"    }\n"
"    tr.innerHTML = `<td>${id}</td><td>${name}</td><td>${snr}</td><td>${n.frames||0}</td><td>${fmtTime(n.ts)}</td>`;\n"
"    tr.onclick = ()=>openDrawer(id);\n"
"    frag.appendChild(tr);\n"
"  }\n"
"  tbody.replaceChildren(frag);\n"
"  const totalShown = matched.length, totalAll = all.length;\n"
"  if (nodesQuery) nodesCount.textContent = `(${Math.min(rows.length,totalShown)}/${totalShown} of ${totalAll})`;\n"
"  else nodesCount.textContent = `(${Math.min(rows.length,totalAll)} of ${totalAll})`;\n"
"  // Update sort arrows.\n"
"  for (const th of document.querySelectorAll('#nodes th.sortable')){\n"
"    const k = th.dataset.sort;\n"
"    th.querySelector('.arr').textContent = (k===nodesSortKey) ? (nodesSortDir<0?'\\u25BC':'\\u25B2') : '';\n"
"  }\n"
"}\n"
"// Wire search + sort once at startup.\n"
"nodesSearch.addEventListener('input', ()=>{ nodesQuery = nodesSearch.value.trim().toLowerCase(); refreshNodes(); });\n"
"for (const th of document.querySelectorAll('#nodes th.sortable')){\n"
"  th.addEventListener('click', ()=>{\n"
"    const k = th.dataset.sort;\n"
"    if (nodesSortKey === k) nodesSortDir = -nodesSortDir;\n"
"    else { nodesSortKey = k; nodesSortDir = (k==='id'||k==='name') ? 1 : -1; }\n"
"    refreshNodes();\n"
"  });\n"
"}\n"
"// Per-node history rings -- bounded so a long-running session in a busy\n"
"// environment doesn't grow without limit. The drawer reads from these.\n"
"const NODE_HIST_MSGS = 50, NODE_HIST_POS = 30, NODE_HIST_SNR = 60;\n"
"function nodeHistory(id){\n"
"  let h = nodes[id] && nodes[id]._hist;\n"
"  if (!h && nodes[id]) {\n"
"    h = nodes[id]._hist = {msgs:[], positions:[], snr:[], channels:{}};\n"
"  }\n"
"  return h;\n"
"}\n"
"function noteNodeFrame(id, p){\n"
"  const h = nodeHistory(id); if (!h) return;\n"
"  if (p.snr_db !== undefined) {\n"
"    h.snr.push({t:p.ts, v:p.snr_db});\n"
"    if (h.snr.length > NODE_HIST_SNR) h.snr.shift();\n"
"  }\n"
"  if (p.text) {\n"
"    h.msgs.unshift({t:p.ts, ch:p.channel_name||'', text:p.text});\n"
"    if (h.msgs.length > NODE_HIST_MSGS) h.msgs.length = NODE_HIST_MSGS;\n"
"  }\n"
"  if (p.lat !== undefined && p.lon !== undefined) {\n"
"    h.positions.unshift({t:p.ts, lat:p.lat, lon:p.lon});\n"
"    if (h.positions.length > NODE_HIST_POS) h.positions.length = NODE_HIST_POS;\n"
"  }\n"
"  if (p.channel_hash !== undefined) {\n"
"    const k = p.channel_hash;\n"
"    if (!h.channels[k]) h.channels[k] = {n:0, name:p.channel_name||null};\n"
"    h.channels[k].n++;\n"
"    if (p.channel_name) h.channels[k].name = p.channel_name;\n"
"  }\n"
"  if (drawerNodeId === id) refreshDrawer();\n"
"}\n"
"// Drawer: per-node detail panel that slides in on row-click.\n"
"let drawerNodeId = null;\n"
"const drawerEl = document.getElementById('drawer');\n"
"const dName = document.getElementById('d-name'), dId = document.getElementById('d-id');\n"
"const dFrames = document.getElementById('d-frames'), dSnr = document.getElementById('d-snr');\n"
"const dLast = document.getElementById('d-last');\n"
"const dMsgs = document.getElementById('drawer-msgs'), dPos = document.getElementById('drawer-pos');\n"
"const dChan = document.getElementById('drawer-channels');\n"
"const dSpark = document.getElementById('drawer-spark');\n"
"function openDrawer(id){\n"
"  drawerNodeId = id;\n"
"  drawerEl.classList.add('open');\n"
"  drawerEl.setAttribute('aria-hidden','false');\n"
"  refreshDrawer();\n"
"  // Repaint table to show the .selected row highlight.\n"
"  refreshNodes();\n"
"}\n"
"function closeDrawer(){\n"
"  drawerEl.classList.remove('open');\n"
"  drawerEl.setAttribute('aria-hidden','true');\n"
"  drawerNodeId = null;\n"
"  refreshNodes();\n"
"}\n"
"// Esc closes the drawer.\n"
"document.addEventListener('keydown', e=>{ if (e.key==='Escape' && drawerNodeId) closeDrawer(); });\n"
"let drawerRafQueued = false;\n"
"function refreshDrawer(){\n"
"  if (drawerRafQueued) return;\n"
"  drawerRafQueued = true;\n"
"  requestAnimationFrame(()=>{ drawerRafQueued = false; renderDrawer(); });\n"
"}\n"
"function renderDrawer(){\n"
"  if (!drawerNodeId) return;\n"
"  const n = nodes[drawerNodeId];\n"
"  if (!n) { closeDrawer(); return; }\n"
"  const h = nodeHistory(drawerNodeId);\n"
"  dName.textContent = n.name || '(unknown)';\n"
"  dId.textContent = drawerNodeId;\n"
"  dFrames.textContent = fmtCount(n.frames||0);\n"
"  if (h && h.snr.length) {\n"
"    const avg = h.snr.reduce((s,x)=>s+x.v,0)/h.snr.length;\n"
"    dSnr.textContent = avg.toFixed(1)+' dB';\n"
"  } else dSnr.textContent = '--';\n"
"  dLast.textContent = fmtAgo(n.ts);\n"
"  // SNR sparkline.\n"
"  const ctx = dSpark.getContext('2d'); const W = dSpark.width, H = dSpark.height;\n"
"  ctx.clearRect(0,0,W,H);\n"
"  if (h && h.snr.length > 1) {\n"
"    const vs = h.snr.map(x=>x.v);\n"
"    const lo = Math.min(...vs), hi = Math.max(...vs);\n"
"    const span = Math.max(1, hi - lo);\n"
"    const isLight = document.documentElement.classList.contains('light');\n"
"    ctx.strokeStyle = isLight ? '#0284c7' : '#38bdf8';\n"
"    ctx.lineWidth = 1.5; ctx.beginPath();\n"
"    for (let i=0;i<vs.length;++i) {\n"
"      const x = (i/(vs.length-1))*W;\n"
"      const y = H - 4 - ((vs[i]-lo)/span) * (H-8);\n"
"      if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);\n"
"    }\n"
"    ctx.stroke();\n"
"    ctx.fillStyle = isLight?'#94a3b8':'#64748b'; ctx.font='9px system-ui';\n"
"    ctx.fillText(hi.toFixed(1)+' dB', 4, 10);\n"
"    ctx.fillText(lo.toFixed(1)+' dB', 4, H-2);\n"
"  } else {\n"
"    ctx.fillStyle = '#64748b'; ctx.font='10px system-ui'; ctx.fillText('no SNR samples yet', 8, H/2+3);\n"
"  }\n"
"  // Messages.\n"
"  if (h && h.msgs.length) {\n"
"    dMsgs.innerHTML = h.msgs.map(m=>`<div class=item><span class=muted>${fmtTime(m.t)}</span> ${m.ch?'<span class=muted>'+m.ch+'</span> ':''}<span class=text>${escHtml(m.text)}</span></div>`).join('');\n"
"  } else dMsgs.innerHTML = '<div class=muted>no text frames captured</div>';\n"
"  // Positions.\n"
"  if (h && h.positions.length) {\n"
"    dPos.innerHTML = '<table>'+h.positions.map(p=>`<tr><td class=muted>${fmtTime(p.t)}</td><td>${p.lat.toFixed(5)}</td><td>${p.lon.toFixed(5)}</td></tr>`).join('')+'</table>';\n"
"  } else dPos.innerHTML = '<div class=muted>no positions captured</div>';\n"
"  // Channels.\n"
"  if (h && Object.keys(h.channels).length) {\n"
"    dChan.innerHTML = Object.keys(h.channels).map(k=>{\n"
"      const c = h.channels[k];\n"
"      const hex = '0x'+(parseInt(k)&0xff).toString(16).padStart(2,'0');\n"
"      return `<div class=item>${c.name||'<span class=muted>(encrypted)</span>'} <span class=muted>${hex} | ${c.n} frames</span></div>`;\n"
"    }).join('');\n"
"  } else dChan.innerHTML = '<div class=muted>no channel data</div>';\n"
"}\n"
"function escHtml(s){return String(s).replace(/[&<>\"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;','\\'':'&#39;'}[c]));}\n"
"let channelsRafQueued = false;\n"
"function refreshChannels(){\n"
"  if (channelsRafQueued) return;\n"
"  channelsRafQueued = true;\n"
"  requestAnimationFrame(()=>{ channelsRafQueued = false; renderChannels(); });\n"
"}\n"
/* aggregateSnr -- collapse per-slot rings into one 60-bucket view for
 * the channel hash (which can span multiple physical slots). Each
 * bucket is the mean across slots that had data in that minute. */
"function aggregateSnr(slotSet){\n"
"  const out = new Array(60).fill(null);\n"
"  const sum = new Array(60).fill(0);\n"
"  const cnt = new Array(60).fill(0);\n"
"  if (!slotSet) return out;\n"
"  for (const slot of slotSet){\n"
"    const ring = chanSnr[slot];\n"
"    if (!ring) continue;\n"
"    for (let i=0; i<60 && i<ring.length; i++){\n"
"      if (ring[i] >= 0){ sum[i] += ring[i]; cnt[i] += 1; }\n"
"    }\n"
"  }\n"
"  for (let i=0; i<60; i++) if (cnt[i]) out[i] = sum[i]/cnt[i];\n"
"  return out;\n"
"}\n"
/* snrSummary -- compress the 60-bucket history into one cell:
 *   current = newest populated minute (rounded dB)
 *   trend   = least-squares slope over up to 10 most-recent populated
 *             buckets. slope > +0.5 dB/min = up, < -0.5 = down, else
 *             flat. Returns null when nothing populated so the cell
 *             shows '--' instead of confusing zeros. */
"function snrSummary(buckets){\n"
"  let current = null, currentIdx = -1;\n"
"  for (let i = buckets.length - 1; i >= 0; i--){\n"
"    if (buckets[i] !== null){ current = buckets[i]; currentIdx = i; break; }\n"
"  }\n"
"  if (currentIdx < 0) return null;\n"
"  const xs = [], ys = [];\n"
"  for (let i = currentIdx; i >= 0 && xs.length < 10; i--){\n"
"    if (buckets[i] !== null){ xs.push(i); ys.push(buckets[i]); }\n"
"  }\n"
"  let trend = 'flat';\n"
"  if (ys.length >= 3){\n"
"    const n = ys.length;\n"
"    const mx = xs.reduce((a,b)=>a+b,0)/n;\n"
"    const my = ys.reduce((a,b)=>a+b,0)/n;\n"
"    let num = 0, den = 0;\n"
"    for (let i = 0; i < n; i++){ const dx = xs[i]-mx; num += dx*(ys[i]-my); den += dx*dx; }\n"
"    const slope = den ? num/den : 0;\n"
"    if (slope >  0.5) trend = 'up';\n"
"    else if (slope < -0.5) trend = 'down';\n"
"  }\n"
"  return { current: Math.round(current), trend };\n"
"}\n"
"function renderChannels(){\n"
"  const hashes = Object.keys(channels).sort((a,b)=>channels[b].ts-channels[a].ts);\n"
"  const frag = document.createDocumentFragment();\n"
"  for (const h of hashes){const c=channels[h]; const tr=document.createElement('tr');\n"
"    const hashHex = '0x'+(parseInt(h)&0xff).toString(16).padStart(2,'0');\n"
"    // Channel name comes from decrypted frame metadata. If we've never\n"
"    // successfully decrypted a frame on this hash, we know the hash but\n"
"    // not the operator's name for the channel -- show '(encrypted)'\n"
"    // rather than a cryptic '?'.\n"
"    const name = c.name || '<span class=muted>(encrypted)</span>';\n"
"    const preset = c.preset || '<span class=muted>--</span>';\n"
"    const dec = c.total ? Math.round(100*c.decrypted/c.total) : 0;\n"
"    const decCell = c.decrypted>0 ? `${c.decrypted}/${c.total} (${dec}%)` : `<span class=muted>0/${c.total}</span>`;\n"
"    const slotN = c.slots ? c.slots.size : 0;\n"
"    const slotCell = slotN>0 ? (c.lastSlot!==undefined ? `${slotN} <span class=muted>(last #${c.lastSlot})</span>` : `${slotN}`) : '<span class=muted>--</span>';\n"
"    const s = snrSummary(aggregateSnr(c.slots));\n"
"    const arrows = {up:'\\u2197', down:'\\u2198', flat:'\\u2192'};\n"
"    const snrCell = s ? `${s.current} dB <span class='snr-arrow snr-${s.trend}'>${arrows[s.trend]}</span>` : `<span class=muted>--</span>`;\n"
"    tr.innerHTML=`<td>${hashHex}</td><td>${name}</td><td>${preset}</td><td>${c.total}</td><td>${decCell}</td><td>${slotCell}</td><td>${snrCell}</td><td>${fmtTime(c.ts)}</td>`;\n"
"    frag.appendChild(tr);\n"
"  }\n"
"  chTbody.replaceChildren(frag);\n"
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
"  while (el.children.length>200) el.removeChild(el.lastChild);\n"
"}\n"
/* msgSummary -- per-port short string for the global Messages pane.
 * Returns null if the event should not appear in the pane (e.g. ATAK
 * which already lands in Discoveries, or unknown ports with no
 * useful summary). Keep each port to one tight line so the log
 * stays readable when 100+ events scroll past. */
"function msgSummary(p) {\n"
"  const pn = p.port_name || '';\n"
"  switch (pn) {\n"
"    case 'TEXT_MESSAGE_APP':\n"
"    case 'RANGE_TEST_APP':\n"
"    case 'DETECTION_SENSOR_APP':\n"
"      return p.text ? `<span class=text>${escHtml(p.text)}</span>` : null;\n"
"    case 'NODEINFO_APP': {\n"
"      const x = [];\n"
"      if (p.long_name)  x.push(escHtml(p.long_name));\n"
"      if (p.short_name) x.push('('+escHtml(p.short_name)+')');\n"
"      if (p.hw_model!==undefined) x.push('hw='+p.hw_model);\n"
"      if (p.role!==undefined)     x.push('role='+p.role);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'POSITION_APP': {\n"
"      const x = [];\n"
"      if (typeof p.lat==='number' && typeof p.lon==='number')\n"
"        x.push(`${p.lat.toFixed(5)},${p.lon.toFixed(5)}`);\n"
"      if (p.alt_m!==undefined)    x.push(`alt=${p.alt_m}m`);\n"
"      if (p.speed_mps!==undefined)x.push(`spd=${p.speed_mps}m/s`);\n"
"      if (p.sats!==undefined)     x.push(`sats=${p.sats}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'TELEMETRY_APP': {\n"
"      const x = [];\n"
"      const d = (p.device && p.device[0]) || {};\n"
"      if (d.battery!==undefined) x.push(`bat=${d.battery}%`);\n"
"      if (d.voltage!==undefined) x.push(`v=${d.voltage.toFixed(2)}`);\n"
"      if (d.ch_util!==undefined) x.push(`chu=${d.ch_util.toFixed(1)}`);\n"
"      if (d.uptime !==undefined) x.push(`up=${d.uptime}s`);\n"
"      const e = (p.environment && p.environment[0]) || {};\n"
"      if (e.temp_c   !==undefined) x.push(`t=${e.temp_c.toFixed(1)}C`);\n"
"      if (e.humidity !==undefined) x.push(`rh=${e.humidity.toFixed(0)}%`);\n"
"      if (e.pressure !==undefined) x.push(`p=${e.pressure.toFixed(0)}hPa`);\n"
"      const ls = (p.local_stats && p.local_stats[0]) || {};\n"
"      if (ls.nodes_online!==undefined) x.push(`online=${ls.nodes_online}`);\n"
"      const aq = (p.air_quality && p.air_quality[0]) || {};\n"
"      if (aq.pm25_std!==undefined) x.push(`pm25=${aq.pm25_std}`);\n"
"      if (aq.co2_ppm !==undefined) x.push(`co2=${aq.co2_ppm}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'WAYPOINT_APP': {\n"
"      const x = [];\n"
"      if (p.wp_name) x.push(escHtml(p.wp_name));\n"
"      if (typeof p.lat==='number' && typeof p.lon==='number')\n"
"        x.push(`${p.lat.toFixed(5)},${p.lon.toFixed(5)}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'MAP_REPORT_APP': {\n"
"      const x = [];\n"
"      if (p.long_name) x.push(escHtml(p.long_name));\n"
"      if (p.firmware)  x.push('fw='+escHtml(p.firmware));\n"
"      if (p.region!==undefined) x.push('region='+p.region);\n"
"      if (typeof p.lat==='number' && typeof p.lon==='number')\n"
"        x.push(`${p.lat.toFixed(5)},${p.lon.toFixed(5)}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'TRACEROUTE_APP':\n"
"      return (p.route && p.route.length) ? `${p.route.length} hops` : null;\n"
"    case 'NEIGHBORINFO_APP':\n"
"      return (p.neighbors && p.neighbors.length) ? `${p.neighbors.length} neighbors` : null;\n"
"    case 'ROUTING_APP':\n"
"      return p.routing_kind || null;\n"
"    case 'PAXCOUNTER_APP': {\n"
"      const x = [];\n"
"      if (p.pax_wifi!==undefined) x.push('wifi='+p.pax_wifi);\n"
"      if (p.pax_ble !==undefined) x.push('ble=' +p.pax_ble);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'STORE_FORWARD_APP':\n"
"      return p.sf_rr || null;\n"
"    case 'KEY_VERIFICATION_APP':\n"
"    case 'REMOTE_HARDWARE_APP':\n"
"    case 'ADMIN_APP':\n"
"      return '\\u2014';\n"  /* en dash; show the row but no useful body */
"    case 'ATAK_PLUGIN':\n"
"      return null;\n"  /* ATAK already lands in Discoveries pane */
"    default:\n"
"      return null;\n"
"  }\n"
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
"// This sniffer's own GPS marker. Distinct from node markers: cyan ring,\n"
"// fixed pixel radius (circleMarker not Marker), 'RX' popup. Only present\n"
"// when --gpsd is running and a recent fix has been propagated through\n"
"// the JSON event stream. One marker, position updated in place.\n"
"let stationMarker = null;\n"
"function noteStation(lat, lon, alt){\n"
"  if (typeof lat !== 'number' || typeof lon !== 'number') return;\n"
"  const ll = [lat, lon];\n"
"  if (!stationMarker) {\n"
"    stationMarker = L.circleMarker(ll, {\n"
"      radius: 8, color: '#38bdf8', weight: 2,\n"
"      fillColor: '#0c4a6e', fillOpacity: 0.85\n"
"    }).addTo(map);\n"
"    stationMarker.bindPopup('<b>RX station</b><br>this sniffer');\n"
"    if (Object.keys(markers).length === 0) map.setView(ll, 11);\n"
"  } else {\n"
"    stationMarker.setLatLng(ll);\n"
"  }\n"
"  if (typeof alt === 'number')\n"
"    stationMarker.setPopupContent(`<b>RX station</b><br>this sniffer<br>${alt.toFixed(1)} m`);\n"
"}\n"
// Activity tab: bucketed by *preset* (radio config: SF/BW/CR), with the
// channels that ride on each preset listed inside the card. The preset
// is the natural physical-layer view; channel-name + hash is the logical
// view nested inside.
"const activityGrid = document.getElementById('activity-grid');\n"
"const activityEmpty = document.getElementById('activity-empty');\n"
"// Standard Meshtastic presets, in firmware order. Pre-populated as cards\n"
"// so the user sees the full grid immediately and idle slots are visible.\n"
"const STANDARD_PRESETS = ['ShortTurbo','ShortFast','ShortSlow','MediumFast','MediumSlow','LongFast','LongMod','LongSlow','LongTurbo'];\n"
"// activityState[preset] = {\n"
"//   sparkBuckets:[60], bucketStart, frames, decrypted, ts, channels:{[hash]:{n,decrypted,name}}\n"
"// }\n"
"const activityState = {};\n"
"function ensurePreset(preset){\n"
"  if (activityState[preset]) return activityState[preset];\n"
"  const now = Math.floor(Date.now()/1000);\n"
"  return activityState[preset] = {\n"
"    sparkBuckets:new Array(60).fill(0),\n"
"    bucketStart: now,\n"
"    frames:0, decrypted:0, ts:0,\n"
"    channels:{},\n"
"    /* Set of distinct decoder slot ids that received frames on this\n"
"     * preset. Lets the card surface 'N slots active out of M' so the\n"
"     * operator sees how broad the activity is across the band. */\n"
"    slots: new Set()\n"
"  };\n"
"}\n"
"// Pre-create the standard preset cards so the grid is fully laid out\n"
"// before any traffic arrives.\n"
"for (const p of STANDARD_PRESETS) ensurePreset(p);\n"
"function activityNote(opts){\n"
"  const preset = opts.preset || '?';\n"
"  const s = ensurePreset(preset);\n"
"  const now = Math.floor(Date.now()/1000);\n"
"  // Slide the spark window forward to 'now' so older buckets age off.\n"
"  const drift = now - s.bucketStart;\n"
"  if (drift > 0) {\n"
"    if (drift >= 60) s.sparkBuckets.fill(0);\n"
"    else { s.sparkBuckets.splice(0, drift); for (let i=0;i<drift;++i) s.sparkBuckets.push(0); }\n"
"    s.bucketStart = now;\n"
"  }\n"
"  if (opts.frame) { s.frames++; s.sparkBuckets[59]++; }\n"
"  if (opts.decrypted) s.decrypted++;\n"
"  if (opts.slot_id !== undefined && opts.slot_id !== null && opts.slot_id >= 0)\n"
"    s.slots.add(opts.slot_id);\n"
"  s.ts = now;\n"
"  if (opts.hash !== undefined) {\n"
"    const h = opts.hash;\n"
"    let ch = s.channels[h];\n"
"    if (!ch) ch = s.channels[h] = {n:0, decrypted:0, name:null};\n"
"    ch.n++;\n"
"    if (opts.decrypted) ch.decrypted++;\n"
"    if (opts.channelName) ch.name = opts.channelName;\n"
"  }\n"
"  activityEmpty.style.display='none';\n"
"}\n"
"function drawSpark(canvas, buckets){\n"
"  const ctx = canvas.getContext('2d');\n"
"  const W = canvas.width, H = canvas.height;\n"
"  ctx.clearRect(0,0,W,H);\n"
"  let max = 1; for (const v of buckets) if (v > max) max = v;\n"
"  const bw = W / buckets.length;\n"
"  const isLight = document.documentElement.classList.contains('light');\n"
"  ctx.fillStyle = isLight ? '#0284c7' : '#38bdf8';\n"
"  for (let i=0;i<buckets.length;++i){\n"
"    const v = buckets[i]; if (v <= 0) continue;\n"
"    const h = Math.max(1, (v/max) * (H-2));\n"
"    ctx.fillRect(i*bw, H-h, Math.max(1, bw-0.5), h);\n"
"  }\n"
"}\n"
"function fmtAgo(ts){\n"
"  /* ts is fractional epoch seconds from the JSON event; floor the whole\n"
"   * delta so we render '14s ago' instead of '14.936086893081665s ago'. */\n"
"  const dt = Math.max(0, Math.floor(Date.now()/1000 - ts));\n"
"  if (dt < 60) return dt+'s ago';\n"
"  if (dt < 3600) return Math.floor(dt/60)+'m ago';\n"
"  return Math.floor(dt/3600)+'h ago';\n"
"}\n"
"// Coalesce activity-grid rebuilds into one frame regardless of how many\n"
"// SSE events arrived since the last paint. Cheap; survives bursty traffic.\n"
"let activityRafQueued = false;\n"
"function refreshActivity(){\n"
"  if (activityRafQueued) return;\n"
"  activityRafQueued = true;\n"
"  requestAnimationFrame(() => { activityRafQueued = false; renderActivity(); });\n"
"}\n"
"function renderActivity(){\n"
"  // Sort: any preset with traffic in last 60s first (by fpm desc), then by\n"
"  // last-seen recency. Idle standard presets always render last.\n"
"  const presets = Object.keys(activityState);\n"
"  presets.sort((a,b)=>{\n"
"    const sa = activityState[a], sb = activityState[b];\n"
"    const fa = sa.sparkBuckets.reduce((x,y)=>x+y,0);\n"
"    const fb = sb.sparkBuckets.reduce((x,y)=>x+y,0);\n"
"    if (fa !== fb) return fb - fa;\n"
"    return sb.ts - sa.ts;\n"
"  });\n"
"  const seen = {};\n"
"  for (const p of presets){\n"
"    const s = activityState[p];\n"
"    const id = 'chan-card-'+p;\n"
"    let card = document.getElementById(id);\n"
"    if (!card){\n"
"      card = document.createElement('div'); card.id = id; card.className='chan-card';\n"
"      card.innerHTML = `<div class=top><span class=nm></span><span class=preset></span></div>`+\n"
"        `<div class=row2><div><span class=lbl>fpm</span><span class='v fpm'>0</span></div>`+\n"
"        `<div><span class=lbl>Frames</span><span class='v frames'>0</span></div>`+\n"
"        `<div><span class=lbl>Channels</span><span class='v chcount'>0</span></div>`+\n"
"        `<div><span class=lbl>Slots</span><span class='v slots'>0</span></div></div>`+\n"
"        `<canvas width=320 height=36></canvas>`+\n"
"        `<div class=ch-list></div>`+\n"
"        `<div class=last></div>`;\n"
"      activityGrid.appendChild(card);\n"
"    }\n"
"    seen[id] = true;\n"
"    const fpm = s.sparkBuckets.reduce((a,b)=>a+b,0);\n"
"    const chKeys = Object.keys(s.channels);\n"
"    const chDecCount = chKeys.filter(k=>s.channels[k].decrypted>0).length;\n"
"    card.querySelector('.nm').textContent = p;\n"
"    card.querySelector('.preset').textContent = s.frames>0 ? Math.round(100*s.decrypted/s.frames)+'% decrypted' : 'idle';\n"
"    card.querySelector('.fpm').textContent = fpm;\n"
"    card.querySelector('.frames').textContent = fmtCount(s.frames);\n"
"    card.querySelector('.chcount').textContent = chKeys.length>0 ? `${chDecCount}/${chKeys.length}` : '0';\n"
"    card.querySelector('.slots').textContent = s.slots ? s.slots.size : 0;\n"
"    card.querySelector('.last').textContent = s.ts ? fmtAgo(s.ts) : '--';\n"
"    card.classList.toggle('hot', fpm > 0);\n"
"    card.classList.toggle('dead', s.ts === 0 || (Math.floor(Date.now()/1000) - s.ts) > 120);\n"
"    drawSpark(card.querySelector('canvas'), s.sparkBuckets);\n"
"    // Channel sub-list: each row is one named channel hash on this preset.\n"
"    const chList = card.querySelector('.ch-list');\n"
"    if (chKeys.length === 0) {\n"
"      chList.innerHTML = '';\n"
"    } else {\n"
"      // Sort channels by frame count desc.\n"
"      chKeys.sort((a,b)=>s.channels[b].n - s.channels[a].n);\n"
"      const rows = chKeys.slice(0, 8).map(h=>{\n"
"        const c = s.channels[h];\n"
"        const hex = '0x'+(parseInt(h)&0xff).toString(16).padStart(2,'0');\n"
"        const isLocked = c.decrypted === 0;\n"
"        const nm = c.name ? c.name : '(encrypted)';\n"
"        return `<div class='ch-row${isLocked?' locked':''}'>`+\n"
"               `<span class=ch-nm>${nm}</span>`+\n"
"               `<span class=ch-stats>${hex} | ${fmtCount(c.n)}</span>`+\n"
"               `</div>`;\n"
"      }).join('');\n"
"      const tail = chKeys.length > 8 ? `<div class='ch-row'><span class=ch-nm class=muted>... ${chKeys.length-8} more</span></div>` : '';\n"
"      chList.innerHTML = rows + tail;\n"
"    }\n"
"  }\n"
"  // Hide the 'waiting for packets' hint once any preset has data.\n"
"  const anyTraffic = Object.values(activityState).some(s=>s.frames>0);\n"
"  activityEmpty.style.display = anyTraffic ? 'none' : 'block';\n"
"  for (const c of Array.from(activityGrid.children)) if (!seen[c.id]) c.remove();\n"
"}\n"
"// Tick the spark windows + last-seen labels every second so cards drift\n"
"// without needing an SSE event to repaint them.\n"
"setInterval(()=>{ if (Object.keys(activityState).length) refreshActivity(); }, 1000);\n"
"// =============================================================\n"
"// Topology tab: force-directed mesh-graph rendered to canvas.\n"
"// Edges come from two sources: NEIGHBORINFO_APP (authoritative\n"
"// 'I heard X with SNR Y') and the relay-hop hint (header.relay_node\n"
"// = upper byte of relayer's id, only resolved when we have a known\n"
"// node with that upper byte). Custom physics rather than vis-network\n"
"// to keep the dashboard CDN-free and bytecount tight.\n"
"// =============================================================\n"
"const topoCanvas = document.getElementById('topo-canvas');\n"
"const topoCtx = topoCanvas.getContext('2d');\n"
"const topoEmpty = document.getElementById('topo-empty');\n"
"// topoNodes[id] = {x, y, vx, vy, id, frames}\n"
"// topoEdges[a+'|'+b] = {a, b, snr, lastTs, count}  (a < b lexically)\n"
"const topoNodes = {}, topoEdges = {};\n"
"let topoActive = false, topoHover = null, topoMouse = {x:0, y:0};\n"
"let topoRafHandle = 0, topoLastTick = 0;\n"
"const TOPO_NODE_MAX = 200; /* render cap; nodes beyond this are pruned by recency */\n"
"// Synthetic 'this station' node id. Drawn at the canvas center,\n"
"// represents the sniffer's own RX. Every frame creates a faint dashed\n"
"// pseudo-edge from the transmitting node to this dot, colored by SNR --\n"
"// so even a sparse mesh with no NEIGHBORINFO traffic shows useful info\n"
"// (what the sniffer can hear and how well).\n"
"const RX_STATION_ID = '__rx_station__';\n"
"function topoNoteEdge(srcId, dstId, snr){\n"
"  if (!srcId || !dstId || srcId === dstId) return;\n"
"  const k = srcId < dstId ? srcId+'|'+dstId : dstId+'|'+srcId;\n"
"  let e = topoEdges[k];\n"
"  if (!e) e = topoEdges[k] = {a: srcId<dstId?srcId:dstId, b: srcId<dstId?dstId:srcId, snr: snr, count: 0, kind:'real'};\n"
"  if (snr !== undefined && snr !== null) e.snr = snr;\n"
"  e.count++; e.lastTs = Date.now()/1000;\n"
"  topoEnsureNode(srcId); topoEnsureNode(dstId);\n"
"  if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';\n"
"}\n"
"// Conversation pairs: per (sender, recipient) direction we mark each\n"
"// half observed. When both halves have been seen at any point in the\n"
"// session, that's a confirmed bidirectional conversation pair and a\n"
"// distinct edge style is drawn (kind='convo'). 'addressed' alone\n"
"// (one direction only) is intent, not RF observation, and is not drawn.\n"
"const topoPairs = {}; /* 'min|max' -> {fwd:bool, rev:bool} */\n"
"function topoNoteAddressed(fromId, toId){\n"
"  if (!fromId || !toId || fromId === toId) return;\n"
"  if (toId === '!ffffffff') return; /* broadcast: not a conversation pair */\n"
"  const lo = fromId < toId ? fromId : toId;\n"
"  const hi = fromId < toId ? toId : fromId;\n"
"  const k = lo+'|'+hi;\n"
"  let p = topoPairs[k];\n"
"  if (!p) p = topoPairs[k] = {fwd:false, rev:false};\n"
"  if (fromId === lo) p.fwd = true; else p.rev = true;\n"
"  if (p.fwd && p.rev) {\n"
"    /* Both directions seen: draw the bidirectional convo edge. */\n"
"    let e = topoEdges[k];\n"
"    if (!e) e = topoEdges[k] = {a: lo, b: hi, snr: undefined, count: 0, kind:'convo'};\n"
"    e.count++; e.lastTs = Date.now()/1000;\n"
"    topoEnsureNode(lo); topoEnsureNode(hi);\n"
"    if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';\n"
"  }\n"
"}\n"
"// Pseudo-edge from a transmitting node to the RX station. Marked\n"
"// kind='heard' so the renderer can dash it differently from real\n"
"// observed-RX edges (NEIGHBORINFO_APP / relay_node hop).\n"
"function topoNoteHeard(srcId, snr){\n"
"  if (!srcId || srcId === RX_STATION_ID) return;\n"
"  const k = srcId < RX_STATION_ID ? srcId+'|'+RX_STATION_ID : RX_STATION_ID+'|'+srcId;\n"
"  let e = topoEdges[k];\n"
"  if (!e) e = topoEdges[k] = {a: srcId<RX_STATION_ID?srcId:RX_STATION_ID,\n"
"                              b: srcId<RX_STATION_ID?RX_STATION_ID:srcId,\n"
"                              snr: snr, count: 0, kind:'heard'};\n"
"  if (snr !== undefined && snr !== null) e.snr = snr;\n"
"  e.count++; e.lastTs = Date.now()/1000;\n"
"  topoEnsureNode(srcId); topoEnsureNode(RX_STATION_ID);\n"
"  if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';\n"
"}\n"
"function topoEnsureNode(id){\n"
"  if (topoNodes[id]) return topoNodes[id];\n"
"  const rect = topoCanvas.getBoundingClientRect();\n"
"  const W = rect.width || 800, H = rect.height || 600;\n"
"  // RX station gets pinned at the canvas center so other nodes\n"
"  // arrange around it geographically. Real nodes seed at a random\n"
"  // ring around center so the force layout converges quickly.\n"
"  if (id === RX_STATION_ID) {\n"
"    topoNodes[id] = {id, x: W/2, y: H/2, vx:0, vy:0, pinned:true};\n"
"  } else {\n"
"    const a = Math.random()*Math.PI*2, r = 50 + Math.random()*60;\n"
"    topoNodes[id] = {id, x: W/2 + Math.cos(a)*r, y: H/2 + Math.sin(a)*r, vx:0, vy:0};\n"
"  }\n"
"  return topoNodes[id];\n"
"}\n"
"function topoSize(){ topoCanvas.width = topoCanvas.clientWidth; topoCanvas.height = topoCanvas.clientHeight; }\n"
"function topoSnrColor(snr, alpha){\n"
"  // SNR -> green (good) ... yellow ... red-ish (poor). Unknown SNR = neutral grey.\n"
"  if (snr === undefined || snr === null) return `rgba(148,163,184,${alpha||0.45})`;\n"
"  const s = Math.max(-25, Math.min(10, snr));\n"
"  const t = (s + 25) / 35; // 0..1\n"
"  const r = Math.round(255 * (1.0 - t));\n"
"  const g = Math.round(180 * t + 60);\n"
"  const b = 80;\n"
"  return `rgba(${r},${g},${b},${alpha||0.7})`;\n"
"}\n"
"function topoPrune(){\n"
"  const ids = Object.keys(topoNodes);\n"
"  if (ids.length <= TOPO_NODE_MAX) return;\n"
"  // Drop nodes with no recent edge activity, oldest first.\n"
"  ids.sort((a,b)=>{\n"
"    const la = (nodes[a] && nodes[a].ts) || 0;\n"
"    const lb = (nodes[b] && nodes[b].ts) || 0;\n"
"    return la - lb;\n"
"  });\n"
"  const drop = ids.length - TOPO_NODE_MAX;\n"
"  for (let i=0;i<drop;++i){\n"
"    delete topoNodes[ids[i]];\n"
"    for (const k of Object.keys(topoEdges)){\n"
"      if (topoEdges[k].a === ids[i] || topoEdges[k].b === ids[i]) delete topoEdges[k];\n"
"    }\n"
"  }\n"
"}\n"
"function topoTick(dt){\n"
"  const ids = Object.keys(topoNodes);\n"
"  if (!ids.length) return;\n"
"  const W = topoCanvas.width, H = topoCanvas.height;\n"
"  const cx = W/2, cy = H/2;\n"
"  // Repulsion (Coulomb-ish): O(n^2). At our 200-node cap that's 40k pair\n"
"  // checks per tick, well under the JS budget at 30 fps.\n"
"  const K_REP = 7000, K_ATT = 0.04, REST = 80, GRAV = 0.012, DAMP = 0.85, V_MAX = 240;\n"
"  for (let i=0;i<ids.length;++i){\n"
"    const a = topoNodes[ids[i]];\n"
"    let fx = 0, fy = 0;\n"
"    for (let j=0;j<ids.length;++j){\n"
"      if (i===j) continue;\n"
"      const b = topoNodes[ids[j]];\n"
"      let dx = a.x - b.x, dy = a.y - b.y;\n"
"      let d2 = dx*dx + dy*dy;\n"
"      if (d2 < 16) { dx = (Math.random()-0.5)*4; dy = (Math.random()-0.5)*4; d2 = 16; }\n"
"      const f = K_REP / d2;\n"
"      const d = Math.sqrt(d2);\n"
"      fx += (dx/d) * f; fy += (dy/d) * f;\n"
"    }\n"
"    // Center gravity so isolated subgraphs don't drift forever.\n"
"    fx += (cx - a.x) * GRAV; fy += (cy - a.y) * GRAV;\n"
"    a._fx = fx; a._fy = fy;\n"
"  }\n"
"  // Spring attraction along edges.\n"
"  for (const k in topoEdges){\n"
"    const e = topoEdges[k];\n"
"    const a = topoNodes[e.a], b = topoNodes[e.b];\n"
"    if (!a || !b) continue;\n"
"    const dx = b.x - a.x, dy = b.y - a.y;\n"
"    const d = Math.sqrt(dx*dx + dy*dy) || 0.001;\n"
"    const f = K_ATT * (d - REST);\n"
"    const fx = (dx/d) * f, fy = (dy/d) * f;\n"
"    a._fx += fx; a._fy += fy;\n"
"    b._fx -= fx; b._fy -= fy;\n"
"  }\n"
"  // Integrate. Pinned nodes (the RX station) skip integration so they\n"
"  // stay at their seeded center position regardless of edge forces.\n"
"  for (const id of ids){\n"
"    const a = topoNodes[id];\n"
"    if (a.pinned) { a.x = W/2; a.y = H/2; a.vx = 0; a.vy = 0; continue; }\n"
"    a.vx = (a.vx + a._fx*dt) * DAMP;\n"
"    a.vy = (a.vy + a._fy*dt) * DAMP;\n"
"    if (a.vx >  V_MAX) a.vx =  V_MAX; else if (a.vx < -V_MAX) a.vx = -V_MAX;\n"
"    if (a.vy >  V_MAX) a.vy =  V_MAX; else if (a.vy < -V_MAX) a.vy = -V_MAX;\n"
"    a.x += a.vx * dt; a.y += a.vy * dt;\n"
"    // Bounce softly at edges.\n"
"    const margin = 24;\n"
"    if (a.x < margin) { a.x = margin; a.vx *= -0.4; }\n"
"    if (a.y < margin) { a.y = margin; a.vy *= -0.4; }\n"
"    if (a.x > W-margin) { a.x = W-margin; a.vx *= -0.4; }\n"
"    if (a.y > H-margin) { a.y = H-margin; a.vy *= -0.4; }\n"
"  }\n"
"}\n"
"function topoNodeAt(mx, my){\n"
"  for (const id of Object.keys(topoNodes)){\n"
"    const a = topoNodes[id];\n"
"    const r = topoNodeRadius(id);\n"
"    const dx = a.x - mx, dy = a.y - my;\n"
"    if (dx*dx + dy*dy <= (r+3)*(r+3)) return id;\n"
"  }\n"
"  return null;\n"
"}\n"
"function topoNodeRadius(id){\n"
"  const n = nodes[id];\n"
"  const f = (n && n.frames) || 1;\n"
"  return Math.min(14, 4 + Math.log2(1 + f) * 1.4);\n"
"}\n"
"function topoRender(){\n"
"  const W = topoCanvas.width, H = topoCanvas.height;\n"
"  topoCtx.clearRect(0,0,W,H);\n"
"  const isLight = document.documentElement.classList.contains('light');\n"
"  // Edges first. 'heard' kind (this-station-to-source pseudo-edge)\n"
"  // renders dashed and a touch fainter so it doesn't compete visually\n"
"  // with real observed-RX edges (NEIGHBORINFO_APP / relay-hop).\n"
"  for (const k in topoEdges){\n"
"    const e = topoEdges[k];\n"
"    const a = topoNodes[e.a], b = topoNodes[e.b];\n"
"    if (!a || !b) continue;\n"
"    const isH = topoHover && (e.a===topoHover || e.b===topoHover);\n"
"    const isHeard = e.kind === 'heard';\n"
"    const isConvo = e.kind === 'convo';\n"
"    if (isConvo) {\n"
"      /* Conversation pair (both directions observed). Soft amber\n"
"       * solid line, distinct from observed-RX SNR-colored edges. */\n"
"      topoCtx.strokeStyle = isH ? 'rgba(251,191,36,0.95)' : 'rgba(251,191,36,0.65)';\n"
"      topoCtx.lineWidth = isH ? 2 : 1.4;\n"
"      topoCtx.setLineDash([]);\n"
"    } else {\n"
"      topoCtx.strokeStyle = topoSnrColor(e.snr, isH ? 0.95 : (isHeard ? 0.30 : 0.55));\n"
"      topoCtx.lineWidth = isH ? 2 : 1;\n"
"      topoCtx.setLineDash(isHeard ? [4, 3] : []);\n"
"    }\n"
"    topoCtx.beginPath(); topoCtx.moveTo(a.x, a.y); topoCtx.lineTo(b.x, b.y); topoCtx.stroke();\n"
"  }\n"
"  topoCtx.setLineDash([]);\n"
"  // Nodes. The RX station (this sniffer) renders distinctly: cyan\n"
"  // outer ring, larger, always labeled 'RX'.\n"
"  topoCtx.font = '12px system-ui';\n"
"  topoCtx.textAlign = 'center'; topoCtx.textBaseline = 'top';\n"
"  for (const id of Object.keys(topoNodes)){\n"
"    const a = topoNodes[id];\n"
"    const isStation = id === RX_STATION_ID;\n"
"    const r = isStation ? 9 : topoNodeRadius(id);\n"
"    const isH = id === topoHover;\n"
"    topoCtx.beginPath(); topoCtx.arc(a.x, a.y, r, 0, Math.PI*2);\n"
"    if (isStation) {\n"
"      topoCtx.fillStyle = isLight ? '#bae6fd' : '#0c4a6e';\n"
"      topoCtx.fill();\n"
"      topoCtx.strokeStyle = isLight ? '#0284c7' : '#38bdf8';\n"
"      topoCtx.lineWidth = 2; topoCtx.stroke();\n"
"      topoCtx.fillStyle = isLight ? '#0f172a' : '#e2e8f0';\n"
"      topoCtx.fillText('RX', a.x, a.y + r + 3);\n"
"      continue;\n"
"    }\n"
"    topoCtx.fillStyle = isH ? '#facc15' : (isLight ? '#0284c7' : '#38bdf8');\n"
"    topoCtx.fill();\n"
"    topoCtx.strokeStyle = isLight ? '#ffffff' : '#0f172a'; topoCtx.lineWidth = 1.2; topoCtx.stroke();\n"
"    if (isH) {\n"
"      const n = nodes[id];\n"
"      const label = (n && n.name) ? n.name : id;\n"
"      topoCtx.fillStyle = isLight ? '#1e293b' : '#e2e8f0';\n"
"      topoCtx.fillText(label, a.x, a.y + r + 3);\n"
"    }\n"
"  }\n"
"}\n"
"function topoLoop(now){\n"
"  if (!topoActive) { topoRafHandle = 0; return; }\n"
"  const dt = topoLastTick ? Math.min(0.05, (now - topoLastTick) / 1000) : 0.016;\n"
"  topoLastTick = now;\n"
"  topoTick(dt);\n"
"  topoRender();\n"
"  topoRafHandle = requestAnimationFrame(topoLoop);\n"
"}\n"
"function topoStart(){\n"
"  topoSize();\n"
"  topoActive = true; topoLastTick = 0;\n"
"  if (Object.keys(topoNodes).length === 0) topoEmpty.style.display = 'block';\n"
"  if (!topoRafHandle) topoRafHandle = requestAnimationFrame(topoLoop);\n"
"}\n"
"function topoStop(){ topoActive = false; }\n"
"window.addEventListener('resize', ()=>{ if (topoActive) topoSize(); });\n"
"topoCanvas.addEventListener('mousemove', e=>{\n"
"  const rect = topoCanvas.getBoundingClientRect();\n"
"  topoMouse.x = e.clientX - rect.left; topoMouse.y = e.clientY - rect.top;\n"
"  const hit = topoNodeAt(topoMouse.x, topoMouse.y);\n"
"  topoHover = hit;\n"
"  topoCanvas.classList.toggle('hovering', !!hit);\n"
"});\n"
"topoCanvas.addEventListener('mouseleave', ()=>{ topoHover = null; topoCanvas.classList.remove('hovering'); });\n"
"topoCanvas.addEventListener('click', ()=>{ if (topoHover && topoHover !== RX_STATION_ID) openDrawer(topoHover); });\n"
"// runs: 999 -> '999', 1234 -> '1.2k', 1234567 -> '1.2M', etc.\n"
"function fmtCount(n){if(n<1000)return String(n|0);if(n<1e6)return (n/1000).toFixed(n<10000?1:0)+'k';if(n<1e9)return (n/1e6).toFixed(n<10e6?1:0)+'M';return (n/1e9).toFixed(1)+'G';}\n"
"function setStat(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}\n"
"const es = new EventSource('/events');\n"
"es.onopen=()=>{const s=document.getElementById('status');if(s){s.textContent='connected';s.style.color='';}};\n"
"es.onerror=()=>{const s=document.getElementById('status');if(s){s.textContent='disconnected';s.style.color='#f87171';}};\n"
"es.onmessage = (e) => {\n"
"  let p; try { p = JSON.parse(e.data); } catch(_){ return; }\n"
"  if (p.event === 'STATS') {\n"
"    setStat('st-msps', (typeof p.msps==='number')?p.msps.toFixed(2):'--');\n"
"    setStat('st-frames', fmtCount(p.frames||0));\n"
"    setStat('st-decrypted', fmtCount(p.decrypted||0));\n"
"    if (p.off_grid !== undefined) {\n"
"      document.getElementById('st-offgrid-wrap').style.display = '';\n"
"      setStat('st-offgrid', fmtCount(p.off_grid));\n"
"    }\n"
"    // Focus pool summary: hide entirely when --deep-decode=off so the\n"
"    // bar stays compact for users who haven't enabled it.\n"
"    if (p.focus_active === true) {\n"
"      const w = p.focus_workers||0;\n"
"      const prom = p.focus_promotions||0;\n"
"      const drop = p.focus_dropped||0;\n"
"      const below = p.focus_below_snr||0;\n"
"      const fr = p.focus_frames||0;\n"
"      document.getElementById('st-focus-wrap').style.display = '';\n"
"      // Compact: 'Nw / Pprom / Ddrop / Bsnr / Ffr' -- expand on hover via title.\n"
"      setStat('st-focus', `${w}w ${fmtCount(prom)}p ${fmtCount(drop)}d ${fmtCount(below)}s ${fmtCount(fr)}f`);\n"
"    }\n"
"    // Clock discipline class. Hidden until first STATS so we don't\n"
"    // flash 'NTP' on a station that hasn't reported yet.\n"
"    if (p.clock) {\n"
"      document.getElementById('st-clock-wrap').style.display = '';\n"
"      const accNs = p.clock_acc_ns;\n"
"      let accLabel = '';\n"
"      if (typeof accNs === 'number') {\n"
"        if (accNs >= 1e6) accLabel = ` (${(accNs/1e6).toFixed(0)} ms)`;\n"
"        else if (accNs >= 1e3) accLabel = ` (${(accNs/1e3).toFixed(0)} us)`;\n"
"        else accLabel = ` (${accNs} ns)`;\n"
"      }\n"
"      setStat('st-clock', p.clock + accLabel);\n"
"    }\n"
"    return;\n"
"  }\n"
"  if (p.event === 'CHAN_SNR') {\n"
/* Per-slot SNR sparkline updates. Each entry is {id, snr:[60 ints,
 * -1 for empty bucket, otherwise rounded dB]}. Store keyed by slot id;
 * renderChannels() aggregates across the slots that share a channel
 * hash because the Channels table groups by hash. */
"    if (Array.isArray(p.channels)) {\n"
"      for (const c of p.channels) chanSnr[c.id] = c.snr;\n"
"      refreshChannels();\n"
"    }\n"
"    return;\n"
"  }\n"
"  if (p.event === 'OFF_GRID_LORA') {\n"
"    // Promote button: POSTs to /api/extra-freq to add a real decoder\n"
"    // slot at the discovered frequency. BW guess uses the scanner's\n"
"    // estimate clamped to a known LoRa BW (62.5 / 125 / 250 / 500 kHz).\n"
"    const bwGuess = p.bw_estimate_hz >= 400000 ? 500000\n"
"                  : p.bw_estimate_hz >= 200000 ? 250000\n"
"                  : p.bw_estimate_hz >= 100000 ? 125000 : 62500;\n"
"    const sf = 11; const cr = 5; // sensible defaults; user can override later\n"
"    const promoteBtn = `<button class=promote data-f=\"${p.f_hz}\" data-bw=\"${bwGuess}\" data-sf=\"${sf}\" data-cr=\"${cr}\">promote</button>`;\n"
"    pushTo(discEl, `<span class=disc>off-grid: ${(p.f_hz/1e6).toFixed(3)} MHz, SNR ${p.snr_db.toFixed(1)} dB, ~${(bwGuess/1000).toFixed(0)} kHz</span> ${promoteBtn}`, p.ts);\n"
"    return;\n"
"  }\n"
"  if (!p.from) return;\n"
"  // Station-self marker on the live map (when --gpsd is running).\n"
"  if (p.station_lat !== undefined && p.station_lon !== undefined) {\n"
"    noteStation(p.station_lat, p.station_lon, p.station_alt_m);\n"
"  }\n"
"  // CRC-failed frames are corrupt -- their 'from'/'to' fields are\n"
"  // bit-flipped versions of real node IDs. Including them in the\n"
"  // topology / nodes table populates phantom nodes that don't exist.\n"
"  // The raw event still goes to the SSE stream so an operator can\n"
"  // see them in JSON for debugging, but the aggregate views default\n"
"  // to dropping them.\n"
"  //\n"
"  // fields_trusted is the explicit boolean from feed.c: true when\n"
"  // either the LoRa CRC passed or the AES payload parsed cleanly.\n"
"  // false catches both CRC-fail (bit-corrupted bytes) AND no-CRC\n"
"  // frames whose payload didn't decrypt (could be a real frame on\n"
"  // an unknown channel PSK, could be a noise pattern that survived\n"
"  // the 5-bit header checksum -- can't tell, so by default don't\n"
"  // surface as a sighting). Toggle via #showUntrusted checkbox in\n"
"  // the Config tab to include them in aggregates for diagnostic use.\n"
"  const untrusted = (p.fields_trusted === false) ||\n"
"                    (p.payload_crc_ok === false);\n"
"  const showUntrusted = document.getElementById('showUntrusted');\n"
"  if (untrusted && !(showUntrusted && showUntrusted.checked)) return;\n"
"  // Topology heard-edge: every frame this station decodes (encrypted\n"
"  // or not) draws a faint pseudo-edge from the source node to the\n"
"  // synthetic RX station, colored by SNR. Useful when there's no\n"
"  // NEIGHBORINFO_APP traffic to mine real mesh-edge info from.\n"
"  topoNoteHeard(p.from, p.snr_db);\n"
"  if (p.to) topoNoteAddressed(p.from, p.to);\n"
"  // Per-channel stats: bucket by channel_hash so unknown networks are visible too.\n"
"  if (p.channel_hash !== undefined){\n"
"    const h = p.channel_hash;\n"
"    if (!channels[h]) channels[h] = {total:0, decrypted:0, ts:0, slots:new Set()};\n"
"    const c = channels[h]; c.total++; c.ts = p.ts;\n"
"    if (p.channel_name) c.name = p.channel_name;\n"
"    if (p.preset) c.preset = p.preset;\n"
"    if (p.slot_id !== undefined && p.slot_id !== null && p.slot_id >= 0) { if (!c.slots) c.slots = new Set(); c.slots.add(p.slot_id); c.lastSlot = p.slot_id; }\n"
"    // 'decrypted' is only emitted when false; presence of port_name/portnum implies success.\n"
"    const wasDecrypted = p.decrypted !== false && p.port_name;\n"
"    if (wasDecrypted) c.decrypted++;\n"
"    refreshChannels();\n"
"    activityNote({preset:p.preset, hash:h, channelName:p.channel_name, slot_id:p.slot_id, frame:true, decrypted:wasDecrypted});\n"
"    refreshActivity();\n"
"  }\n"
"  const id = p.from;\n"
"  if (!nodes[id]) nodes[id] = {ts:0, frames:0};\n"
"  const n = nodes[id]; n.ts = p.ts; n.frames = (n.frames||0) + 1;\n"
"  if (p.snr_db !== undefined) n.snr_db = p.snr_db;\n"
"  if (p.decrypted === false) n.has_encrypted = true;\n"
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
"    for (const nb of p.neighbors) {\n"
"      noteEdge(id, nb.id, nb.snr_db);\n"
"      topoNoteEdge(id, nb.id, nb.snr_db);\n"
"    }\n"
"  }\n"
"  // Relay-hop hint: try to resolve the upper byte to a known node and add\n"
"  // a topology edge between this node and the relayer. The map-side noteEdge\n"
"  // requires both to be positioned; the topology graph doesn't.\n"
"  if (p.relay_node !== undefined && p.relay_node !== null) {\n"
"    const relayByte = p.relay_node & 0xff;\n"
"    for (const candId of Object.keys(nodes)) {\n"
"      if (candId === id) continue;\n"
"      const numId = parseInt(candId.replace(/^!/,''), 16);\n"
"      if (((numId >> 24) & 0xff) === relayByte) topoNoteEdge(id, candId);\n"
"    }\n"
"  }\n"
"  if (Math.random() < 0.05) topoPrune();\n"
"  // Slot ids 1019..1023 are focused-pool / manual-focus workers (see\n"
"  // CHANNELIZER_MAX_CHANNELS in channelizer.h); flag those so the\n"
"  // operator can tell which frames the deep-decode path delivered.\n"
"  const focusedBadge = (typeof p.slot_id === 'number' && p.slot_id >= 1019)\n"
"    ? '<span class=muted style=\"color:#38bdf8\">[focused]</span> ' : '';\n"
"  const summary = msgSummary(p);\n"
"  if (summary) pushTo(msgsEl, `${focusedBadge}<b>${n.name||id}</b> <span class=muted>${p.channel_name||''}</span> <span class=port>${p.port_name||''}</span>: ${summary}`, p.ts);\n"
"  if (p.atak_callsign) pushTo(discEl, `<span class=atak>ATAK ${p.atak_callsign} (${p.atak_team}/${p.atak_role})${p.atak_chat?' chat: '+p.atak_chat:''}</span>`, p.ts);\n"
"  noteNodeFrame(id, p);\n"
"  evictNodes();\n"
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

/* Constant-time string compare for auth tokens. Returns 1 on match. */
static int ct_str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    /* Walk the longer of the two so a length mismatch doesn't short-circuit. */
    size_t n = la > lb ? la : lb;
    unsigned diff = (unsigned)la ^ (unsigned)lb;
    for (size_t i = 0; i < n; ++i) {
        unsigned ca = i < la ? (unsigned char)a[i] : 0;
        unsigned cb = i < lb ? (unsigned char)b[i] : 0;
        diff |= ca ^ cb;
    }
    return diff == 0;
}

/* Bearer-token auth check on POST /api endpoints.
 *
 * Returns 1 if the request is authorised (either no token is configured,
 * or the request carries the correct 'Authorization: Bearer SECRET' header).
 * On failure, sends a 401 response and returns 0; caller should `continue`.
 *
 * Header parsing is line-oriented: split on \r\n, find the line starting
 * with 'authorization:' (case-insensitive), then expect 'Bearer '. Tokens
 * with whitespace are unsupported.
 */
static int api_auth_ok(const char *buf, int fd)
{
    if (!opt_api_token) return 1; /* no auth configured -> allow */
    /* Search the request headers for an Authorization line. */
    const char *p = buf;
    const char *end = strstr(buf, "\r\n\r\n");
    if (!end) end = buf + strlen(buf);
    while (p < end) {
        const char *eol = strstr(p, "\r\n");
        if (!eol || eol >= end) break;
        /* Each header line: "Name: Value". Case-insensitive on the name. */
        if ((size_t)(eol - p) > 15 && !strncasecmp(p, "authorization:", 14)) {
            const char *v = p + 14;
            while (v < eol && (*v == ' ' || *v == '\t')) ++v;
            if ((size_t)(eol - v) > 7 && !strncasecmp(v, "Bearer ", 7)) {
                v += 7;
                while (v < eol && (*v == ' ' || *v == '\t')) ++v;
                size_t tlen = (size_t)(eol - v);
                char tok[256];
                if (tlen >= sizeof(tok)) tlen = sizeof(tok) - 1;
                memcpy(tok, v, tlen); tok[tlen] = 0;
                if (ct_str_eq(tok, opt_api_token)) return 1;
            }
        }
        p = eol + 2;
    }
    send_response(fd, 401,
        "{\"error\":\"missing or invalid Authorization: Bearer token\"}");
    return 0;
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
 * The base64-url payload is a protobuf ChannelSet { Channel channels = 1 }.
 *
 *   Channel { int32 index = 1; ChannelSettings settings = 2; Role role = 3; }
 *   ChannelSettings { uint32 channel_num = 1 [deprecated];
 *                     bytes psk = 2; string name = 3; ... }
 *
 * For each channel found, calls keyset_add(name, psk_bytes, psk_len).
 * Returns the number of channels added, or -1 on parse error. */
static int share_skip(const uint8_t **pp, const uint8_t *end, uint32_t wt)
{
    const uint8_t *p = *pp;
    if (wt == 0) {
        while (p < end && (*p++ & 0x80)) {}
    } else if (wt == 1) {
        if (end - p < 8) return -1;
        p += 8;
    } else if (wt == 2) {
        uint64_t l = 0; int sh = 0;
        while (p < end) {
            uint8_t b = *p++;
            l |= (uint64_t)(b & 0x7f) << sh;
            if (!(b & 0x80)) break;
            sh += 7;
        }
        if ((uint64_t)(end - p) < l) return -1;
        p += (size_t)l;
    } else if (wt == 5) {
        if (end - p < 4) return -1;
        p += 4;
    } else {
        return -1;
    }
    *pp = p;
    return 0;
}
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

            /* Parse Channel: look for field 2 (settings) submessage. */
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
                if (f2 != 2 || w2 != 2) {
                    if (share_skip(&cp, cend, w2) < 0) break;
                    continue;
                }
                uint64_t l2 = 0; s2 = 0;
                while (cp < cend) {
                    uint8_t b = *cp++;
                    l2 |= (uint64_t)(b & 0x7f) << s2;
                    if (!(b & 0x80)) break;
                    s2 += 7;
                }
                if ((uint64_t)(cend - cp) < l2) break;
                const uint8_t *sp = cp; const uint8_t *send = cp + l2; cp += l2;

                /* Parse ChannelSettings: field 2 = psk (bytes), field 3 = name (string). */
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
                    if (w3 != 2) {
                        if (share_skip(&sp, send, w3) < 0) break;
                        continue;
                    }
                    uint64_t l3 = 0; s3 = 0;
                    while (sp < send) {
                        uint8_t b = *sp++;
                        l3 |= (uint64_t)(b & 0x7f) << s3;
                        if (!(b & 0x80)) break;
                        s3 += 7;
                    }
                    if ((uint64_t)(send - sp) < l3) break;
                    if (f3 == 2 && l3 <= sizeof(psk)) {        /* psk */
                        memcpy(psk, sp, l3); psk_len = (size_t)l3;
                    } else if (f3 == 3 && l3 < sizeof(name)) { /* name */
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

    pthread_mutex_lock(&g_lock);
    /* Replay the history ring oldest-to-newest before going live, then
     * add to the broadcast list atomically -- so the new client doesn't
     * miss events published between replay-end and add-to-list. */
    int start = (g_history_count < HISTORY_RING_SIZE) ? 0 : g_history_head;
    static const char data_prefix[] = "data: ";
    for (int k = 0; k < g_history_count; ++k) {
        int idx = (start + k) % HISTORY_RING_SIZE;
        history_entry_t *e = &g_history[idx];
        if (!e->buf || e->len == 0) continue;
        /* Blocking sends here: the connection is fresh so the kernel buffer
         * is empty, and the dashboard JS handles dupes idempotently. If a
         * peer is genuinely slow we'll spend more time in the lock, but the
         * publishers (low-rate stats + per-frame events) tolerate it. */
        if (send(fd, data_prefix, 6, MSG_NOSIGNAL) < 0) break;
        if (send(fd, e->buf, e->len, MSG_NOSIGNAL) < 0) break;
        if (send(fd, "\n", 1, MSG_NOSIGNAL) < 0) break;
    }
    set_nonblock(fd);
    if (g_sse_count < MAX_SSE_CLIENTS) {
        g_sse_fds[g_sse_count++] = fd;
        if (verbose) fprintf(stderr, "web: SSE client connected (%d total, replayed %d events)\n",
                             g_sse_count, g_history_count);
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
#if defined(__APPLE__)
    pthread_setname_np("web");
#elif defined(_GNU_SOURCE)
    pthread_setname_np(pthread_self(), "web");
#endif
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
        else if (strncmp(buf, "POST /api/keys", 14) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            c2_response_t r;
            c2_keys_add(find_body(buf), &r);
            send_response(fd, r.status, r.body);
        }
        else if (strncmp(buf, "POST /api/share-url", 19) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            const char *body = find_body(buf);
            c2_response_t r;
            /* HTTP-form bodies arrive URL-encoded; decode before dispatch.
             * The share-URL parser itself is transport-agnostic in c2.c. */
            if (!body) { c2_share_url(NULL, &r); }
            else {
                char dec[1024];
                size_t bl = strlen(body);
                if (bl >= sizeof(dec)) bl = sizeof(dec) - 1;
                memcpy(dec, body, bl); dec[bl] = 0;
                url_decode_inplace(dec);
                c2_share_url(dec, &r);
            }
            send_response(fd, r.status, r.body);
        }
        else if (strncmp(buf, "POST /api/extra-freq", 20) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            c2_response_t r;
            c2_extra_freq(find_body(buf), &r);
            send_response(fd, r.status, r.body);
        }
        else if (strncmp(buf, "POST /api/cot-multicast", 23) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            c2_response_t r;
            c2_cot_multicast(find_body(buf), &r);
            send_response(fd, r.status, r.body);
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
    fprintf(stderr, "web: listening on port %d\n", port);
}

void web_publish_line(const char *json, size_t len)
{
    if (!json || len == 0) return;
    /* Assemble "data: <json>\n" (json already ends with its own newline,
     * so the trailing '\n' here completes the SSE event terminator) into
     * one buffer and write it with a single send(). Splitting into three
     * send() calls let a slow browser take the header, return EAGAIN on
     * the body, and keep the FD open mid-frame -- the next event then
     * appended a fresh "data: " on top of the half-written one and
     * corrupted every subsequent message on that client. */
    static const char HDR[] = "data: ";
    const size_t hdrlen = sizeof(HDR) - 1;
    const size_t total  = hdrlen + len + 1;

    char  stackbuf[4096];
    char *buf = stackbuf;
    if (total > sizeof(stackbuf)) {
        buf = malloc(total);
        if (!buf) return;
    }
    memcpy(buf, HDR, hdrlen);
    memcpy(buf + hdrlen, json, len);
    buf[hdrlen + len] = '\n';

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_sse_count; ) {
        int fd = g_sse_fds[i];
        ssize_t w = send(fd, buf, total, MSG_NOSIGNAL | MSG_DONTWAIT);
        /* Any short write or EAGAIN means we cannot keep this client
         * framed -- close it. A reload reconnects fresh and replays
         * from g_history. */
        if (w < (ssize_t)total) {
            close(fd);
            g_sse_fds[i] = g_sse_fds[--g_sse_count];
            continue;
        }
        ++i;
    }
    /* Push into the history ring so a browser refresh / late-joining tab
     * can reconstruct dashboard state without waiting for new traffic.
     * Same lock as the broadcast list -- atomicity matters: the new
     * client's replay (under this lock) must not miss events published
     * between replay-start and add-to-list. */
    history_entry_t *e = &g_history[g_history_head];
    free(e->buf); /* free(NULL) is a no-op for slots not yet written */
    e->buf = malloc(len);
    if (e->buf) {
        memcpy(e->buf, json, len);
        e->len = len;
        g_history_head = (g_history_head + 1) % HISTORY_RING_SIZE;
        if (g_history_count < HISTORY_RING_SIZE) ++g_history_count;
    } else {
        e->buf = NULL; e->len = 0; /* malloc fail: slot empty, ring intact */
    }
    pthread_mutex_unlock(&g_lock);

    if (buf != stackbuf) free(buf);
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
    /* Release the history ring so leak detectors don't flag exit-time bytes. */
    for (int i = 0; i < HISTORY_RING_SIZE; ++i) {
        free(g_history[i].buf);
        g_history[i].buf = NULL;
        g_history[i].len = 0;
    }
    g_history_head = g_history_count = 0;
    pthread_mutex_unlock(&g_lock);
}
