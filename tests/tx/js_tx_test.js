// Runtime test of the dashboard's TX functions with a stub DOM + fetch.
const fs = require('fs');
const all = fs.readFileSync(process.argv[2], 'utf8');
const start = all.indexOf('// Transmit: Send box');
const end = all.indexOf('txInit();', start) + 'txInit();'.length;
const code = all.slice(start, end);

let fails = 0;
const check = (c, m) => { console.log((c ? 'ok   ' : 'FAIL ') + m); if (!c) fails++; };

function el(id) {
  return { id, value: '', checked: false, disabled: false, textContent: '', className: '',
           style: {}, listeners: {}, dataset: {}, addEventListener(t, f) { this.listeners[t] = f; }, focus() {} };
}
const els = {};
const ids = ['tx-box', 'tx-config', 'tx-token-row', 'tx-info', 'tx-text', 'tx-send', 'tx-status',
             'txcfg-status', 'tx-channel', 'tx-psk', 'tx-preset', 'tx-slot', 'tx-to', 'tx-hop',
             'tx-gain', 'tx-long_name', 'tx-short_name', 'tx-amp', 'tx-token',
             'tx-reply', 'tx-reply-label', 'drawer-tx', 'dtx-text', 'dtx-dm', 'dtx-ack', 'dtx-status', 'dtx-log', 'dtx-pki', 'dtx-pubkey'];
for (const i of ids) els[i] = el(i);
const reqButtons = [el('r1'), el('r2')];
const document = { getElementById: id => els[id] || (() => { throw new Error('no element ' + id); })(),
                   querySelectorAll: () => reqButtons };
const store = {}, sess = {};
const localStorage = { getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = v; } };
const sessionStorage = { getItem: k => sess[k] ?? null, setItem: (k, v) => { sess[k] = v; } };
function setStatus(id, txt, ok) { els[id].textContent = txt; els[id].className = 'hint ' + (ok ? 'status-ok' : 'status-err'); }
const pushed = [];
function pushTo(target, html) { pushed.push(html); }
function escHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
const msgsEl = el('msgs');
const nodes = { '!aabbccdd': { name: 'Alice <x>' }, '!11223344': { name: 'Relay' } };
const fmtTime = t => 'T';
const msgSummary = p => p.lat !== undefined ? `${p.lat},${p.lon}` : null;

let requests = [], nextResponse = null;
async function fetch(url, opts) {
  requests.push({ url, opts });
  if (url === '/api/tx' && !opts) return { ok: true, json: async () => statusResp };
  const r = nextResponse;
  return { ok: r.status === 200, status: r.status, json: async () => r.body };
}
let statusResp = { enabled: true, tool: true, mode: 'hackrf-inline', region: 'US', from: '!12345678', auth: true };

(async () => {
  store.txSettings = JSON.stringify({ channel: 'Ops', psk: 'AQ==', preset: 'LONG_FAST', slot: '', to: '',
                                      hop: '3', gain: '14', long_name: 'Sniffer TX', short_name: 'STX', amp: true });
  sess.txToken = 's3cret';
  const run = new Function('document', 'fetch', 'localStorage', 'sessionStorage', 'setStatus', 'pushTo',
                           'escHtml', 'msgsEl', 'nodes', 'fmtTime', 'msgSummary',
                           'let drawerNodeId = null;\n' + code +
                           '\nreturn {txSend, txSaveSettings, txRequest, txDirect, txOnEvent, txReplyButton, txSetReply,' +
                           ' txClearReply, txRenderDrawer, setDrawer: v => { drawerNodeId = v; }};');
  const args = () => [document, fetch, localStorage, sessionStorage, setStatus, pushTo, escHtml, msgsEl, nodes, fmtTime, msgSummary];
  const api = run(...args());
  await new Promise(r => setTimeout(r, 10));  // let txInit() finish

  check(els['tx-box'].style.display === 'flex' && els['tx-config'].style.display === 'block', 'enabled -> send box + config shown');
  check(els['tx-token-row'].style.display !== 'none', 'token row shown when --api-token set');
  check(/!12345678/.test(els['tx-info'].textContent) && /RX pauses/.test(els['tx-info'].textContent), 'info line: ' + els['tx-info'].textContent);
  check(els['tx-channel'].value === 'Ops' && els['tx-amp'].checked && els['tx-token'].value === 's3cret', 'saved settings restored');

  els['tx-text'].value = '  hi <b>&mesh  ';
  nextResponse = { status: 200, body: { ok: true, from: '!12345678', freq_mhz: 906.875, packets: 2, id: 'abcd', airtime_ms: 1118 } };
  await api.txSend();
  const req = requests[requests.length - 1];
  const body = new URLSearchParams(req.opts.body);
  check(req.url === '/api/tx' && req.opts.method === 'POST', 'POST /api/tx');
  check(req.opts.headers['X-Mesh-Tx'] === '1' && req.opts.headers['Authorization'] === 'Bearer s3cret', 'CSRF + auth headers');
  check(body.get('text') === 'hi <b>&mesh' && body.get('channel') === 'Ops' && body.get('gain') === '14' &&
        body.get('amp') === '1' && body.get('long_name') === 'Sniffer TX' && !body.has('slot') && !body.has('to'),
        'form body: ' + req.opts.body);
  check(els['tx-text'].value === '' && /sent 2 packet/.test(els['tx-status'].textContent), 'cleared + status: ' + els['tx-status'].textContent);
  check(pushed.length === 1 && pushed[0].includes('hi &lt;b&gt;&amp;mesh') && !pushed[0].includes('<b>&mesh'), 'echo is HTML-escaped: ' + pushed[0]);
  check(!els['tx-send'].disabled, 'button re-enabled');

  els['tx-text'].value = 'again';
  nextResponse = { status: 429, body: { error: 'wait a few seconds between sends' } };
  await api.txSend();
  check(/TX failed: wait/.test(els['tx-status'].textContent) && els['tx-text'].value === 'again', 'error shown, text kept');

  const n = requests.length;
  els['tx-text'].value = '   ';
  await api.txSend();
  check(requests.length === n, 'blank text not sent');

  let enterPressed = false;
  els['tx-text'].listeners.keydown({ key: 'Enter', preventDefault() { enterPressed = true; } });
  check(enterPressed, 'Enter key triggers send');

  check(els['drawer-tx'].style.display === 'block', 'drawer Interact section shown');

  // ---- reply to a channel message / a DM ----
  const chanMsg = { from: '!aabbccdd', to: '!ffffffff', packet_id: 0x1a2b3c4d, port_name: 'TEXT_MESSAGE_APP', text: 'yo' };
  const btnHtml = api.txReplyButton(chanMsg);
  check(/data-rid="1a2b3c4d"/.test(btnHtml) && /data-dm="0"/.test(btnHtml), 'reply button on channel text: ' + btnHtml);
  check(api.txReplyButton({ ...chanMsg, port_name: 'POSITION_APP' }) === '', 'no reply button on non-text ports');
  msgsEl.listeners.click({ target: { closest: () => ({ dataset: { rid: '1a2b3c4d', from: '!aabbccdd', dm: '0' } }) } });
  check(els['tx-reply'].style.display === 'flex' && /Alice <x>/.test(els['tx-reply-label'].textContent) &&
        /in channel/.test(els['tx-reply-label'].textContent), 'reply chip: ' + els['tx-reply-label'].textContent);
  els['tx-text'].value = 'sure';
  nextResponse = { status: 200, body: { ok: true, from: '!12345678', to: 'broadcast', kind: 'text', freq_mhz: 906.875, packets: 2, id: '0000beef', airtime_ms: 900 } };
  await api.txSend();
  let b = new URLSearchParams(requests[requests.length - 1].opts.body);
  check(b.get('reply_id') === '1a2b3c4d' && b.get('to') === 'broadcast' && b.get('kind') === 'text',
        'channel reply -> broadcast + reply_id: ' + b.toString());
  check(els['tx-reply'].style.display === 'none', 'reply chip cleared after send');
  api.txSetReply('00000042', '!aabbccdd', true);
  els['tx-text'].value = 'dm back';
  await api.txSend();
  b = new URLSearchParams(requests[requests.length - 1].opts.body);
  check(b.get('reply_id') === '00000042' && b.get('to') === '!aabbccdd', 'DM reply -> to sender + reply_id');
  api.txSetReply('zz<script>', '!aabbccdd', true);
  check(els['tx-reply'].style.display === 'none', 'malformed reply id ignored');

  // ---- drawer actions ----
  api.setDrawer('!aabbccdd');
  nextResponse = { status: 200, body: { ok: true, from: '!12345678', to: '!aabbccdd', kind: 'position', freq_mhz: 906.875, packets: 1, id: 'cafe0001', airtime_ms: 400 } };
  els['dtx-ack'].checked = true;
  await api.txRequest('position');
  b = new URLSearchParams(requests[requests.length - 1].opts.body);
  check(b.get('kind') === 'position' && b.get('to') === '!aabbccdd' && b.get('ack') === '1' && !b.has('text') && !b.has('reply_id'),
        'position request form: ' + b.toString());
  check(/waiting for an answer/.test(els['dtx-status'].textContent) && /position request sent/.test(els['dtx-log'].innerHTML),
        'drawer status + log after request');
  check(!els['dtx-dm'].disabled && !reqButtons[0].disabled, 'drawer buttons re-enabled');

  // the answer arrives (request_id = our id)
  pushed.length = 0;
  api.txOnEvent({ from: '!aabbccdd', to: '!12345678', port_name: 'POSITION_APP', request_id: 0xcafe0001, lat: 45.1, lon: 9.2, ts: 1 });
  check(pushed.length === 1 && /answered our position request/.test(pushed[0]) && /45.1,9.2/.test(pushed[0]) &&
        /Alice &lt;x&gt;/.test(pushed[0]), 'position answer matched: ' + pushed[0]);
  check(/45.1,9.2/.test(els['dtx-log'].innerHTML), 'answer in the drawer log');
  api.txOnEvent({ from: '!aabbccdd', port_name: 'POSITION_APP', request_id: 0x99, lat: 1, lon: 2 });
  check(pushed.length === 1, 'unrelated request_id ignored');

  // traceroute + routing ACK/NAK
  nextResponse = { status: 200, body: { ok: true, from: '!12345678', to: '!aabbccdd', kind: 'traceroute', freq_mhz: 906.875, packets: 1, id: 'cafe0002', airtime_ms: 400 } };
  await api.txRequest('traceroute');
  api.txOnEvent({ from: '!aabbccdd', port_name: 'TRACEROUTE_APP', request_id: 0xcafe0002, route: ['!11223344'],
                  snr_towards_db: [6.25, -3], route_back: [], snr_back_db: [5] });
  check(/route: !12345678 &rarr; Relay <span class=muted>\(6.3 dB\)<\/span> &rarr; Alice &lt;x&gt; <span class=muted>\(-3.0 dB\)/.test(pushed[pushed.length - 1]) &&
        /back: Alice &lt;x&gt; &rarr; !12345678 <span class=muted>\(5.0 dB\)/.test(pushed[pushed.length - 1]),
        'traceroute rendered: ' + pushed[pushed.length - 1]);
  nextResponse = { status: 200, body: { ok: true, from: '!12345678', to: '!aabbccdd', kind: 'text', freq_mhz: 906.875, packets: 1, id: 'cafe0003', airtime_ms: 400 } };
  els['dtx-text'].value = 'ping';
  await api.txDirect();
  b = new URLSearchParams(requests[requests.length - 1].opts.body);
  check(b.get('kind') === 'text' && b.get('text') === 'ping' && b.get('to') === '!aabbccdd' && els['dtx-text'].value === '',
        'drawer DM form: ' + b.toString());
  api.txOnEvent({ from: '!aabbccdd', port_name: 'ROUTING_APP', request_id: 0xcafe0003 });
  check(/ACK: message delivered/.test(pushed[pushed.length - 1]), 'routing ACK: ' + pushed[pushed.length - 1]);
  api.txOnEvent({ from: '!11223344', port_name: 'ROUTING_APP', request_id: 0xcafe0003, error_reason: 8 });
  check(/NAK: NO_RESPONSE/.test(pushed[pushed.length - 1]), 'routing NAK: ' + pushed[pushed.length - 1]);
  api.txOnEvent({ from: '!aabbccdd', port_name: 'ROUTING_APP', request_id: 0xcafe0003, error_reason: 6 });
  check(/NO_CHANNEL \(the node only accepts PKI/.test(pushed[pushed.length - 1]), 'DM NO_CHANNEL explained');

  // our own packet: heard directly (ignored) vs rebroadcast by the mesh
  els['tx-status'].textContent = '';
  api.txOnEvent({ from: '!12345678', packet_id: 0xcafe0003, hop_limit: 3, hop_start: 3 });
  check(els['tx-status'].textContent === '', 'own packet heard directly is not "on the mesh"');
  api.txOnEvent({ from: '!12345678', packet_id: 0xcafe0003, hop_limit: 2, hop_start: 3 });
  check(/heard on the mesh/.test(els['tx-status'].textContent), 'rebroadcast of our packet noticed');

  // ---- public-key DMs ----
  api.setDrawer('!aabbccdd');
  api.txRenderDrawer('!aabbccdd');
  check(/not seen yet/.test(els['dtx-pki'].textContent), 'drawer: key unknown at first');
  api.txOnEvent({ from: '!aabbccdd', port_name: 'NODEINFO_APP', public_key: 'ab'.repeat(32) });
  check(/key known/.test(els['dtx-pki'].textContent), 'NodeInfo with public_key -> key known');
  els['dtx-pubkey'].value = 'KEYB64=';
  els['dtx-text'].value = 'psst';
  nextResponse = { status: 200, body: { ok: true, from: '!12345678', to: '!aabbccdd', kind: 'text', freq_mhz: 869.525, packets: 2, id: 'cafe0004', airtime_ms: 300, pki: true } };
  await api.txDirect();
  b = new URLSearchParams(requests[requests.length - 1].opts.body);
  check(b.get('pubkey') === 'KEYB64=' && els['dtx-pubkey'].value === '' && /public-key encrypted/.test(els['dtx-status'].textContent),
        'pasted key sent, cleared after a PKI send: ' + els['dtx-status'].textContent);
  check(/&#128274;/.test(pushed[pushed.length - 1]), 'PKI DM echo has a lock');
  nextResponse = { status: 200, body: { ok: true, from: '!12345678', to: '!aabbccdd', kind: 'text', freq_mhz: 869.525, packets: 1, id: 'cafe0005', airtime_ms: 300, pki: false, warning: 'no public key known' } };
  els['dtx-text'].value = 'legacy';
  await api.txDirect();
  b = new URLSearchParams(requests[requests.length - 1].opts.body);
  check(!b.has('pubkey') && /no public key known/.test(els['dtx-status'].textContent) && /status-err/.test(els['dtx-status'].className),
        'server warning shown as an error');
  api.txOnEvent({ from: '!aabbccdd', to: '!12345678', port_name: 'TEXT_MESSAGE_APP', text: 'hello you', pki_encrypted: true });
  check(/RX<\/span>DM &#128274;: hello you/.test(els['dtx-log'].innerHTML), 'unsolicited PKI DM to us logged in the drawer');
  api.txOnEvent({ from: '!aabbccdd', to: '!12345678', port_name: 'TEXT_MESSAGE_APP', text: 'thx', reply_id: 0xcafe0004, pki_encrypted: true });
  check(/reply &#128274;: thx/.test(pushed[pushed.length - 1]), 'PKI reply to our DM matched');

  // drawer failure path
  nextResponse = { status: 400, body: { error: 'requests need a destination node (to=!aabbccdd)' } };
  await api.txRequest('telemetry');
  check(/TX failed: requests need/.test(els['dtx-status'].textContent), 'drawer shows server error');

  // disabled sniffer -> nothing shown
  for (const i of ids) els[i] = el(i);
  statusResp = { enabled: false };
  run(...args());
  await new Promise(r => setTimeout(r, 10));
  check(els['tx-box'].style.display === undefined && els['drawer-tx'].style.display === undefined,
        'TX disabled -> send box and drawer actions stay hidden');

  console.log('FAILS:', fails);
  process.exit(fails ? 1 : 0);
})();
