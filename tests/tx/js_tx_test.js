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
           style: {}, listeners: {}, addEventListener(t, f) { this.listeners[t] = f; } };
}
const els = {};
const ids = ['tx-box', 'tx-config', 'tx-token-row', 'tx-info', 'tx-text', 'tx-send', 'tx-status',
             'txcfg-status', 'tx-channel', 'tx-psk', 'tx-preset', 'tx-slot', 'tx-to', 'tx-hop',
             'tx-gain', 'tx-long_name', 'tx-short_name', 'tx-amp', 'tx-token'];
for (const i of ids) els[i] = el(i);
const document = { getElementById: id => els[id] || (() => { throw new Error('no element ' + id); })() };
const store = {}, sess = {};
const localStorage = { getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = v; } };
const sessionStorage = { getItem: k => sess[k] ?? null, setItem: (k, v) => { sess[k] = v; } };
function setStatus(id, txt, ok) { els[id].textContent = txt; els[id].className = 'hint ' + (ok ? 'status-ok' : 'status-err'); }
const pushed = [];
function pushTo(target, html) { pushed.push(html); }
function escHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
const msgsEl = {};

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
                           'escHtml', 'msgsEl', code + '\nreturn {txSend, txSaveSettings};');
  const api = run(document, fetch, localStorage, sessionStorage, setStatus, pushTo, escHtml, msgsEl);
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

  // disabled sniffer -> nothing shown
  for (const i of ids) els[i] = el(i);
  statusResp = { enabled: false };
  run(document, fetch, localStorage, sessionStorage, setStatus, pushTo, escHtml, msgsEl);
  await new Promise(r => setTimeout(r, 10));
  check(els['tx-box'].style.display === undefined, 'TX disabled -> send box stays hidden');

  console.log('FAILS:', fails);
  process.exit(fails ? 1 : 0);
})();
