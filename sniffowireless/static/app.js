'use strict';

const KINDS = {
  ap: { label: 'Access points', short: 'AP', color: '#4cc2ff' },
  wifi_client: { label: 'Wi-Fi clients', short: 'Wi-Fi client', color: '#3ecf8e' },
  ble: { label: 'BLE devices', short: 'BLE', color: '#f5b84a' },
  bt_classic: { label: 'Bluetooth classic', short: 'BT classic', color: '#ef6f6c' },
  lan: { label: 'LAN devices', short: 'LAN', color: '#a8b3c2' },
};
// Kinds of radios an admin has switched off (Settings → Modules): their menu entries, cards and statistics are hidden.
let MODS = {}, PRIVACY = {};
const KIND_MOD = { ap: 'wifi', wifi_client: 'wifi', ble: 'bluetooth', bt_classic: 'bluetooth', lan: 'lan', zigbee: 'zigbee', lora: 'lora' };
// Radios that are not devices with a MAC: counted from their own tables, shown on the overview next to the kinds above.
const EXTRA_KINDS = {
  zigbee: { label: 'Zigbee radios', color: '#ff9f6b', href: '#/zigbee' },
  lora: { label: 'LoRa nodes', color: '#c792ea', href: '#/lora' },
};
const extraEntries = () => Object.entries(EXTRA_KINDS).filter(([k]) => kindOn(k));
const SENSOR_MOD = { wifi: 'wifi', bluetooth: 'bluetooth', ethernet: 'lan', zigbee: 'zigbee', lora: 'lora' };
const modOn = m => MODS[m] !== false;
const kindOn = k => modOn(KIND_MOD[k]);
const kindEntries = () => Object.entries(KINDS).filter(([k]) => kindOn(k));
function paintModules() {
  document.querySelectorAll('[data-mod]').forEach(e => { e.hidden = !modOn(e.dataset.mod); });
  const pill = document.getElementById('anon-pill');
  if (pill) {
    const what = [PRIVACY.macs ? 'MAC addresses' : '', PRIVACY.ssids ? 'SSIDs' : ''].filter(Boolean).join(' and ');
    pill.hidden = !what;
    pill.title = what ? `Anonymised view: ${what} are shown as pseudonyms (Settings → Privacy)` : '';
  }
}
async function loadModules() {
  try {
    const r = await fetch('/api/modules');
    if (r.ok) { MODS = {}; const j = await r.json(); j.modules.forEach(m => { MODS[m.id] = m.enabled; }); PRIVACY = j.privacy || {}; }
  } catch { /* keep showing everything */ }
  paintModules();
}
let TEXT = '#e6e7e9', MUTED = '#8a8f98', FAINT = '#5b6068', GRID = '#1f2227';
const TZ = new Date().getTimezoneOffset();
const IFACE_HIST_MAX = 60;  // 10s poll interval -> 10 minutes of history, kept in the browser only
const IFACE_COLORS = ['#4cc2ff', '#3ecf8e', '#f5b84a', '#ef6f6c', '#a8b3c2', '#c792ea', '#6fd3ff', '#ffb86b'];
const app = document.getElementById('app');

if (window.Chart) {
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.size = 11;
  Chart.defaults.plugins.legend.display = false;
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.animation = false;
}

// Take the (possibly admin-customised) colours from the CSS variables into the JS palettes and chart defaults.
function themeToJs() {
  const cs = getComputedStyle(document.documentElement), v = (n, d) => (cs.getPropertyValue(n) || '').trim() || d;
  TEXT = v('--text', TEXT); MUTED = v('--muted', MUTED); FAINT = v('--faint', FAINT); GRID = v('--border', GRID);
  Object.keys(KINDS).forEach(k => { KINDS[k].color = v(`--${k}`, KINDS[k].color); });
  const ap = KINDS.ap.color, custom = APPEARANCE && (APPEARANCE.custom_colors || []).includes('ap');
  BANDS['2.4'].color = ap;
  BANDS['5'].color = custom ? mixHex(ap, '#ffffff', 0.37) : '#8fd8ff';
  BANDS['6'].color = custom ? mixHex(ap, '#ffffff', 0.75) : '#d2efff';
  if (window.Chart) {
    Chart.defaults.color = MUTED;
    Chart.defaults.borderColor = GRID;
    Chart.defaults.plugins.tooltip.backgroundColor = v('--panel-2', '#16181c');
    Chart.defaults.plugins.tooltip.borderColor = v('--border-2', '#2a2e35');
    Chart.defaults.plugins.tooltip.titleColor = TEXT;
    Chart.defaults.plugins.tooltip.bodyColor = MUTED;
  }
}
const PANEL = () => (getComputedStyle(document.documentElement).getPropertyValue('--panel') || '').trim() || '#111316';
function mixHex(a, b, t) {
  const p = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16));
  if (!/^#[0-9a-f]{6}$/i.test(a)) return a;
  const x = p(a), y = p(b);
  return '#' + x.map((c, i) => Math.round(c + (y[i] - c) * t).toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------ helpers
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = encodeURIComponent;
const isMac = s => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s || '');

let ME = null;  // {username, role} of the logged-in user
const isAdmin = () => !ME || ME.role === 'admin';

async function api(path) {
  const r = await fetch(path, { headers: { 'X-Sniffowireless': '1' } });
  if (r.status === 401) { location.href = '/login'; throw new Error('Not logged in'); }
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}
// Mutating request; throws Error(detail) on failure.
async function send(method, path, body) {
  const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', 'X-Sniffowireless': '1' },
    body: body === undefined ? undefined : JSON.stringify(body) });
  if (r.status === 401) { location.href = '/login'; throw new Error('Not logged in'); }
  let data = null;
  try { data = await r.json(); } catch { /* empty */ }
  if (!r.ok) {
    const d = data && data.detail;
    throw new Error(Array.isArray(d) ? d.map(x => x.msg).join('; ') : d || `${r.status} ${r.statusText}`);
  }
  return data;
}
// Copy to the clipboard; falls back to a temporary textarea where the async API isn't available (plain http).
async function copyText(text, done = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(done); return; } catch { /* fall through */ }
  const t = document.createElement('textarea');
  t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
  document.body.appendChild(t); t.select();
  try { document.execCommand('copy'); toast(done); } catch { toast('Copy failed — select the address bar instead', true); }
  t.remove();
}
function toast(msg, bad = false) {
  const t = document.createElement('div');
  t.className = 'toast' + (bad ? ' bad' : '');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), bad ? 6000 : 3000);
}

function ago(ts) {
  if (!ts) return '—';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function dur(s) {
  if (s == null) return '—';
  s = Math.round(s);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60 ? (s % 60) + 's' : ''}`.trim();
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor(s % 86400 / 3600)}h`;
}
function dt(ts, withDate = true) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  const t = d.toLocaleTimeString([], clockOpts({ hour: '2-digit', minute: '2-digit' }));
  if (!withDate) return t;
  return `${d.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${t}`;
}
function axisTime(ts, span) {
  const d = new Date(ts * 1000);
  if (span <= 86400 * 1.1) return d.toLocaleTimeString([], clockOpts({ hour: '2-digit', minute: '2-digit' }));
  return d.toLocaleDateString([], { weekday: 'short', day: 'numeric' }) + (span < 86400 * 4 ? ' ' + hourLabel(d.getHours(), true) + (uses12h() ? '' : 'h') : '');
}
const num = n => (Number(n) || 0).toLocaleString();  // Number(): never echo a string from the server
const BANDS = { '2.4': { label: '2.4 GHz', color: '#4cc2ff' }, '5': { label: '5 GHz', color: '#8fd8ff' }, '6': { label: '6 GHz', color: '#d2efff' } };
// Fixed order: JS would otherwise list the integer-like keys '5' and '6' before '2.4'.
const BAND_LIST = ['2.4', '5', '6'].map(b => [b, BANDS[b]]);
const DEV_TYPES = {
  phone: 'Phone', tablet: 'Tablet', laptop: 'Laptop', desktop: 'Desktop PC', computer: 'Computer', watch: 'Smartwatch',
  wearable: 'Wearable', headphones: 'Headphones', speaker: 'Speaker', tv: 'TV', streaming: 'Streaming device',
  console: 'Game console', controller: 'Game controller', printer: 'Printer', camera: 'Camera', tag: 'Tracker tag',
  sensor: 'Sensor', iot: 'IoT device', light: 'Smart light', input: 'Keyboard / mouse', car: 'Car', charger: 'EV charger',
  router: 'Router / access point', hotspot: 'Mobile hotspot', smart_home: 'Smart home', beacon: 'Beacon',
  sbc: 'Single-board computer', media: 'Media device', network: 'Network device', nas: 'NAS / storage', server: 'Server', bike: 'Bike / e-bike',
};
const genLabel = g => g == null ? 'Unknown' : g === 66 ? 'Wi-Fi 6E' : g === 3 ? 'Legacy a/b/g' : `Wi-Fi ${g}`;
const eraLabel = y => y == null ? 'Unknown' : y <= 2003 ? 'before ~2010' : `${y} or newer`;
const typeLabel = t => t ? (DEV_TYPES[t] || t) : 'Unknown';
const ADDR_TYPES = { public: 'Public (fixed)', 'random-static': 'Random static', 'random-resolvable': 'Random resolvable (private)',
  'random-nonresolvable': 'Random non-resolvable' };
// A Bluetooth version is exact ("5.4", the device reported it) or a lower bound ("5.2+", from the features it advertises).
function btVerTag(v, basis) {
  if (!v) return '<span class="faint">—</span>';
  if (v.endsWith('+')) return `<span class="tag" title="At least this version, going by its ${esc(basis || 'advertised features')}: the device does not report a version">${esc(v)}</span>`;
  return `<span class="tag on" title="${esc(basis ? basis.charAt(0).toUpperCase() + basis.slice(1) : 'Reported by the device')}">${esc(v)}</span>`;
}
// The version row of the device page: exact (reported / from the model's specification) or a lower bound.
function btVerDetail(ex) {
  const v = ex.bt_ver || ex.bt_version, basis = ex.bt_basis || '';
  if (v.endsWith('+')) return `${esc(v)} <span class="faint">at least, going by its ${esc(basis || 'features')} (the device does not report a version)</span>`;
  if (!basis || basis === 'reported by the device') return `${esc(v)}${ex.chip ? ` <span class="faint">(${esc(ex.chip)})</span>` : ''}`;
  return `${esc(v)} <span class="faint">${esc(basis)}</span>`;
}
const MOBILITY = { fixed: 'Fixed', mostly: 'Mostly fixed', mobile: 'Mobile' };
const FILTER_FMT = { wifi_gen: v => genLabel(+v), dev_type: typeLabel, era: v => eraLabel(+v), addr_type: v => ADDR_TYPES[v] || v, bt_ver: v => v.endsWith('+') ? 'at least ' + v.slice(0, -1) : v, mobility: v => MOBILITY[v] || v };
function identCell(x) {
  const id = x.ident || {};
  const label = id.label || (x.vendor ? esc(x.vendor) : '');
  const gen = x.wifi_gen ? ` <span class="tag">${genLabel(x.wifi_gen).replace('Wi-Fi ', 'Wi-Fi\u00a0')}</span>` : '';
  return (label ? esc(label) : '<span class="faint">—</span>') + gen;
}
function chText(ch, band) {
  if (ch == null) return '<span class="faint">—</span>';
  return band ? `${esc(ch)}<span class="faint"> · ${esc(band)}G</span>` : esc(ch);
}
const bytes = b => b > 1e9 ? (b / 1e9).toFixed(1) + ' GB' : b > 1e6 ? (b / 1e6).toFixed(1) + ' MB' : Math.round(b / 1e3) + ' kB';

function kindBadge(k) {
  const m = KINDS[k] || { short: k, color: FAINT };
  return `<span class="kind"><span class="swatch" style="background:${m.color}"></span>${esc(m.short)}</span>`;
}
function rssiBars(r) {
  if (r == null) return '<span class="faint">—</span>';
  const lvl = r >= -55 ? 4 : r >= -67 ? 3 : r >= -78 ? 2 : 1;
  const bars = [4, 6, 8, 10].map((h, i) => `<i style="height:${h}px" class="${i < lvl ? 'on' : ''}"></i>`).join('');
  return `<span class="rssi">${bars}</span>${r} dBm`;
}
function devLabel(d) {
  if (!d) return '';
  if (d.label) return d.label;
  if (d.kind === 'ap') return d.ssid || (d.ssid === '' ? '<hidden>' : '');
  return d.name || '';
}
function devLink(mac, label) {
  if (!isMac(mac)) return `<span class="mono">${esc(mac || '—')}</span>`;
  return `<a href="#/device/${enc(mac)}" class="mono">${esc(label || mac)}</a>`;
}
function seg(name, options, current) {
  return `<div class="seg" data-seg="${name}">${options.map(([v, l]) =>
    `<button data-v="${v}" class="${String(v) === String(current) ? 'on' : ''}">${l}</button>`).join('')}</div>`;
}
function onSeg(root, name, fn) {
  const el = root.querySelector(`[data-seg="${name}"]`);
  if (!el) return;
  el.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b) return;
    el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
    fn(b.dataset.v);
  });
}
function hrefWith(path, params) {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '' && v !== false) p.set(k, v); });
  const s = p.toString();
  return `#${path}${s ? '?' + s : ''}`;
}

// --------------------------------------------------------- page lifecycle
let timers = [], charts = [], leaveFns = [], routeId = 0;
function cleanup() {
  timers.forEach(clearInterval); timers = [];
  charts.forEach(c => c.destroy()); charts = [];
  leaveFns.forEach(fn => { try { fn(); } catch { /* ignore */ } }); leaveFns = [];
}
function every(ms, fn) { timers.push(setInterval(() => { if (!document.hidden) fn(); }, ms)); }  // background tabs don't poll
function onLeave(fn) { leaveFns.push(fn); }  // run when navigating away (close streams etc.)
function chart(canvas, cfg) {
  if (!window.Chart) { canvas.parentElement.innerHTML = '<div class="empty">Chart library unavailable</div>'; return null; }
  const prev = Chart.getChart(canvas);
  if (prev) { prev.destroy(); charts = charts.filter(c => c !== prev); }
  const c = new Chart(canvas, cfg);
  charts.push(c);
  return c;
}
function timeScale(span) {
  return {
    type: 'linear', grid: { display: false },
    ticks: { maxTicksLimit: 8, callback: v => axisTime(v, span), color: FAINT },
  };
}
function yScale(extra = {}) {
  return { beginAtZero: true, grid: { color: GRID }, border: { display: false }, ticks: { precision: 0, color: FAINT }, ...extra };
}

function parseHash() {
  const h = location.hash.slice(1) || '/';
  const [path, qs] = h.split('?');
  return { path, params: new URLSearchParams(qs || '') };
}
const ROUTES = [];  // [prefix, handler(rest, params)] registered by views.js
function addRoute(prefix, fn) { ROUTES.push([prefix, fn]); }

async function route() {
  cleanup();
  closeModal();
  const id = ++routeId;
  const { path, params } = parseHash();
  document.querySelectorAll('[data-nav]').forEach(a => {
    const n = a.dataset.nav;
    a.classList.toggle('active', n === '/' ? path === '/' : path.startsWith(n));
  });
  try {
    const custom = ROUTES.find(([p]) => p.endsWith('/') ? path.startsWith(p) : path === p);
    if (custom) await custom[1](decodeURIComponent(path.slice(custom[0].length)), params);
    else if (path === '/') await viewOverview(params);
    else if (path === '/devices') await viewDevices(params);
    else if (path.startsWith('/device/')) await viewDevice(decodeURIComponent(path.slice(8)), params);
    else if (path === '/stats') await viewStats(params);
    else if (path === '/sessions') await viewSessions(params);
    else if (path === '/events') await viewEvents(params);
    else app.innerHTML = '<div class="empty">Not found</div>';
  } catch (e) {
    if (id === routeId) app.innerHTML = `<div class="empty">Failed to load: ${esc(e.message)}</div>`;
  }
  window.scrollTo(0, 0);
}
window.addEventListener('hashchange', route);

// The header pill and the Overview both ask for /api/status when a page opens; share that one request.
let statusMemo = { t: 0, p: null };
function apiStatus() {
  if (!statusMemo.p || Date.now() - statusMemo.t > 1000) {
    const p = api('/api/status');
    statusMemo = { t: Date.now(), p };
    p.catch(() => { if (statusMemo.p === p) statusMemo.p = null; });
  }
  return statusMemo.p;
}
// How one interface / sensor entry is doing right now. The server reports a remote sensor that stopped sending as
// state "offline", and an error it has cleared is simply no longer there.
const HEALTH_TEXT = { ok: 'working', warn: 'needs attention', bad: 'error', off: 'offline' };
function sensorHealth(x) {
  if (x.state === 'offline') return 'off';
  if (x.state === 'error') return 'bad';
  if (x.error || x.warning || x.state === 'starting' || x.state === 'updating') return 'warn';
  return 'ok';
}
function healthCounts(list) {
  const c = { ok: 0, warn: 0, bad: 0, off: 0 };
  list.forEach(x => { c[sensorHealth(x)]++; });
  return c;
}
// The server was updated while this page was open: the scripts here are the old ones, so say so instead of quietly
// showing old behaviour and numbers.
let seenUi = null;
function checkBuild(b) {
  if (!b || !b.ui) return;
  if (seenUi === null) { seenUi = b.ui; return; }
  if (b.ui === seenUi || document.getElementById('update-banner')) return;
  const bar = document.createElement('div');
  bar.id = 'update-banner';
  bar.className = 'update-banner';
  bar.innerHTML = `<span>sniffowireless was updated${b.version && b.version !== 'dev' ? ' to <b>' + esc(b.version) + '</b>' : ''}. Reload this page to use the new version.</span>
    <button class="btn small primary" type="button">Reload</button><button class="btn small ghost" type="button" aria-label="Dismiss">✕</button>`;
  bar.querySelector('.primary').onclick = () => location.reload();
  bar.querySelector('.ghost').onclick = () => bar.remove();
  document.body.appendChild(bar);
}
async function pollStatus() {
  const el = document.getElementById('live');
  try {
    const s = await apiStatus();
    checkBuild(s.build);
    const c = healthCounts(s.sensors);
    const total = s.sensors.reduce((a, x) => a + (Number(x.pps) || 0), 0);
    const plural = (n, w) => `${n} ${w}${n > 1 ? 's' : ''}`;
    el.className = 'live ' + (c.bad ? 'err' : c.off || c.warn ? 'warn' : (s.sensors.length || s.demo ? 'ok' : ''));
    el.textContent = s.demo ? 'demo mode' : c.bad ? plural(c.bad, 'sensor error') : c.off ? `${c.off} offline` : c.warn ? plural(c.warn, 'warning')
      : s.sensors.length ? `${s.sensors.length} sensor${s.sensors.length > 1 ? 's' : ''} · ${total.toFixed(0)} pkt/s` : 'no sensors';
  } catch { el.className = 'live err'; el.textContent = 'offline'; }
}
setInterval(() => { if (!document.hidden) pollStatus(); }, 10000);

// ------------------------------------------------------------------ sessions
// Drill-down of the Statistics "Session durations" chart: the sessions in one duration bucket.
const DUR_LABELS = ['under 1 minute', '1–5 minutes', '5–30 minutes', '30 minutes – 2 hours', '2–8 hours', 'over 8 hours'];
async function viewSessions(params) {
  const st = { type: params.get('type') || 'assoc', b: params.get('b') ?? '', days: params.get('days') || '7', sort: params.get('sort') || 'start' };
  const offset = +(params.get('offset') || 0), limit = 100;
  const go = ch => { location.hash = hrefWith('/sessions', { ...st, ...ch }); };
  const noun = st.type === 'assoc' ? 'Connections' : 'Visits';
  app.innerHTML = `
    <div class="page-head"><div><a class="muted" href="${hrefWith('/stats', { days: st.days })}">← Statistics</a><h1>${noun}${st.b !== '' ? ` · ${DUR_LABELS[+st.b] || ''}` : ''}</h1>
      <div class="sub" id="count">&nbsp;</div></div>${seg('days', [[1, '24h'], [7, '7 days'], [30, '30 days']], st.days)}</div>
    <div class="filters">
      <select id="stype"><option value="assoc" ${st.type === 'assoc' ? 'selected' : ''}>Connections</option><option value="presence" ${st.type === 'presence' ? 'selected' : ''}>Visits</option></select>
      <select id="sb"><option value="">Any duration</option>${DUR_LABELS.map((l, i) => `<option value="${i}" ${String(st.b) === String(i) ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <select id="ssort"><option value="start" ${st.sort === 'start' ? 'selected' : ''}>Most recent first</option><option value="duration" ${st.sort === 'duration' ? 'selected' : ''}>Longest first</option></select>
    </div>
    <section class="panel"><div class="table-wrap" id="tbl"></div><div class="pager" id="pager"></div></section>`;
  onSeg(app, 'days', v => go({ days: v, offset: '' }));
  document.getElementById('stype').onchange = e => go({ type: e.target.value, offset: '' });
  document.getElementById('sb').onchange = e => go({ b: e.target.value, offset: '' });
  document.getElementById('ssort').onchange = e => go({ sort: e.target.value, offset: '' });
  const d = await api('/api/sessions?' + new URLSearchParams({ type: st.type, days: st.days, sort: st.sort, limit, offset, ...(st.b !== '' ? { b: st.b } : {}) }));
  document.getElementById('count').textContent = `${num(d.total)} session${d.total === 1 ? '' : 's'} in the last ${st.days === '1' ? '24 hours' : st.days + ' days'}`;
  document.getElementById('tbl').innerHTML = d.items.length ? `<table><thead><tr><th>Device</th>${st.type === 'assoc' ? '<th>Connected to</th>' : ''}
    <th>Started</th><th>Ended</th><th class="num">Duration</th><th>Signal</th><th>Ended because</th></tr></thead><tbody>
    ${d.items.map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}">
      <td>${x.kind ? kindBadge(x.kind) : ''} <span class="mono" style="margin-left:6px">${esc(x.label || x.name || x.vendor || x.mac)}</span></td>
      ${st.type === 'assoc' ? `<td>${x.peer ? `${esc(x.peer_ssid || '')} <span class="mono faint">${esc(x.peer)}</span>` : '<span class="faint">—</span>'}</td>` : ''}
      <td class="muted">${esc(dt(x.start_ts))}</td><td class="muted">${x.open ? '<span class="tag on">ongoing</span>' : esc(dt(x.end_ts))}</td>
      <td class="num">${dur(x.end_ts - x.start_ts)}</td><td>${rssiBars(x.rssi_max)}</td><td class="muted">${esc((x.end_reason || '').replace(/_/g, ' ') || '—')}</td></tr>`).join('')}
    </tbody></table>` : '<div class="empty">No sessions match</div>';
  linkRows(document.getElementById('tbl'));
  const pager = document.getElementById('pager');
  pager.innerHTML = `<span>${d.total ? `${offset + 1}–${Math.min(offset + limit, d.total)} of ${num(d.total)}` : ''}</span>
    <span><button class="btn" id="prev" ${offset ? '' : 'disabled'}>Previous</button> <button class="btn" id="next" ${offset + limit < d.total ? '' : 'disabled'}>Next</button></span>`;
  pager.querySelector('#prev').onclick = () => go({ offset: Math.max(0, offset - limit) });
  pager.querySelector('#next').onclick = () => go({ offset: offset + limit });
}

// ------------------------------------------------------------------ overview
// System resources: one meter per resource; the value is always printed, colour only adds emphasis above 80 / 95 %.
const sysPct = v => v == null ? null : Math.max(0, Math.min(100, v));
function sysMeter(label, p, value, detail, title = '') {
  const lvl = p == null ? '' : p >= 95 ? 'bad' : p >= 80 ? 'warn' : '';
  return `<div class="sysm ${lvl}" title="${esc(title)}"><div class="sysm-top"><span class="muted">${label}</span><b class="mono">${value}</b></div>
    <div class="sysm-track" role="meter" aria-label="${label}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${p == null ? '' : Math.round(p)}"><i style="width:${p == null ? 0 : p}%"></i></div>
    <div class="faint small-text">${detail}</div></div>`;
}
// Load and memory of one machine, as shown for a remote sensor: the load average per core (1.0 = every core busy) and memory in use.
function loadFigures(sys) {
  const c = (sys && sys.cpu) || {}, m = (sys && sys.memory) || {}, d = sys && sys.disk;
  const load = Array.isArray(c.load) ? c.load : null, cores = c.cores || 1;
  return { load, cores, loadP: load ? load[0] / cores * 100 : null, cpu: c.percent,
    memP: m.total && m.used != null ? m.used / m.total * 100 : null, m, diskP: d && d.total ? d.used / d.total * 100 : null, d };
}
function renderSensorSystems(list) {
  const panel = document.getElementById('sensor-sys-panel');
  if (!panel) return;
  panel.hidden = !list.length;
  if (!list.length) return;
  document.getElementById('sensor-systems').innerHTML = list.map(x => {
    if (x.stale) return `<div class="sysrow"><div><span class="state-dot off"></span><b>${esc(x.name)}</b> <span class="faint">offline · no report for ${dur(x.quiet_for || 0)}</span></div></div>`;
    const f = loadFigures(x.system);
    return `<div class="sysrow"><div><span class="state-dot ok"></span><b>${esc(x.name)}</b>${x.room ? ` <span class="faint">${esc(x.room)}</span>` : ''}</div>
      ${sysMeter('Load', sysPct(f.loadP), f.load ? f.load[0].toFixed(2) : '—', f.load ? `${f.load.map(v => v.toFixed(2)).join(' · ')} · ${num(f.cores)} core${f.cores > 1 ? 's' : ''}${f.cpu != null ? ` · CPU ${Number(f.cpu).toFixed(0)}%` : ''}` : 'load unknown', 'Load average over 1, 5 and 15 minutes; the bar is the 1-minute load per core')}
      ${sysMeter('Memory', sysPct(f.memP), f.memP == null ? '—' : `${f.memP.toFixed(0)}%`, `${f.m.used != null ? bytes(f.m.used) : '—'} of ${f.m.total ? bytes(f.m.total) : '—'}${f.m.sniffowireless_rss ? ` · sniffowireless ${bytes(f.m.sniffowireless_rss)}` : ''}${f.d ? ` · ${bytes(f.d.free)} disk free` : ''}`, 'Memory in use on the sensor machine (excluding cache)')}</div>`;
  }).join('');
}
function renderSystem(sys) {
  const el = document.getElementById('system');
  if (!el || !sys) return;
  const pct = sysPct, meter = sysMeter;
  const c = sys.cpu || {}, m = sys.memory || {}, d = sys.disk, db = sys.db || {};
  const load = Array.isArray(c.load) ? c.load.map(x => Number(x).toFixed(2)).join(' · ') : '—';
  const memP = m.total && m.used != null ? m.used / m.total * 100 : null;
  const diskP = d && d.total ? d.used / d.total * 100 : null;
  el.innerHTML = meter('CPU', pct(c.percent), c.percent == null ? '…' : `${Number(c.percent).toFixed(0)}%`,
      `load ${load} · ${num(c.cores)} cores${c.sniffowireless_percent != null ? ` · sniffowireless ${Number(c.sniffowireless_percent).toFixed(1)}%` : ''}`, 'Host CPU use; load average over 1, 5 and 15 minutes')
    + meter('Memory', pct(memP), memP == null ? '—' : `${memP.toFixed(0)}%`,
      `${m.used != null ? bytes(m.used) : '—'} of ${m.total ? bytes(m.total) : '—'}${m.sniffowireless_rss ? ` · sniffowireless ${bytes(m.sniffowireless_rss)}` : ''}`, 'Host memory in use (excluding cache)')
    + meter('Database', pct(diskP), bytes(db.bytes || 0),
      d ? `${bytes(d.free)} free on the data disk (${diskP.toFixed(0)}% used)` : 'data disk size unknown', `Database ${bytes(db.main || 0)} + write-ahead log ${bytes(db.wal || 0)}; the bar shows the data disk`);
}
let tlView = (() => { try { return localStorage.getItem('sniffowireless.tlview') || 'band'; } catch { return 'band'; } })();
let actWin = (() => { try { return +localStorage.getItem('sniffowireless.actwin') || 300; } catch { return 300; } })();
const ACT_WINDOWS = [[120, '2 min'], [300, '5 min'], [600, '10 min'], [3600, '60 min'], [10800, '3 hours'], [21600, '6 hours'], [43200, '12 hours'], [86400, '24 hours']];
const actLabel = () => (ACT_WINDOWS.find(([v]) => v === actWin) || [0, '5 min'])[1];
const BAND_PANELS = [['2.4', '2.4 GHz'], ['5', '5 GHz'], ['6', '6 GHz']];

async function viewOverview(params) {
  // A shared link may carry the window (?window=<seconds>); it wins over the remembered choice.
  const w = +(params && params.get('window'));
  if (ACT_WINDOWS.some(([v]) => v === w)) actWin = w;
  let live = true, lastUpdate = 0;
  if (!modOn('wifi')) tlView = 'type';  // the by-band view is about Wi-Fi
  app.innerHTML = `
    <div class="page-head"><div><h1>Overview</h1><div class="sub">Devices seen within the selected window are counted as active.</div></div>
      <div class="row"><button class="btn small ghost live-btn on" id="livebtn" type="button" aria-pressed="true" title="Pause or resume automatic refresh"><span class="pulse-dot"></span><span id="livetxt">Live</span></button>
        <button class="btn small ghost" id="ov-link" type="button" title="Copy a link to this view">Copy link</button>
        <span class="muted">Active = seen in last</span><select id="actwin">${ACT_WINDOWS.map(([v, l]) => `<option value="${v}" ${v === actWin ? 'selected' : ''}>${l}</option>`).join('')}</select></div></div>
    <div class="grid cards-auto" id="cards"></div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel span-2">
        <header><h2>Active devices over time</h2><div class="row">${modOn('wifi') ? seg('tlview', [['band', 'By band'], ['type', 'By type']], tlView) : ''}${seg('range', [[6, '6h'], [24, '24h'], [168, '7d'], [720, '30d']], 24)}</div></header>
        <div class="body"><div class="legend" id="tl-legend" style="margin-bottom:10px"></div><div id="tl-box"></div></div>
      </section>
      <div class="stack">
        <section class="panel"><header><h2>System</h2><span class="faint small-text" id="sys-note"></span></header><div class="body" id="system"></div></section>
        <section class="panel"><header><h2>Sensors</h2><span id="sensors-health"></span></header><div class="body flush" id="sensors"></div></section>
        <section class="panel" id="sensor-sys-panel" hidden><header><h2>Sensor load</h2><span class="faint small-text">remote sensors</span></header><div class="body" id="sensor-systems"></div></section>
      </div>
      <section class="panel" id="ov-bt" ${modOn('bluetooth') ? '' : 'hidden'}><header><h2>Bluetooth</h2><span class="faint small-text">devices per period, by address type</span></header>
        <div class="body"><div class="legend" id="bt-legend" style="margin-bottom:10px"></div><div class="chart-box short"><canvas id="bt-chart"></canvas></div></div></section>
      <section class="panel" id="ov-zbg" ${modOn('zigbee') ? '' : 'hidden'}><header><h2>Zigbee, Thread &amp; 802.15.4</h2><span class="faint small-text">radios per period, by protocol</span></header>
        <div class="body"><div class="legend" id="zb-legend" style="margin-bottom:10px"></div><div class="chart-box short"><canvas id="zb-chart"></canvas></div></div></section>
      <section class="panel" id="ov-lorag" ${modOn('lora') ? '' : 'hidden'}><header><h2>LoRa</h2><span class="faint small-text">nodes per period, by protocol</span></header>
        <div class="body"><div class="legend" id="lora-legend" style="margin-bottom:10px"></div><div class="chart-box short"><canvas id="lora-chart"></canvas></div></div></section>
      <section class="panel span-3">
        <header><h2>Interface activity</h2><span class="faint small-text">Packets/sec per capturing interface, live over the last ${Math.round(IFACE_HIST_MAX * 10 / 60)} minutes</span></header>
        <div class="body"><div class="legend" id="iface-legend" style="margin-bottom:10px"></div><div class="chart-box short"><canvas id="iface-chart"></canvas></div></div>
      </section>
      <section class="panel span-2">
        <header><h2>Connected right now</h2><a class="muted" href="#/devices?connected=1">View all →</a></header>
        <div class="body flush table-wrap" id="connected"></div>
      </section>
      <section class="panel"><header><h2>Recent events</h2><a class="muted" href="#/events">All →</a></header><div class="body flush" id="events"></div></section>
      <section class="panel span-3"><header><h2>Watched devices</h2><a class="muted" href="#/devices?watch=1">View all →</a></header>
        <div class="body flush table-wrap" id="watched"></div></section>
      <section class="panel span-3"><header><h2>Latest discovered devices</h2><a class="muted" href="#/devices?sort=first_seen&order=desc">View all →</a></header>
        <div class="body flush table-wrap" id="discovered"></div></section>
      <section class="panel span-3" id="ov-zigbee" ${modOn('zigbee') ? '' : 'hidden'}><header><h2>Zigbee discovered</h2><a class="muted" href="#/zigbee">View all →</a></header>
        <div class="body flush table-wrap" id="zigbee-disc"></div></section>
      <section class="panel span-3" id="ov-lora" ${modOn('lora') ? '' : 'hidden'}><header><h2>LoRa discovered</h2><a class="muted" href="#/lora">View all →</a></header>
        <div class="body flush table-wrap" id="lora-disc"></div></section>
    </div>`;
  let hours = 24, lastCounts = null;
  const ifaceHist = {}, ifaceColors = {};  // name -> [{t, pps}], reset each time this page is entered
  const ifaceColor = name => ifaceColors[name] || (ifaceColors[name] = IFACE_COLORS[Object.keys(ifaceColors).length % IFACE_COLORS.length]);
  const onVis = () => { if (!document.hidden && live) refresh(); };  // catch up when the tab comes back
  document.getElementById('actwin').addEventListener('change', e => {
    actWin = +e.target.value;
    try { localStorage.setItem('sniffowireless.actwin', String(actWin)); } catch { /* private mode */ }
    history.replaceState(null, '', hrefWith('/', { window: actWin }));
    loadSummary();
  });
  document.getElementById('ov-link').onclick = () => copyText(location.origin + location.pathname + hrefWith('/', { window: actWin }), 'Link copied');
  const liveBtn = document.getElementById('livebtn'), liveTxt = document.getElementById('livetxt');
  const paintLive = () => {
    liveBtn.classList.toggle('on', live); liveBtn.setAttribute('aria-pressed', String(live));
    liveTxt.textContent = live ? 'Live' : 'Paused' + (lastUpdate ? ' · ' + new Date(lastUpdate).toLocaleTimeString() : '');
  };
  liveBtn.onclick = () => { live = !live; paintLive(); if (live) refresh(); };
  onSeg(app, 'range', v => { hours = +v; loadTimeline(); });
  onSeg(app, 'tlview', v => { tlView = v; try { localStorage.setItem('sniffowireless.tlview', v); } catch { /* private mode */ } loadTimeline(); });



  async function loadSummary() {
    const s = await api(`/api/summary?window=${actWin}`);
    const prev = lastCounts; lastCounts = {};
    document.getElementById('cards').innerHTML = kindEntries().map(([k, m]) => {
      const v = s.kinds[k] || {};
      const conn = k === 'wifi_client' || k === 'bt_classic' || k === 'ble'
        ? `<a href="#/devices?kind=${k}&connected=1">${num(v.connected || 0)} connected</a>` : '';
      lastCounts[k] = v.active || 0;
      const changed = prev && prev[k] !== undefined && prev[k] !== lastCounts[k];
      return `<div class="card link${changed ? ' bump' : ''}" data-href="#/devices?kind=${k}&active=${actWin}">
        <div class="label"><span class="swatch" style="background:${m.color}"></span>${m.label}</div>
        <div class="value">${num(v.active)}<small>of ${num(v.total)}</small></div>
        <div class="meta"><span>+${num(v.new_24h)} new 24h</span>${conn ? `<span>${conn}</span>` : ''}</div></div>`;
    }).join('');
    extraEntries().forEach(([k, m]) => {
      const v = s[k] || {};
      lastCounts[k] = v.active || 0;
      const changed = prev && prev[k] !== undefined && prev[k] !== lastCounts[k];
      document.getElementById('cards').insertAdjacentHTML('beforeend', `<div class="card link${changed ? ' bump' : ''}" data-href="${m.href}">
        <div class="label"><span class="swatch" style="background:${m.color}"></span>${m.label}</div>
        <div class="value">${num(v.active)}<small>of ${num(v.total)}</small></div>
        <div class="meta"><span>+${num(v.new_24h)} new 24h</span></div></div>`);
    });
    document.querySelectorAll('#cards .card').forEach(c => c.onclick = e => { if (!e.target.closest('a')) location.hash = c.dataset.href; });
    const ev = s.events;
    document.getElementById('events').innerHTML = ev.length ? `<ul class="events">${ev.slice(0, 14).map(e => eventRow(e)).join('')}</ul>` : '<div class="empty">No events yet</div>';
  }
  async function loadConnected() {
    const d = await api('/api/devices?connected=1&limit=12&sort=last_seen&slim=1');
    document.getElementById('connected').innerHTML = d.items.length ? `<table><thead><tr>
      <th>Device</th><th>Vendor</th><th>Connected to</th><th>Signal</th><th class="num">Last seen</th></tr></thead><tbody>
      ${d.items.map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}">
        <td>${kindBadge(x.kind)} <span class="mono" style="margin-left:8px">${esc(x.name || x.mac)}</span></td>
        <td class="trunc muted">${esc(x.vendor || (x.randomized ? 'Randomized MAC' : '—'))}</td>
        <td>${x.bssid ? `${esc(x.bssid_ssid || '')} <span class="mono faint">${esc(x.bssid)}</span>` : '<span class="faint">sensor adapter</span>'}</td>
        <td>${rssiBars(x.last_rssi)}</td><td class="num muted">${ago(x.last_seen)}</td></tr>`).join('')}
      </tbody></table>` : '<div class="empty">No connected clients</div>';
    linkRows(document.getElementById('connected'));
  }
  async function loadWatched() {
    const d = await api('/api/devices?watch=1&limit=50&sort=last_seen&slim=1');
    document.getElementById('watched').innerHTML = d.items.length ? `<table><thead><tr>
      <th>Device</th><th>Group</th><th>Status</th><th>Last seen</th><th>Signal</th></tr></thead><tbody>
      ${d.items.map(x => {
        const secs = d.now - x.last_seen;
        const status = x.connected ? '<span class="tag on">connected</span>' : secs < actWin ? '<span class="tag on">active</span>' : '<span class="faint">away</span>';
        return `<tr class="link" data-href="#/device/${enc(x.mac)}">
        <td><span class="star" title="Watched">★</span> ${kindBadge(x.kind)} <span style="margin-left:8px">${x.label ? `<b>${esc(x.label)}</b>` : `<span class="mono">${esc(devLabel(x) || x.mac)}</span>`}</span></td>
        <td>${x.group_name ? `<span class="tag">${esc(x.group_name)}</span>` : '<span class="faint">—</span>'}</td>
        <td>${status}</td>
        <td><span class="mono">${esc(dt(x.last_seen))}</span> <span class="muted">· ${ago(x.last_seen)}</span></td>
        <td>${rssiBars(x.last_rssi)}</td></tr>`;
      }).join('')}</tbody></table>` : '<div class="empty">No watched devices yet — open a device and star it to watch it here</div>';
    linkRows(document.getElementById('watched'));
  }
  async function loadDiscovered() {
    const d = await api('/api/devices?limit=20&sort=first_seen&order=desc&slim=1');
    document.getElementById('discovered').innerHTML = d.items.length ? `<table><thead><tr>
      <th>Device</th><th>Identified as</th><th>Vendor</th><th>Signal</th><th class="num">Discovered</th></tr></thead><tbody>
      ${d.items.map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}">
        <td>${kindBadge(x.kind)} <span class="mono" style="margin-left:8px">${esc(devLabel(x) || x.mac)}</span>${x.randomized ? ' <span class="tag warn" title="Locally administered / randomized address">rand</span>' : ''}</td>
        <td class="trunc muted">${identCell(x)}</td>
        <td class="trunc muted">${esc(x.vendor || (x.randomized ? 'Randomized MAC' : '—'))}</td>
        <td>${rssiBars(x.last_rssi)}</td><td class="num muted" title="${esc(dt(x.first_seen))}">${ago(x.first_seen)}</td></tr>`).join('')}
      </tbody></table>` : '<div class="empty">No devices discovered yet</div>';
    linkRows(document.getElementById('discovered'));
  }
  async function loadZigbeeDisc() {
    if (!modOn('zigbee')) return;
    const z = await api('/api/zigbee?hours=168');
    const pan = p => p == null ? '—' : '0x' + p.toString(16).padStart(4, '0');
    const nets = z.networks.map(n => ({ at: n.first_seen || n.last_seen, kind: 'Network', id: pan(n.pan), what: `${esc(n.ext_pan)} · channel ${n.channel}${n.permit_join ? ' · <b>joining open</b>' : ''}`, last: n.last_seen }));
    const rads = z.radios.map(r => ({ at: r.first_seen || r.last_seen, kind: 'Radio', id: esc(r.addr), what: `${esc(r.hint_label || 'unknown')}${r.vendor ? ' · ' + esc(r.vendor) + '?' : ''} · PAN ${pan(r.pan)}`, last: r.last_seen }));
    const items = [...nets, ...rads].sort((a, b) => b.at - a.at).slice(0, 12);
    document.getElementById('zigbee-disc').innerHTML = items.length ? `<table><thead><tr><th>Type</th><th>Address</th><th>Details</th><th class="num">Discovered</th></tr></thead><tbody>
      ${items.map(x => `<tr class="link" data-href="#/zigbee"><td>${x.kind}</td><td class="mono">${x.id}</td><td class="trunc muted">${x.what}</td><td class="num muted" title="${esc(dt(x.at))}">${ago(x.at)}</td></tr>`).join('')}</tbody></table>`
      : `<div class="empty">${z.configured ? 'Nothing found yet' : 'No Zigbee stick configured'}</div>`;
    linkRows(document.getElementById('zigbee-disc'));
  }
  async function loadLoraDisc() {
    if (!modOn('lora')) return;
    const l = await api('/api/lora?hours=168');
    const nodes = l.nodes.slice().sort((a, b) => (b.first_seen || 0) - (a.first_seen || 0)).slice(0, 12);
    document.getElementById('lora-disc').innerHTML = nodes.length ? `<table><thead><tr><th>Protocol</th><th>Address</th><th>Name</th><th>Type</th><th class="num">Packets</th><th class="num">Signal</th><th class="num">Discovered</th></tr></thead><tbody>
      ${nodes.map(n => `<tr class="link" data-href="#/lora"><td>${esc(n.label)}</td><td class="mono">${esc(n.addr)}</td><td>${esc(n.given_name || n.name || '—')}</td><td class="muted">${esc(n.kind || '—')}</td><td class="num">${num(n.packets)}</td><td class="num">${n.rssi != null ? Math.round(n.rssi) + ' dBm' : '—'}</td><td class="num muted" title="${esc(dt(n.first_seen))}">${ago(n.first_seen)}</td></tr>`).join('')}</tbody></table>`
      : `<div class="empty">${l.configured ? 'Nothing heard yet' : 'No LoRa receiver configured'}</div>`;
    linkRows(document.getElementById('lora-disc'));
  }
  async function loadSensors() {
    const s = await apiStatus();
    renderSystem(s.system);
    renderSensorSystems(s.sensor_systems || []);
    const list = s.sensors.filter(x => modOn(SENSOR_MOD[x.type]));
    const hc = healthCounts(list);
    document.getElementById('sensors-health').innerHTML = !list.length ? '' : [
      hc.bad ? `<span class="tag bad">${hc.bad} error${hc.bad > 1 ? 's' : ''}</span>` : '', hc.warn ? `<span class="tag warn">${hc.warn} warning${hc.warn > 1 ? 's' : ''}</span>` : '',
      hc.off ? `<span class="tag">${hc.off} offline</span>` : '', !hc.bad && !hc.warn && !hc.off ? '<span class="tag on">all working</span>' : ''].filter(Boolean).join(' ');
    document.getElementById('sensors').innerHTML = (list.length ? list.map(x => `<div class="sensor">
      <div><div><span class="state-dot ${sensorHealth(x)}" title="${HEALTH_TEXT[sensorHealth(x)]}"></span><b>${esc(x.name)}</b>
      ${x.mon && x.mon !== x.iface ? `<span class="faint mono"> → ${esc(x.mon)}</span>` : ''}</div>
      ${x.state === 'offline' ? `<div class="muted">offline · no report for ${dur(x.quiet_for || 0)}</div>` : x.error ? `<div class="err">${esc(x.error)}</div>` : `<div class="muted">${esc(x.state)}${x.channel ? ' · ch ' + esc(x.channel) : ''}${Array.isArray(x.bands) ? ' · ' + x.bands.map(b => esc(b) + 'G').join('/') : ''}${x.adverts != null ? ' · ' + num(x.adverts) + ' adverts' : ''}${x.bt_version ? ` · Bluetooth ${esc(x.bt_version)}${x.chip ? ' (' + esc(x.chip) + ')' : ''}` : ''}</div>${Array.isArray(x.caps) && x.caps.length ? `<div class="faint small-text">${x.caps.map(esc).join(' · ')}</div>` : ''}
      ${x.band_frames && Array.isArray(x.bands) ? `<div class="faint small-text">frames ${x.bands.map(b => `${esc(b)}G ${num((x.band_frames || {})[b] || 0)}`).join(' · ')}</div>` : ''}
      ${x.relabelled ? `<div class="faint small-text">${num(x.relabelled)} frames had a wrong band from the driver (corrected)</div>` : ''}`}
      ${x.warning ? `<div class="warn-text small-text">${esc(x.warning)}</div>` : ''}${x.note ? `<div class="faint small-text">${esc(x.note)}</div>` : ''}${isAdmin() && /^(wifi|bt|zigbee|lora):/.test(x.remote ? x.name.slice(x.remote.length + 1) : x.name) ? `<div><button class="btn small ghost" data-reset="${esc(x.remote || 'local')}|${esc(x.remote ? x.name.slice(x.remote.length + 1) : x.name)}" title="Reset this adapter">Reset…</button>${/^lora:/.test(x.remote ? x.name.slice(x.remote.length + 1) : x.name) ? ` <button class="btn small ghost" data-flash="${esc(x.remote || 'local')}|${esc(x.remote ? x.name.slice(x.remote.length + 1) : x.name)}" title="Write the newest sniffer firmware to this board">Update firmware…</button>` : ''}</div>` : ''}</div>
      <div class="muted mono" style="text-align:right">${(Number(x.pps) || 0).toFixed(1)} pkt/s<br>${num(x.packets)} total</div></div>`).join('')
      : `<div class="empty">${s.demo ? 'Demo mode — synthetic data' : 'No sensors configured'}</div>`)
      + `<div class="sensor muted"><span>Queue ${num(s.store.queue)} · dropped ${num(s.store.dropped)}</span><span>${num(s.store.open_presence)} present</span></div>`;
    document.querySelectorAll('#sensors button[data-reset]').forEach(b => b.onclick = () => resetAdapter(...b.dataset.reset.split('|')));
    document.querySelectorAll('#sensors button[data-flash]').forEach(b => b.onclick = () => flashLora(...b.dataset.flash.split('|')));
    renderIfaceChart(list);
  }
  function renderIfaceChart(list) {
    const now = Date.now() / 1000;
    const seen = new Set();
    list.forEach(x => {
      seen.add(x.name);
      const h = ifaceHist[x.name] || (ifaceHist[x.name] = []);
      h.push({ t: now, y: Number(x.pps) || 0 });
      if (h.length > IFACE_HIST_MAX) h.shift();
    });
    // An interface that's gone (adapter unplugged, sensor removed) stops growing and ages out on its own.
    Object.keys(ifaceHist).forEach(name => { if (!seen.has(name) && ifaceHist[name].length) ifaceHist[name].shift(); });
    const names = Object.keys(ifaceHist).filter(n => ifaceHist[n].length);
    const legend = document.getElementById('iface-legend'), canvas = document.getElementById('iface-chart');
    if (!names.length) { legend.innerHTML = ''; if (canvas) canvas.parentElement.innerHTML = '<div class="empty">No interfaces yet</div>'; return; }
    legend.innerHTML = names.map(n => `<span><span class="swatch" style="background:${ifaceColor(n)}"></span>${esc(n)}</span>`).join('');
    const span = IFACE_HIST_MAX * 10;
    chart(document.getElementById('iface-chart'), {
      type: 'line',
      data: { datasets: names.map(n => ({ label: n, data: ifaceHist[n].map(p => ({ x: p.t, y: p.y })),
        borderColor: ifaceColor(n), fill: false, borderWidth: 1.5, pointRadius: 0, tension: .3 })) },
      options: {
        maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        scales: { x: { ...timeScale(span), min: now - span, max: now }, y: yScale({ ticks: { color: FAINT, callback: v => v + ' pkt/s' } }) },
        plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } },
      },
    });
  }
  // Bluetooth (random against static addresses), Zigbee / Thread / other 802.15.4 and LoRa each get a graph of their own.
  async function loadRadios() {
    if (!modOn('bluetooth') && !modOn('zigbee') && !modOn('lora')) return;
    const t = await api(`/api/timeline/radios?hours=${hours}`);
    if (!document.getElementById('bt-chart')) return;  // left the page meanwhile
    const span = hours * 3600, xy = arr => t.t.map((x, i) => ({ x, y: (arr || [])[i] || 0 }));
    const avg = arr => (arr && arr.length) ? Math.round(arr.reduce((a, v) => a + (v || 0), 0) / arr.length) : 0;
    const sw = (c, label) => `<span><span class="swatch" style="background:${c}"></span>${label}</span>`;
    const draw = (id, legendId, defs) => {
      const live = defs.filter(([, arr]) => arr && arr.some(v => v));
      const shown = live.length ? live : defs.slice(0, 1);
      document.getElementById(legendId).innerHTML = shown.map(([label, arr, color]) => sw(color, `${label} · avg ${num(avg(arr))}`)).join('');
      chart(document.getElementById(id), { type: 'line', options: {
        maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        scales: { x: { ...timeScale(span), min: t.t[0], max: t.t[t.t.length - 1], ticks: { ...timeScale(span).ticks, maxTicksLimit: 4 } }, y: yScale({}) },
        plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } } },
        data: { datasets: shown.map(([label, arr, color]) => ({ label, data: xy(arr), borderColor: color, fill: false, borderWidth: 1.5, pointRadius: 0, tension: .3 })) } });
    };
    if (modOn('bluetooth')) draw('bt-chart', 'bt-legend', [['Random addresses', t.bluetooth.ble_random, KINDS.ble.color],
      ['Static addresses', t.bluetooth.ble_static, '#4cc2ff'], ['Classic', t.bluetooth.classic, KINDS.bt_classic.color]]);
    if (modOn('zigbee')) draw('zb-chart', 'zb-legend', [['Zigbee', t.zigbee.zigbee, EXTRA_KINDS.zigbee.color],
      ['Thread', t.zigbee.thread, '#4cc2ff'], ['Other 802.15.4', t.zigbee.other, '#8b95a5']]);
    if (modOn('lora')) {
      const colors = typeof LORA_COLORS !== 'undefined' ? LORA_COLORS : {};
      const names = Object.keys(t.lora).sort();
      draw('lora-chart', 'lora-legend', names.length ? names.map(n => [n, t.lora[n], colors[n] || EXTRA_KINDS.lora.color]) : [['No nodes heard', [], EXTRA_KINDS.lora.color]]);
    }
  }
  async function loadTimeline() {
    loadRadios();
    const t = await api(`/api/timeline?hours=${hours}`);
    const span = hours * 3600;
    const box = document.getElementById('tl-box');
    const line = (label, data, color, extra = {}) => ({ label, data, borderColor: color, fill: false, borderWidth: 1.5,
      pointRadius: 0, tension: .3, ...extra });
    const xy = arr => t.t.map((x, i) => ({ x, y: (arr || [])[i] || 0 }));
    const avg = arr => (arr && arr.length) ? Math.round(arr.reduce((a, v) => a + (v || 0), 0) / arr.length) : 0;
    const dashed = { borderDash: [4, 4], borderWidth: 1.2 };
    const opts = (ymax, small) => ({
      maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { ...timeScale(span), min: t.t[0], max: t.t[t.t.length - 1], ticks: { ...timeScale(span).ticks, maxTicksLimit: small ? 4 : 8 } },
        y: yScale(ymax ? { suggestedMax: ymax } : {}) },
      plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } },
    });
    const sw = (c, label, dash) => `<span><span class="swatch" style="background:${c}${dash ? ';opacity:.6' : ''}"></span>${label}</span>`;
    if (tlView === 'type') {
      const all = [...kindEntries(), ...extraEntries()];
      document.getElementById('tl-legend').innerHTML = all.map(([k, m]) => sw(m.color, `${m.label} · avg ${num(avg(t.series[k]))}`)).join('')
        + sw(TEXT, `Connected clients · avg ${num(avg(t.connected))}`, true);
      box.innerHTML = '<div class="chart-box tall"><canvas id="tl"></canvas></div>';
      const ds = all.map(([k, m]) => line(m.label, xy(t.series[k]), m.color));
      ds.push(line('Connected clients', xy(t.connected), TEXT, dashed));
      chart(document.getElementById('tl'), { type: 'line', data: { datasets: ds }, options: opts() });
      return;
    }
    // By band: one small chart per Wi-Fi band, each auto-scaled to its own data (a quiet 6 GHz band stays readable),
    // plus Bluetooth & LAN (no band).
    document.getElementById('tl-legend').innerHTML = sw(KINDS.ap.color, 'Access points') + sw(KINDS.wifi_client.color, 'Wi-Fi clients')
      + sw(TEXT, 'Connected clients', true);
    const bands = t.bands || {}, others = ['ble', 'bt_classic', 'lan', 'zigbee', 'lora'].filter(kindOn), info = k => KINDS[k] || EXTRA_KINDS[k];
    const names = [['bluetooth', 'Bluetooth'], ['lan', 'LAN'], ['zigbee', 'Zigbee'], ['lora', 'LoRa']].filter(([m]) => modOn(m)).map(([, n]) => n);
    const otherTitle = names.length > 1 ? names.slice(0, -1).join(', ') + ' &amp; ' + names[names.length - 1] : names[0] || '';
    const now = (b, k) => { const a = (bands[b] || {})[k] || []; return a.length ? a[a.length - 1] : 0; };
    box.innerHTML = `<div class="band-grid">${BAND_PANELS.map(([b, label]) => `<div class="band-cell"><div class="band-head"><b>${label}</b>
        <span class="faint small-text">${num(now(b, 'ap'))} AP${now(b, 'ap') === 1 ? '' : 's'} <span class="faint">(avg ${num(avg((bands[b] || {}).ap))})</span> · ${num(now(b, 'wifi_client'))} client${now(b, 'wifi_client') === 1 ? '' : 's'} <span class="faint">(avg ${num(avg((bands[b] || {}).wifi_client))})</span> · ${num(now(b, 'connected'))} connected <span class="faint">(avg ${num(avg((bands[b] || {}).connected))})</span></span></div>
        <div class="chart-box short"><canvas id="tl-${b.replace('.', '')}"></canvas></div></div>`).join('')}
      ${others.length ? `<div class="band-cell"><div class="band-head"><b>${otherTitle}</b>
        <span class="legend small-text">${others.map(k => sw(info(k).color, `${info(k).label} · avg ${num(avg(t.series[k]))}`)).join('')}</span></div>
        <div class="chart-box short"><canvas id="tl-other"></canvas></div></div>` : ''}</div>
      <p class="faint small-text band-note">Wi-Fi clients count on the band they were last heard on; connected clients on the band of the access point they were connected to. Averages are over the selected time range.</p>`;
    BAND_PANELS.forEach(([b]) => {
      const v = bands[b] || {};
      chart(document.getElementById(`tl-${b.replace('.', '')}`), { type: 'line', data: { datasets: [
        line('Access points', xy(v.ap), KINDS.ap.color), line('Wi-Fi clients', xy(v.wifi_client), KINDS.wifi_client.color),
        line('Connected clients', xy(v.connected), TEXT, dashed)] }, options: opts(null, true) });
    });
    if (others.length) chart(document.getElementById('tl-other'), { type: 'line', data: { datasets: others.map(k =>
      line(info(k).label, xy(t.series[k]), info(k).color)) }, options: opts(null, true) });
  }

  await Promise.all([loadSummary(), loadSensors(), loadTimeline(), loadConnected(), loadWatched(), loadDiscovered(), loadZigbeeDisc(), loadLoraDisc(), pollStatus()]);
  lastUpdate = Date.now();
  setTimeout(() => { if (document.getElementById('system')) loadSensors(); }, 1500);  // CPU % needs a second sample
  const refresh = () => { loadSummary(); loadSensors(); loadConnected(); loadWatched(); loadDiscovered(); loadZigbeeDisc(); loadLoraDisc(); lastUpdate = Date.now(); };
  every(10000, () => { if (live && !document.hidden) refresh(); });
  document.addEventListener('visibilitychange', onVis);
  onLeave(() => document.removeEventListener('visibilitychange', onVis));
  every(60000, loadTimeline);
}

function eventRow(e, full = false) {
  const rf = (e.mac || '').startsWith('rf:');
  const who = rf ? `${esc(e.mac.slice(3))} GHz radio` : e.label || (e.kind === 'ap' ? (e.ssid || e.mac) : (e.name || e.vendor || e.mac));
  let detail = '';
  if (e.peer && e.peer.startsWith('ssid:')) detail = `<a href="#/investigation/${enc(e.peer.slice(5))}">dossier</a>`;
  else if (e.peer) detail = `→ ${isMac(e.peer) ? `<a href="#/device/${enc(e.peer)}">${esc(e.peer_ssid || e.peer)}</a>` : esc(e.peer)}`;
  if (e.detail && e.type !== 'new_device') detail += ` <span class="faint">${esc(e.detail)}</span>`;
  return `<li><span class="t" title="${esc(dt(e.ts))}">${full ? dt(e.ts) : ago(e.ts)}</span><span class="ev ev-${esc(e.type)}">${esc(e.type.replace(/_/g, ' '))}</span>
    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.kind ? `<span class="swatch" style="background:${(KINDS[e.kind] || {}).color};margin-right:6px"></span>` : ''}${rf ? `<a href="#/channels">${esc(who)}</a>` : `<a href="#/device/${enc(e.mac)}">${esc(who)}</a>`} ${detail}</span></li>`;
}
function linkRows(root) {
  root.querySelectorAll('tr[data-href]').forEach(tr => tr.addEventListener('click', e => {
    if (e.target.closest('a')) return;
    location.hash = tr.dataset.href;
  }));
}

// ------------------------------------------------------------------ devices
const FILTER_LABELS = { vendor: 'Vendor', brand: 'Brand', dev_type: 'Device type', os: 'OS', wifi_gen: 'Wi-Fi', era: 'Age', fp: 'Fingerprint',
  ssid: 'SSID', probe: 'Probed', bssid: 'Connected to', channel: 'Channel', connected: 'Connected now',
  addr_type: 'Address type', company: 'Bluetooth company', bt_ver: 'Bluetooth version', mobility: 'Movement' };

async function viewDevices(params) {
  const st = Object.fromEntries(params.entries());
  st.sort = st.sort || 'last_seen';
  st.order = st.order || 'desc';
  const offset = +(st.offset || 0), limit = 100;
  const exportHref = fmt => {
    const q = new URLSearchParams(st); q.delete('offset');
    return `/api/export/devices.${fmt}${q.toString() ? '?' + q : ''}`;
  };
  const chips = Object.keys(FILTER_LABELS).filter(k => st[k]).map(k => {
    const rest = { ...st }; delete rest[k]; delete rest.offset;
    return `<span class="chip">${FILTER_LABELS[k]}${k === 'connected' ? '' : ': <b>' + esc(FILTER_FMT[k] ? FILTER_FMT[k](st[k]) : st[k]) + '</b>'}<a href="${hrefWith('/devices', rest)}">✕</a></span>`;
  }).join('');
  app.innerHTML = `
    <div class="page-head"><div><h1>Devices</h1><div class="sub" id="count">&nbsp;</div></div>
      <div class="row"><button class="btn muted" id="copylink" type="button" title="Copy a link to this filtered view">Copy link</button>
        <a class="btn muted" id="exp-csv" href="${exportHref('csv')}" title="Download the devices matching the current filters">Export CSV</a>
        <a class="btn muted" id="exp-json" href="${exportHref('json')}" title="Download the devices matching the current filters">Export JSON</a></div></div>
    <div class="filters">
      <input type="search" id="q" placeholder="Search MAC, name, SSID, brand, model…" value="${esc(st.q || '')}">
      <select id="kind"><option value="">All types</option>${kindEntries().map(([k, m]) => `<option value="${k}" ${st.kind === k ? 'selected' : ''}>${m.label}</option>`).join('')}</select>
      <select id="devtype"><option value="">All device types</option>${Object.entries(DEV_TYPES).map(([k, l]) => `<option value="${k}" ${st.dev_type === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <select id="active">${[['', 'Any time'], ['300', 'Active (5 min)'], ['3600', 'Last hour'], ['86400', 'Last 24 h'], ['604800', 'Last 7 days']].map(([v, l]) => `<option value="${v}" ${String(st.active || '') === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <select id="band"><option value="">All bands</option>${BAND_LIST.map(([b, m]) => `<option value="${b}" ${st.band === b ? 'selected' : ''}>${m.label}</option>`).join('')}</select>
      <select id="known"><option value="">Known &amp; unknown</option><option value="1" ${st.known === '1' ? 'selected' : ''}>Known</option><option value="0" ${st.known === '0' ? 'selected' : ''}>Unknown</option><option value="w" ${st.watch === '1' ? 'selected' : ''}>Watched</option></select>
      <label class="check"><input type="checkbox" id="hiderand" ${st.randomized === '0' ? 'checked' : ''}>Hide randomized MACs</label>
      ${chips}
    </div>
    <section class="panel"><div class="table-wrap" id="tbl"></div><div class="pager" id="pager"></div></section>`;

  const go = changes => {
    const next = { ...st, ...changes };
    if (!('offset' in changes)) delete next.offset;
    location.hash = hrefWith('/devices', next);
  };
  document.getElementById('copylink').onclick = () => copyText(location.href.replace(/&offset=\d+/, ''), 'Link copied');
  let qTimer;
  document.getElementById('q').addEventListener('input', e => { clearTimeout(qTimer); qTimer = setTimeout(() => go({ q: e.target.value }), 350); });
  document.getElementById('kind').addEventListener('change', e => go({ kind: e.target.value }));
  document.getElementById('active').addEventListener('change', e => go({ active: e.target.value }));
  document.getElementById('known').addEventListener('change', e => go(e.target.value === 'w' ? { watch: '1', known: '' } : { known: e.target.value, watch: '' }));
  document.getElementById('devtype').addEventListener('change', e => go({ dev_type: e.target.value }));
  document.getElementById('band').addEventListener('change', e => go({ band: e.target.value }));
  document.getElementById('hiderand').addEventListener('change', e => go({ randomized: e.target.checked ? '0' : '' }));
  const qi = document.getElementById('q');
  if (st.q) { qi.focus(); qi.setSelectionRange(qi.value.length, qi.value.length); }

  const cols = [
    ['kind', 'Type'], ['mac', 'Address'], ['name', 'Name / SSID'], ['brand', 'Identified as'], [null, 'Connection'],
    ['channel', 'Ch'], ['last_rssi', 'Signal'], ['packets', 'Frames', 'num'], ['first_seen', 'First seen', 'num'], ['last_seen', 'Last seen', 'num'],
  ];
  async function load() {
    const qs = new URLSearchParams({ ...st, limit, offset, slim: 1 });
    const d = await api('/api/devices?' + qs);
    document.getElementById('count').textContent = `${num(d.total)} device${d.total === 1 ? '' : 's'}`;
    const showBt = d.items.some(x => x.kind === 'ble' || x.kind === 'bt_classic');  // the Bluetooth version column, only when the page has Bluetooth rows
    const head = (showBt ? [...cols.slice(0, 4), [null, 'Bluetooth'], ...cols.slice(4)] : cols).map(([k, l, cls]) => {
      if (!k) return `<th>${l}</th>`;
      const on = st.sort === k;
      return `<th class="sort ${cls || ''}" data-sort="${k}">${l}${on ? ` <span class="arrow">${st.order === 'asc' ? '↑' : '↓'}</span>` : ''}</th>`;
    }).join('');
    const body = d.items.map(x => {
      const active = d.now - x.last_seen < 300;
      let conn = '<span class="faint">—</span>';
      if (x.kind === 'ap') conn = x.clients_now ? `<span class="tag on">${x.clients_now} client${x.clients_now > 1 ? 's' : ''}</span>` : '<span class="faint">no clients</span>';
      else if (x.connected) conn = `<span class="tag on">connected</span> <span class="muted">${esc(x.bssid_ssid || (isMac(x.bssid) ? x.bssid : 'sensor'))}</span>`;
      else if (x.bssid) conn = `<span class="muted">last: ${esc(x.bssid_ssid || x.bssid)}</span>`;
      const label = devLabel(x);
      return `<tr class="link" data-href="#/device/${enc(x.mac)}">
        <td>${kindBadge(x.kind)}</td>
        <td class="mono"><span class="state-dot ${active ? 'on' : ''}"></span>${esc(x.mac)}${x.randomized ? ' <span class="tag warn" title="Locally administered / randomized address">rand</span>' : ''}</td>
        <td class="trunc">${x.watch ? '<span class="star" title="Watched">★</span>' : ''}${label ? (x.label ? `<b>${esc(label)}</b>` : esc(label)) : '<span class="faint">—</span>'}${x.group_name ? ` <span class="tag">${esc(x.group_name)}</span>` : ''}${x.kind === 'ap' && x.enc ? ` <span class="tag ${x.enc.includes('OPN') ? 'bad' : ''}">${esc(x.enc.replace(/\/PSK|\/SAE/g, ''))}</span>` : ''}</td>
        <td class="trunc muted" style="max-width:300px">${identCell(x)}</td>
        ${showBt ? `<td>${btVerTag(x.bt_ver, x.bt_basis)}</td>` : ''}
        <td>${conn}</td>
        <td class="muted">${chText(x.channel, x.band)}</td>
        <td>${rssiBars(x.last_rssi)}</td>
        <td class="num muted">${num(x.packets)}</td>
        <td class="num muted" title="${esc(dt(x.first_seen))}">${ago(x.first_seen)}</td>
        <td class="num" title="${esc(dt(x.last_seen))}">${ago(x.last_seen)}</td></tr>`;
    }).join('');
    const tbl = document.getElementById('tbl');
    tbl.innerHTML = d.items.length ? `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>` : '<div class="empty">No devices match these filters</div>';
    tbl.querySelectorAll('th[data-sort]').forEach(th => th.addEventListener('click', () => {
      const k = th.dataset.sort;
      go({ sort: k, order: st.sort === k && st.order === 'desc' ? 'asc' : 'desc' });
    }));
    linkRows(tbl);
    const pager = document.getElementById('pager');
    pager.innerHTML = `<span>${d.total ? `${offset + 1}–${Math.min(offset + limit, d.total)} of ${num(d.total)}` : ''}</span>
      <span><button class="btn" id="prev" ${offset ? '' : 'disabled'}>Previous</button> <button class="btn" id="next" ${offset + limit < d.total ? '' : 'disabled'}>Next</button></span>`;
    pager.querySelector('#prev').onclick = () => go({ offset: Math.max(0, offset - limit) });
    pager.querySelector('#next').onclick = () => go({ offset: offset + limit });
  }
  await load();
  every(15000, load);
}

// ------------------------------------------------------------------ device
async function viewDevice(mac, params) {
  const d = await api(`/api/devices/${enc(mac)}`);
  if (d.meta && d.meta.label) d.label = d.meta.label;
  const m = KINDS[d.kind] || { label: d.kind, color: FAINT };
  const isAp = d.kind === 'ap', isBt = d.kind === 'ble' || d.kind === 'bt_classic';
  const idn = d.ident || {};
  const title = devLabel(d) || idn.label || d.vendor || d.mac;
  const ex = d.extra || {};
  const facts = [
    ['Address', `<span class="mono">${esc(d.mac)}</span>`],
    ['Type', kindBadge(d.kind)],
    ['Vendor', esc(d.vendor || (d.randomized ? 'Randomized address' : 'Unknown'))],
    isAp ? ['SSID', d.ssid ? `${esc(d.ssid)} <a class="faint" href="#/investigation/${enc(d.ssid)}">dossier →</a>` : esc(d.ssid === '' || ex.hidden ? '<hidden>' : '—')] : null,
    isAp ? ['Security', encHtml(d.enc)] : null,
    ...(isAp ? wifiApRows(ex, d) : []),
    !isBt ? ['Channel', d.channel ? `<span title="${esc(channelHelp(d))}">${d.channel}${d.band ? ` · ${BANDS[d.band] ? BANDS[d.band].label : esc(d.band)}` : ''}${d.freq ? ` <span class="faint">(${d.freq} MHz)</span>` : ''}</span>` : '—'] : null,
    ...(!isAp && !isBt ? wifiClientRows(ex, d) : []),
    isBt && d.name ? ['Name', esc(d.name)] : null,
    ex.addr_type ? ['Address type', esc(ex.addr_type)] : null,
    ex.company ? ['Manufacturer data', btCompanyHtml(ex.company)] : null,
    ex.mfg_raw ? ['Raw manufacturer data', btRawMfgHtml(ex.mfg_raw)] : null,
    ex.appearance ? ['Appearance', esc(ex.appearance)] : null,
    ex.class ? ['Device class', esc(ex.class)] : null,
    ex.tx_power != null ? ['TX power', `${ex.tx_power} dBm`] : null,
    ex.flags != null ? ['Advertised flags', btFlagsText(ex.flags)] : null,
    ex.conn_interval ? ['Preferred connection interval', ex.conn_interval[0] === ex.conn_interval[1] ? `${ex.conn_interval[0]} ms` : `${ex.conn_interval[0]}–${ex.conn_interval[1]} ms`] : null,
    ex.adv_interval ? ['Advertising interval', `≈ ${ex.adv_interval} ms <span class="faint">(estimated from how often it was heard)</span>`] : null,
    ex.ibeacon ? ['iBeacon', `<span class="mono">${esc(ex.ibeacon.uuid)}</span> <span class="faint">major</span> ${ex.ibeacon.major} <span class="faint">minor</span> ${ex.ibeacon.minor}${ex.ibeacon.power != null ? ` <span class="faint">· ${ex.ibeacon.power} dBm at 1 m</span>` : ''}`] : null,
    ex.bt_ver || ex.bt_version ? ['Bluetooth version', btVerDetail(ex)] : null,
    ex.mobility ? ['Movement', `${esc(MOBILITY[ex.mobility.c] || ex.mobility.c)} <span class="faint">(signal varies ±${ex.mobility.std} dB over ${ex.mobility.bins} ten-minute periods)</span>`] : null,
    ex.bt_probe ? ['Last version request', ex.bt_probe.ok ? `answered <span class="faint">${ago(ex.bt_probe.ts)}${ex.bt_probe.adapter ? ' via ' + esc(ex.bt_probe.adapter) : ''}</span>`
      : `<span class="warn-text">failed</span> <span class="faint">${ago(ex.bt_probe.ts)}: ${esc(ex.bt_probe.error || 'unknown error')}</span>`] : null,
    ex.phy ? ['Radio (PHY)', esc(ex.phy) + (ex.phy === 'Coded' ? ' <span class="faint">(long range)</span>' : '')] : null,
    ex.auracast ? ['LE Audio broadcast', esc([ex.auracast.name, ex.auracast.id ? 'ID ' + ex.auracast.id : '', ex.auracast.encrypted ? 'encrypted' : 'open', ex.auracast.quality ? ex.auracast.quality + ' quality' : ''].filter(Boolean).join(' · '))] : null,
    ex.esl ? ['Electronic shelf label', 'yes'] : null,
    ex.matter ? ['Matter commissioning', `${ex.matter.vendor != null ? 'vendor ID 0x' + ex.matter.vendor.toString(16).padStart(4, '0') : ''} ${ex.matter.product != null ? 'product ID 0x' + ex.matter.product.toString(16).padStart(4, '0') : ''} <span class="faint">· discriminator ${ex.matter.discriminator} (a Matter device waiting to be set up)</span>`] : null,
    ((ex.fp || {}).lan || {}).mdns && ex.fp.lan.mdns.meshcop ? ['Thread border router', `${esc(ex.fp.lan.mdns.meshcop.nn || 'Thread network')} <span class="mono faint">${esc(ex.fp.lan.mdns.meshcop.xp)}</span> <a class="faint" href="#/zigbee">networks →</a>`] : null,
    ex.encrypted_ad ? ['Encrypted advertising data', 'yes <span class="faint">(Bluetooth 5.4)</span>'] : null,
    ex.uuids && ex.uuids.length ? ['Services', btServiceTags(ex.uuids)] : null,
    ['Signal (last / best)', `${rssiBars(d.last_rssi)} <span class="faint">/ ${d.best_rssi ?? '—'}</span>`],
    ['Frames', num(d.packets)],
    ['First seen', `${dt(d.first_seen)} <span class="faint">${ago(d.first_seen)}</span>`],
    ['Last seen', `${dt(d.last_seen)} <span class="faint">${ago(d.last_seen)}</span>`],
    d.room ? ['Room', `<a href="#/map">${esc(d.room)}</a>${d.sightings && d.sightings.length > 1 ? ` <span class="faint">heard by ${d.sightings.length} sensors</span>` : ''}`] : null,
    ['Time present', `${dur(d.presence.total)} <span class="faint">in ${num(d.presence.n)} visits</span>`],
    ['Average visit', dur(d.presence.avg)],
    ['Longest visit', dur(d.presence.longest)],
    !isAp ? ['Time connected', `${dur(d.connections.total)} <span class="faint">in ${num(d.connections.n)} sessions</span>`] : null,
    d.connected_now ? ['Connected now', `<span class="tag on">since ${dt(d.connected_now.start_ts, false)}</span> ${isMac(d.connected_now.peer) ? devLink(d.connected_now.peer, d.connected_now.peer_ssid || d.connected_now.peer) : esc(d.connected_now.peer)}`] : null,
  ].filter(Boolean);

  const range = params.get('range') || '24';
  app.innerHTML = `
    <div class="page-head"><div>
      <div class="crumbs"><a href="#/devices">Devices</a> / <a href="#/devices?kind=${enc(d.kind)}">${esc(m.label)}</a></div>
      <h1>${esc(title)}</h1><div class="sub mono">${esc(d.mac)}${d.randomized ? ' · randomized address' : ''}</div></div>
      <div class="row">${d.kind === 'ble' && isAdmin() ? `<button class="btn" id="read-bt-version" type="button" ${d.now - d.last_seen > 120 ? 'disabled' : ''} title="${d.now - d.last_seen > 120 ? 'Only for a device heard in the last two minutes' : 'Connects to the device for a few seconds to read its exact Bluetooth version. This transmits.'}">Read exact version…</button>` : ''}
        ${d.kind === 'ble' ? `<button class="btn" id="play-sound" type="button" title="Connects and asks the device to play its find-me sound. Doesn't work on genuine Apple AirTags — see the button for why.">Play sound</button>` : ''}
        ${seg('range', [[1, '1h'], [6, '6h'], [24, '24h'], [168, '7d'], [720, '30d']], range)}</div></div>
    <div class="grid cols-3">
      <section class="panel span-3"><div class="body"><div class="kv">${facts.map(([k, v]) => `<div><span${lblAttr(k)}>${k}</span><b>${v}</b></div>`).join('')}</div></div></section>
      ${trackPanel(d)}
      ${matchPanel(d)}
      ${lanPanel(d)}
      ${identPanel(d)}
      <section class="panel span-2"><header><h2>Signal strength</h2><span class="legend"><span><span class="swatch" style="background:${m.color}"></span>avg</span><span><span class="swatch" style="background:${m.color}44"></span>min–max</span></span></header>
        <div class="body"><div class="chart-box"><canvas id="rssi"></canvas></div></div></section>
      <section class="panel"><header><h2>Weekly pattern</h2><span class="faint">minutes present, last 4 weeks</span></header><div class="body" id="heat"></div></section>
      <section class="panel span-3"><header><h2>Presence &amp; connectivity timeline</h2><span class="faint" id="gantt-sub"></span></header><div class="body" id="gantt"></div></section>
      ${isAp ? `<section class="panel span-3"><header><h2>Connected clients over time</h2></header><div class="body"><div class="chart-box short"><canvas id="clients"></canvas></div></div></section>` : ''}
      <section class="panel span-2"><header><h2>${isAp ? 'Clients' : 'Connected to'}</h2><span class="faint">${d.peers.length} total</span></header><div class="body flush table-wrap" id="peers"></div></section>
      <section class="panel"><header><h2>${isAp ? 'Same SSID' : 'Probed networks'}</h2></header><div class="body flush table-wrap" id="side"></div></section>
      <section class="panel span-2"><header><h2>Sessions</h2>${seg('stype', [['assoc', 'Connections'], ['presence', 'Visits']], isAp ? 'presence' : 'assoc')}</header><div class="body flush table-wrap" id="sessions"></div></section>
      <section class="panel"><header><h2>Events</h2><a class="muted" href="#/events?mac=${enc(d.mac)}">All →</a></header><div class="body flush" id="devevents"></div></section>
    </div>`;

  bindTrackPanel(d);
  bindLanPanel(d);
  bindMatchPanel(d);
  const soundBtn = document.getElementById('play-sound');
  if (soundBtn) soundBtn.onclick = async () => {
    soundBtn.disabled = true;
    const was = soundBtn.textContent;
    soundBtn.textContent = 'Connecting…';
    try {
      await send('POST', `/api/devices/${enc(mac)}/sound`);
      toast('Sound command sent');
    } catch (e) { toast(e.message, true); }
    finally { soundBtn.disabled = false; soundBtn.textContent = was; }
  };
  const verBtn = document.getElementById('read-bt-version');
  if (verBtn) verBtn.onclick = () => {
    const before = (d.extra.bt_probe || {}).ts;
    openModal('Read the exact Bluetooth version', `
      <p><b>This transmits.</b> Unlike everything else sniffowireless does, this makes a Bluetooth adapter of yours <b>connect to this device</b> for a few seconds, to ask it which Bluetooth version it implements.</p>
      <ul>
        <li>The device can notice a connection from your sensor. Some show an activity light or briefly stop advertising; one that is busy may refuse.</li>
        <li>Nothing is paired, written or read except the Bluetooth version and the maker's ID. The connection is closed straight away.</li>
        <li>It only works for a device heard in the last two minutes, and once a minute per device. The adapter that hears it best does it, also on a remote sensor.</li>
        <li>Do this only to devices you own or may test.</li>
      </ul>
      <label class="check"><input type="checkbox" name="ok"> I own this device or have permission to test it</label>
      <p class="faint small-text" id="ver-progress" style="margin-bottom:0"></p>`, async form => {
      if (!form.elements.ok.checked) throw new Error('Tick the box to confirm');
      const progress = form.querySelector('#ver-progress');
      progress.textContent = 'Asking the adapter…';
      await send('POST', `/api/devices/${enc(mac)}/bt-version`);
      progress.textContent = 'Connecting to the device…';
      for (let i = 0; i < 20; i++) {  // a remote sensor gets the request with its next upload, then reports the answer the same way
        await new Promise(r => setTimeout(r, 1500));
        const nd = await api(`/api/devices/${enc(mac)}`);
        const bp = (nd.extra || {}).bt_probe;
        if (bp && bp.ts !== before) {
          if (!bp.ok) throw new Error(bp.error || 'The request failed');
          toast(`Bluetooth ${nd.extra.bt_ver || nd.extra.bt_version}`);
          route();
          return;
        }
      }
      throw new Error('No answer yet. A remote sensor picks the request up with its next upload; check this page again in a moment.');
    }, { submit: 'Connect and read the version' });
  };
  // facts / static sections
  const peers = document.getElementById('peers');
  peers.innerHTML = d.peers.length ? `<table><thead><tr><th>${isAp ? 'Client' : 'Access point / adapter'}</th><th>${isAp ? 'Vendor' : 'SSID'}</th><th class="num">Sessions</th><th class="num">Total time</th><th class="num">First</th><th class="num">Last</th></tr></thead><tbody>
    ${d.peers.map(p => `<tr class="${isMac(p.mac) ? 'link' : ''}" data-href="${isMac(p.mac) ? '#/device/' + enc(p.mac) : ''}">
      <td>${p.connected ? '<span class="state-dot on"></span>' : '<span class="state-dot"></span>'}<span class="mono">${esc(isAp ? (p.name || p.mac) : p.mac)}</span>${p.randomized ? ' <span class="tag warn">rand</span>' : ''}</td>
      <td class="trunc muted">${esc(isAp ? (p.vendor || '—') : (p.ssid || (isMac(p.mac) ? '—' : 'sensor Bluetooth adapter')))}</td>
      <td class="num">${num(p.sessions)}</td><td class="num">${dur(p.total)}</td>
      <td class="num muted">${dt(p.first)}</td><td class="num muted">${p.connected ? '<span class="tag on">now</span>' : ago(p.last)}</td></tr>`).join('')}
    </tbody></table>` : `<div class="empty">${isAp ? 'No clients observed' : 'No connections observed'}</div>`;
  linkRows(peers);

  const side = document.getElementById('side');
  if (isAp) {
    side.innerHTML = d.siblings.length ? `<table><tbody>${d.siblings.map(s => `<tr class="link" data-href="#/device/${enc(s.mac)}">
      <td class="mono">${esc(s.mac)}</td><td class="muted">ch ${chText(s.channel, s.band)}</td><td>${rssiBars(s.last_rssi)}</td></tr>`).join('')}</tbody></table>
      <div class="pager"><a href="#/devices?ssid=${enc(d.ssid)}">All devices on “${esc(d.ssid)}” →</a></div>`
      : `<div class="empty">No other BSSIDs${d.ssid ? ` for “${esc(d.ssid)}”` : ''}</div>${d.ssid ? `<div class="pager"><a href="#/devices?ssid=${enc(d.ssid)}">All devices on “${esc(d.ssid)}” →</a></div>` : ''}`;
  } else {
    side.innerHTML = d.probes.length ? `<table><thead><tr><th>SSID</th><th class="num">Frames</th><th class="num">Last</th></tr></thead><tbody>${d.probes.map(p => `<tr class="link" data-href="#/devices?probe=${enc(p.ssid)}">
      <td class="trunc">${esc(p.ssid)}${p.aps ? ' <span class="tag">nearby</span>' : ''}</td><td class="num muted">${num(p.count)}</td><td class="num muted">${ago(p.last_seen)}</td></tr>`).join('')}</tbody></table>`
      : `<div class="empty">${isBt ? 'Not applicable' : 'No directed probes seen'}</div>`;
  }
  linkRows(side);
  document.getElementById('devevents').innerHTML = d.events.length ? `<ul class="events">${d.events.slice(0, 25).map(e => eventRow(e.mac === d.mac ? { ...e, kind: d.kind, name: d.name, ssid: d.ssid, vendor: d.vendor } : e)).join('')}</ul>` : '<div class="empty">No events</div>';

  // heatmap
  api(`/api/devices/${enc(mac)}/heatmap?days=28&tz=${TZ}`).then(h => {
    const max = Math.max(1, ...h.grid.flat());
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    let html = '<div class="heat"><span></span>' + Array.from({ length: 24 }, (_, i) => `<span class="h">${i % 6 === 0 ? hourLabel(i, true) : ''}</span>`).join('');
    h.grid.forEach((row, di) => {
      html += `<span class="d">${days[di]}</span>` + row.map((v, hi) =>
        `<span class="cell" title="${days[di]} ${hourLabel(hi)} — ${v} min" style="${v ? `background:${m.color};opacity:${(0.15 + 0.85 * v / max).toFixed(2)}` : ''}"></span>`).join('');
    });
    document.getElementById('heat').innerHTML = html + '</div>';
  });

  let hours = +range, stype = isAp ? 'presence' : 'assoc', sessCache = null;
  onSeg(app, 'range', v => { hours = +v; history.replaceState(null, '', hrefWith(`/device/${enc(mac)}`, { range: v })); loadRange(); });
  onSeg(app, 'stype', v => { stype = v; renderSessions(); });

  async function loadRssi() {
    if (d.kind === 'lan') {
      document.getElementById('rssi').parentElement.innerHTML = '<div class="empty">Wired / LAN device: no radio signal</div>';
      return;
    }
    const r = await api(`/api/devices/${enc(mac)}/rssi?hours=${hours}`);
    const now = Date.now() / 1000, span = hours * 3600;
    const pts = r.points.filter(p => p.avg != null);
    chart(document.getElementById('rssi'), {
      type: 'line',
      data: {
        datasets: [
          { label: 'max', data: pts.map(p => ({ x: p.t, y: p.max })), borderWidth: 0, pointRadius: 0, fill: '+1', backgroundColor: m.color + '22' },
          { label: 'min', data: pts.map(p => ({ x: p.t, y: p.min })), borderWidth: 0, pointRadius: 0, fill: false },
          { label: 'avg dBm', data: pts.map(p => ({ x: p.t, y: p.avg })), borderColor: m.color, borderWidth: 1.5, pointRadius: 0, tension: .25, spanGaps: r.bucket * 3 },
        ],
      },
      options: {
        maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        scales: { x: { ...timeScale(span), min: now - span, max: now }, y: yScale({ beginAtZero: false, suggestedMax: -30, suggestedMin: -95, ticks: { color: FAINT, callback: v => v + ' dBm' } }) },
        plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } },
      },
    });
  }

  async function loadSessions() {
    const [own, asPeer] = await Promise.all([
      api(`/api/devices/${enc(mac)}/sessions?hours=${hours}`),
      isAp ? api(`/api/devices/${enc(mac)}/sessions?hours=${hours}&as_peer=1`) : Promise.resolve({ items: [] }),
    ]);
    sessCache = { own: own.items, peer: asPeer.items, now: own.now };
    const now = own.now, start = now - hours * 3600, span = now - start;
    const pos = (a, b) => {
      const l = Math.max(0, (a - start) / span * 100), r = Math.min(100, (b - start) / span * 100);
      return `left:${l}%;width:max(2px, ${Math.max(0, r - l)}%)`;
    };
    const bar = (s, color, label) => `<span class="bar" style="${pos(s.start_ts, s.end_ts)};background:${color}"
      title="${esc(label)}\n${esc(dt(s.start_ts))} → ${s.open ? 'now' : esc(dt(s.end_ts))} (${dur(s.end_ts - s.start_ts)})${s.end_reason ? '\nended: ' + esc(s.end_reason) : ''}"></span>`;
    const lanes = [];
    const presence = own.items.filter(s => s.type === 'presence');
    lanes.push(['In range', presence.map(s => bar(s, m.color, 'In range')).join('')]);
    if (isAp) {
      const byClient = {};
      asPeer.items.forEach(s => (byClient[s.mac] = byClient[s.mac] || []).push(s));
      Object.entries(byClient).slice(0, 30).forEach(([cm, ss]) => {
        const lab = (ss[0].peer_name || ss[0].peer_vendor) ? `${ss[0].peer_name || ss[0].peer_vendor} ·${cm.slice(-5)}` : cm;
        lanes.push([`<a href="#/device/${enc(cm)}" title="${esc(cm)}">${esc(lab)}</a>`, ss.map(s => bar(s, KINDS.wifi_client.color, cm)).join('')]);
      });
    } else {
      const byPeer = {};
      own.items.filter(s => s.type === 'assoc').forEach(s => (byPeer[s.peer] = byPeer[s.peer] || []).push(s));
      Object.entries(byPeer).forEach(([p, ss]) => {
        const lab = ss[0].peer_ssid ? `${ss[0].peer_ssid} ·${p.slice(-5)}` : p;
        const name = isMac(p) ? `<a href="#/device/${enc(p)}" title="${esc(p)}">→ ${esc(lab)}</a>` : `→ ${esc(lab)}`;
        lanes.push([name, ss.map(s => bar(s, TEXT, `Connected to ${lab}`)).join('')]);
      });
    }
    const ticks = Array.from({ length: 7 }, (_, i) => start + span * i / 6);
    document.getElementById('gantt').innerHTML = `<div class="gantt">${lanes.map(([l, b]) =>
      `<div class="lane"><div class="lane-label">${l}</div><div class="track">${b}</div></div>`).join('')}
      <div class="axis"><span></span><div class="ticks">${ticks.map((t, i) => `<span style="left:${i / 6 * 100}%">${axisTime(t, span)}</span>`).join('')}</div></div></div>`;
    const visits = presence.length, conns = own.items.filter(s => s.type === 'assoc').length;
    document.getElementById('gantt-sub').textContent = `${visits} visit${visits === 1 ? '' : 's'}${isAp ? `, ${Object.keys(asPeer.items.reduce((a, s) => (a[s.mac] = 1, a), {})).length} clients` : `, ${conns} connection${conns === 1 ? '' : 's'}`} in range`;
    renderSessions();
  }

  function renderSessions() {
    if (!sessCache) return;
    let list = stype === 'assoc' ? (isAp ? sessCache.peer : sessCache.own.filter(s => s.type === 'assoc')) : sessCache.own.filter(s => s.type === 'presence');
    list = list.slice().reverse().slice(0, 200);
    const el = document.getElementById('sessions');
    el.innerHTML = list.length ? `<table><thead><tr>${stype === 'assoc' ? `<th>${isAp ? 'Client' : 'Connected to'}</th>` : ''}<th>Start</th><th>End</th><th class="num">Duration</th><th class="num">Frames</th><th>Signal</th><th>Ended by</th></tr></thead><tbody>
      ${list.map(s => {
        const who = isAp ? s.mac : s.peer;
        const lab = isAp ? (s.peer_name || s.peer_vendor || s.mac) : (s.peer_ssid || s.peer);
        const avg = s.rssi_count ? Math.round(s.rssi_sum / s.rssi_count) : null;
        return `<tr>${stype === 'assoc' ? `<td>${devLink(who, lab)}</td>` : ''}<td>${dt(s.start_ts)}</td>
          <td>${s.open ? '<span class="tag on">ongoing</span>' : dt(s.end_ts)}</td><td class="num">${dur(s.end_ts - s.start_ts)}</td>
          <td class="num muted">${num(s.packets)}</td><td class="muted">${avg != null ? `${avg} <span class="faint">(${s.rssi_min}…${s.rssi_max})</span>` : '—'}</td>
          <td class="muted">${esc(s.open ? '' : s.end_reason || '')}</td></tr>`;
      }).join('')}</tbody></table>` : '<div class="empty">No sessions in this range</div>';
  }

  async function loadClients() {
    if (!isAp) return;
    const c = await api(`/api/devices/${enc(mac)}/clients?hours=${hours}`);
    const span = hours * 3600;
    chart(document.getElementById('clients'), {
      type: 'line', data: { datasets: [{ label: 'Clients', data: c.t.map((x, i) => ({ x, y: c.n[i] })), borderColor: KINDS.wifi_client.color,
        backgroundColor: KINDS.wifi_client.color + '22', fill: true, stepped: true, borderWidth: 1.5, pointRadius: 0 }] },
      options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        scales: { x: { ...timeScale(span), min: c.t[0], max: c.t[c.t.length - 1] }, y: yScale() },
        plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } } },
    });
  }

  const loadRange = () => Promise.all([loadRssi(), loadSessions(), loadClients()]);
  await loadRange();
  every(30000, loadRange);
}

// ------------------------------------------------------------------ stats
// Doughnut breakdowns per device kind (Statistics page).
// Slice colors: validated for the dark panel surface (OKLCH L 0.48–0.67, chroma >= 0.1, neighbouring slices incl. the
// last→first wrap distinct for protan/deutan readers); identity never relies on color alone: the legend names each
// slice with its count and share. Anything past the top 5 folds into a neutral gray "Other".
const PIE_COLORS = ['#3690e3', '#d46a34', '#05a388', '#c34f4b', '#97902a'];
const PIE_TOP = PIE_COLORS.length;
const BREAKDOWN_KINDS = [['ble', 'BLE'], ['wifi_client', 'Wi-Fi clients'], ['bt_classic', 'BT classic'], ['ap', 'Access points'], ['lan', 'LAN']];

// One doughnut per sensor: what kinds of device it heard in the selected period.
function sensorPies(el, data) {
  const by = {};
  data.forEach(r => { (by[r.id] = by[r.id] || { name: r.name, kinds: {} }).kinds[r.kind] = r.n; });
  const sensors = Object.entries(by).map(([id, v]) => ({ id, ...v, total: Object.values(v.kinds).reduce((a, n) => a + n, 0) }))
    .sort((a, b) => b.total - a.total);
  el.hidden = !sensors.length;
  if (!sensors.length) return;
  el.innerHTML = `<header><h2>Per sensor</h2><span class="faint">device types each sensor heard · a device heard by several sensors counts for each</span></header>
    <div class="body"><div class="pie-grid">${sensors.map((x, i) => `<div class="pie-card"><h3 class="subhead">${esc(x.name)}</h3>
      <div class="pie-wrap"><div class="pie-box"><canvas id="sp-${i}" role="img" aria-label="${esc(x.name)} device types"></canvas><div class="pie-total"><b>${num(x.total)}</b><span>devices</span></div></div>
      <ul class="pie-legend">${kindEntries().filter(([k]) => x.kinds[k]).map(([k, m]) => `<li><span class="swatch" style="background:${m.color}"></span><span class="pl-name">${esc(m.label)}</span>
        <span class="pl-n">${num(x.kinds[k])}</span><span class="pl-p">${Math.round(x.kinds[k] / x.total * 100)}%</span></li>`).join('')}</ul></div></div>`).join('')}</div></div>`;
  sensors.forEach((x, i) => {
    const ks = kindEntries().filter(([k]) => x.kinds[k]);
    chart(document.getElementById(`sp-${i}`), {
      type: 'doughnut',
      data: { labels: ks.map(([, m]) => m.label), datasets: [{ data: ks.map(([k]) => x.kinds[k]), backgroundColor: ks.map(([, m]) => m.color),
        borderColor: PANEL(), borderWidth: 2, hoverBorderColor: PANEL(), hoverOffset: 4, borderRadius: 2 }] },
      options: { maintainAspectRatio: false, cutout: '64%', animation: false,
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => ` ${c.label}: ${num(c.parsed)} (${Math.round(c.parsed / x.total * 100)}%)` } } } },
    });
  });
}

function breakdown(el, s, kind) {
  if (window.Chart) el.querySelectorAll('canvas').forEach(c => { const p = Chart.getChart(c); if (p) p.destroy(); });
  const of = (rows, key = 'v') => rows.filter(r => r.kind === kind).map(r => ({ v: r[key], n: r.n }));
  const charts = [
    ['Device type', of(s.dev_type), 'dev_type', v => typeLabel(v)],
    ['Vendor', of(s.vendors, 'vendor').map(r => ({ v: r.v === 'Unknown' ? null : r.v, n: r.n })), 'vendor', v => v],
    ['Brand', of(s.brand), 'brand', v => v],
    ['Operating system', of(s.os), 'os', v => v],
  ];
  if (kind === 'ble') charts.push(['Address type', of(s.addr_type), 'addr_type', v => ADDR_TYPES[v] || v],
    ['Bluetooth company', of(s.company), 'company', v => v]);
  if (kind === 'ble' || kind === 'bt_classic') charts.push(['Bluetooth version', of(s.bt_ver), 'bt_ver', v => v.endsWith('+') ? 'at least ' + v.slice(0, -1) : v]);
  charts.push(['Movement', of(s.mobility), 'mobility', v => MOBILITY[v] || v]);
  const total = charts[0][1].reduce((a, r) => a + r.n, 0);
  el.innerHTML = `<header><h2>Breakdown</h2><span class="faint">${num(total)} ${esc((KINDS[kind] || {}).label || kind)} · click a slice or row for the devices</span>
      ${seg('bkind', BREAKDOWN_KINDS.filter(([k]) => kindOn(k)), kind)}</header>
    <div class="body">${total ? `<div class="pie-grid">${charts.map((c, i) => `<div class="pie-card"><h3 class="subhead">${c[0]}</h3>
      <div class="pie-wrap"><div class="pie-box"><canvas id="pie-${i}" role="img" aria-label="${esc(c[0])} breakdown"></canvas><div class="pie-total"><b>${num(total)}</b><span>devices</span></div></div>
      <ul class="pie-legend" id="pie-leg-${i}"></ul></div></div>`).join('')}</div>` : '<div class="empty">No devices of this kind in this period</div>'}</div>`;
  onSeg(el, 'bkind', v => breakdown(el, s, v));
  if (!total) return;
  charts.forEach(([title, rows, key, label], i) => {
    const agg = {};
    rows.forEach(r => { const k = r.v == null || r.v === '' ? '' : String(r.v); agg[k] = (agg[k] || 0) + r.n; });
    const sorted = Object.entries(agg).sort((a, b) => b[1] - a[1]);
    // "Unknown" is shown but never takes a color slot ahead of identified values.
    const known = sorted.filter(([k]) => k !== ''), unknown = agg[''] || 0;
    const top = known.slice(0, PIE_TOP);
    const rest = known.slice(PIE_TOP).reduce((a, [, n]) => a + n, 0) + unknown;
    const slices = top.map(([k, n], j) => ({ k, n, name: label(k), color: PIE_COLORS[j] }));
    if (rest) slices.push({ k: known.length > PIE_TOP ? null : '', n: rest, name: known.length > PIE_TOP ? (unknown ? 'Other / unknown' : 'Other') : 'Unknown', color: FAINT });
    const sum = slices.reduce((a, x) => a + x.n, 0);
    const pct = n => `${Math.round(n / sum * 100)}%`;
    const href = x => x.k === null ? null : hrefWith('/devices', { kind, [key]: x.k === '' ? 'Unknown' : x.k });
    document.getElementById(`pie-leg-${i}`).innerHTML = slices.map(x => {
      const h = href(x);
      return `<li${h ? ` data-href="${h}"` : ''}><span class="swatch" style="background:${x.color}"></span><span class="pl-name" title="${esc(x.name)}">${x.k === '' ? `<span class="faint">${esc(x.name)}</span>` : esc(x.name)}</span>
        <span class="pl-n">${num(x.n)}</span><span class="pl-p">${pct(x.n)}</span></li>`;
    }).join('');
    chart(document.getElementById(`pie-${i}`), {
      type: 'doughnut',
      data: { labels: slices.map(x => x.name), datasets: [{ data: slices.map(x => x.n), backgroundColor: slices.map(x => x.color),
        borderColor: PANEL(), borderWidth: 2, hoverBorderColor: PANEL(), hoverOffset: 4, borderRadius: 2 }] },
      options: { maintainAspectRatio: false, cutout: '64%', animation: false,
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => ` ${c.label}: ${num(c.parsed)} (${pct(c.parsed)})` } } },
        onHover: (e, els) => { e.native.target.style.cursor = els.length && href(slices[els[0].index]) ? 'pointer' : 'default'; },
        onClick: (e, els) => { if (els.length) { const h = href(slices[els[0].index]); if (h) location.hash = h; } } },
    });
  });
  bindLi(el);
}

// Statistics lists show the top 20; the panel title opens the list in full (#/stats?list=<id>), or the page that owns it.
const STAT_CAP = 20, STAT_FULL = 1000;
async function viewStats(params) {
  const days = params.get('days') || '1';
  const listId = params.get('list') || '';
  const CAP = listId ? STAT_FULL : STAT_CAP;
  const ttl = (id, text, href) => `<a class="h-link" href="${href || hrefWith('/stats', { days, list: id })}" title="Show the full list">${text}</a>`;
  app.innerHTML = `
    <div class="page-head"><div>${listId ? `<a class="muted" href="${hrefWith('/stats', { days })}">← Statistics</a>` : ''}<h1 id="stats-h1">Statistics</h1><div class="sub">${listId ? 'Full list.' : `Lists show the top ${STAT_CAP}: click a title for the full list, or any bar, row or slice to drill down.`}</div></div>
      ${seg('days', [[1, '24h'], [7, '7 days'], [30, '30 days']], days)}</div>
    <div class="grid cols-3" id="stats"><div class="empty span-all">Loading…</div></div>`;
  onSeg(app, 'days', v => { location.hash = hrefWith('/stats', { days: v, list: listId }); });
  const s = await api(`/api/stats?days=${days}&tz=${TZ}&limit=${CAP}`);
  const root = document.getElementById('stats');
  root.innerHTML = `
    <section class="panel span-3" id="breakdown"></section>
    <section class="panel span-3" id="per-sensor" hidden></section>
    <section class="panel span-2"><header><h2>Activity by hour of day</h2><span class="faint">average distinct devices per hour</span></header><div class="body"><div class="chart-box"><canvas id="hourly"></canvas></div></div></section>
    <section class="panel"><header><h2>MAC address privacy</h2></header><div class="body" id="rand"></div></section>
    <section class="panel span-2"><header><h2>Weekly activity pattern</h2><span class="faint">relative busyness by day and hour</span></header><div class="body" id="weekheat"></div></section>
    <section class="panel" data-list="new-vendors"><header><h2>${ttl('new-vendors', 'New vendors')}</h2><span class="faint">first seen, ever, in this period</span></header><div class="body flush table-wrap" id="new-vendors"></div></section>
    <section class="panel span-2"><header><h2>New devices per day</h2></header><div class="body"><div class="chart-box short"><canvas id="newday"></canvas></div></div></section>
    <section class="panel"><header><h2>${ttl('', 'Session durations', hrefWith('/sessions', { type: 'assoc', days }))}</h2>${seg('dtype', [['assoc', 'Connections'], ['presence', 'Visits']], 'assoc')}</header><div class="body"><div class="chart-box short"><canvas id="durs"></canvas></div></div></section>
    <section class="panel" data-list="st-type"><header><h2>${ttl('st-type', 'Device types')}</h2><span class="faint">identified</span></header><div class="body"><ul class="bars-list" id="st-type"></ul></div></section>
    <section class="panel" data-list="st-brand"><header><h2>${ttl('st-brand', 'Brands')}</h2><select id="vkind" style="padding:2px 6px"><option value="">All</option>${kindEntries().map(([k, m]) => `<option value="${k}">${m.short}</option>`).join('')}</select></header><div class="body"><ul class="bars-list" id="st-brand"></ul></div></section>
    <section class="panel" data-list="st-gen"><header><h2>${ttl('st-gen', 'Wi-Fi generation')}</h2><span class="faint">newest standard supported</span></header><div class="body"><ul class="bars-list" id="st-gen"></ul></div></section>
    <section class="panel" data-list="st-era"><header><h2>${ttl('st-era', 'Estimated age')}</h2><span class="faint">earliest possible year</span></header><div class="body"><ul class="bars-list" id="st-era"></ul></div></section>
    <section class="panel" data-list="st-os"><header><h2>${ttl('st-os', 'Operating systems')}</h2></header><div class="body"><ul class="bars-list" id="st-os"></ul></div></section>
    <section class="panel" data-list="st-fp"><header><h2>${ttl('st-fp', 'Shared fingerprints')}</h2><span class="faint">same probe layout = same model / OS</span></header><div class="body flush table-wrap" id="st-fp"></div></section>
    <section class="panel"><header><h2>${ttl('', 'AP channels', '#/channels')}</h2><span class="legend" id="bandlegend"></span></header><div class="body"><div class="chart-box"><canvas id="chans"></canvas></div><ul class="bars-list" id="bands" style="margin-top:12px"></ul></div></section>
    <section class="panel"><header><h2>${ttl('', 'Events', '#/events')}</h2></header><div class="body flush table-wrap" id="evtypes"></div></section>
    <section class="panel span-3"><header><h2>${ttl('', 'Networks (SSIDs)', '#/ssids')}</h2><span class="row"><span class="faint" id="ssids-count"></span><button class="btn small" id="ssids-more" hidden></button></span></header><div class="body flush table-wrap" id="ssids"></div></section>
    <section class="panel" data-list="topc"><header><h2>${ttl('topc', 'Most connected clients')}</h2></header><div class="body flush table-wrap" id="topc"></div></section>
    <section class="panel" data-list="topap"><header><h2>${ttl('topap', 'Busiest access points')}</h2></header><div class="body flush table-wrap" id="topap"></div></section>
    <section class="panel" data-list="probes"><header><h2>${ttl('probes', 'Probed SSIDs')}</h2><span class="faint">networks clients are looking for</span></header><div class="body flush table-wrap" id="probes"></div></section>`;

  if (!modOn('wifi')) ['st-gen', 'chans', 'ssids', 'topc', 'topap', 'probes'].forEach(id => { const p = document.getElementById(id) || root.querySelector(`[data-list="${id}"]`); const sec = p && p.closest('section'); if (sec) sec.hidden = true; });

  if (listId) {
    const keep = root.querySelector(`[data-list="${listId}"]`);
    root.querySelectorAll(':scope > section').forEach(el => { el.hidden = el !== keep; });
    if (keep) {
      keep.classList.add('span-3');
      document.getElementById('stats-h1').textContent = keep.querySelector('h2').textContent;
    } else root.innerHTML = '<div class="empty span-all">Unknown list</div>';
  }
  if (!listId) {
    breakdown(document.getElementById('breakdown'), s, (BREAKDOWN_KINDS.find(([k]) => kindOn(k)) || ['ble'])[0]);
    sensorPies(document.getElementById('per-sensor'), s.sensor_kinds || []);
  }

  // hourly
  const hours = Array.from({ length: 24 }, (_, i) => i);
  chart(document.getElementById('hourly'), {
    type: 'bar',
    data: { labels: hours.map(h => hourLabel(h)), datasets: kindEntries().map(([k, m]) => ({
      label: m.label, backgroundColor: m.color + 'cc', borderRadius: 2, maxBarThickness: 40, stack: 'a',
      data: hours.map(h => +((s.hourly.rows.find(r => r.h === h && r.kind === k) || { n: 0 }).n / s.hourly.days).toFixed(1)),
    })) },
    options: { maintainAspectRatio: false, scales: { x: { stacked: true, grid: { display: false }, ticks: { color: FAINT } }, y: yScale({ stacked: true }) },
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 8, boxHeight: 8, color: MUTED } } },
      onClick: (e, els) => { if (els.length) location.hash = hrefWith('/devices', { kind: (kindEntries()[els[0].datasetIndex] || [])[0] }); } },
  });

  // new per day
  const daysList = [...new Set(s.new_per_day.map(r => r.day))].sort((a, b) => a - b);
  chart(document.getElementById('newday'), {
    type: 'bar',
    data: { labels: daysList.map(d => new Date(d * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' })),
      datasets: kindEntries().map(([k, m]) => ({ label: m.label, backgroundColor: m.color + 'cc', borderRadius: 2, maxBarThickness: 40, stack: 'a',
        data: daysList.map(d => (s.new_per_day.find(r => r.day === d && r.kind === k) || { n: 0 }).n) })) },
    options: { maintainAspectRatio: false, scales: { x: { stacked: true, grid: { display: false }, ticks: { color: FAINT } }, y: yScale({ stacked: true }) } },
  });

  // durations
  const DB = ['<1m', '1–5m', '5–30m', '30m–2h', '2–8h', '>8h'];
  let durType = 'assoc';
  const drawDur = t => (durType = t, chart(document.getElementById('durs'), {
    type: 'bar', data: { labels: DB, datasets: [{ data: DB.map((_, b) => (s.durations.find(r => r.type === t && r.b === b) || { n: 0 }).n), backgroundColor: TEXT + 'bb', borderRadius: 2, maxBarThickness: 40 }] },
    options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { color: FAINT } }, y: yScale() },
      plugins: { tooltip: { callbacks: { footer: () => 'Click to list these sessions' } } },
      onHover: (e, els) => { e.native.target.style.cursor = els.length ? 'pointer' : 'default'; },
      onClick: (e, els) => { if (els.length) location.hash = hrefWith('/sessions', { type: durType, b: els[0].index, days }); } },
  }));
  drawDur('assoc');
  onSeg(root, 'dtype', drawDur);

  // randomized
  const rnd = kindEntries().filter(([k]) => k !== 'ap').map(([k, m]) => {
    const r = s.randomized.filter(x => x.kind === k);
    const tot = r.reduce((a, x) => a + x.n, 0), rn = (r.find(x => x.randomized) || { n: 0 }).n;
    return { k, m, tot, rn };
  });
  document.getElementById('rand').innerHTML = `<ul class="bars-list">${rnd.map(({ k, m, tot, rn }) => `
    <li data-href="${hrefWith('/devices', { kind: k, randomized: 1 })}"><div><div class="name">${m.label} <span class="faint">· ${tot ? Math.round(rn / tot * 100) : 0}% randomized</span></div>
      <div class="track"><i style="width:${tot ? rn / tot * 100 : 0}%;background:${m.color}"></i><i style="width:${tot ? (tot - rn) / tot * 100 : 0}%;background:${m.color}44"></i></div></div>
      <div class="n">${num(tot)}</div></li>`).join('')}</ul>
    <p class="faint" style="margin:12px 0 0">Randomized (locally administered / private) addresses rotate, so one physical device can appear as many entries. Connections usually keep a stable per-network address.</p>`;

  // weekly activity pattern: distinct devices per (weekday, hour), same heat-grid style as a device's own
  const WDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const heatCell = {};
  s.weekly_heat.forEach(r => { heatCell[`${r.wd}:${r.h}`] = r.n; });
  const heatMax = Math.max(1, ...s.weekly_heat.map(r => r.n));
  let weekHtml = '<div class="heat"><span></span>' + Array.from({ length: 24 }, (_, i) => `<span class="h">${i % 6 === 0 ? hourLabel(i, true) : ''}</span>`).join('');
  WDAYS.forEach((label, wd) => {
    weekHtml += `<span class="d">${label}</span>` + Array.from({ length: 24 }, (_, h) => {
      const v = heatCell[`${wd}:${h}`] || 0;
      return `<span class="cell" title="${label} ${hourLabel(h)} — ${v ? num(v) : 'no'} device${v === 1 ? '' : 's'}" style="${v ? `background:${TEXT};opacity:${(0.15 + 0.85 * v / heatMax).toFixed(2)}` : ''}"></span>`;
    }).join('');
  });
  document.getElementById('weekheat').innerHTML = weekHtml + '</div>';

  // new vendors: the first time ever this vendor was seen fell in this period
  const nvEl = document.getElementById('new-vendors');
  nvEl.innerHTML = s.new_vendors.length ? `<table><thead><tr><th>Vendor</th><th class="num">First seen</th><th class="num">Devices (all time)</th></tr></thead><tbody>
    ${s.new_vendors.slice(0, listId ? 1000 : STAT_CAP).map(v => `<tr class="link" data-href="${hrefWith('/devices', { vendor: v.vendor })}">
      <td>${esc(v.vendor)}</td><td class="num muted">${dt(v.first_seen)}</td><td class="num">${num(v.devices)}</td></tr>`).join('')}
    </tbody></table>` : '<div class="empty">No new vendors in this period</div>';
  linkRows(nvEl);

  // identification breakdowns
  const barList = (id, rows, label, filterKey, kind = '', order = null) => {
    const agg = {};
    rows.filter(r => !kind || r.kind === kind).forEach(r => {
      const k = r.v == null ? '' : String(r.v);
      agg[k] = agg[k] || { n: 0, kinds: {} };
      agg[k].n += r.n; agg[k].kinds[r.kind] = (agg[k].kinds[r.kind] || 0) + r.n;
    });
    let list = Object.entries(agg);
    list = order ? list.sort(order) : list.sort((a, b) => b[1].n - a[1].n);
    list = list.slice(0, CAP);
    const max = Math.max(1, ...list.map(([, o]) => o.n));
    document.getElementById(id).innerHTML = list.map(([v, o]) => `<li data-href="${hrefWith('/devices', { [filterKey]: v === '' ? (filterKey === 'wifi_gen' || filterKey === 'era' ? '0' : 'Unknown') : v, kind })}">
      <div><div class="name">${v === '' ? '<span class="faint">Unknown</span>' : esc(label(v))}</div><div class="track">${Object.entries(o.kinds).map(([k, n]) => `<i style="width:${n / max * 100}%;background:${(KINDS[k] || {}).color || FAINT}"></i>`).join('')}</div></div>
      <div class="n">${num(o.n)}</div></li>`).join('') || '<div class="empty">No data</div>';
    bindLi(root);
  };
  const numDesc = (a, b) => (b[0] === '' ? -1 : +b[0]) - (a[0] === '' ? -1 : +a[0]);
  barList('st-type', s.dev_type, typeLabel, 'dev_type');
  barList('st-brand', s.brand, v => v, 'brand');
  const genRank = v => v === '' ? -1 : +v === 66 ? 6.5 : +v;  // 66 = Wi-Fi 6E sits between 6 and 7
  barList('st-gen', s.wifi_gen.filter(r => r.kind === 'ap' || r.kind === 'wifi_client'), v => genLabel(+v), 'wifi_gen', '', (a, b) => genRank(b[0]) - genRank(a[0]));
  barList('st-era', s.era, v => eraLabel(+v), 'era', '', numDesc);
  barList('st-os', s.os, v => v, 'os');
  document.getElementById('vkind').addEventListener('change', e => barList('st-brand', s.brand, v => v, 'brand', e.target.value));
  const fpEl = document.getElementById('st-fp');
  fpEl.innerHTML = s.fingerprints.length ? `<table><thead><tr><th>Fingerprint</th><th>Likely</th><th class="num">MACs</th></tr></thead><tbody>${s.fingerprints.map(f => `<tr class="link" data-href="${hrefWith('/devices', { fp: f.fp_hash })}">
    <td class="mono">${esc(f.fp_hash)}</td><td class="trunc muted">${esc([f.brand, typeLabel(f.dev_type) !== 'Unknown' ? typeLabel(f.dev_type) : null, f.wifi_gen ? genLabel(f.wifi_gen) : null].filter(Boolean).join(' · ') || '—')}</td>
    <td class="num">${f.n}${f.randomized ? ` <span class="tag warn">${f.randomized} rand</span>` : ''}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">No shared fingerprints yet</div>';
  linkRows(fpEl);

  // channels + bands
  document.getElementById('bandlegend').innerHTML = BAND_LIST.map(([b, m]) => `<span><span class="swatch" style="background:${m.color}"></span>${b}G</span>`).join('');
  chart(document.getElementById('chans'), {
    type: 'bar', data: { labels: s.channels.map(c => c.b === '6' ? `6G:${c.channel}` : c.channel),
      datasets: [{ data: s.channels.map(c => c.aps), backgroundColor: s.channels.map(c => (BANDS[c.b] || BANDS['2.4']).color + 'cc'), borderRadius: 2, maxBarThickness: 40 }] },
    options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { color: FAINT } }, y: yScale() },
      plugins: { tooltip: { callbacks: { title: i => `Channel ${i[0].label} (${s.channels[i[0].dataIndex].b} GHz)`, label: i => `${i.raw} access points` } } },
      onClick: (e, els) => { if (els.length) { const c = s.channels[els[0].index]; location.hash = hrefWith('/devices', { kind: 'ap', channel: c.channel, band: c.b }); } } },
  });
  const bandTot = {};
  s.bands.forEach(r => { bandTot[r.band] = bandTot[r.band] || { ap: 0, wifi_client: 0 }; bandTot[r.band][r.kind] = r.n; });
  const bmax = Math.max(1, ...Object.values(bandTot).map(o => o.ap + o.wifi_client));
  document.getElementById('bands').innerHTML = BAND_LIST.filter(([b]) => bandTot[b]).map(([b, m]) => {
    const o = bandTot[b];
    return `<li data-href="${hrefWith('/devices', { band: b })}"><div><div class="name">${m.label} <span class="faint">· ${num(o.ap)} APs, ${num(o.wifi_client)} clients</span></div>
      <div class="track"><i style="width:${o.ap / bmax * 100}%;background:${KINDS.ap.color}"></i><i style="width:${o.wifi_client / bmax * 100}%;background:${KINDS.wifi_client.color}"></i></div></div>
      <div class="n">${num(o.ap + o.wifi_client)}</div></li>`;
  }).join('');

  const table = (id, head, rowsHtml, empty = 'No data') => {
    const el = document.getElementById(id);
    el.innerHTML = rowsHtml ? `<table><thead><tr>${head}</tr></thead><tbody>${rowsHtml}</tbody></table>` : `<div class="empty">${empty}</div>`;
    linkRows(el);
  };
  table('evtypes', '<th>Type</th><th class="num">Count</th>', s.events.map(e => `<tr class="link" data-href="#/events?type=${enc(e.type)}">
    <td class="ev ev-${esc(e.type)}">${esc(e.type.replace(/_/g, ' '))}</td><td class="num">${num(e.n)}</td></tr>`).join(''));
  // Networks: the 20 most recently seen, expandable to the 100 the API returns.
  const renderSsids = n => {
    const list = s.ssids.slice(0, n), total = s.ssid_total ?? s.ssids.length;
    table('ssids', `<th>SSID</th><th class="num">BSSIDs</th><th class="num">Clients</th><th class="num">Sessions</th><th>Channels</th><th>Security</th><th>Best signal</th><th class="num">Last seen</th>${isAdmin() ? '<th></th>' : ''}`,
      list.map(x => `<tr class="link" data-href="${hrefWith('/devices', { ssid: x.ssid })}"><td class="trunc">${esc(x.ssid)}${x.mine ? ' <span class="tag on">mine</span>' : ''}${x.ignored ? ' <span class="tag">ignored</span>' : ''}</td>
        <td class="num">${x.aps}</td><td class="num">${x.clients}</td><td class="num muted">${num(x.sessions)}</td><td class="muted">${esc(x.channels || '—')}</td>
        <td>${(x.enc || '').split(',').filter((v, i, a) => v && a.indexOf(v) === i).map(e => `<span class="tag ${e === 'OPN' ? 'bad' : ''}">${esc(e)}</span>`).join(' ') || '—'}</td>
        <td data-v="${x.rssi ?? ''}">${rssiBars(x.rssi)}</td><td class="num muted" data-v="${x.last_seen || ''}">${ago(x.last_seen)}</td>${isAdmin() ? `<td class="num">${x.mine ? '' : `<button class="btn small" data-ig="${esc(x.ssid)}">${x.ignored ? 'Unignore' : 'Ignore'}</button>`}</td>` : ''}</tr>`).join(''));
    document.querySelectorAll('#ssids [data-ig]').forEach(b => b.onclick = e => {
      e.stopPropagation();
      const x = s.ssids.find(v => v.ssid === b.dataset.ig);
      ignoreNetwork(x.ssid, x.ignored, () => { x.ignored = !x.ignored; renderSsids(n); });
    });
    document.getElementById('ssids-count').textContent = list.length < total ? `last seen ${list.length} of ${num(total)}` : `${num(total)} seen`;
    const more = document.getElementById('ssids-more');
    more.hidden = s.ssids.length <= 20;
    more.textContent = n > 20 ? 'Show 20' : `Show ${Math.min(100, s.ssids.length)}`;
    more.onclick = () => renderSsids(n > 20 ? 20 : 100);
  };
  renderSsids(20);
  table('topc', '<th>Client</th><th class="num">Networks</th><th class="num">Connected</th>', s.top_clients.map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}">
    <td>${kindBadge(x.kind)} <span class="mono" style="margin-left:6px">${esc(x.name || x.vendor || x.mac)}</span></td><td class="num muted">${x.peers}</td><td class="num">${dur(x.secs)}</td></tr>`).join(''));
  table('topap', '<th>Access point</th><th class="num">Clients</th><th class="num">Client-time</th>', s.top_aps.map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}">
    <td>${esc(x.ssid || '<hidden>')} <span class="mono faint">ch ${esc(x.channel ?? '?')}${x.band ? ' · ' + esc(x.band) + 'G' : ''}</span></td><td class="num">${x.clients}</td><td class="num muted">${dur(x.secs)}</td></tr>`).join(''));
  table('probes', '<th>SSID</th><th class="num">Clients</th><th class="num">Frames</th>', s.probes.map(x => `<tr class="link" data-href="${hrefWith('/devices', { probe: x.ssid })}">
    <td class="trunc">${esc(x.ssid)}${x.aps ? ' <span class="tag">nearby</span>' : ''}</td><td class="num">${x.clients}</td><td class="num muted">${num(x.frames)}</td></tr>`).join(''), 'No directed probes');
  bindLi(root);
}
function bindLi(root) {
  root.querySelectorAll('li[data-href]').forEach(li => { li.onclick = () => { location.hash = li.dataset.href; }; });
}

// ------------------------------------------------------------------ events
async function viewEvents(params) {
  const st = Object.fromEntries(params.entries());
  app.innerHTML = `
    <div class="page-head"><div><h1>Events</h1><div class="sub">Arrivals, departures, connections, roaming and deauthentication.</div></div></div>
    <div class="filters">
      <select id="etype"><option value="">All types</option></select>
      <select id="ekind"><option value="">All device types</option>${kindEntries().map(([k, m]) => `<option value="${k}" ${st.kind === k ? 'selected' : ''}>${m.label}</option>`).join('')}</select>
      ${st.mac ? `<span class="chip">Device: <b class="mono">${esc(st.mac)}</b><a href="${hrefWith('/events', { ...st, mac: '' })}">✕</a></span>` : ''}
    </div>
    <section class="panel"><div class="body flush" id="elist"></div><div class="pager"><span id="ecount"></span><button class="btn" id="more">Load more</button></div></section>`;
  const go = ch => { location.hash = hrefWith('/events', { ...st, ...ch }); };
  document.getElementById('ekind').onchange = e => go({ kind: e.target.value });
  let before = 0, all = [];
  async function load(append) {
    const qs = new URLSearchParams({ limit: 100 });
    ['type', 'mac', 'kind'].forEach(k => st[k] && qs.set(k, st[k]));
    if (append && before) qs.set('before', before);
    const r = await api('/api/events?' + qs);
    const sel = document.getElementById('etype');
    if (sel.options.length === 1) {
      sel.innerHTML += r.types.map(t => `<option value="${esc(t)}" ${st.type === t ? 'selected' : ''}>${esc(t.replace(/_/g, ' '))}</option>`).join('');
      sel.onchange = e => go({ type: e.target.value });
    }
    all = append ? all.concat(r.items) : r.items;
    if (r.items.length) before = r.items[r.items.length - 1].id;
    document.getElementById('elist').innerHTML = all.length ? `<ul class="events wide">${all.map(e => eventRow(e, true)).join('')}</ul>` : '<div class="empty">No events</div>';
    document.getElementById('ecount').textContent = `${all.length} shown`;
    document.getElementById('more').disabled = r.items.length < 100;
  }
  document.getElementById('more').onclick = () => load(true);
  await load(false);
}

function identPanel(d) {
  const idn = d.ident;
  if (!idn) return '';
  const f = idn.fields || {};
  const row = (label, key, fmt = v => esc(v), filter = null) => {
    const x = f[key];
    if (!x) return `<div><span${lblAttr(label)}>${label}</span><b class="faint">unknown</b></div>`;
    const val = filter ? `<a href="${hrefWith('/devices', { [filter]: filter === 'dev_type' ? x.value : d[filter] ?? x.value })}">${fmt(x.value)}</a>` : fmt(x.value);
    const agree = x.agree > 1 ? ` · ${x.agree} independent kinds of evidence agree` : '';
    const rivals = (x.also || []).map(o => `${o.value} (${o.conf}%, ${o.source})`).join('; ');
    return `<div><span${lblAttr(label)}>${label}</span><b>${val} <span class="conf conf-${x.level}" title="${x.conf}% confidence${esc(agree)}">${x.level}</span>${rivals ? ` <span class="tag warn" title="${esc('Other evidence points elsewhere, so the confidence is lowered. Also suggested: ' + rivals)}">contested</span>` : ''}</b></div>`;
  };
  const caps = idn.wifi_caps || {};
  const capText = [caps.ss ? `${caps.ss}×${caps.ss} MIMO` : null, caps.width ? `${caps.width} MHz` : null].filter(Boolean).join(' · ');
  const wps = idn.wps || {};
  const ev = idn.evidence || [];
  return `<section class="panel span-3"><header><h2>Identification</h2><span class="faint">passive fingerprinting · ${ev.length} clue${ev.length === 1 ? '' : 's'}</span></header>
    <div class="body"><div class="kv">
      ${row('Brand', 'brand', esc, 'brand')}
      ${row('Model', 'model')}
      ${row('Device type', 'type', typeLabel, 'dev_type')}
      ${row('Operating system', 'os', esc, 'os')}
      ${row('Wi-Fi', 'wifi', v => `<span title="${esc(wifiRowHelp(v + ' ' + capText))}">${esc(v)}</span>` + (capText ? ` <span class="faint">${capText}</span>` : ''), d.wifi_gen ? 'wifi_gen' : null)}
      ${row('Wi-Fi chipset', 'chipset')}
      <div><span${lblAttr('Estimated age')}>Estimated age</span><b>${idn.age_hint ? esc(idn.age_hint) : '<span class="faint">unknown</span>'}</b></div>
      ${d.fp_hash ? `<div><span${lblAttr('Probe fingerprint')}>Probe fingerprint</span><b><a class="mono" href="${hrefWith('/devices', { fp: d.fp_hash })}">${esc(d.fp_hash)}</a> <span class="faint">${d.fp_peers ? `shared with ${d.fp_peers} other MAC${d.fp_peers > 1 ? 's' : ''}` : 'unique'}</span></b></div>` : ''}
      ${wps.device_name || wps.manufacturer ? `<div><span${lblAttr('WPS info')}>WPS info</span><b>${esc([wps.manufacturer, wps.model, wps.model_number, wps.device_name].filter(Boolean).join(' · '))}</b></div>` : ''}
    </div>
    ${wifiFeaturesHtml(caps.capinfo)}
    ${idn.features && idn.features.length ? `<div style="margin-top:14px">${idn.features.map(x => tagWithHelp(x, featureHelp(x), 'margin:0 6px 6px 0')).join('')}</div>` : ''}
    ${ev.length ? `<details style="margin-top:12px"><summary class="muted" style="cursor:pointer">Evidence</summary>
      <table style="margin-top:8px"><thead><tr><th>Finding</th><th>Value</th><th>Source</th><th class="num">Confidence</th></tr></thead><tbody>
      ${ev.map(e => `<tr><td class="muted">${esc(e.field)}</td><td>${esc(e.field === 'type' ? typeLabel(e.value) : e.value)}</td><td class="muted" style="white-space:normal">${esc(e.source)}</td><td class="num muted">${e.conf}%</td></tr>`).join('')}
      </tbody></table></details>` : ''}
    </div></section>`;
}

// ------------------------------------------------------------------ modal
function closeModal() { document.querySelectorAll('.modal-bg').forEach(m => m.remove()); }
// body: HTML for the form fields; onSubmit(form) may throw to show an error.
function openModal(title, body, onSubmit, { submit = 'Save', danger = false, wide = false } = {}) {
  closeModal();
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  bg.innerHTML = `<form class="modal${wide ? ' wide' : ''}"><header><h2>${esc(title)}</h2><button type="button" class="x" aria-label="Close">✕</button></header>
    <div class="modal-body">${body}</div><div class="modal-err"></div>
    <footer><button type="button" class="btn ghost cancel">Cancel</button>${onSubmit ? `<button class="btn ${danger ? 'danger' : 'primary'}">${esc(submit)}</button>` : ''}</footer></form>`;
  document.body.appendChild(bg);
  const form = bg.querySelector('form');
  bg.querySelector('.x').onclick = bg.querySelector('.cancel').onclick = closeModal;
  bg.addEventListener('mousedown', e => { if (e.target === bg) closeModal(); });
  form.onsubmit = async e => {
    e.preventDefault();
    const btn = form.querySelector('footer .btn:last-child');
    btn.disabled = true;
    try { await onSubmit(form); closeModal(); } catch (err) { form.querySelector('.modal-err').textContent = err.message; }
    btn.disabled = false;
  };
  const first = form.querySelector('input,select,textarea');
  if (first) first.focus();
  return form;
}
// Ignore (or stop ignoring) a whole network from wherever it's listed. `onDone` runs after the change is saved.
function ignoreNetwork(ssid, ignored, onDone) {
  const done = r => {
    toast(ignored ? `No longer ignoring “${ssid}”` : r.skipped.length ? `“${ssid}” is one of your own networks, so it can't be ignored`
      : `Ignoring “${ssid}”${r.purged ? ` · deleted ${r.purged} stored devices` : ''}`, !ignored && r.skipped.length > 0);
    if (onDone) onDone(r);
  };
  if (ignored) {
    if (!confirm(`Stop ignoring “${ssid}”? It will be recorded again from now on.`)) return;
    send('POST', '/api/settings/ignore/networks', { ssids: [ssid], remove: true }).then(done).catch(e => toast(e.message, true));
    return;
  }
  openModal(`Ignore “${ssid}”`, `<p class="muted" style="margin-top:0">Its access points are dropped before anything is stored: they won't appear anywhere or trigger alerts.
      Change this later under Settings → Ignore list.</p>
    <label class="check"><input type="checkbox" name="clients" checked> Also ignore the devices connected to it</label>
    <label class="check"><input type="checkbox" name="purge"> Also delete the data already stored for it</label>`,
  async f => {
    const r = await send('POST', '/api/settings/ignore/networks', { ssids: [ssid], clients: fv(f, 'clients'), purge: fv(f, 'purge') });
    done(r);
  }, { submit: 'Ignore network', danger: true });
}
const fv = (form, name) => { const el = form.elements[name]; return el ? (el.type === 'checkbox' ? el.checked : el.value.trim()) : undefined; };

window.addEventListener('DOMContentLoaded', async () => {
  themeToJs();
  const appearance = loadAppearance().then(themeToJs);
  try {
    const st = await (await fetch('/api/auth/state')).json();
    if (!st.user) { location.href = '/login'; return; }
    ME = st.user;
    const u = document.getElementById('user');
    if (u) u.innerHTML = st.disabled ? '<span class="faint">auth disabled</span>'
      : `<span>${esc(ME.username)}</span><span class="faint">${esc(ME.role)}</span><a href="#" id="logout">Sign out</a>`;
    const lo = document.getElementById('logout');
    if (lo) lo.onclick = async e => { e.preventDefault(); await send('POST', '/api/auth/logout'); location.href = '/login'; };
    document.body.classList.toggle('viewer', !isAdmin());
  } catch { /* offline: route() will show the error */ }
  const side = document.querySelector('.side'), menu = document.getElementById('menu-btn');
  const setMenu = open => { side.classList.toggle('open', open); menu.setAttribute('aria-expanded', open); };
  if (menu) {
    menu.onclick = () => setMenu(!side.classList.contains('open'));
    window.addEventListener('hashchange', () => setMenu(false));
    document.addEventListener('keydown', e => { if (e.key === 'Escape') setMenu(false); });
  }
  await Promise.all([appearance, loadModules()]);
  route();
  pollStatus();
});
