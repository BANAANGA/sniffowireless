'use strict';

const KINDS = {
  ap: { label: 'Access points', short: 'AP', color: '#4cc2ff' },
  wifi_client: { label: 'Wi-Fi clients', short: 'Wi-Fi client', color: '#3ecf8e' },
  ble: { label: 'BLE devices', short: 'BLE', color: '#f5b84a' },
  bt_classic: { label: 'Bluetooth classic', short: 'BT classic', color: '#ef6f6c' },
};
const TEXT = '#e6e7e9', MUTED = '#8a8f98', FAINT = '#5b6068', GRID = '#1f2227';
const TZ = new Date().getTimezoneOffset();
const app = document.getElementById('app');

if (window.Chart) {
  Chart.defaults.color = MUTED;
  Chart.defaults.borderColor = GRID;
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.size = 11;
  Chart.defaults.plugins.legend.display = false;
  Chart.defaults.plugins.tooltip.backgroundColor = '#16181c';
  Chart.defaults.plugins.tooltip.borderColor = '#2a2e35';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.titleColor = TEXT;
  Chart.defaults.plugins.tooltip.bodyColor = MUTED;
  Chart.defaults.animation = false;
}

// ------------------------------------------------------------------ helpers
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = encodeURIComponent;
const isMac = s => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s || '');

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
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
  const t = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (!withDate) return t;
  return `${d.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${t}`;
}
function axisTime(ts, span) {
  const d = new Date(ts * 1000);
  if (span <= 86400 * 1.1) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString([], { weekday: 'short', day: 'numeric' }) + (span < 86400 * 4 ? ' ' + d.getHours() + 'h' : '');
}
const num = n => (n ?? 0).toLocaleString();
const BANDS = { '2.4': { label: '2.4 GHz', color: '#4cc2ff' }, '5': { label: '5 GHz', color: '#8fd8ff' }, '6': { label: '6 GHz', color: '#d2efff' } };
// Fixed order: JS would otherwise list the integer-like keys '5' and '6' before '2.4'.
const BAND_LIST = ['2.4', '5', '6'].map(b => [b, BANDS[b]]);
const DEV_TYPES = {
  phone: 'Phone', tablet: 'Tablet', laptop: 'Laptop', desktop: 'Desktop PC', computer: 'Computer', watch: 'Smartwatch',
  wearable: 'Wearable', headphones: 'Headphones', speaker: 'Speaker', tv: 'TV', streaming: 'Streaming device',
  console: 'Game console', controller: 'Game controller', printer: 'Printer', camera: 'Camera', tag: 'Tracker tag',
  sensor: 'Sensor', iot: 'IoT device', light: 'Smart light', input: 'Keyboard / mouse', car: 'Car',
  router: 'Router / access point', hotspot: 'Mobile hotspot', smart_home: 'Smart home', beacon: 'Beacon',
  sbc: 'Single-board computer', media: 'Media device', network: 'Network device',
};
const genLabel = g => g == null ? 'Unknown' : g === 66 ? 'Wi-Fi 6E' : g === 3 ? 'Legacy a/b/g' : `Wi-Fi ${g}`;
const eraLabel = y => y == null ? 'Unknown' : y <= 2003 ? 'before ~2010' : `${y} or newer`;
const typeLabel = t => t ? (DEV_TYPES[t] || t) : 'Unknown';
const FILTER_FMT = { wifi_gen: v => genLabel(+v), dev_type: typeLabel, era: v => eraLabel(+v) };
function identCell(x) {
  const id = x.ident || {};
  const label = id.label || (x.vendor ? esc(x.vendor) : '');
  const gen = x.wifi_gen ? ` <span class="tag">${genLabel(x.wifi_gen).replace('Wi-Fi ', 'Wi-Fi\u00a0')}</span>` : '';
  return (label ? esc(label) : '<span class="faint">—</span>') + gen;
}
function chText(ch, band) {
  if (ch == null) return '<span class="faint">—</span>';
  return band ? `${ch}<span class="faint"> · ${band}G</span>` : `${ch}`;
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
let timers = [], charts = [], routeId = 0;
function cleanup() {
  timers.forEach(clearInterval); timers = [];
  charts.forEach(c => c.destroy()); charts = [];
}
function every(ms, fn) { timers.push(setInterval(fn, ms)); }
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
async function route() {
  cleanup();
  const id = ++routeId;
  const { path, params } = parseHash();
  document.querySelectorAll('[data-nav]').forEach(a => {
    const n = a.dataset.nav;
    a.classList.toggle('active', n === '/' ? path === '/' : path.startsWith(n));
  });
  try {
    if (path === '/') await viewOverview();
    else if (path === '/devices') await viewDevices(params);
    else if (path.startsWith('/device/')) await viewDevice(decodeURIComponent(path.slice(8)), params);
    else if (path === '/stats') await viewStats(params);
    else if (path === '/events') await viewEvents(params);
    else app.innerHTML = '<div class="empty">Not found</div>';
  } catch (e) {
    if (id === routeId) app.innerHTML = `<div class="empty">Failed to load: ${esc(e.message)}</div>`;
  }
  window.scrollTo(0, 0);
}
window.addEventListener('hashchange', route);

async function pollStatus() {
  const el = document.getElementById('live');
  try {
    const s = await api('/api/status');
    const errs = s.sensors.filter(x => x.state === 'error');
    const total = s.sensors.reduce((a, x) => a + (x.pps || 0), 0);
    el.className = 'live ' + (errs.length ? 'err' : (s.sensors.length || s.demo ? 'ok' : ''));
    el.textContent = s.demo ? 'demo mode' : errs.length ? `${errs.length} sensor error${errs.length > 1 ? 's' : ''}`
      : s.sensors.length ? `${s.sensors.length} sensor${s.sensors.length > 1 ? 's' : ''} · ${total.toFixed(0)} pkt/s` : 'no sensors';
  } catch { el.className = 'live err'; el.textContent = 'offline'; }
}
setInterval(pollStatus, 10000);

// ------------------------------------------------------------------ overview
async function viewOverview() {
  app.innerHTML = `
    <div class="page-head"><div><h1>Overview</h1><div class="sub">Devices seen within the last 5 minutes are counted as active.</div></div></div>
    <div class="grid cols-4" id="cards"></div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel span-2">
        <header><h2>Active devices over time</h2>${seg('range', [[6, '6h'], [24, '24h'], [168, '7d'], [720, '30d']], 24)}</header>
        <div class="body"><div class="legend" id="tl-legend" style="margin-bottom:10px"></div><div class="chart-box tall"><canvas id="tl"></canvas></div></div>
      </section>
      <section class="panel"><header><h2>Sensors</h2><span class="muted mono" id="dbsize"></span></header><div class="body flush" id="sensors"></div></section>
      <section class="panel span-2">
        <header><h2>Connected right now</h2><a class="muted" href="#/devices?connected=1">View all →</a></header>
        <div class="body flush table-wrap" id="connected"></div>
      </section>
      <section class="panel"><header><h2>Recent events</h2><a class="muted" href="#/events">All →</a></header><div class="body flush" id="events"></div></section>
    </div>`;
  let hours = 24;
  onSeg(app, 'range', v => { hours = +v; loadTimeline(); });

  const legend = Object.entries(KINDS).map(([k, m]) => `<span><span class="swatch" style="background:${m.color}"></span>${m.label}</span>`).join('')
    + `<span><span class="swatch" style="background:${TEXT}"></span>Connected clients</span>`;
  document.getElementById('tl-legend').innerHTML = legend;

  async function loadSummary() {
    const s = await api('/api/summary');
    document.getElementById('cards').innerHTML = Object.entries(KINDS).map(([k, m]) => {
      const v = s.kinds[k] || {};
      const conn = k === 'wifi_client' || k === 'bt_classic' || k === 'ble'
        ? `<a href="#/devices?kind=${k}&connected=1">${num(v.connected || 0)} connected</a>` : '';
      return `<div class="card link" data-href="#/devices?kind=${k}&active=300">
        <div class="label"><span class="swatch" style="background:${m.color}"></span>${m.label}</div>
        <div class="value">${num(v.active)}<small>of ${num(v.total)}</small></div>
        <div class="meta"><span>+${num(v.new_24h)} new 24h</span>${conn ? `<span>${conn}</span>` : ''}</div></div>`;
    }).join('');
    document.querySelectorAll('#cards .card').forEach(c => c.onclick = e => { if (!e.target.closest('a')) location.hash = c.dataset.href; });
    const ev = s.events;
    document.getElementById('events').innerHTML = ev.length ? `<ul class="events">${ev.slice(0, 14).map(e => eventRow(e)).join('')}</ul>` : '<div class="empty">No events yet</div>';
  }
  async function loadConnected() {
    const d = await api('/api/devices?connected=1&limit=12&sort=last_seen');
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
  async function loadSensors() {
    const s = await api('/api/status');
    document.getElementById('dbsize').textContent = bytes(s.store.db_bytes);
    const list = s.sensors;
    document.getElementById('sensors').innerHTML = (list.length ? list.map(x => `<div class="sensor">
      <div><div><span class="state-dot ${x.state === 'error' ? '' : 'on'}"></span><b>${esc(x.name)}</b>
      ${x.mon && x.mon !== x.iface ? `<span class="faint mono"> → ${esc(x.mon)}</span>` : ''}</div>
      ${x.error ? `<div class="err">${esc(x.error)}</div>` : `<div class="muted">${esc(x.state)}${x.channel ? ' · ch ' + esc(x.channel) : ''}${x.bands ? ' · ' + x.bands.map(b => b + 'G').join('/') : ''}${x.adverts != null ? ' · ' + num(x.adverts) + ' adverts' : ''}</div>`}</div>
      <div class="muted mono" style="text-align:right">${(x.pps || 0).toFixed(1)} pkt/s<br>${num(x.packets)} total</div></div>`).join('')
      : `<div class="empty">${s.demo ? 'Demo mode — synthetic data' : 'No sensors configured'}</div>`)
      + `<div class="sensor muted"><span>Queue ${num(s.store.queue)} · dropped ${num(s.store.dropped)}</span><span>${num(s.store.open_presence)} present</span></div>`;
  }
  async function loadTimeline() {
    const t = await api(`/api/timeline?hours=${hours}`);
    const span = hours * 3600;
    const ds = Object.entries(KINDS).map(([k, m]) => ({
      label: m.label, data: t.t.map((x, i) => ({ x, y: (t.series[k] || [])[i] || 0 })),
      borderColor: m.color, fill: false, borderWidth: 1.5, pointRadius: 0, tension: .3,
    }));
    ds.push({ label: 'Connected clients', data: t.t.map((x, i) => ({ x, y: t.connected[i] })), borderColor: TEXT,
      borderDash: [4, 4], borderWidth: 1.2, pointRadius: 0, fill: false, tension: .3 });
    chart(document.getElementById('tl'), {
      type: 'line', data: { datasets: ds },
      options: {
        maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        scales: { x: { ...timeScale(span), min: t.t[0], max: t.t[t.t.length - 1] }, y: yScale() },
        plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } },
      },
    });
  }
  await Promise.all([loadSummary(), loadSensors(), loadTimeline(), loadConnected(), pollStatus()]);
  every(10000, () => { loadSummary(); loadSensors(); loadConnected(); });
  every(60000, loadTimeline);
}

function eventRow(e, full = false) {
  const who = e.kind === 'ap' ? (e.ssid || e.mac) : (e.name || e.vendor || e.mac);
  let detail = '';
  if (e.peer) detail = `→ ${isMac(e.peer) ? `<a href="#/device/${enc(e.peer)}">${esc(e.peer_ssid || e.peer)}</a>` : esc(e.peer)}`;
  if (e.detail && e.type !== 'new_device') detail += ` <span class="faint">${esc(e.detail)}</span>`;
  return `<li><span class="t" title="${esc(dt(e.ts))}">${full ? dt(e.ts) : ago(e.ts)}</span><span class="ev ev-${esc(e.type)}">${esc(e.type.replace(/_/g, ' '))}</span>
    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.kind ? `<span class="swatch" style="background:${(KINDS[e.kind] || {}).color};margin-right:6px"></span>` : ''}<a href="#/device/${enc(e.mac)}">${esc(who)}</a> ${detail}</span></li>`;
}
function linkRows(root) {
  root.querySelectorAll('tr[data-href]').forEach(tr => tr.addEventListener('click', e => {
    if (e.target.closest('a')) return;
    location.hash = tr.dataset.href;
  }));
}

// ------------------------------------------------------------------ devices
const FILTER_LABELS = { vendor: 'Vendor', brand: 'Brand', dev_type: 'Device type', os: 'OS', wifi_gen: 'Wi-Fi', era: 'Age', fp: 'Fingerprint',
  ssid: 'SSID', probe: 'Probed', bssid: 'Connected to', channel: 'Channel', connected: 'Connected now' };

async function viewDevices(params) {
  const st = Object.fromEntries(params.entries());
  st.sort = st.sort || 'last_seen';
  st.order = st.order || 'desc';
  const offset = +(st.offset || 0), limit = 100;
  const chips = Object.keys(FILTER_LABELS).filter(k => st[k]).map(k => {
    const rest = { ...st }; delete rest[k]; delete rest.offset;
    return `<span class="chip">${FILTER_LABELS[k]}${k === 'connected' ? '' : ': <b>' + esc(FILTER_FMT[k] ? FILTER_FMT[k](st[k]) : st[k]) + '</b>'}<a href="${hrefWith('/devices', rest)}">✕</a></span>`;
  }).join('');
  app.innerHTML = `
    <div class="page-head"><div><h1>Devices</h1><div class="sub" id="count">&nbsp;</div></div>
      <a class="btn muted" href="/api/export/devices.csv">Export CSV</a></div>
    <div class="filters">
      <input type="search" id="q" placeholder="Search MAC, name, SSID, brand, model…" value="${esc(st.q || '')}">
      <select id="kind"><option value="">All types</option>${Object.entries(KINDS).map(([k, m]) => `<option value="${k}" ${st.kind === k ? 'selected' : ''}>${m.label}</option>`).join('')}</select>
      <select id="devtype"><option value="">All device types</option>${Object.entries(DEV_TYPES).map(([k, l]) => `<option value="${k}" ${st.dev_type === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <select id="active">${[['', 'Any time'], ['300', 'Active (5 min)'], ['3600', 'Last hour'], ['86400', 'Last 24 h'], ['604800', 'Last 7 days']].map(([v, l]) => `<option value="${v}" ${String(st.active || '') === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <select id="band"><option value="">All bands</option>${BAND_LIST.map(([b, m]) => `<option value="${b}" ${st.band === b ? 'selected' : ''}>${m.label}</option>`).join('')}</select>
      <label class="check"><input type="checkbox" id="hiderand" ${st.randomized === '0' ? 'checked' : ''}>Hide randomized MACs</label>
      ${chips}
    </div>
    <section class="panel"><div class="table-wrap" id="tbl"></div><div class="pager" id="pager"></div></section>`;

  const go = changes => {
    const next = { ...st, ...changes };
    if (!('offset' in changes)) delete next.offset;
    location.hash = hrefWith('/devices', next);
  };
  let qTimer;
  document.getElementById('q').addEventListener('input', e => { clearTimeout(qTimer); qTimer = setTimeout(() => go({ q: e.target.value }), 350); });
  document.getElementById('kind').addEventListener('change', e => go({ kind: e.target.value }));
  document.getElementById('active').addEventListener('change', e => go({ active: e.target.value }));
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
    const qs = new URLSearchParams({ ...st, limit, offset });
    const d = await api('/api/devices?' + qs);
    document.getElementById('count').textContent = `${num(d.total)} device${d.total === 1 ? '' : 's'}`;
    const head = cols.map(([k, l, cls]) => {
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
        <td class="trunc">${label ? esc(label) : '<span class="faint">—</span>'}${x.kind === 'ap' && x.enc ? ` <span class="tag ${x.enc.includes('OPN') ? 'bad' : ''}">${esc(x.enc.replace(/\/PSK|\/SAE/g, ''))}</span>` : ''}</td>
        <td class="trunc muted" style="max-width:300px">${identCell(x)}</td>
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
  const m = KINDS[d.kind] || { label: d.kind, color: FAINT };
  const isAp = d.kind === 'ap', isBt = d.kind === 'ble' || d.kind === 'bt_classic';
  const idn = d.ident || {};
  const title = devLabel(d) || idn.label || d.vendor || d.mac;
  const ex = d.extra || {};
  const facts = [
    ['Address', `<span class="mono">${esc(d.mac)}</span>`],
    ['Type', kindBadge(d.kind)],
    ['Vendor', esc(d.vendor || (d.randomized ? 'Randomized address' : 'Unknown'))],
    isAp ? ['SSID', esc(d.ssid || (d.ssid === '' || ex.hidden ? '<hidden>' : '—'))] : null,
    isAp ? ['Security', esc(d.enc || '—')] : null,
    !isBt ? ['Channel', d.channel ? `${d.channel}${d.band ? ` · ${BANDS[d.band] ? BANDS[d.band].label : d.band}` : ''}${d.freq ? ` <span class="faint">(${d.freq} MHz)</span>` : ''}` : '—'] : null,
    isBt && d.name ? ['Name', esc(d.name)] : null,
    ex.addr_type ? ['Address type', esc(ex.addr_type)] : null,
    ex.company ? ['Manufacturer data', esc(ex.company)] : null,
    ex.appearance ? ['Appearance', esc(ex.appearance)] : null,
    ex.class ? ['Device class', esc(ex.class)] : null,
    ex.tx_power != null ? ['TX power', `${ex.tx_power} dBm`] : null,
    ex.uuids && ex.uuids.length ? ['Services', `<span class="mono">${esc(ex.uuids.join(', '))}</span>`] : null,
    ['Signal (last / best)', `${rssiBars(d.last_rssi)} <span class="faint">/ ${d.best_rssi ?? '—'}</span>`],
    ['Frames', num(d.packets)],
    ['First seen', `${dt(d.first_seen)} <span class="faint">${ago(d.first_seen)}</span>`],
    ['Last seen', `${dt(d.last_seen)} <span class="faint">${ago(d.last_seen)}</span>`],
    ['Time present', `${dur(d.presence.total)} <span class="faint">in ${num(d.presence.n)} visits</span>`],
    ['Average visit', dur(d.presence.avg)],
    ['Longest visit', dur(d.presence.longest)],
    !isAp ? ['Time connected', `${dur(d.connections.total)} <span class="faint">in ${num(d.connections.n)} sessions</span>`] : null,
    d.connected_now ? ['Connected now', `<span class="tag on">since ${dt(d.connected_now.start_ts, false)}</span> ${isMac(d.connected_now.peer) ? devLink(d.connected_now.peer, d.connected_now.peer_ssid || d.connected_now.peer) : esc(d.connected_now.peer)}`] : null,
  ].filter(Boolean);

  const range = params.get('range') || '24';
  app.innerHTML = `
    <div class="page-head"><div>
      <div class="crumbs"><a href="#/devices">Devices</a> / <a href="#/devices?kind=${d.kind}">${m.label}</a></div>
      <h1>${esc(title)}</h1><div class="sub mono">${esc(d.mac)}${d.randomized ? ' · randomized address' : ''}</div></div>
      ${seg('range', [[1, '1h'], [6, '6h'], [24, '24h'], [168, '7d'], [720, '30d']], range)}</div>
    <div class="grid cols-3">
      <section class="panel span-3"><div class="body"><div class="kv">${facts.map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join('')}</div></div></section>
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
    let html = '<div class="heat"><span></span>' + Array.from({ length: 24 }, (_, i) => `<span class="h">${i % 6 === 0 ? i : ''}</span>`).join('');
    h.grid.forEach((row, di) => {
      html += `<span class="d">${days[di]}</span>` + row.map((v, hi) =>
        `<span class="cell" title="${days[di]} ${hi}:00 — ${v} min" style="${v ? `background:${m.color};opacity:${(0.15 + 0.85 * v / max).toFixed(2)}` : ''}"></span>`).join('');
    });
    document.getElementById('heat').innerHTML = html + '</div>';
  });

  let hours = +range, stype = isAp ? 'presence' : 'assoc', sessCache = null;
  onSeg(app, 'range', v => { hours = +v; history.replaceState(null, '', hrefWith(`/device/${enc(mac)}`, { range: v })); loadRange(); });
  onSeg(app, 'stype', v => { stype = v; renderSessions(); });

  async function loadRssi() {
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
async function viewStats(params) {
  const days = params.get('days') || '7';
  app.innerHTML = `
    <div class="page-head"><div><h1>Statistics</h1><div class="sub">Click any bar, row or slice to drill down into the matching devices.</div></div>
      ${seg('days', [[1, '24h'], [7, '7 days'], [30, '30 days']], days)}</div>
    <div class="grid cols-3" id="stats"><div class="empty span-all">Loading…</div></div>`;
  onSeg(app, 'days', v => { location.hash = hrefWith('/stats', { days: v }); });
  const s = await api(`/api/stats?days=${days}&tz=${TZ}`);
  const root = document.getElementById('stats');
  root.innerHTML = `
    <section class="panel span-2"><header><h2>Activity by hour of day</h2><span class="faint">average distinct devices per hour</span></header><div class="body"><div class="chart-box"><canvas id="hourly"></canvas></div></div></section>
    <section class="panel"><header><h2>MAC address privacy</h2></header><div class="body" id="rand"></div></section>
    <section class="panel span-2"><header><h2>New devices per day</h2></header><div class="body"><div class="chart-box short"><canvas id="newday"></canvas></div></div></section>
    <section class="panel"><header><h2>Session durations</h2>${seg('dtype', [['assoc', 'Connections'], ['presence', 'Visits']], 'assoc')}</header><div class="body"><div class="chart-box short"><canvas id="durs"></canvas></div></div></section>
    <section class="panel"><header><h2>Device types</h2><span class="faint">identified</span></header><div class="body"><ul class="bars-list" id="st-type"></ul></div></section>
    <section class="panel"><header><h2>Brands</h2><select id="vkind" style="padding:2px 6px"><option value="">All</option>${Object.entries(KINDS).map(([k, m]) => `<option value="${k}">${m.short}</option>`).join('')}</select></header><div class="body"><ul class="bars-list" id="st-brand"></ul></div></section>
    <section class="panel"><header><h2>Wi-Fi generation</h2><span class="faint">newest standard supported</span></header><div class="body"><ul class="bars-list" id="st-gen"></ul></div></section>
    <section class="panel"><header><h2>Estimated age</h2><span class="faint">earliest possible year</span></header><div class="body"><ul class="bars-list" id="st-era"></ul></div></section>
    <section class="panel"><header><h2>Operating systems</h2></header><div class="body"><ul class="bars-list" id="st-os"></ul></div></section>
    <section class="panel"><header><h2>Shared fingerprints</h2><span class="faint">same probe layout = same model / OS</span></header><div class="body flush table-wrap" id="st-fp"></div></section>
    <section class="panel"><header><h2>AP channels</h2><span class="legend" id="bandlegend"></span></header><div class="body"><div class="chart-box"><canvas id="chans"></canvas></div><ul class="bars-list" id="bands" style="margin-top:12px"></ul></div></section>
    <section class="panel"><header><h2>Events</h2></header><div class="body flush table-wrap" id="evtypes"></div></section>
    <section class="panel span-3"><header><h2>Networks (SSIDs)</h2><span class="faint">${s.ssids.length} seen</span></header><div class="body flush table-wrap" id="ssids"></div></section>
    <section class="panel"><header><h2>Most connected clients</h2></header><div class="body flush table-wrap" id="topc"></div></section>
    <section class="panel"><header><h2>Busiest access points</h2></header><div class="body flush table-wrap" id="topap"></div></section>
    <section class="panel"><header><h2>Probed SSIDs</h2><span class="faint">networks clients are looking for</span></header><div class="body flush table-wrap" id="probes"></div></section>`;

  // hourly
  const hours = Array.from({ length: 24 }, (_, i) => i);
  chart(document.getElementById('hourly'), {
    type: 'bar',
    data: { labels: hours.map(h => `${h}:00`), datasets: Object.entries(KINDS).map(([k, m]) => ({
      label: m.label, backgroundColor: m.color + 'cc', borderRadius: 2, maxBarThickness: 40, stack: 'a',
      data: hours.map(h => +((s.hourly.rows.find(r => r.h === h && r.kind === k) || { n: 0 }).n / s.hourly.days).toFixed(1)),
    })) },
    options: { maintainAspectRatio: false, scales: { x: { stacked: true, grid: { display: false }, ticks: { color: FAINT } }, y: yScale({ stacked: true }) },
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 8, boxHeight: 8, color: MUTED } } },
      onClick: (e, els) => { if (els.length) location.hash = hrefWith('/devices', { kind: Object.keys(KINDS)[els[0].datasetIndex] }); } },
  });

  // new per day
  const daysList = [...new Set(s.new_per_day.map(r => r.day))].sort((a, b) => a - b);
  chart(document.getElementById('newday'), {
    type: 'bar',
    data: { labels: daysList.map(d => new Date(d * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' })),
      datasets: Object.entries(KINDS).map(([k, m]) => ({ label: m.label, backgroundColor: m.color + 'cc', borderRadius: 2, maxBarThickness: 40, stack: 'a',
        data: daysList.map(d => (s.new_per_day.find(r => r.day === d && r.kind === k) || { n: 0 }).n) })) },
    options: { maintainAspectRatio: false, scales: { x: { stacked: true, grid: { display: false }, ticks: { color: FAINT } }, y: yScale({ stacked: true }) } },
  });

  // durations
  const DB = ['<1m', '1–5m', '5–30m', '30m–2h', '2–8h', '>8h'];
  const drawDur = t => chart(document.getElementById('durs'), {
    type: 'bar', data: { labels: DB, datasets: [{ data: DB.map((_, b) => (s.durations.find(r => r.type === t && r.b === b) || { n: 0 }).n), backgroundColor: TEXT + 'bb', borderRadius: 2, maxBarThickness: 40 }] },
    options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { color: FAINT } }, y: yScale() } },
  });
  drawDur('assoc');
  onSeg(root, 'dtype', drawDur);

  // randomized
  const rnd = Object.entries(KINDS).filter(([k]) => k !== 'ap').map(([k, m]) => {
    const r = s.randomized.filter(x => x.kind === k);
    const tot = r.reduce((a, x) => a + x.n, 0), rn = (r.find(x => x.randomized) || { n: 0 }).n;
    return { k, m, tot, rn };
  });
  document.getElementById('rand').innerHTML = `<ul class="bars-list">${rnd.map(({ k, m, tot, rn }) => `
    <li data-href="${hrefWith('/devices', { kind: k, randomized: 1 })}"><div><div class="name">${m.label} <span class="faint">· ${tot ? Math.round(rn / tot * 100) : 0}% randomized</span></div>
      <div class="track"><i style="width:${tot ? rn / tot * 100 : 0}%;background:${m.color}"></i><i style="width:${tot ? (tot - rn) / tot * 100 : 0}%;background:${m.color}44"></i></div></div>
      <div class="n">${num(tot)}</div></li>`).join('')}</ul>
    <p class="faint" style="margin:12px 0 0">Randomized (locally administered / private) addresses rotate, so one physical device can appear as many entries. Connections usually keep a stable per-network address.</p>`;

  // identification breakdowns
  const barList = (id, rows, label, filterKey, kind = '', limit = 12, order = null) => {
    const agg = {};
    rows.filter(r => !kind || r.kind === kind).forEach(r => {
      const k = r.v == null ? '' : String(r.v);
      agg[k] = agg[k] || { n: 0, kinds: {} };
      agg[k].n += r.n; agg[k].kinds[r.kind] = (agg[k].kinds[r.kind] || 0) + r.n;
    });
    let list = Object.entries(agg);
    list = order ? list.sort(order) : list.sort((a, b) => b[1].n - a[1].n);
    list = list.slice(0, limit);
    const max = Math.max(1, ...list.map(([, o]) => o.n));
    document.getElementById(id).innerHTML = list.map(([v, o]) => `<li data-href="${hrefWith('/devices', { [filterKey]: v === '' ? (filterKey === 'wifi_gen' || filterKey === 'era' ? '0' : 'Unknown') : v, kind })}">
      <div><div class="name">${v === '' ? '<span class="faint">Unknown</span>' : esc(label(v))}</div><div class="track">${Object.entries(o.kinds).map(([k, n]) => `<i style="width:${n / max * 100}%;background:${KINDS[k].color}"></i>`).join('')}</div></div>
      <div class="n">${num(o.n)}</div></li>`).join('') || '<div class="empty">No data</div>';
    bindLi(root);
  };
  const numDesc = (a, b) => (b[0] === '' ? -1 : +b[0]) - (a[0] === '' ? -1 : +a[0]);
  barList('st-type', s.dev_type, typeLabel, 'dev_type');
  barList('st-brand', s.brand, v => v, 'brand', '', 14);
  const genRank = v => v === '' ? -1 : +v === 66 ? 6.5 : +v;  // 66 = Wi-Fi 6E sits between 6 and 7
  barList('st-gen', s.wifi_gen.filter(r => r.kind === 'ap' || r.kind === 'wifi_client'), v => genLabel(+v), 'wifi_gen', '', 10,
    (a, b) => genRank(b[0]) - genRank(a[0]));
  barList('st-era', s.era, v => eraLabel(+v), 'era', '', 10, numDesc);
  barList('st-os', s.os, v => v, 'os');
  document.getElementById('vkind').addEventListener('change', e => barList('st-brand', s.brand, v => v, 'brand', e.target.value, 14));
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
  table('ssids', '<th>SSID</th><th class="num">BSSIDs</th><th class="num">Clients</th><th class="num">Sessions</th><th>Channels</th><th>Security</th><th>Best signal</th>',
    s.ssids.map(x => `<tr class="link" data-href="${hrefWith('/devices', { ssid: x.ssid })}"><td class="trunc">${esc(x.ssid)}</td>
      <td class="num">${x.aps}</td><td class="num">${x.clients}</td><td class="num muted">${num(x.sessions)}</td><td class="muted">${esc(x.channels || '—')}</td>
      <td>${(x.enc || '').split(',').filter((v, i, a) => v && a.indexOf(v) === i).map(e => `<span class="tag ${e === 'OPN' ? 'bad' : ''}">${esc(e)}</span>`).join(' ') || '—'}</td>
      <td>${rssiBars(x.rssi)}</td></tr>`).join(''));
  table('topc', '<th>Client</th><th class="num">Networks</th><th class="num">Connected</th>', s.top_clients.map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}">
    <td>${kindBadge(x.kind)} <span class="mono" style="margin-left:6px">${esc(x.name || x.vendor || x.mac)}</span></td><td class="num muted">${x.peers}</td><td class="num">${dur(x.secs)}</td></tr>`).join(''));
  table('topap', '<th>Access point</th><th class="num">Clients</th><th class="num">Client-time</th>', s.top_aps.map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}">
    <td>${esc(x.ssid || '<hidden>')} <span class="mono faint">ch ${x.channel ?? '?'}${x.band ? ' · ' + x.band + 'G' : ''}</span></td><td class="num">${x.clients}</td><td class="num muted">${dur(x.secs)}</td></tr>`).join(''));
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
      <select id="ekind"><option value="">All device types</option>${Object.entries(KINDS).map(([k, m]) => `<option value="${k}" ${st.kind === k ? 'selected' : ''}>${m.label}</option>`).join('')}</select>
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
    if (!x) return `<div><span>${label}</span><b class="faint">unknown</b></div>`;
    const val = filter ? `<a href="${hrefWith('/devices', { [filter]: filter === 'dev_type' ? x.value : d[filter] ?? x.value })}">${fmt(x.value)}</a>` : fmt(x.value);
    return `<div><span>${label}</span><b>${val} <span class="conf conf-${x.level}" title="${x.conf}% confidence">${x.level}</span></b></div>`;
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
      ${row('Wi-Fi', 'wifi', v => esc(v) + (capText ? ` <span class="faint">${capText}</span>` : ''), d.wifi_gen ? 'wifi_gen' : null)}
      ${row('Wi-Fi chipset', 'chipset')}
      <div><span>Estimated age</span><b>${idn.age_hint ? esc(idn.age_hint) : '<span class="faint">unknown</span>'}</b></div>
      ${d.fp_hash ? `<div><span>Probe fingerprint</span><b><a class="mono" href="${hrefWith('/devices', { fp: d.fp_hash })}">${esc(d.fp_hash)}</a> <span class="faint">${d.fp_peers ? `shared with ${d.fp_peers} other MAC${d.fp_peers > 1 ? 's' : ''}` : 'unique'}</span></b></div>` : ''}
      ${wps.device_name || wps.manufacturer ? `<div><span>WPS info</span><b>${esc([wps.manufacturer, wps.model, wps.model_number, wps.device_name].filter(Boolean).join(' · '))}</b></div>` : ''}
    </div>
    ${idn.features && idn.features.length ? `<div style="margin-top:14px">${idn.features.map(x => `<span class="tag" style="margin:0 6px 6px 0">${esc(x)}</span>`).join('')}</div>` : ''}
    ${ev.length ? `<details style="margin-top:12px"><summary class="muted" style="cursor:pointer">Evidence</summary>
      <table style="margin-top:8px"><thead><tr><th>Finding</th><th>Value</th><th>Source</th><th class="num">Confidence</th></tr></thead><tbody>
      ${ev.map(e => `<tr><td class="muted">${esc(e.field)}</td><td>${esc(e.field === 'type' ? typeLabel(e.value) : e.value)}</td><td class="muted" style="white-space:normal">${esc(e.source)}</td><td class="num muted">${e.conf}%</td></tr>`).join('')}
      </tbody></table></details>` : ''}
    </div></section>`;
}

route();
pollStatus();
