'use strict';
/* Sensors page: every sensor (this server and the remote ones), each interface's status and hardware, live frame rates, and a live
   graph to compare the signal strength of chosen devices as each sensor hears them. Uses helpers from app.js/views.js/adapters.js. */

const SIG_KINDS = ['ap', 'wifi_client', 'ble', 'bt_classic'];  // device kinds that have a signal strength
const SIG_COLORS = ['#4cc2ff', '#f5b84a', '#3ecf8e', '#ef6f6c', '#c792ea', '#ffb86b', '#6fd3ff', '#a8b3c2'];
const SIG_DASH = [[], [6, 4], [2, 3], [10, 3, 2, 3], [1, 2]];  // one line style per sensor
const SIG_BUCKET = 2;  // seconds: readings are averaged per device, sensor and this many seconds
// Kept while moving around the app, so coming back shows the history gathered so far (the server keeps 15 minutes too).
const sigState = { points: {}, after: 0, sensors: {}, devices: {} };
const rateHist = {};  // interface -> [{t, y}] frames per second, kept in the browser only

addRoute('/sensors', async (_, params) => {
  const macs = (params.get('mac') || '').split(',').filter(isMac).slice(0, 8);
  const win = [120, 300, 900].includes(+params.get('win')) ? +params.get('win') : 300;
  const mode = params.get('mode') === 'best' ? 'best' : 'all';
  const only = params.get('sensor') || '';
  const go = change => { location.hash = hrefWith('/sensors', { mac: macs.join(','), win, mode, sensor: only, ...change }); };

  app.innerHTML = `<div class="page-head"><div><h1>Sensors</h1><div class="sub">This server and every remote sensor: how each interface is doing, what hardware it is, and how strongly each sensor hears the devices you pick.</div></div>
      ${isAdmin() ? '<div class="row"><a class="btn" href="#/settings?tab=sensors">Manage sensors</a></div>' : ''}</div>
    <div class="grid cols-4" id="sn-cards"></div>
    <div id="sn-list" style="margin-top:16px"><div class="empty">Loading…</div></div>
    <section class="panel" style="margin-top:16px"><header><h2>Frames per second</h2><span class="faint">per interface, since this page was opened</span></header>
      <div class="body"><div class="legend" id="sn-rate-legend"></div><div class="chart-box short"><canvas id="sn-rate"></canvas></div></div></section>
    <section class="panel" style="margin-top:16px" id="sig"><header><h2>Signal comparison</h2><span class="faint">live, per sensor · up to 8 devices</span></header>
      <div class="body">
        <div class="row sig-controls">
          <div class="sig-search"><input type="search" id="sig-q" placeholder="Add a device: name, vendor or address" autocomplete="off" aria-label="Find a device to add">
            <ul class="sig-results" id="sig-results" hidden></ul></div>
          <button class="btn small" id="sig-strong" title="The devices heard most strongly right now">Strongest now</button>
          <button class="btn small" id="sig-watched" title="Your watched devices">Watched</button>
          ${macs.length ? '<button class="btn small ghost" id="sig-clear">Clear</button>' : ''}
          <span class="grow"></span>
          ${seg('win', [[120, '2 min'], [300, '5 min'], [900, '15 min']], win)}
          ${seg('mode', [['all', 'Per sensor'], ['best', 'Strongest sensor']], mode)}
          <select id="sig-sensor" aria-label="Sensor"><option value="">All sensors</option></select>
        </div>
        <div class="sig-chips" id="sig-chips"></div>
        <div class="chart-box" style="height:420px"><canvas id="sig-chart"></canvas></div>
        <div class="table-wrap" id="sig-table"></div>
        <p class="faint small-text" style="margin:8px 0 0">Every reading of the chosen devices, averaged per ${SIG_BUCKET} seconds. Each device has its own colour and each sensor its own line style. Readings are gathered while this page is open and kept for 15 minutes. Signal strength depends on the adapter and its antenna, so compare devices as heard by the same sensor, or one device across sensors, rather than absolute values between different adapters.</p>
      </div></section>`;

  onSeg(app, 'win', v => go({ win: v }));
  onSeg(app, 'mode', v => go({ mode: v }));

  // ---------------------------------------------------------------- sensors and their interfaces
  let about = null;
  async function loadSensors() {
    const [st, ss] = await Promise.all([apiStatus(), api('/api/sensors')]);
    if (!about) about = await api('/api/about').catch(() => ({}));
    const entries = st.sensors.filter(x => modOn(SENSOR_MOD[x.type]));
    const by = {};
    entries.forEach(x => { (by[x.remote || 'local'] = by[x.remote || 'local'] || []).push(x); });
    const hc = healthCounts(entries);
    const online = ss.filter(s => s.online).length;
    const pps = entries.reduce((a, x) => a + (x.state === 'offline' ? 0 : Number(x.pps) || 0), 0);
    document.getElementById('sn-cards').innerHTML = [
      ['Sensors', `${num(online)}<small>of ${num(ss.length)}</small>`, 'online'],
      ['Interfaces', num(hc.ok), `working${hc.off ? ` · ${hc.off} offline` : ''}`],
      ['Need attention', num(hc.warn + hc.bad), hc.bad ? `${hc.bad} with an error` : 'warnings and errors'],
      ['Frames', `${pps.toFixed(0)}<small>per second</small>`, 'all interfaces together'],
    ].map(([l, v, m]) => `<div class="card"><div class="label">${l}</div><div class="value">${v}</div><div class="meta">${esc(m)}</div></div>`).join('');
    document.getElementById('sn-list').innerHTML = ss.map(s => sensorPanel(s, by[s.id] || [], st)).join('')
      || '<div class="empty">No sensors</div>';
    document.querySelectorAll('#sn-list button[data-reset]').forEach(b => b.onclick = () => resetAdapter(...b.dataset.reset.split('|')));
    renderRates(entries);
    fillSensorSelect(ss);
  }

  function sensorPanel(s, list, st) {
    const v = s.id === 'local' ? about : s.info && s.info.version;
    const sys = s.id === 'local' ? { system: st.system } : (st.sensor_systems || []).find(x => x.id === s.id);
    const f = sys && !sys.stale ? loadFigures(sys.system) : null;
    const hc = healthCounts(list);
    const dot = !s.online ? 'off' : hc.bad ? 'bad' : hc.warn ? 'warn' : 'ok';
    const differs = v && about && s.id !== 'local' && v.version && about.version && v.version !== about.version;
    return `<section class="panel sn-sensor"><header><h2 class="sn-title"><span class="state-dot ${dot}"></span>${esc(s.name)}</h2>
        <span class="row faint small-text">${s.room ? `<span class="tag">${esc(s.room)}</span>` : ''}
          ${v && v.version ? `<span>version <b>${esc(v.version)}</b>${v.arch ? ` · ${esc(v.arch)}` : ''}</span>` : ''}${differs ? '<span class="tag warn">differs from the server</span>' : ''}
          <span>${s.id === 'local' ? 'this server' : s.online ? `last report ${ago(s.last_seen)}` : `<span class="warn-text">offline${s.last_seen ? ` · last report ${ago(s.last_seen)}` : ''}</span>`}</span></span></header>
      ${f ? `<div class="body sn-sys">
        ${sysMeter('Load', sysPct(f.loadP), f.load ? f.load[0].toFixed(2) : '—', f.load ? `${num(f.cores)} core${f.cores > 1 ? 's' : ''}${f.cpu != null ? ` · CPU ${Number(f.cpu).toFixed(0)}%` : ''}` : 'unknown')}
        ${sysMeter('Memory', sysPct(f.memP), f.memP == null ? '—' : `${f.memP.toFixed(0)}%`, f.m.total ? `${bytes(f.m.used || 0)} of ${bytes(f.m.total)}` : 'unknown')}
        ${f.d ? sysMeter('Disk', sysPct(f.diskP), f.diskP == null ? '—' : `${f.diskP.toFixed(0)}%`, `${bytes(f.d.free)} free`) : ''}</div>` : ''}
      <div class="body flush">${tableHtml('<th>Interface</th><th>Status</th><th>Hardware</th><th>Listening on</th><th class="num">Frames</th>',
        list.map(ifaceRow).join(''), s.online || s.id === 'local' ? 'No interfaces on this sensor' : 'Offline: no interfaces reported')}</div></section>`;
  }

  function ifaceRow(x) {
    const short = x.remote ? x.name.slice(x.remote.length + 1) : x.name;
    const h = sensorHealth(x);
    const status = x.state === 'offline' ? `offline · no report for ${dur(x.quiet_for || 0)}`
      : x.error ? `<span class="err">${esc(x.error)}</span>` : esc(x.state || '—');
    const hwTop = [x.hw_maker, x.hw_product].filter(Boolean).join(' ') || x.chip || '';
    const hwBits = [x.hw_driver && `driver ${x.hw_driver}`, x.hw_bus && x.hw_bus.toUpperCase() + (x.hw_speed ? ` ${x.hw_speed}` : ''), x.hw_usb && `ID ${x.hw_usb}`,
      x.hw_phy, x.hw_link && `link ${x.hw_link}`].filter(Boolean);
    const extra = [];
    if (x.bt_version) extra.push(`Bluetooth ${esc(x.bt_version)}${x.chip && x.chip !== hwTop ? ` · ${esc(x.chip)}` : ''}`);
    if (x.firmware) extra.push(`firmware ${esc(x.firmware)}`);
    if (x.fw_version) extra.push(`sniffer firmware v${esc(String(x.fw_version))}`);
    if (Array.isArray(x.supported_bands) && x.supported_bands.length) extra.push(`bands ${x.supported_bands.map(b => esc(b) + ' GHz').join(', ')}`);
    const caps = Array.isArray(x.caps) && x.caps.length ? `<div class="sn-caps">${x.caps.slice(0, 8).map(c => `<span class="tag">${esc(c)}</span>`).join('')}${x.caps.length > 8 ? `<span class="faint small-text">+${x.caps.length - 8}</span>` : ''}</div>` : '';
    const hw = hwTop || hwBits.length || extra.length || caps
      ? `${hwTop ? `<div>${esc(hwTop)}</div>` : ''}${hwBits.length ? `<div class="faint small-text">${esc(hwBits.join(' · '))}</div>` : ''}${extra.length ? `<div class="faint small-text">${extra.join(' · ')}</div>` : ''}${caps}`
      : '<span class="faint" title="Not reported: the adapter is built in, the sensor runs an older version, or the container cannot read it">—</span>';
    const on = x.type === 'wifi' ? [x.channel && `ch ${esc(x.channel)}`, Array.isArray(x.bands) && x.bands.length && x.bands.map(b => esc(b) + ' GHz').join(', '),
      Array.isArray(x.channels) && x.channels.length > 1 && `${x.channels.length} channels`].filter(Boolean).join(' · ')
      : x.type === 'zigbee' ? (Array.isArray(x.zb_channels) && x.zb_channels.length ? `ch ${x.zb_channels.join(', ')}` : x.channel ? `ch ${esc(x.channel)}` : '')
      : x.type === 'lora' ? esc(x.profile || (Array.isArray(x.profiles) ? x.profiles.join(', ') : ''))
      : x.type === 'bluetooth' ? [x.scan === 'extended' ? 'extended scan' : 'LE scan', x.inquiries ? `${num(x.inquiries)} inquiries` : ''].filter(Boolean).join(' · ')
      : x.type === 'ethernet' ? (x.promisc ? 'promiscuous' : 'own traffic') : '';
    const reset = isAdmin() && !x.demo && /^(wifi|bt|zigbee|lora):/.test(short) && x.state !== 'offline'
      ? `<button class="btn small ghost" data-reset="${esc(x.remote || 'local')}|${esc(short)}" title="Reset this adapter">Reset…</button>` : '';
    return `<tr><td><span class="state-dot ${h}" title="${HEALTH_TEXT[h]}"></span><b class="mono">${esc(short)}</b>${x.mon && x.mon !== x.iface ? `<span class="faint mono"> → ${esc(x.mon)}</span>` : ''}
        <div class="faint small-text">${esc({ wifi: 'Wi-Fi', bluetooth: 'Bluetooth', ethernet: 'Ethernet', zigbee: 'Zigbee / 802.15.4', lora: 'LoRa' }[x.type] || x.type || '')}</div></td>
      <td>${status}${x.warning ? `<div class="warn-text small-text">${esc(x.warning)}</div>` : ''}${x.note ? `<div class="faint small-text">${esc(x.note)}</div>` : ''}${reset ? `<div>${reset}</div>` : ''}</td>
      <td class="sn-hw">${hw}</td><td class="muted">${on || '<span class="faint">—</span>'}</td>
      <td class="num"><b class="mono">${(Number(x.pps) || 0).toFixed(1)}</b><span class="faint">/s</span><div class="faint small-text">${num(x.packets || 0)} total</div></td></tr>`;
  }

  function renderRates(list) {
    const now = Date.now() / 1000;
    list.forEach(x => {
      const h = rateHist[x.name] || (rateHist[x.name] = []);
      if (h.length && now - h[h.length - 1].t < 4) return;  // not more often than the sensors report
      h.push({ t: now, y: x.state === 'offline' ? 0 : Number(x.pps) || 0 });
      while (h.length && h[0].t < now - 900) h.shift();
    });
    const names = Object.keys(rateHist).filter(n => rateHist[n].length && list.some(x => x.name === n));
    const color = n => IFACE_COLORS[names.indexOf(n) % IFACE_COLORS.length];
    document.getElementById('sn-rate-legend').innerHTML = names.map(n => `<span><span class="swatch" style="background:${color(n)}"></span>${esc(n)}</span>`).join('');
    const canvas = document.getElementById('sn-rate');
    if (!canvas) return;
    const data = { datasets: names.map(n => ({ label: n, data: rateHist[n].map(p => ({ x: p.t, y: p.y })), borderColor: color(n), fill: false, borderWidth: 1.5, pointRadius: 0, tension: .3 })) };
    const span = Math.max(60, Math.min(900, now - Math.min(...names.map(n => rateHist[n][0].t))));
    const c = window.Chart && Chart.getChart(canvas);
    if (c) {
      c.data = data;
      Object.assign(c.options.scales.x, { min: now - span, max: now });
      c.update('none');
      return;
    }
    chart(canvas, { type: 'line', data, options: { maintainAspectRatio: false, animation: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { ...timeScale(span), min: now - span, max: now }, y: yScale({ ticks: { color: FAINT, callback: v => v + '/s' } }) },
      plugins: { legend: { display: false } } } });
  }

  // ---------------------------------------------------------------- signal comparison
  const devColor = m => SIG_COLORS[macs.indexOf(m) % SIG_COLORS.length];
  function fillSensorSelect(ss) {
    const el = document.getElementById('sig-sensor');
    if (!el || el.dataset.filled) return;
    el.dataset.filled = '1';
    el.insertAdjacentHTML('beforeend', ss.map(s => `<option value="${esc(s.id)}" ${s.id === only ? 'selected' : ''}>${esc(s.name)}</option>`).join(''));
    el.onchange = () => go({ sensor: el.value });
  }
  const devName = m => {
    const d = sigState.devices[m];
    return d ? d.label || d.name || d.ident || (d.kind === 'ap' && d.ssid) || d.vendor || m : m;
  };
  function renderChips() {
    document.getElementById('sig-chips').innerHTML = macs.map(m => `<span class="sig-chip" style="border-color:${devColor(m)}">
      <span class="swatch" style="background:${devColor(m)}"></span><a href="#/device/${enc(m)}">${esc(devName(m))}</a>
      ${devName(m) !== m ? `<span class="mono faint">${esc(m)}</span>` : ''}${sigState.devices[m] ? ` ${kindBadge(sigState.devices[m].kind)}` : ''}
      <button class="sig-x" data-rm="${esc(m)}" aria-label="Remove ${esc(devName(m))}">×</button></span>`).join('')
      || '<div class="empty" style="padding:24px">Add devices to compare: search above, or take the strongest or your watched devices.</div>';
    document.querySelectorAll('#sig-chips button[data-rm]').forEach(b => b.onclick = () => go({ mac: macs.filter(m => m !== b.dataset.rm).join(',') }));
  }
  const addMacs = list => {
    const next = [...new Set([...macs, ...list.filter(isMac)])].slice(0, 8);
    if (next.length > macs.length) go({ mac: next.join(',') });
    else toast(list.length ? 'Those devices are already in the graph, or it is full (8)' : 'No devices found', true);
  };

  async function pollSignal() {
    if (!macs.length) { renderChips(); renderSignal(); return; }
    const qs = new URLSearchParams();
    macs.forEach(m => qs.append('mac', m));
    // the server keeps 15 minutes; on the first request of this page take all it has
    qs.set('after', sigState.after ? String(sigState.after) : '0');
    const r = await api('/api/signal/live?' + qs);
    Object.assign(sigState.devices, r.devices);
    Object.assign(sigState.sensors, r.sensors);
    for (const [m, pts] of Object.entries(r.points)) {
      const have = sigState.points[m] || (sigState.points[m] = []);
      const last = have.length ? have[have.length - 1][0] : 0;
      pts.forEach(p => { if (p[0] > last) have.push(p); });
    }
    sigState.after = Math.max(sigState.after, ...Object.values(r.points).flat().map(p => p[0]), 0);
    sigState.latest = r.latest;
    const cut = r.now - r.keep;
    Object.keys(sigState.points).forEach(m => { const a = sigState.points[m]; while (a.length && a[0][0] < cut) a.shift(); });
    sigState.now = r.now;
    renderChips();
    renderSignal();
  }

  function series() {
    // [{mac, sensor, pts: [{x, y}]}]: per device and sensor (or the strongest sensor), averaged per SIG_BUCKET seconds
    const now = sigState.now || Date.now() / 1000, from = now - win, out = [];
    macs.forEach(m => {
      const per = {};
      (sigState.points[m] || []).forEach(([t, s, v]) => {
        if (t < from || (only && s !== only)) return;
        const b = Math.floor(t / SIG_BUCKET) * SIG_BUCKET;
        const k = mode === 'best' ? '*' : s;
        const slot = ((per[k] = per[k] || {})[b] = per[k][b] || { sum: 0, n: 0, best: -999, by: {} });
        slot.sum += v; slot.n++;
        (slot.by[s] = slot.by[s] || []).push(v);
      });
      Object.entries(per).forEach(([s, slots]) => {
        const pts = Object.entries(slots).sort((a, b) => a[0] - b[0]).map(([b, x]) => ({ x: +b + SIG_BUCKET / 2,
          y: s === '*' ? Math.max(...Object.values(x.by).map(a => a.reduce((p, q) => p + q, 0) / a.length)) : x.sum / x.n }));
        out.push({ mac: m, sensor: s, pts });
      });
    });
    return out;
  }
  const sensorName = s => s === '*' ? 'strongest sensor' : sigState.sensors[s] || s;
  function renderSignal() {
    const canvas = document.getElementById('sig-chart');
    if (!canvas) return;
    const lines = series();
    const sensorsSeen = [...new Set(lines.map(l => l.sensor))].sort();
    const now = sigState.now || Date.now() / 1000;
    const datasets = lines.map(l => ({ label: `${devName(l.mac)} · ${sensorName(l.sensor)}`, data: l.pts, borderColor: devColor(l.mac),
      borderDash: SIG_DASH[sensorsSeen.indexOf(l.sensor) % SIG_DASH.length], borderWidth: 1.6, pointRadius: l.pts.length < 30 ? 2 : 0,
      tension: .25, spanGaps: SIG_BUCKET * 8 * 1000, fill: false }));
    const opts = { maintainAspectRatio: false, animation: false, interaction: { mode: 'nearest', intersect: false },
      scales: { x: { ...timeScale(win), min: now - win, max: now },
        y: { grid: { color: GRID }, border: { display: false }, suggestedMin: -95, suggestedMax: -35, ticks: { color: FAINT, callback: v => v + ' dBm' } } },
      plugins: { legend: { display: datasets.length > 0, position: 'bottom', labels: { boxWidth: 18, boxHeight: 2, color: MUTED } },
        tooltip: { callbacks: { title: c => new Date(c[0].parsed.x * 1000).toLocaleTimeString(), label: c => ` ${c.dataset.label}: ${c.parsed.y.toFixed(1)} dBm` } } } };
    const c = window.Chart && Chart.getChart(canvas);
    if (c) { c.data.datasets = datasets; c.options.scales.x.min = now - win; c.options.scales.x.max = now; c.options.plugins.legend.display = datasets.length > 0; c.update('none'); }
    else chart(canvas, { type: 'line', data: { datasets }, options: opts });
    // the figures behind the lines, and the latest smoothed value per sensor for devices not heard in this window
    const rows = [];
    macs.forEach(m => {
      const per = {};
      (sigState.points[m] || []).forEach(([t, s, v]) => { if (t >= now - win && (!only || s === only)) (per[s] = per[s] || []).push([t, v]); });
      const sensorsOf = new Set([...Object.keys(per), ...(sigState.latest || []).filter(x => x.mac === m && (!only || x.sensor === only)).map(x => x.sensor)]);
      [...sensorsOf].sort().forEach(s => {
        const v = (per[s] || []).map(p => p[1]);
        const last = (sigState.latest || []).find(x => x.mac === m && x.sensor === s);
        rows.push(`<tr><td><span class="swatch" style="background:${devColor(m)}"></span>${esc(devName(m))}</td><td>${esc(sensorName(s))}</td>
          <td class="num">${v.length ? rssiBars(Math.round(v[v.length - 1])) : '<span class="faint">—</span>'}</td>
          <td class="num">${v.length ? (v.reduce((a, b) => a + b, 0) / v.length).toFixed(1) : '—'}</td><td class="num">${v.length ? Math.min(...v) : '—'}</td><td class="num">${v.length ? Math.max(...v) : '—'}</td>
          <td class="num">${num(v.length)}</td><td class="num muted">${last ? ago(last.last_seen) : '—'}</td></tr>`);
      });
    });
    document.getElementById('sig-table').innerHTML = rows.length ? `<table><thead><tr><th>Device</th><th>Sensor</th><th class="num">Now</th><th class="num">Average</th>
      <th class="num">Weakest</th><th class="num">Strongest</th><th class="num">Readings</th><th class="num">Last heard</th></tr></thead><tbody>${rows.join('')}</tbody></table>` : '';
  }

  // device search
  const q = document.getElementById('sig-q'), results = document.getElementById('sig-results');
  let qTimer = null;
  q.oninput = () => {
    clearTimeout(qTimer);
    qTimer = setTimeout(async () => {
      const text = q.value.trim();
      if (text.length < 2) { results.hidden = true; return; }
      const d = await api(`/api/devices?${new URLSearchParams({ q: text, limit: 20, sort: 'last_seen', order: 'desc', slim: 1 })}`);
      const items = d.items.filter(x => SIG_KINDS.includes(x.kind) && !macs.includes(x.mac)).slice(0, 8);
      results.innerHTML = items.length ? items.map(x => `<li><button type="button" data-add="${esc(x.mac)}">${kindBadge(x.kind)} <span>${esc(devLabel(x) || x.vendor || x.mac)}</span>
        <span class="mono faint">${esc(x.mac)}</span><span class="faint">${ago(x.last_seen)}</span></button></li>`).join('') : '<li class="faint" style="padding:8px">No device with a signal matches</li>';
      results.hidden = false;
      results.querySelectorAll('button[data-add]').forEach(b => b.onclick = () => addMacs([b.dataset.add]));
    }, 250);
  };
  q.onkeydown = e => { if (e.key === 'Escape') { results.hidden = true; q.value = ''; } };
  document.addEventListener('click', e => { if (!e.target.closest('.sig-search')) results.hidden = true; });
  document.getElementById('sig-strong').onclick = async () => {
    const d = await api(`/api/devices?${new URLSearchParams({ active: 300, sort: 'last_rssi', order: 'desc', limit: 30, slim: 1 })}`);
    addMacs(d.items.filter(x => SIG_KINDS.includes(x.kind) && x.last_rssi != null).slice(0, 8 - macs.length).map(x => x.mac));
  };
  document.getElementById('sig-watched').onclick = async () => {
    const d = await api(`/api/devices?${new URLSearchParams({ watch: 1, limit: 50, sort: 'last_seen', order: 'desc', slim: 1 })}`);
    addMacs(d.items.filter(x => SIG_KINDS.includes(x.kind)).slice(0, 8 - macs.length).map(x => x.mac));
  };
  const clear = document.getElementById('sig-clear');
  if (clear) clear.onclick = () => go({ mac: '' });

  renderChips();
  await Promise.all([loadSensors(), pollSignal()]);
  every(5000, loadSensors);
  every(2000, pollSignal);
});
