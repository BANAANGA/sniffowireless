'use strict';
/* SSID picker (shared by My networks, Ignore list and Investigations), the Investigations settings tab,
   and the Investigations overview / dossier pages. */

// ===================================================================== SSID picker
/* Opens a searchable list of every SSID yolo has seen (broadcast or probed for). Resolves with the chosen
   SSIDs, or null when cancelled. `selected` are pre-ticked; `title` names the list being edited. */
function pickSsids({ title, selected = [], hint = '' } = {}) {
  return new Promise(resolve => {
    const chosen = new Set(selected);
    let items = [], done = false;
    const form = openModal(title || 'Choose networks', `
      ${hint ? `<p class="muted small-text" style="margin-top:0">${esc(hint)}</p>` : ''}
      <div class="row" style="margin-bottom:10px"><input type="search" id="sp-q" placeholder="Search SSIDs…" style="flex:1" autocomplete="off">
        <label class="check" style="margin:0"><input type="checkbox" id="sp-probed"> include networks only looked for by devices</label></div>
      <div class="sp-list" id="sp-list"><div class="empty">Loading…</div></div>
      <div class="row" style="margin-top:10px"><input id="sp-custom" placeholder="Not listed? Type an SSID" maxlength="64" style="flex:1">
        <button type="button" class="btn small" id="sp-add">Add</button></div>
      <div class="faint small-text" id="sp-count" style="margin-top:8px"></div>`,
    async () => { done = true; resolve([...chosen]); }, { submit: 'Use selection', wide: true });
    const list = form.querySelector('#sp-list'), q = form.querySelector('#sp-q'), probed = form.querySelector('#sp-probed');
    const count = () => { form.querySelector('#sp-count').textContent = `${chosen.size} selected`; };
    function draw() {
      const needle = q.value.trim().toLowerCase();
      const rows = items.filter(x => (probed.checked || x.aps > 0 || chosen.has(x.ssid)) && (!needle || x.ssid.toLowerCase().includes(needle)));
      const extra = [...chosen].filter(s => !items.some(x => x.ssid === s));  // chosen but never seen
      list.innerHTML = (extra.length || rows.length) ? `<table><thead><tr><th></th><th>SSID</th><th class="num">APs</th><th class="num">Clients</th>
        <th class="num">Looked for by</th><th>Security</th><th class="num">Last seen</th><th></th></tr></thead><tbody>
        ${extra.map(s => `<tr><td><input type="checkbox" data-s="${esc(s)}" checked></td><td><b>${esc(s)}</b></td><td colspan="5" class="faint">not seen yet</td><td></td></tr>`).join('')}
        ${rows.map(x => `<tr><td><input type="checkbox" data-s="${esc(x.ssid)}" ${chosen.has(x.ssid) ? 'checked' : ''}></td>
          <td class="trunc" style="max-width:240px">${hl(x.ssid, q.value.trim())}</td><td class="num">${num(x.aps)}</td><td class="num">${num(x.clients)}</td>
          <td class="num">${num(x.probers)}</td><td class="muted small-text">${esc((x.enc || '').split(',').filter(Boolean).join(' '))}</td>
          <td class="num muted">${ago(x.last_seen)}</td>
          <td>${x.mine ? '<span class="tag on">mine</span>' : ''}${x.ignored ? ' <span class="tag">ignored</span>' : ''}${x.investigated ? ' <span class="tag warn">investigated</span>' : ''}</td></tr>`).join('')}
        </tbody></table>` : '<div class="empty">No networks match</div>';
      list.querySelectorAll('[data-s]').forEach(cb => cb.onchange = () => { cb.checked ? chosen.add(cb.dataset.s) : chosen.delete(cb.dataset.s); count(); });
      list.querySelectorAll('tbody tr').forEach(tr => tr.onclick = e => {
        if (e.target.tagName === 'INPUT') return;
        const cb = tr.querySelector('input'); cb.checked = !cb.checked; cb.onchange();
      });
      count();
    }
    q.oninput = draw;
    probed.onchange = draw;
    const add = () => {
      const v = form.querySelector('#sp-custom').value.trim();
      if (v) { chosen.add(v); form.querySelector('#sp-custom').value = ''; draw(); }
    };
    form.querySelector('#sp-add').onclick = add;
    form.querySelector('#sp-custom').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); add(); } };
    // resolve(null) when the modal is closed any other way
    const bg = form.parentElement;
    new MutationObserver((_, obs) => { if (!document.body.contains(bg)) { obs.disconnect(); if (!done) resolve(null); } })
      .observe(document.body, { childList: true });
    api('/api/ssids?limit=1000&days=90').then(r => { items = r.items; draw(); }).catch(err => { list.innerHTML = `<div class="empty">${esc(err.message)}</div>`; });
    q.focus();
  });
}

// ===================================================================== settings: my networks (picker)
SETTINGS_VIEWS.networks = async function (el) {
  const n = await api('/api/settings/networks');
  let ssids = [...n.ssids];
  const ro = !isAdmin();
  const render = () => {
    el.innerHTML = `<section class="panel"><header><h2>My networks</h2>${ro ? '' : '<button class="btn" id="pick">Choose networks…</button>'}</header><div class="body">
      <p class="muted">SSIDs you own. Enables the <a href="#/mynet">My networks</a> health view, evil-twin detection and configuration checks on the <a href="#/security">Security</a> page.</p>
      <div class="chips">${ssids.map((s, i) => `<span class="chip">${esc(s)}${ro ? '' : `<a href="#" data-rm="${i}" aria-label="Remove">✕</a>`}</span>`).join('') || '<span class="faint">None yet</span>'}</div>
      ${ro ? '' : '<div style="margin-top:16px"><button class="btn primary" id="save-net">Save</button></div>'}
      ${n.bssids.length ? `<h3 class="subhead">Access points broadcasting them</h3>${tableHtml('<th>BSSID</th><th>SSID</th><th>Channel</th><th>Security</th><th>Trusted</th>',
        n.bssids.map(b => `<tr><td>${devLink(b.mac)}</td><td>${esc(b.ssid)}</td><td>${chText(b.channel, b.band)}</td><td class="muted">${esc(b.enc || '')}</td><td>${n.trusted_bssids.includes(b.mac) ? '<span class="tag on">yes</span>' : '<span class="tag">no</span>'}</td></tr>`).join(''))}
        <p class="faint small-text">Mark trusted access points on the <a href="#/security">Security</a> page.</p>` : ''}</div></section>`;
    el.querySelectorAll('[data-rm]').forEach(a => a.onclick = e => { e.preventDefault(); ssids.splice(+a.dataset.rm, 1); render(); });
    const pick = el.querySelector('#pick');
    if (pick) pick.onclick = async () => {
      const r = await pickSsids({ title: 'My networks', selected: ssids, hint: 'Tick the networks that are yours.' });
      if (r) { ssids = r; render(); }
    };
    const sv = el.querySelector('#save-net');
    if (sv) sv.onclick = async () => { try { await send('PUT', '/api/settings/networks', { ssids, trusted_bssids: n.trusted_bssids }); toast('Saved'); } catch (e) { toast(e.message, true); } };
  };
  render();
};

// ===================================================================== settings: investigations
SETTINGS_VIEWS.investigate = async function (el) {
  const cfg = await api('/api/settings/investigate');
  let rows = cfg.ssids.map(x => ({ ...x }));
  const ro = !isAdmin();
  const render = () => {
    el.innerHTML = `<section class="panel"><header><h2>Networks under investigation</h2>${ro ? '' : '<button class="btn" id="pick">Choose networks…</button>'}</header><div class="body">
      <p class="muted">Networks you want to keep an eye on: an unknown network that appeared nearby, a suspected rogue hotspot, a network a device keeps joining.
        yolo raises an event whenever such a network is on the air, a device connects to it, or a device looks for it, and builds a <a href="#/investigations">dossier</a> per network.
        Use the alert rule “Networks under investigation” (Alerts → Rules) to get notified.</p>
      ${rows.length ? `<table><thead><tr><th>SSID</th><th>Note</th><th class="num">Added</th><th></th></tr></thead><tbody>${rows.map((r, i) => `<tr>
        <td><a href="#/investigation/${enc(r.ssid)}"><b>${esc(r.ssid)}</b></a></td>
        <td style="width:50%"><input data-note="${i}" value="${esc(r.note || '')}" placeholder="Why is this network under investigation?" maxlength="2000" style="width:100%" ${ro ? 'readonly' : ''}></td>
        <td class="num muted">${r.added ? ago(r.added) : 'new'}</td><td class="num">${ro ? '' : `<a href="#" data-rm="${i}" aria-label="Remove">✕</a>`}</td></tr>`).join('')}</tbody></table>`
      : '<div class="empty">No networks under investigation</div>'}
      ${ro ? '' : '<div style="margin-top:16px"><button class="btn primary" id="save-inv">Save</button></div>'}</div></section>`;
    el.querySelectorAll('[data-note]').forEach(x => x.oninput = () => { rows[+x.dataset.note].note = x.value; });
    el.querySelectorAll('[data-rm]').forEach(a => a.onclick = e => { e.preventDefault(); rows.splice(+a.dataset.rm, 1); render(); });
    const pick = el.querySelector('#pick');
    if (pick) pick.onclick = async () => {
      const r = await pickSsids({ title: 'Networks under investigation', selected: rows.map(x => x.ssid), hint: 'Tick the networks to investigate. Include networks that are only looked for by devices to watch who searches for them.' });
      if (!r) return;
      const old = Object.fromEntries(rows.map(x => [x.ssid, x]));
      rows = r.map(s => old[s] || { ssid: s, note: '' });
      render();
    };
    const sv = el.querySelector('#save-inv');
    if (sv) sv.onclick = async () => {
      try { await send('PUT', '/api/settings/investigate', { ssids: rows.map(r => ({ ssid: r.ssid, note: r.note || null })) }); toast('Saved'); SETTINGS_VIEWS.investigate(el); }
      catch (e) { toast(e.message, true); }
    };
  };
  render();
};

// ===================================================================== pages
const INV_EVENT = { seen: 'on the air', connect: 'connections', probe: 'looked for' };

addRoute('/investigations', async (_, params) => {
  const days = +(params.get('days') || 7);
  const r = await api(`/api/investigations?days=${days}`);
  app.innerHTML = `<div class="page-head"><div><h1>Investigations</h1><div class="sub">Networks under investigation and what they've been doing.</div></div>
    <div class="row">${seg('days', [[1, '24h'], [7, '7 days'], [30, '30 days']], days)} ${isAdmin() ? '<a class="btn" href="#/settings?tab=investigate">Manage list</a>' : ''}</div></div>
    ${r.items.length ? `<div class="grid cols-3">${r.items.map(x => `<a class="card" href="#/investigation/${enc(x.ssid)}">
      <div class="label">${x.aps ? `<span class="state-dot ${Date.now() / 1000 - (x.last_seen || 0) < 600 ? 'on' : ''}"></span>${x.aps} access point${x.aps === 1 ? '' : 's'}` : '<span class="state-dot"></span>not broadcast'}${x.enc ? ' · ' + esc(x.enc.split(',')[0]) : ''}</div>
      <div class="value" style="font-size:18px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.ssid)}</div>
      ${x.note ? `<div class="faint small-text" style="margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.note)}</div>` : ''}
      <div class="meta"><span>${num(x.clients)} client${x.clients === 1 ? '' : 's'}</span><span>${num(x.probers)} looked for it</span><span>last seen ${ago(x.last_seen)}</span></div>
      <div class="meta">${Object.entries(INV_EVENT).map(([k, l]) => `<span>${num((x.events || {})[k])} ${l}</span>`).join('')}</div></a>`).join('')}</div>`
    : `<div class="callout">No networks under investigation yet. ${isAdmin() ? 'Add some under <a href="#/settings?tab=investigate">Settings → Investigations</a>, or open any network and choose <b>Investigate</b>.' : ''}</div>`}`;
  onSeg(app, 'days', v => { location.hash = hrefWith('/investigations', { days: v }); });
});

addRoute('/investigation/', (ssid, params) => renderSsid(ssid, params, 'investigation'));
addRoute('/ssid/', (ssid, params) => renderSsid(ssid, params, 'ssid'));

// Dossier for any SSID; `base` decides where the breadcrumb and range links point.
async function renderSsid(ssid, params, base) {
  const days = +(params.get('days') || 30);
  const d = await api(`/api/investigations/${enc(ssid)}?days=${days}`);
  const lanes = [];
  const byAp = {};
  d.presence.forEach(s => (byAp[s.mac] = byAp[s.mac] || []).push(s));
  d.aps.forEach(a => lanes.push([`<a href="#/device/${enc(a.mac)}" title="${esc(a.mac)}">AP ${esc(a.mac.slice(-8))}</a>`,
    (byAp[a.mac] || []).map(s => ({ s: s.start_ts, e: s.end_ts, color: KINDS.ap.color, title: `On the air ${dt(s.start_ts)} → ${dt(s.end_ts)}` }))]));
  const byClient = {};
  d.sessions.forEach(s => (byClient[s.mac] = byClient[s.mac] || []).push(s));
  const cname = Object.fromEntries(d.clients.map(c => [c.mac, c.label || c.name || c.ident || c.vendor || c.mac]));
  Object.entries(byClient).slice(0, 25).forEach(([m, ss]) => lanes.push([`<a href="#/device/${enc(m)}" title="${esc(m)}">${esc(cname[m] || m)}</a>`,
    ss.map(s => ({ s: s.start_ts, e: s.end_ts, color: KINDS.wifi_client.color, title: `Connected ${dt(s.start_ts)} → ${dt(s.end_ts)}` }))]));
  const who = x => x.label ? `<b>${esc(x.label)}</b>` : esc(x.name || x.ident || x.vendor || '');
  app.innerHTML = `<div class="page-head"><div><div class="crumbs">${base === 'ssid' ? '<a href="#/ssids">Networks</a>' : '<a href="#/investigations">Investigations</a>'}</div>
      <h1>${esc(d.ssid)} ${d.investigated ? '<span class="tag warn">under investigation</span>' : ''} ${d.mine ? '<span class="tag on">my network</span>' : ''}</h1>
      <div class="sub">${d.entry && d.entry.note ? esc(d.entry.note) : `${d.aps.length} access point${d.aps.length === 1 ? '' : 's'} · ${d.clients.length} client${d.clients.length === 1 ? '' : 's'} · ${d.probers.length} device${d.probers.length === 1 ? '' : 's'} looked for it`}</div></div>
    <div class="row">${seg('days', [[1, '24h'], [7, '7d'], [30, '30d']], days)}
      ${isAdmin() ? `<button class="btn ${d.investigated ? '' : 'primary'}" id="inv-toggle">${d.investigated ? 'Stop investigating' : 'Investigate'}</button>` : ''}</div></div>
    <div class="grid cols-3">
      <section class="panel span-3"><header><h2>Timeline</h2><span class="legend"><span><span class="swatch" style="background:${KINDS.ap.color}"></span>access point on the air</span><span><span class="swatch" style="background:${KINDS.wifi_client.color}"></span>device connected</span></span></header>
        <div class="body">${lanes.length ? ganttHtml(lanes, d.since, d.now) : '<div class="empty">Not seen in this period</div>'}</div></section>
      <section class="panel span-3"><header><h2>Access points broadcasting it</h2></header><div class="body flush">${tableHtml(
        '<th>BSSID</th><th>Vendor / identified as</th><th>Channel</th><th>Security</th><th>Signal</th><th class="num">First seen</th><th class="num">Last seen</th>',
        d.aps.map(a => `<tr class="link" data-href="#/device/${enc(a.mac)}"><td class="mono">${esc(a.mac)}${a.randomized ? ' <span class="tag warn">rand</span>' : ''}${a.label ? ` <b>${esc(a.label)}</b>` : ''}${a.current_ssid !== d.ssid ? ` <span class="tag warn" title="This access point also broadcasts other names">now “${esc(a.current_ssid || '')}”</span>` : ''}</td>
          <td class="muted trunc">${esc(a.ident || a.vendor || '—')}</td><td>${chText(a.channel, a.band)}</td><td><span class="tag ${(a.enc || '').includes('OPN') ? 'bad' : ''}">${esc(a.enc || '—')}</span></td>
          <td>${rssiBars(a.last_rssi)}${a.room ? ` <span class="faint">${esc(a.room)}</span>` : ''}</td><td class="num muted">${dt(a.first_seen)}</td><td class="num">${ago(a.last_seen)}</td></tr>`).join(''),
        'No access point has broadcast this name (it may only be looked for by devices)')}</div></section>
      <section class="panel span-2"><header><h2>Devices that connected</h2></header><div class="body flush">${tableHtml(
        '<th>Device</th><th class="num">Sessions</th><th class="num">Connected</th><th class="num">First</th><th class="num">Last</th>',
        d.clients.map(c => `<tr class="link" data-href="#/device/${enc(c.mac)}"><td>${c.connected ? '<span class="state-dot on"></span>' : '<span class="state-dot"></span>'}${kindBadge(c.kind)} ${who(c)} <span class="mono faint">${esc(c.mac)}</span>${c.randomized ? ' <span class="tag warn">rand</span>' : ''}</td>
          <td class="num">${num(c.sessions)}</td><td class="num">${dur(c.secs)}</td><td class="num muted">${dt(c.first)}</td><td class="num">${c.connected ? '<span class="tag on">now</span>' : ago(c.last)}</td></tr>`).join(''), 'No device connected in this period')}</div></section>
      <section class="panel"><header><h2>Devices that looked for it</h2></header><div class="body flush">${tableHtml(
        '<th>Device</th><th class="num">Times</th><th class="num">Last</th>',
        d.probers.map(p => `<tr class="link" data-href="#/device/${enc(p.mac)}"><td>${who(p) || ''} <span class="mono faint">${esc(p.mac)}</span>${p.randomized ? ' <span class="tag warn">rand</span>' : ''}</td>
          <td class="num">${num(p.count)}</td><td class="num muted">${ago(p.last_seen)}</td></tr>`).join(''), 'Nobody looked for it')}</div></section>
      <section class="panel span-3"><header><h2>Events</h2>${d.investigated ? '' : '<span class="faint">recorded while the network is under investigation</span>'}</header><div class="body flush">${d.events.length ? `<ul class="events wide">${d.events.map(e => eventRow(e, true)).join('')}</ul>` : '<div class="empty">No events yet</div>'}</div></section>
    </div>`;
  linkRows(app);
  onSeg(app, 'days', v => { location.hash = hrefWith(`/${base}/${enc(ssid)}`, { days: v }); });
  const tg = document.getElementById('inv-toggle');
  if (tg) tg.onclick = async () => {
    const cfg = await api('/api/settings/investigate');
    let list = cfg.ssids.map(x => ({ ssid: x.ssid, note: x.note }));
    if (d.investigated) {
      if (!confirm(`Stop investigating “${d.ssid}”? Its history stays.`)) return;
      list = list.filter(x => x.ssid !== d.ssid);
    } else {
      list.push({ ssid: d.ssid, note: null });
    }
    try { await send('PUT', '/api/settings/investigate', { ssids: list }); toast(d.investigated ? 'Removed from investigations' : 'Now under investigation'); route(); }
    catch (e) { toast(e.message, true); }
  };
}
