'use strict';
/* Networks (all SSIDs → per-SSID dossier) and Bluetooth ↔ Wi-Fi device matching. */

// ===================================================================== networks list
addRoute('/ssids', async (_, params) => {
  const days = +(params.get('days') || 7);
  const show = params.get('show') || 'broadcast';
  const r = await api(`/api/ssids?limit=1000&days=${days}`);
  app.innerHTML = `<div class="page-head"><div><h1>Networks</h1><div class="sub">Every Wi-Fi network name (SSID) seen. Open one for its access points, clients and the devices looking for it.</div></div>
    <div class="row">${seg('show', [['broadcast', 'Broadcast'], ['probed', 'Looked for only'], ['all', 'All']], show)}${seg('days', [[1, '24h'], [7, '7 days'], [30, '30 days']], days)}</div></div>
    <div class="filters"><input type="search" id="ss-q" placeholder="Filter networks…" style="width:320px"><span class="faint small-text" id="ss-count"></span></div>
    <section class="panel"><div class="body flush" id="ss-list"></div></section>`;
  onSeg(app, 'days', v => { location.hash = hrefWith('/ssids', { days: v, show }); });
  onSeg(app, 'show', v => { location.hash = hrefWith('/ssids', { days, show: v }); });
  const q = document.getElementById('ss-q');
  const draw = () => {
    const needle = q.value.trim().toLowerCase();
    const rows = r.items.filter(x => (show === 'all' || (show === 'broadcast' ? x.aps > 0 : x.aps === 0)) &&
      (!needle || x.ssid.toLowerCase().includes(needle)));
    document.getElementById('ss-count').textContent = `${rows.length} network${rows.length === 1 ? '' : 's'}`;
    const el = document.getElementById('ss-list');
    el.innerHTML = tableHtml('<th>SSID</th><th class="num">Access points</th><th class="num">Clients</th><th class="num">Looked for by</th><th>Security</th><th>Bands</th><th>Best signal</th><th class="num">Last seen</th>',
      rows.map(x => `<tr class="link" data-href="#/ssid/${enc(x.ssid)}"><td class="trunc" style="max-width:320px"><b>${hl(x.ssid, q.value.trim())}</b>
        ${x.mine ? ' <span class="tag on">mine</span>' : ''}${x.investigated ? ' <span class="tag warn">investigated</span>' : ''}${x.ignored ? ' <span class="tag">ignored</span>' : ''}</td>
        <td class="num">${num(x.aps)}</td><td class="num">${num(x.clients)}</td><td class="num muted">${num(x.probers)}</td>
        <td>${(x.enc || '').split(',').filter((v, i, a) => v && a.indexOf(v) === i).map(e => `<span class="tag ${e === 'OPN' ? 'bad' : ''}">${esc(e)}</span>`).join(' ') || '<span class="faint">—</span>'}</td>
        <td class="muted">${(x.bands || '').split(',').filter(Boolean).map(b => esc(b) + 'G').join(' · ') || '—'}</td>
        <td>${x.best_rssi != null ? rssiBars(x.best_rssi) : '<span class="faint">—</span>'}</td><td class="num muted">${ago(x.last_seen)}</td></tr>`).join(''),
      needle ? 'No networks match' : 'No networks in this period');
    linkRows(el);
  };
  q.oninput = draw;
  draw();
});

// ===================================================================== matching
const radioName = d => d.label || d.name || d.brand || d.vendor || d.mac;
function matchCard(x, actions = true) {
  const side = (d, kindLabel) => `<div class="mt-side"><div class="faint small-text">${kindLabel}</div>
    <a href="#/device/${enc(d.mac)}"><b>${esc(radioName(d))}</b></a><div class="mono faint small-text">${esc(d.mac)}${d.ip ? ' · ' + esc(d.ip) : ''}</div>
    <div class="faint small-text">${esc([d.brand || d.vendor, d.dev_type && typeLabel(d.dev_type)].filter(Boolean).join(' · ') || ' ')}</div></div>`;
  return `<div class="mt-card">${side(x.bt, (KINDS[x.bt.kind] || {}).label || 'Bluetooth')}<div class="mt-mid">
      ${x.level ? `<span class="conf conf-${x.level}">${x.level}</span>` : '<span class="tag on">linked</span>'}${x.score != null ? `<div class="faint small-text">${Math.round(x.score * 100)}%</div>` : ''}</div>
    ${side(x.wifi, 'Wi-Fi')}
    ${x.reasons ? `<ul class="mt-why">${x.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
    ${actions && isAdmin() ? `<div class="mt-act">${x.level
      ? `<button class="btn small primary" data-link="${esc(x.bt.mac)}|${esc(x.wifi.mac)}|${x.score}">Link</button> <button class="btn small" data-reject="${esc(x.bt.mac)}|${esc(x.wifi.mac)}">Not the same</button>`
      : `<button class="btn small" data-unlink="${esc(x.bt.mac)}|${esc(x.wifi.mac)}">Unlink</button>`}</div>` : ''}</div>`;
}
function bindMatchButtons(root, done) {
  root.querySelectorAll('[data-link]').forEach(b => b.onclick = async () => {
    const [a, c, score] = b.dataset.link.split('|');
    await send('POST', '/api/links', { a, b: c, status: 'linked', score: +score });
    toast('Linked: same device'); done();
  });
  root.querySelectorAll('[data-reject]').forEach(b => b.onclick = async () => {
    const [a, c] = b.dataset.reject.split('|');
    await send('POST', '/api/links', { a, b: c, status: 'rejected' });
    toast('Won’t suggest this pair again'); done();
  });
  root.querySelectorAll('[data-unlink]').forEach(b => b.onclick = async () => {
    const [a, c] = b.dataset.unlink.split('|');
    await send('DELETE', `/api/links/${enc(a)}/${enc(c)}`);
    toast('Unlinked'); done();
  });
}

addRoute('/matching', async () => {
  const r = await api('/api/matching');
  app.innerHTML = `<div class="page-head"><div><h1>Matching</h1><div class="sub">Which Bluetooth address belongs to which phone or laptop Wi-Fi address — guessed from the last ${r.days} days.</div></div></div>
    <section class="panel"><header><h2>Suggestions</h2><span class="faint">${r.suggestions.length}</span></header><div class="body">
      ${r.suggestions.length ? r.suggestions.map(x => matchCard(x)).join('') : '<div class="empty">No likely pairs right now. Pairs need at least 20 minutes of overlap; earbuds, watches, tags and bikes are left out (they move with a phone but are separate devices).</div>'}</div></section>
    <section class="panel" style="margin-top:16px"><header><h2>Linked devices</h2><span class="faint">${r.linked.length}</span></header><div class="body">
      ${r.linked.length ? r.linked.map(x => matchCard(x)).join('') : '<div class="empty">Nothing linked yet</div>'}</div></section>
    <p class="faint small-text">Signals: present at the same minutes, arriving and leaving together, signal strength rising and falling together, adjacent hardware addresses, similar names and the same brand. Phones rotate Bluetooth addresses, so a link may need renewing. Linking also puts both in the same group.</p>`;
  bindMatchButtons(app, route);
});

// ===================================================================== device panel
function matchPanel(d) {
  if (!['ble', 'bt_classic', 'wifi_client'].includes(d.kind)) return '';
  return `<section class="panel span-3" id="mt-panel" hidden><header><h2>Same device, other radio</h2><a class="muted" href="#/matching">All matches →</a></header><div class="body" id="mt-body"></div></section>`;
}
async function bindMatchPanel(d) {
  const panel = document.getElementById('mt-panel');
  if (!panel) return;
  const r = await api(`/api/devices/${enc(d.mac)}/matches`);
  if (!r.linked.length && !r.suggestions.length) return;
  const me = { mac: d.mac, kind: d.kind, name: d.name, label: d.label, brand: d.brand, vendor: d.vendor, dev_type: d.dev_type, ip: d.ip };
  const isBt = d.kind !== 'wifi_client';
  const asPair = (o, extra) => isBt ? { bt: me, wifi: o, ...extra } : { bt: o, wifi: me, ...extra };
  panel.hidden = false;
  const body = document.getElementById('mt-body');
  body.innerHTML = r.linked.map(o => matchCard(asPair(o, { score: o.score }))).join('') +
    (r.suggestions.length ? `<h3 class="subhead">${r.linked.length ? 'Other candidates' : 'Likely the same device'}</h3>` + r.suggestions.map(x => matchCard(x)).join('') : '');
  bindMatchButtons(body, route);
}
