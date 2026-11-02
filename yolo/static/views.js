'use strict';
/* Pages added on top of app.js: groups, alerts, security, channels, my networks, map, reports, settings.
   Uses the helpers defined in app.js (api, send, esc, openModal, chart, every, ...). */

const SEV_CLASS = { high: 'bad', medium: 'warn', low: '' };
const sevTag = s => `<span class="tag ${SEV_CLASS[s] || ''}">${esc(s)}</span>`;
const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const adminBtn = (id, label, cls = '') => isAdmin() ? `<button class="btn ${cls}" id="${id}">${label}</button>` : '';
function tableHtml(head, rows, empty = 'Nothing here yet') {
  return rows ? `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>`
    : `<div class="empty">${empty}</div>`;
}
function ganttHtml(lanes, start, end) {
  const span = end - start;
  const pos = (a, b) => {
    const l = Math.max(0, (a - start) / span * 100), r = Math.min(100, (b - start) / span * 100);
    return `left:${l}%;width:max(2px, ${Math.max(0, r - l)}%)`;
  };
  const ticks = Array.from({ length: 7 }, (_, i) => start + span * i / 6);
  return `<div class="gantt">${lanes.map(([label, bars]) => `<div class="lane"><div class="lane-label">${label}</div><div class="track">${
    bars.map(b => `<span class="bar" style="${pos(b.s, b.e)};background:${b.color}" title="${esc(b.title || '')}"></span>`).join('')}</div></div>`).join('')}
    <div class="axis"><span></span><div class="ticks">${ticks.map((t, i) => `<span style="left:${i / 6 * 100}%">${axisTime(t, span)}</span>`).join('')}</div></div></div>`;
}
function bindTabs(root, name, fn) { onSeg(root, name, fn); }

// ===================================================================== device: label & tracking
function trackPanel(d) {
  const m = d.meta || {};
  return `<section class="panel span-3"><header><h2>Label &amp; tracking</h2>${adminBtn('edit-meta', 'Edit', 'small')}</header>
    <div class="body"><div class="kv">
      <div><span>Label</span><b>${m.label ? esc(m.label) : '<span class="faint">none</span>'}</b></div>
      <div><span>Status</span><b>${m.known ? '<span class="tag on">known</span>' : '<span class="tag">unknown</span>'} ${m.watch ? '<span class="tag warn">★ watched</span>' : ''}</b></div>
      <div><span>Group</span><b>${m.group_id ? `<a href="#/group/${m.group_id}">${esc(m.group_name)}</a>` : '<span class="faint">none</span>'}</b></div>
      ${m.notes ? `<div style="grid-column:1/-1"><span>Notes</span><b style="white-space:pre-wrap;font-weight:400">${esc(m.notes)}</b></div>` : ''}
    </div><div id="suggest"></div></div></section>`;
}

async function metaModal(d, onDone) {
  const groups = await api('/api/groups');
  const m = d.meta || {};
  const form = openModal(`Label & tracking · ${d.mac}`, `
    <label class="field">Label<input name="label" value="${esc(m.label || '')}" placeholder="e.g. Sam's iPhone" maxlength="80"></label>
    <label class="field">Notes<textarea name="notes" rows="3">${esc(m.notes || '')}</textarea></label>
    <label class="field">Group<select name="group"><option value="">No group</option>${groups.map(g => `<option value="${g.id}" ${g.id === m.group_id ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}<option value="new">+ New group…</option></select></label>
    <label class="field" id="newg" hidden>New group name<input name="newgroup" placeholder="e.g. Sam"></label>
    <label class="check"><input type="checkbox" name="known" ${m.known ? 'checked' : ''}> Known device <span class="faint">— no "unknown device" alerts</span></label>
    <label class="check"><input type="checkbox" name="watch" ${m.watch ? 'checked' : ''}> Watch <span class="faint">— alert when it arrives or leaves</span></label>`,
  async f => {
    let gid = fv(f, 'group');
    if (gid === 'new') gid = (await send('POST', '/api/groups', { name: fv(f, 'newgroup') || 'New group' })).id;
    await send('PUT', `/api/devices/${enc(d.mac)}/meta`, { label: fv(f, 'label'), notes: fv(f, 'notes'), known: fv(f, 'known'),
      watch: fv(f, 'watch'), group_id: gid ? +gid : null, clear_group: !gid });
    toast('Saved');
    onDone();
  });
  form.elements.group.onchange = e => { form.querySelector('#newg').hidden = e.target.value !== 'new'; };
}

async function bindTrackPanel(d) {
  const btn = document.getElementById('edit-meta');
  if (btn) btn.onclick = () => metaModal(d, route);
  if (!d.fp_hash && !d.name) return;
  const sug = await api(`/api/devices/${enc(d.mac)}/suggestions`);
  const el = document.getElementById('suggest');
  if (!el || !sug.length) return;
  const gid = d.meta && d.meta.group_id;
  el.innerHTML = `<h3 class="subhead">Possibly the same physical device <span class="faint">— ${esc(sug[0].reason)}, never present at the same time</span></h3>
    ${tableHtml('<th>Address</th><th>Identified as</th><th class="num">First seen</th><th class="num">Last seen</th><th class="num">Gap</th><th></th>',
    sug.slice(0, 8).map(c => `<tr><td>${devLink(c.mac)}</td><td class="muted">${esc([c.brand, c.dev_type && typeLabel(c.dev_type)].filter(Boolean).join(' · ') || '—')}</td>
      <td class="num muted">${dt(c.first_seen)}</td><td class="num muted">${ago(c.last_seen)}</td><td class="num muted">${c.gap != null ? dur(c.gap) : '—'}</td>
      <td class="num">${isAdmin() ? (c.group_id ? '<span class="faint">in a group</span>' : `<button class="btn small" data-merge="${c.mac}">${gid ? 'Add to group' : 'Group together'}</button>`) : ''}</td></tr>`).join(''))}`;
  el.querySelectorAll('[data-merge]').forEach(b => b.onclick = async () => {
    let g = gid;
    if (!g) {
      const name = prompt('Name for the new group (e.g. the owner):', (d.meta && d.meta.label) || d.ident && d.ident.label || 'Device');
      if (!name) return;
      g = (await send('POST', '/api/groups', { name })).id;
    }
    await send('POST', `/api/groups/${g}/members`, { macs: [d.mac, b.dataset.merge] });
    toast('Grouped');
    route();
  });
}

// ===================================================================== groups
addRoute('/groups', async () => {
  const gs = await api('/api/groups');
  app.innerHTML = `<div class="page-head"><div><h1>Groups</h1><div class="sub">People or things made of several devices (a phone, watch and earbuds; a phone's rotating MACs).</div></div>${adminBtn('new-group', 'New group', 'primary')}</div>
    <div class="grid cols-3">${gs.map(g => `<a class="card" href="#/group/${g.id}">
      <div class="label"><span class="state-dot ${g.present ? 'on' : ''}"></span>${g.kind === 'person' ? 'Person' : 'Thing'}${g.watch ? ' · <span class="star">★</span> watched' : ''}</div>
      <div class="value" style="font-size:20px">${esc(g.name)}</div>
      <div class="meta"><span>${g.members} device${g.members === 1 ? '' : 's'}</span><span>${g.present ? 'present now' : 'last seen ' + ago(g.last_seen)}</span></div></a>`).join('')
    || '<div class="empty span-all">No groups yet. Open a device and use “Label &amp; tracking” to add it to a group.</div>'}</div>`;
  const b = document.getElementById('new-group');
  if (b) b.onclick = () => groupModal(null);
});

function groupModal(g) {
  openModal(g ? 'Edit group' : 'New group', `
    <label class="field">Name<input name="name" value="${esc(g ? g.name : '')}" required maxlength="60"></label>
    <label class="field">Kind<select name="kind"><option value="person">Person (counts in occupancy reports)</option><option value="thing" ${g && g.kind === 'thing' ? 'selected' : ''}>Thing</option></select></label>
    <label class="field">Notes<textarea name="notes" rows="2">${esc(g ? g.notes || '' : '')}</textarea></label>
    <label class="check"><input type="checkbox" name="watch" ${g && g.watch ? 'checked' : ''}> Watch <span class="faint">— alert when the group arrives / leaves</span></label>`,
  async f => {
    const body = { name: fv(f, 'name'), kind: fv(f, 'kind'), notes: fv(f, 'notes'), watch: fv(f, 'watch') };
    if (g) await send('PUT', `/api/groups/${g.id}`, body);
    else location.hash = `#/group/${(await send('POST', '/api/groups', body)).id}`;
    route();
  });
}

addRoute('/group/', async (id, params) => {
  const hours = +(params.get('range') || 168);
  const g = await api(`/api/groups/${id}?hours=${hours}`);
  const present = g.members.some(m => g.now - m.last_seen < 300);
  const colors = Object.fromEntries(Object.entries(KINDS).map(([k, v]) => [k, v.color]));
  const lanes = [['<b>Present</b>', g.presence.map(([a, b]) => ({ s: a, e: b, color: TEXT, title: `${dt(a)} → ${dt(b)} (${dur(b - a)})` }))]];
  g.members.forEach(m => lanes.push([`<a href="#/device/${enc(m.mac)}">${esc(m.label || m.name || m.mac)}</a>`,
    g.sessions.filter(s => s.mac === m.mac && s.type === 'presence').map(s => ({ s: s.start_ts, e: s.end_ts, color: colors[m.kind] || FAINT, title: `${dt(s.start_ts)} → ${dt(s.end_ts)}` }))]));
  const total = g.presence.reduce((a, [x, y]) => a + (y - x), 0);
  app.innerHTML = `<div class="page-head"><div><div class="crumbs"><a href="#/groups">Groups</a></div>
      <h1>${esc(g.name)} ${g.watch ? '<span class="star">★</span>' : ''}</h1><div class="sub"><span class="state-dot ${present ? 'on' : ''}"></span>${present ? 'Present now' : 'Away'} · ${g.kind} · ${g.members.length} devices</div></div>
      <div class="row">${seg('range', [[24, '24h'], [168, '7d'], [720, '30d']], hours)} ${adminBtn('edit-group', 'Edit')} ${adminBtn('del-group', 'Delete', 'danger')}</div></div>
    <div class="grid cols-3">
      <section class="panel span-3"><header><h2>Presence</h2><span class="faint">${dur(total)} present in this range · ${g.presence.length} visits</span></header><div class="body">${ganttHtml(lanes, g.since, g.now)}</div></section>
      <section class="panel span-2"><header><h2>Devices</h2>${isAdmin() ? '<button class="btn small" id="add-member">Add device</button>' : ''}</header><div class="body flush">${tableHtml(
        '<th>Device</th><th>Identified as</th><th>Signal</th><th class="num">Last seen</th>',
        g.members.map(m => `<tr class="link" data-href="#/device/${enc(m.mac)}"><td>${kindBadge(m.kind)} <b style="margin-left:6px">${esc(m.label || m.name || '')}</b> <span class="mono faint">${esc(m.mac)}</span></td>
          <td class="muted trunc">${esc((m.ident || {}).label || m.vendor || '—')}</td><td>${rssiBars(m.last_rssi)}</td><td class="num">${ago(m.last_seen)}</td></tr>`).join(''), 'No devices')}</div></section>
      <section class="panel"><header><h2>Events</h2></header><div class="body flush">${g.events.length ? `<ul class="events">${g.events.slice(0, 20).map(e => eventRow(e)).join('')}</ul>` : '<div class="empty">No events</div>'}</div></section>
    </div>`;
  linkRows(app);
  onSeg(app, 'range', v => { location.hash = hrefWith(`/group/${id}`, { range: v }); });
  const eb = document.getElementById('edit-group');
  if (eb) eb.onclick = () => groupModal(g);
  const db = document.getElementById('del-group');
  if (db) db.onclick = () => openModal('Delete group', `<p>Delete “${esc(g.name)}”? Its devices keep their labels but leave the group.</p>`,
    async () => { await send('DELETE', `/api/groups/${id}`); location.hash = '#/groups'; }, { submit: 'Delete', danger: true });
  const ab = document.getElementById('add-member');
  if (ab) ab.onclick = () => openModal('Add device to group', `<label class="field">MAC address(es)<textarea name="macs" rows="3" placeholder="aa:bb:cc:dd:ee:ff, one per line"></textarea></label>`,
    async f => { await send('POST', `/api/groups/${id}/members`, { macs: fv(f, 'macs').split(/[\s,]+/).filter(Boolean) }); route(); });
});

// ===================================================================== alerts
let ALERT_META = null;
async function alertMeta() { return ALERT_META || (ALERT_META = await api('/api/alerts/meta')); }

addRoute('/alerts', async (_, params) => {
  const tab = new URLSearchParams(location.hash.split('?')[1] || '').get('tab') || 'history';
  app.innerHTML = `<div class="page-head"><div><h1>Alerts</h1><div class="sub">Rules turn events into notifications. Without a notification channel, alerts are only listed here.</div></div>
    ${seg('tab', [['history', 'History'], ['rules', 'Rules']], tab)}</div><div id="alerts-body"></div>`;
  onSeg(app, 'tab', v => { history.replaceState(null, '', hrefWith('/alerts', { tab: v })); draw(v); });
  async function draw(t) {
    const el = document.getElementById('alerts-body');
    if (t === 'history') {
      const h = await api('/api/alerts?limit=200');
      el.innerHTML = `<section class="panel"><div class="body flush">${tableHtml('<th>Time</th><th>Severity</th><th>Alert</th><th>Rule</th><th>Delivered</th>',
        h.items.map(a => `<tr class="link" data-href="#/device/${enc(a.mac)}"><td class="muted">${dt(a.ts)}</td><td>${sevTag(a.severity)}</td>
          <td><b>${esc(a.title)}</b><div class="faint small-text">${esc((a.body || '').split('\n').slice(1, 3).join(' · '))}</div></td><td class="muted">${esc(a.rule_name)}</td>
          <td>${Object.entries(a.delivered || {}).map(([n, r]) => `<span class="tag ${r === 'ok' ? 'on' : 'bad'}" title="${esc(r)}">${esc(n)}</span>`).join(' ') || '<span class="faint">not sent</span>'}</td></tr>`).join(''),
        'No alerts yet')}</div></section>`;
      linkRows(el);
    } else {
      const [rules, meta, notifiers, groups] = await Promise.all([api('/api/alert-rules'), alertMeta(),
        isAdmin() ? api('/api/notifiers') : Promise.resolve([]), api('/api/groups')]);
      const nname = Object.fromEntries(notifiers.map(n => [n.id, n.name]));
      const target = r => ({ any: 'Any device', watchlist: 'Watched devices & groups', unknown: 'Unknown devices',
        macs: `${(r.target.macs || []).length} device(s)`, groups: (r.target.groups || []).map(id => (groups.find(g => g.id === id) || {}).name || id).join(', '),
        kinds: (r.target.kinds || []).map(k => (KINDS[k] || {}).short || typeLabel(k)).join(', ') }[r.target.mode] || r.target.mode);
      el.innerHTML = `<section class="panel"><header><h2>Rules</h2><div class="row">${isAdmin() ? '<a class="btn" href="#/settings?tab=notify">Notification channels</a> <button class="btn primary" id="new-rule">New rule</button>' : ''}</div></header>
        <div class="body flush">${tableHtml('<th>Rule</th><th>Events</th><th>Devices</th><th>When</th><th>Send to</th><th></th>',
        rules.map(r => `<tr><td><span class="state-dot ${r.enabled ? 'on' : ''}"></span><b>${esc(r.name)}</b></td>
          <td class="muted" style="white-space:normal">${r.events.map(e => esc(meta.events[e] || e)).join(', ')}</td><td class="muted">${esc(target(r))}</td>
          <td class="muted">${r.schedule && r.schedule.start ? `${esc(r.schedule.start)}–${esc(r.schedule.end)}` : 'Always'}${r.schedule && r.schedule.days && r.schedule.days.length ? ' · ' + r.schedule.days.map(d => WEEKDAYS[d]).join(' ') : ''}</td>
          <td>${(r.notifiers || []).map(id => `<span class="tag">${esc(nname[id] || '#' + id)}</span>`).join(' ') || '<span class="faint">history only</span>'}</td>
          <td class="num">${isAdmin() ? `<button class="btn small" data-edit="${r.id}">Edit</button>` : ''}</td></tr>`).join(''))}</div></section>`;
      const nb = document.getElementById('new-rule');
      if (nb) nb.onclick = () => ruleModal(null, meta, notifiers, groups, () => draw('rules'));
      el.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => ruleModal(rules.find(r => r.id === +b.dataset.edit), meta, notifiers, groups, () => draw('rules')));
    }
  }
  draw(tab);
});

function ruleModal(r, meta, notifiers, groups, done) {
  r = r || { name: '', enabled: 1, events: ['arrived', 'left'], target: { mode: 'watchlist' }, schedule: {}, notifiers: [], cooldown: 300 };
  const t = r.target || {}, sc = r.schedule || {};
  const kindOpts = [...Object.entries(KINDS).map(([k, v]) => [k, v.label]), ...Object.entries(DEV_TYPES)];
  const form = openModal(r.id ? 'Edit rule' : 'New alert rule', `
    <label class="field">Name<input name="name" value="${esc(r.name)}" required></label>
    <div class="field">Events<div class="checks">${Object.entries(meta.events).map(([k, l]) => `<label class="check"><input type="checkbox" name="ev" value="${k}" ${r.events.includes(k) ? 'checked' : ''}> ${esc(l)}</label>`).join('')}</div></div>
    <label class="field">Devices<select name="mode">${[['any', 'Any device'], ['watchlist', 'Watched devices & groups'], ['unknown', 'Unknown (not marked known)'], ['macs', 'Specific devices'], ['groups', 'Specific groups'], ['kinds', 'Device types']].map(([v, l]) => `<option value="${v}" ${t.mode === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
    <div class="tgt" data-mode="macs"><label class="field">MAC addresses<textarea name="macs" rows="2">${esc((t.macs || []).join('\n'))}</textarea></label></div>
    <div class="tgt" data-mode="groups"><div class="checks">${groups.map(g => `<label class="check"><input type="checkbox" name="grp" value="${g.id}" ${(t.groups || []).includes(g.id) ? 'checked' : ''}> ${esc(g.name)}</label>`).join('') || '<span class="faint">No groups yet</span>'}</div></div>
    <div class="tgt" data-mode="kinds"><div class="checks">${kindOpts.map(([k, l]) => `<label class="check"><input type="checkbox" name="knd" value="${k}" ${(t.kinds || []).includes(k) ? 'checked' : ''}> ${esc(l)}</label>`).join('')}</div></div>
    <div class="tgt" data-mode="unknown"><label class="check"><input type="checkbox" name="rand" ${t.randomized ? 'checked' : ''}> Include randomized MACs <span class="faint">(noisy: phones rotate addresses)</span></label>
      <label class="check"><input type="checkbox" name="aps" ${t.aps ? 'checked' : ''}> Include access points</label></div>
    <div class="field">Only between <span class="row"><input type="time" name="start" value="${esc(sc.start || '')}"> and <input type="time" name="end" value="${esc(sc.end || '')}"> <span class="faint">(empty = always)</span></span></div>
    <div class="field">On days <div class="checks">${WEEKDAYS.map((d, i) => `<label class="check"><input type="checkbox" name="day" value="${i}" ${(sc.days || []).includes(i) ? 'checked' : ''}> ${d}</label>`).join('')}</div></div>
    <div class="field">Send to <div class="checks">${notifiers.map(n => `<label class="check"><input type="checkbox" name="nt" value="${n.id}" ${(r.notifiers || []).includes(n.id) ? 'checked' : ''}> ${esc(n.name)} <span class="faint">${esc(n.type)}</span></label>`).join('') || '<span class="faint">No channels yet — add one under Settings → Notifications. Alerts still appear in the history.</span>'}</div></div>
    <label class="field">Cooldown per device (minutes)<input type="number" name="cooldown" min="0" value="${Math.round((r.cooldown || 0) / 60)}"></label>
    <label class="check"><input type="checkbox" name="enabled" ${r.enabled ? 'checked' : ''}> Enabled</label>
    ${r.id ? '<button type="button" class="btn danger small" id="del-rule">Delete rule</button>' : ''}`,
  async f => {
    const all = n => [...f.querySelectorAll(`input[name="${n}"]:checked`)].map(x => x.value);
    const mode = fv(f, 'mode');
    const target = { mode };
    if (mode === 'macs') target.macs = fv(f, 'macs').toLowerCase().split(/[\s,]+/).filter(Boolean);
    if (mode === 'groups') target.groups = all('grp').map(Number);
    if (mode === 'kinds') target.kinds = all('knd');
    if (mode === 'unknown') { target.randomized = fv(f, 'rand'); target.aps = fv(f, 'aps'); }
    const schedule = {};
    if (fv(f, 'start') && fv(f, 'end')) { schedule.start = fv(f, 'start'); schedule.end = fv(f, 'end'); }
    if (all('day').length) schedule.days = all('day').map(Number);
    const body = { name: fv(f, 'name'), enabled: fv(f, 'enabled'), events: all('ev'), target, schedule,
      notifiers: all('nt').map(Number), cooldown: (+fv(f, 'cooldown') || 0) * 60 };
    if (r.id) await send('PUT', `/api/alert-rules/${r.id}`, body); else await send('POST', '/api/alert-rules', body);
    toast('Rule saved');
    done();
  }, { wide: true });
  const sync = () => form.querySelectorAll('.tgt').forEach(x => { x.hidden = x.dataset.mode !== form.elements.mode.value; });
  form.elements.mode.onchange = sync;
  sync();
  const del = form.querySelector('#del-rule');
  if (del) del.onclick = async () => { if (confirm('Delete this rule?')) { await send('DELETE', `/api/alert-rules/${r.id}`); closeModal(); done(); } };
}

// ===================================================================== security
addRoute('/security', async () => {
  const s = await api('/api/security');
  const cnt = Object.fromEntries(s.counts.map(c => [c.severity, c.n]));
  const open = s.findings.filter(f => f.status !== 'resolved');
  app.innerHTML = `<div class="page-head"><div><h1>Security</h1><div class="sub">Evil-twin / rogue access points, deauthentication floods, KARMA-style APs and weak settings on your own networks.</div></div></div>
    <div class="grid cols-4">
      ${[['high', 'High'], ['medium', 'Medium'], ['low', 'Low']].map(([k, l]) => `<div class="card"><div class="label">${sevTag(k)} open findings</div><div class="value">${cnt[k] || 0}</div></div>`).join('')}
      <div class="card"><div class="label">My networks</div><div class="value" style="font-size:18px">${s.networks.ssids.map(esc).join(', ') || '<span class="faint">not set</span>'}</div>
        <div class="meta"><a href="#/settings?tab=networks">Configure</a></div></div>
    </div>
    ${!s.networks.ssids.length ? `<div class="callout">Add your own SSIDs under <a href="#/settings?tab=networks">Settings → My networks</a> and mark their access points as trusted to enable evil-twin detection and configuration checks.</div>` : ''}
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel span-3"><header><h2>Findings</h2><span class="faint">${open.length} open or acknowledged</span></header><div class="body flush">${tableHtml(
        '<th>Severity</th><th>Finding</th><th>Network / device</th><th class="num">Seen</th><th class="num">Last</th><th>Status</th><th></th>',
        s.findings.map(f => `<tr class="${f.status === 'resolved' ? 'dim' : ''}"><td>${sevTag(f.severity)}</td><td style="white-space:normal;min-width:280px"><b>${esc(f.title)}</b><div class="faint small-text">${esc(f.detail || '')}</div></td>
          <td>${esc(f.ssid || '')} ${f.mac ? devLink(f.mac) : ''}</td><td class="num muted">${num(f.count)}×</td><td class="num muted" title="first ${esc(dt(f.first_seen))}">${ago(f.last_seen)}</td>
          <td><span class="tag ${f.status === 'open' ? 'warn' : f.status === 'resolved' ? 'on' : ''}">${esc(f.status)}</span></td>
          <td class="num">${isAdmin() && f.status !== 'resolved' ? `${f.status === 'open' ? `<button class="btn small" data-f="${f.id}" data-s="acknowledged">Acknowledge</button>` : ''} <button class="btn small" data-f="${f.id}" data-s="resolved">Resolve</button>` : ''}</td></tr>`).join(''),
        'No findings — nothing suspicious seen yet')}</div></section>
      <section class="panel span-2"><header><h2>Access points broadcasting my networks</h2>${isAdmin() && s.bssids.some(b => !b.trusted) ? '<button class="btn small" id="trust-all">Trust all listed</button>' : ''}</header><div class="body flush">${tableHtml(
        '<th>BSSID</th><th>SSID</th><th>Ch</th><th>Security</th><th>Vendor</th><th class="num">First seen</th><th>Trusted</th>',
        s.bssids.map(b => `<tr><td>${devLink(b.mac)}${b.randomized ? ' <span class="tag warn">rand</span>' : ''}</td><td>${esc(b.ssid)}</td><td class="muted">${chText(b.channel, b.band)}</td>
          <td><span class="tag ${(b.enc || '').includes('OPN') ? 'bad' : ''}">${esc(b.enc || '—')}</span></td><td class="muted trunc">${esc(b.vendor || '—')}</td><td class="num muted">${ago(b.first_seen)}</td>
          <td>${isAdmin() ? `<label class="switch"><input type="checkbox" data-trust="${b.mac}" ${b.trusted ? 'checked' : ''}><span></span></label>` : (b.trusted ? 'yes' : 'no')}</td></tr>`).join(''),
        'No access points with your SSIDs seen yet')}</div></section>
      <section class="panel span-3" id="trackers"></section>
      <section class="panel"><header><h2>Security events</h2></header><div class="body flush">${s.events.length ? `<ul class="events">${s.events.slice(0, 30).map(e => eventRow(e)).join('')}</ul>` : '<div class="empty">None in the last 7 days</div>'}</div></section>
    </div>`;
  loadTrackers(document.getElementById('trackers'));
  app.querySelectorAll('[data-f]').forEach(b => b.onclick = async () => { await send('POST', `/api/security/findings/${b.dataset.f}`, { status: b.dataset.s }); route(); });
  app.querySelectorAll('[data-trust]').forEach(c => c.onchange = async () => {
    await send('POST', '/api/security/trust', { bssids: [c.dataset.trust], trust: c.checked });
    toast(c.checked ? 'Trusted' : 'No longer trusted');
  });
  const ta = document.getElementById('trust-all');
  if (ta) ta.onclick = async () => { await send('POST', '/api/security/trust', { bssids: s.bssids.map(b => b.mac), trust: true }); route(); };
});

// ===================================================================== channels
addRoute('/channels', async (_, params) => {
  const hours = +(params.get('hours') || 24);
  const c = await api(`/api/channels?hours=${hours}`);
  app.innerHTML = `<div class="page-head"><div><h1>Channels</h1><div class="sub">Estimated airtime use, retransmissions and noise per channel, measured while the sensor listens on each channel.</div></div>
    ${seg('hours', [[1, '1h'], [24, '24h'], [168, '7d']], hours)}</div>
    ${!c.has_survey ? '<div class="callout">No channel measurements yet. They appear once a Wi-Fi sensor has been hopping for a few minutes.</div>' : ''}
    ${c.advice.length ? `<section class="panel" style="margin-bottom:16px"><header><h2>Recommendations for my access points</h2></header><div class="body flush">${tableHtml(
      '<th>Access point</th><th>Band</th><th>Current</th><th>Recommended</th><th></th>', c.advice.map(a => `<tr><td>${esc(a.ssid)} ${devLink(a.mac)}</td><td class="muted">${a.band} GHz</td><td>ch ${a.channel}</td>
        <td>${a.change ? `<b>ch ${a.recommended}</b>` : `ch ${a.channel}`}</td><td class="muted">${a.change ? `less congested (score ${a.best_score} vs ${a.current_score})` : '<span class="tag on">already a good choice</span>'}</td></tr>`).join(''))}</div></section>` : ''}
    <div class="grid cols-3">
      ${['2.4', '5', '6'].map(b => { const rows = c.channels.filter(x => x.band === b); return `<section class="panel ${b === '6' && !rows.length ? '' : ''}"><header><h2>${b} GHz</h2><span class="faint">${rows.length} channels measured</span></header>
        <div class="body"><div class="chart-box short"><canvas id="ch-${b.replace('.', '')}"></canvas></div>
        <h3 class="subhead">Best channels</h3><ol class="rank">${(c.recommend[b] || []).slice(0, 3).map(r => `<li><b>ch ${r.channel}</b> <span class="faint">${r.aps} AP${r.aps === 1 ? '' : 's'}${r.utilization != null ? ` · ${Math.round(r.utilization * 100)}% busy` : ''}${r.dfs ? ' · DFS' : ''}${r.note ? ' · ' + r.note : ''}</span></li>`).join('')}</ol></div></section>`; }).join('')}
      <section class="panel span-3"><header><h2>All channels</h2><span class="faint">click a row for its history</span></header><div class="body flush">${tableHtml(
        '<th>Channel</th><th class="num">APs</th><th class="num">Strongest</th><th class="num">Airtime</th><th class="num">Retries</th><th class="num">Noise</th><th class="num">Frames/s</th>',
        c.channels.map(x => `<tr class="link" data-freq="${x.freq}"><td>${chText(x.channel, x.band)} <span class="faint">${x.freq} MHz</span></td><td class="num">${x.aps}</td><td class="num">${x.strongest != null ? x.strongest + ' dBm' : '—'}</td>
          <td class="num"><span class="meter"><i style="width:${Math.round((x.utilization || 0) * 100)}%"></i></span> ${x.utilization != null ? Math.round(x.utilization * 100) + '%' : '—'}</td>
          <td class="num">${x.retry_rate != null ? (x.retry_rate * 100).toFixed(1) + '%' : '—'}</td><td class="num muted">${x.noise != null ? x.noise + ' dBm' : '—'}</td><td class="num muted">${x.fps ?? '—'}</td></tr>`).join(''), 'No measurements')}</div></section>
      <section class="panel span-3" id="intf"></section>
      <section class="panel span-3" id="ch-hist" hidden><header><h2 id="ch-hist-title">History</h2></header><div class="body"><div class="chart-box short"><canvas id="ch-tl"></canvas></div></div></section>
    </div>`;
  onSeg(app, 'hours', v => { location.hash = hrefWith('/channels', { hours: v }); });
  loadInterference(document.getElementById('intf'), Math.max(1, Math.min(30, hours / 24)));
  ['2.4', '5', '6'].forEach(b => {
    const rows = c.channels.filter(x => x.band === b);
    const el = document.getElementById(`ch-${b.replace('.', '')}`);
    if (!rows.length) { el.parentElement.innerHTML = '<div class="empty">Not measured (no adapter for this band, or not in the channel list)</div>'; return; }
    chart(el, { type: 'bar', data: { labels: rows.map(x => x.channel), datasets: [
      { label: 'Airtime %', data: rows.map(x => Math.round((x.utilization || 0) * 100)), backgroundColor: (BANDS[b] || {}).color + 'cc', borderRadius: 2, maxBarThickness: 28 },
      { label: 'Retries %', data: rows.map(x => +((x.retry_rate || 0) * 100).toFixed(1)), type: 'line', borderColor: KINDS.bt_classic.color, pointRadius: 2, borderWidth: 1.5 }] },
      options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { color: FAINT } }, y: yScale({ max: 100, ticks: { color: FAINT, callback: v => v + '%' } }) } } });
  });
  app.querySelectorAll('tr[data-freq]').forEach(tr => tr.onclick = async () => {
    const f = +tr.dataset.freq, t = await api(`/api/channels/timeline?freq=${f}&hours=${hours}`);
    const box = document.getElementById('ch-hist');
    box.hidden = false;
    document.getElementById('ch-hist-title').textContent = `History · ${tr.cells[0].textContent}`;
    const now = Date.now() / 1000;
    chart(document.getElementById('ch-tl'), { type: 'line', data: { datasets: [
      { label: 'Airtime %', data: t.points.map(p => ({ x: p.t, y: Math.round((p.util || 0) * 100) })), borderColor: KINDS.ap.color, pointRadius: 0, borderWidth: 1.5, tension: .3 },
      { label: 'Retries %', data: t.points.map(p => ({ x: p.t, y: +((p.retry || 0) * 100).toFixed(1) })), borderColor: KINDS.bt_classic.color, pointRadius: 0, borderWidth: 1.2, tension: .3 }] },
      options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, scales: { x: { ...timeScale(hours * 3600), min: now - hours * 3600, max: now }, y: yScale({ ticks: { color: FAINT, callback: v => v + '%' } }) },
        plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 8, boxHeight: 8, color: MUTED } }, tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } } } });
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
});

// ===================================================================== my networks
addRoute('/mynet', async (_, params) => {
  const days = +(params.get('days') || 7);
  const n = await api(`/api/mynet?days=${days}`);
  if (!n.configured) {
    app.innerHTML = `<div class="page-head"><div><h1>My networks</h1></div></div><div class="callout">Tell yolo which SSIDs are yours under <a href="#/settings?tab=networks">Settings → My networks</a> to see client health, roaming and band use.</div>`;
    return;
  }
  const s = n.summary || {};
  app.innerHTML = `<div class="page-head"><div><h1>My networks</h1><div class="sub">${n.ssids.map(esc).join(', ')}</div></div>${seg('days', [[1, '24h'], [7, '7 days'], [30, '30 days']], days)}</div>
    <div class="grid cols-4">${[['Clients', s.clients, 'seen in range'], ['Connected now', s.connected_now, ''], ['Roams', s.roams, `${s.pingpong || 0} ping-pong`],
      ['Sticky clients', s.sticky, `weak signal (< -75 dBm) while another AP exists`]].map(([l, v, m]) => `<div class="card"><div class="label">${l}</div><div class="value">${num(v)}</div><div class="meta">${m}</div></div>`).join('')}</div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel span-2"><header><h2>Connected clients over time</h2><span class="legend">${n.ssids.map((x, i) => `<span><span class="swatch" style="background:${[KINDS.wifi_client.color, KINDS.ap.color, KINDS.ble.color, KINDS.bt_classic.color][i % 4]}"></span>${esc(x)}</span>`).join('')}</span></header><div class="body"><div class="chart-box"><canvas id="mn-tl"></canvas></div></div></section>
      <section class="panel"><header><h2>Band use</h2><span class="faint">share of connected time</span></header><div class="body"><ul class="bars-list">${BAND_LIST.filter(([b]) => n.band_share[b] != null).map(([b, m]) => `<li><div><div class="name">${m.label}</div><div class="track"><i style="width:${n.band_share[b] * 100}%;background:${m.color}"></i></div></div><div class="n">${Math.round(n.band_share[b] * 100)}%</div></li>`).join('') || '<div class="empty">No data</div>'}</ul>
        <h3 class="subhead">Disconnect reasons</h3><ul class="bars-list">${n.disconnect_reasons.map(([r, c]) => `<li><div><div class="name">${esc(r)}</div></div><div class="n">${c}</div></li>`).join('') || '<div class="faint">None</div>'}</ul></div></section>
      <section class="panel span-3"><header><h2>Access points</h2></header><div class="body flush">${tableHtml('<th>BSSID</th><th>SSID</th><th>Channel</th><th>Wi-Fi</th><th>Security</th><th>Signal</th><th class="num">Clients now</th><th class="num">Clients in range</th>',
        n.aps.map(a => `<tr class="link" data-href="#/device/${enc(a.mac)}"><td class="mono">${esc(a.mac)}${a.trusted ? '' : ' <span class="tag bad" title="Not on your trusted list — see Security">untrusted</span>'}</td><td>${esc(a.ssid)}</td><td>${chText(a.channel, a.band)}</td><td class="muted">${a.wifi_gen ? genLabel(a.wifi_gen) : '—'}</td>
          <td class="muted">${esc(a.enc || '—')}</td><td>${rssiBars(a.last_rssi)}</td><td class="num">${a.clients_now}</td><td class="num muted">${a.clients_total}</td></tr>`).join(''))}</div></section>
      <section class="panel span-3"><header><h2>Clients</h2><span class="faint">sorted by connected time</span></header><div class="body flush">${tableHtml(
        '<th>Client</th><th>Connected to</th><th class="num">Signal now</th><th class="num">Avg signal</th><th class="num">Time</th><th class="num">Sessions</th><th class="num">APs</th><th class="num">Roams</th><th class="num">Kicked</th><th>Flags</th>',
        n.clients.map(c => `<tr class="link" data-href="#/device/${enc(c.mac)}"><td>${c.label ? `<b>${esc(c.label)}</b>` : esc(c.name || c.ident || c.vendor || '')} <span class="mono faint">${esc(c.mac)}</span></td>
          <td>${c.connected_to ? `${esc(c.connected_ssid)} <span class="faint">${c.connected_band}G</span>` : '<span class="faint">—</span>'}</td>
          <td class="num">${c.rssi_now != null ? c.rssi_now + ' dBm' : '—'}</td><td class="num muted">${c.avg_rssi != null ? c.avg_rssi + ' dBm' : '—'}</td><td class="num">${dur(c.secs)}</td>
          <td class="num muted">${c.sessions}</td><td class="num muted">${c.aps}</td><td class="num">${c.roams}${c.pingpong ? ` <span class="tag warn" title="A→B→A within 2 minutes">${c.pingpong} ping-pong</span>` : ''}</td>
          <td class="num ${c.kicked ? '' : 'muted'}">${c.kicked}</td><td>${c.sticky ? '<span class="tag warn">sticky</span>' : ''}${c.connected_band === '2.4' && c.wifi_gen >= 5 ? ' <span class="tag" title="Supports 5 GHz but is on 2.4 GHz">on 2.4G</span>' : ''}</td></tr>`).join(''))}</div></section>
    </div>`;
  linkRows(app);
  onSeg(app, 'days', v => { location.hash = hrefWith('/mynet', { days: v }); });
  const colors = [KINDS.wifi_client.color, KINDS.ap.color, KINDS.ble.color, KINDS.bt_classic.color];
  const tl = n.timeline;
  chart(document.getElementById('mn-tl'), { type: 'line', data: { datasets: Object.entries(tl.series).map(([ssid, v], i) => ({
    label: ssid, data: tl.t.map((x, j) => ({ x, y: v[j] })), borderColor: colors[i % 4], backgroundColor: colors[i % 4] + '18', fill: true, stepped: true, pointRadius: 0, borderWidth: 1.5 })) },
    options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, scales: { x: { ...timeScale(days * 86400), min: tl.t[0], max: tl.t[tl.t.length - 1] }, y: yScale() },
      plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } } } });
});

// ===================================================================== map
addRoute('/map', async (_, params) => {
  let filter = params.get('show') || 'all', editing = false;
  app.innerHTML = `<div class="page-head"><div><h1>Map</h1><div class="sub">Room = sensor that hears a device best. Position = signal-weighted average of the sensors that hear it (approximate).</div></div>
    <div class="row">${seg('show', [['all', 'All'], ['people', 'Phones & wearables'], ['labelled', 'Labelled']], filter)} ${isAdmin() ? '<button class="btn" id="edit-map">Edit layout</button>' : ''}</div></div>
    <div class="grid cols-3"><section class="panel span-2"><div class="body"><div class="map" id="map"></div><div id="map-tools" hidden class="map-tools">
      <label class="btn">Upload floor plan<input type="file" id="fp-file" accept="image/png,image/jpeg,image/webp,image/svg+xml" hidden></label>
      <button class="btn" id="fp-del">Remove floor plan</button><span class="faint">Drag sensors onto their real position. Set room names under Settings → Sensors.</span></div></div></section>
      <section class="panel"><header><h2>Rooms</h2></header><div class="body" id="rooms"></div></section></div>`;
  onSeg(app, 'show', v => { filter = v; draw(); });
  let data = null;
  async function load() { data = await api('/api/map'); draw(); }
  function draw() {
    if (!data) return;
    const m = document.getElementById('map');
    const fp = data.floorplan;
    const ratio = fp.width && fp.height ? fp.height / fp.width : 0.64;
    m.style.paddingTop = `${ratio * 100}%`;
    m.style.backgroundImage = fp.image ? `url(/api/floorplan/image?v=${fp.updated || fp.width || 1})` : '';
    const show = d => filter === 'all' || (filter === 'labelled' ? d.label : ['phone', 'watch', 'wearable', 'headphones'].includes(d.dev_type));
    const devs = data.devices.filter(d => d.pos_x != null && show(d));
    m.innerHTML = `${!fp.image ? '<div class="map-empty">No floor plan uploaded' + (isAdmin() ? ' — use “Edit layout”' : '') + '</div>' : ''}
      ${data.sensors.filter(s => s.x != null || editing).map((s, i) => `<div class="sensor-pin ${s.online ? '' : 'off'} ${editing ? 'drag' : ''}" data-sid="${esc(s.id)}" style="left:${(s.x ?? 0.05 + i * 0.08) * 100}%;top:${(s.y ?? 0.06) * 100}%" title="${esc(s.name)}"><span>${esc(s.room || s.name)}</span></div>`).join('')}
      ${devs.map(d => `<a class="dev-dot ${d.watch ? 'watch' : ''}" href="#/device/${enc(d.mac)}" style="left:${d.pos_x * 100}%;top:${d.pos_y * 100}%;background:${(KINDS[d.kind] || {}).color}" title="${esc(d.label_text)}${d.room ? ' · ' + esc(d.room) : ''}">${d.watch && d.label ? `<span>${esc(d.label)}</span>` : ''}</a>`).join('')}`;
    const rooms = Object.entries(data.rooms).sort((a, b) => b[1].devices - a[1].devices);
    document.getElementById('rooms').innerHTML = rooms.length ? `<ul class="bars-list">${rooms.map(([r, c]) => `<li><div><div class="name">${esc(r)}</div><div class="faint small-text">${c.devices} devices · ${c.people} phones</div></div><div class="n">${c.devices}</div></li>`).join('')}</ul>
      <h3 class="subhead">Labelled devices</h3><ul class="plain">${data.devices.filter(d => d.label && d.room).map(d => `<li><a href="#/device/${enc(d.mac)}">${esc(d.label)}</a> <span class="faint">${esc(d.room)}</span></li>`).join('') || '<li class="faint">none present</li>'}</ul>`
      : '<div class="faint">Rooms appear once sensors have a room name (Settings → Sensors). With more than one sensor, devices are assigned to the room of the sensor that hears them best.</div>';
    if (editing) bindDrag(m);
  }
  function bindDrag(m) {
    m.querySelectorAll('.sensor-pin').forEach(pin => {
      pin.onpointerdown = e => {
        e.preventDefault();
        pin.setPointerCapture(e.pointerId);
        const rect = m.getBoundingClientRect();
        const move = ev => {
          pin.style.left = `${Math.min(1, Math.max(0, (ev.clientX - rect.left) / rect.width)) * 100}%`;
          pin.style.top = `${Math.min(1, Math.max(0, (ev.clientY - rect.top) / rect.height)) * 100}%`;
        };
        pin.onpointermove = move;
        pin.onpointerup = async ev => {
          pin.onpointermove = pin.onpointerup = null;
          move(ev);
          await send('PUT', `/api/sensors/${enc(pin.dataset.sid)}`, { x: parseFloat(pin.style.left) / 100, y: parseFloat(pin.style.top) / 100 });
          toast('Sensor position saved');
        };
      };
    });
  }
  const eb = document.getElementById('edit-map');
  if (eb) eb.onclick = () => {
    editing = !editing;
    eb.classList.toggle('primary', editing);
    eb.textContent = editing ? 'Done' : 'Edit layout';
    document.getElementById('map-tools').hidden = !editing;
    if (!editing) load(); else draw();
  };
  const file = document.getElementById('fp-file');
  file.onchange = async () => {
    const f = file.files[0];
    if (!f) return;
    const url = URL.createObjectURL(f);
    const img = new Image();
    img.onload = async () => {
      const r = await fetch(`/api/floorplan?width=${img.naturalWidth || 1000}&height=${img.naturalHeight || 640}`, { method: 'POST', headers: { 'Content-Type': f.type, 'X-Yolo': '1' }, body: f });
      if (!r.ok) toast((await r.json()).detail || 'Upload failed', true); else { toast('Floor plan uploaded'); load(); }
      URL.revokeObjectURL(url);
    };
    img.src = url;
  };
  document.getElementById('fp-del').onclick = async () => { await send('DELETE', '/api/floorplan'); load(); };
  await load();
  every(10000, () => { if (!editing) load(); });
});

// ===================================================================== reports
addRoute('/reports', async (_, params) => {
  const days = +(params.get('days') || 7);
  const r = await api(`/api/reports/occupancy?days=${days}&tz=${TZ}`);
  const s = r.summary;
  const rcfg = await api('/api/settings/report');
  app.innerHTML = `<div class="page-head"><div><h1>Occupancy report</h1><div class="sub">${dt(r.since)} – ${dt(r.until)}</div></div>
    <div class="row no-print">${seg('days', [[7, '7 days'], [14, '14 days'], [30, '30 days']], days)} <button class="btn" id="print">Print / PDF</button>${isAdmin() ? ' <button class="btn" id="send-now">Email weekly report now</button>' : ''}</div></div>
    <div class="grid cols-4">${[['People (estimated)', s.unique, `${s.new} new`], ['Average present', s.avg_present, 'per hour'], ['Peak', s.peak, s.peak_at ? new Date(s.peak_at * 1000).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' }) : ''],
      ['Median visit', dur(s.median_dwell), 'per person per day']].map(([l, v, m]) => `<div class="card"><div class="label">${l}</div><div class="value">${v}</div><div class="meta">${esc(m)}</div></div>`).join('')}</div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel span-3"><header><h2>People present per hour</h2></header><div class="body"><div class="chart-box"><canvas id="occ"></canvas></div></div></section>
      <section class="panel span-2"><header><h2>Typical week</h2><span class="faint">average people present</span></header><div class="body" id="occ-heat"></div></section>
      <section class="panel"><header><h2>Weekly email</h2></header><div class="body small-text">${rcfg.email ? `Sent every ${WEEKDAYS[rcfg.weekday]} at ${String(rcfg.hour).padStart(2, '0')}:00${rcfg.last_sent ? `; last sent ${dt(rcfg.last_sent)}` : ''}.` : 'Not scheduled.'} <a href="#/settings?tab=report" class="no-print">Configure</a></div></section>
      <section class="panel span-3"><header><h2>Per day</h2></header><div class="body flush">${tableHtml('<th>Day</th><th class="num">People</th><th class="num">New</th><th class="num">Returning</th><th class="num">Peak</th><th class="num">Median visit</th>',
        r.days.slice().reverse().map(d => `<tr><td>${new Date(d.day * 1000).toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' })}</td><td class="num">${d.people}</td><td class="num muted">${d.new}</td><td class="num muted">${d.returning}</td><td class="num">${d.peak}</td><td class="num">${dur(d.median_dwell)}</td></tr>`).join(''), 'No data in this range')}</div></section>
    </div><p class="faint small-text" style="margin-top:12px">${esc(r.method)}</p>`;
  onSeg(app, 'days', v => { location.hash = hrefWith('/reports', { days: v }); });
  document.getElementById('print').onclick = () => window.print();
  const sn = document.getElementById('send-now');
  if (sn) sn.onclick = async () => { try { await send('POST', '/api/reports/send'); toast('Report sent'); } catch (e) { toast(e.message, true); } };
  chart(document.getElementById('occ'), { type: 'line', data: { datasets: [{ label: 'People', data: r.t.map((x, i) => ({ x, y: r.series[i] })), borderColor: KINDS.wifi_client.color, backgroundColor: KINDS.wifi_client.color + '22', fill: true, stepped: true, pointRadius: 0, borderWidth: 1.5 }] },
    options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, scales: { x: { ...timeScale(days * 86400), min: r.t[0], max: r.t[r.t.length - 1] }, y: yScale() }, plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } } } });
  const max = Math.max(1, ...r.heat.flat());
  let html = '<div class="heat"><span></span>' + Array.from({ length: 24 }, (_, i) => `<span class="h">${i % 3 === 0 ? i : ''}</span>`).join('');
  r.heat.forEach((row, di) => { html += `<span class="d">${WEEKDAYS[di]}</span>` + row.map((v, hi) => `<span class="cell" title="${WEEKDAYS[di]} ${hi}:00 — ${v} people" style="${v ? `background:${KINDS.wifi_client.color};opacity:${(0.15 + 0.85 * v / max).toFixed(2)}` : ''}"></span>`).join(''); });
  document.getElementById('occ-heat').innerHTML = html + '</div>';
});

// ===================================================================== settings
const SETTINGS_TABS = [['account', 'Account'], ['users', 'Users'], ['networks', 'My networks'], ['ignore', 'Ignore list'], ['sensors', 'Sensors'],
  ['notify', 'Notifications'], ['report', 'Weekly report'], ['security', 'Detection'], ['tokens', 'API tokens'], ['backup', 'Backup']];

addRoute('/settings', async (_, params) => {
  const tabs = isAdmin() ? SETTINGS_TABS : SETTINGS_TABS.filter(([k]) => ['account', 'networks', 'ignore'].includes(k));
  let tab = params.get('tab') || 'account';
  app.innerHTML = `<div class="page-head"><div><h1>Settings</h1></div></div><div class="settings"><nav class="subnav">${tabs.map(([k, l]) => `<a href="${hrefWith('/settings', { tab: k })}" class="${k === tab ? 'active' : ''}">${l}</a>`).join('')}</nav><div id="set-body" class="set-body"></div></div>`;
  const el = document.getElementById('set-body');
  const fn = SETTINGS_VIEWS[tab] || SETTINGS_VIEWS.account;
  await fn(el);
});

const SETTINGS_VIEWS = {
  async account(el) {
    el.innerHTML = `<section class="panel"><header><h2>Account</h2></header><div class="body"><p>Signed in as <b>${esc(ME.username)}</b> (${esc(ME.role)}).</p>
      <form id="pw" class="form-narrow"><label class="field">Current password<input type="password" name="current" autocomplete="current-password" required></label>
      <label class="field">New password<input type="password" name="password" autocomplete="new-password" minlength="10" required></label>
      <label class="field">Repeat new password<input type="password" name="password2" autocomplete="new-password" required></label>
      <button class="btn primary">Change password</button> <span class="faint small-text">You'll be signed out everywhere.</span></form></div></section>`;
    el.querySelector('#pw').onsubmit = async e => {
      e.preventDefault();
      const f = e.target;
      if (fv(f, 'password') !== fv(f, 'password2')) return toast('Passwords do not match', true);
      try { await send('POST', '/api/me/password', { current: f.elements.current.value, password: f.elements.password.value }); location.href = '/login'; } catch (err) { toast(err.message, true); }
    };
  },
  async users(el) {
    const us = await api('/api/users');
    el.innerHTML = `<section class="panel"><header><h2>Users</h2><button class="btn primary" id="add-user">Add user</button></header><div class="body flush">${tableHtml('<th>User</th><th>Role</th><th class="num">Last login</th><th></th>',
      us.map(u => `<tr><td><b>${esc(u.username)}</b>${u.from_env ? ' <span class="tag">from WEB_USER</span>' : ''}${u.username === ME.username ? ' <span class="faint">(you)</span>' : ''}</td>
        <td>${u.username === ME.username ? esc(u.role) : `<select data-role="${u.id}">${['admin', 'viewer'].map(r => `<option ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}</select>`}</td>
        <td class="num muted">${u.last_login ? ago(u.last_login) : 'never'}</td><td class="num">${u.username !== ME.username ? `<button class="btn small danger" data-del="${u.id}">Delete</button>` : ''}</td></tr>`).join(''))}
      </div></section><p class="faint small-text">Admins can change settings, labels, alert rules and the ignore list. Viewers can only look.</p>`;
    el.querySelector('#add-user').onclick = () => openModal('Add user', `<label class="field">Username<input name="username" required autocomplete="off"></label>
      <label class="field">Password<input type="password" name="password" minlength="10" required autocomplete="new-password"></label>
      <label class="field">Role<select name="role"><option value="viewer">Viewer (read-only)</option><option value="admin">Admin</option></select></label>`,
    async f => { await send('POST', '/api/users', { username: fv(f, 'username'), password: f.elements.password.value, role: fv(f, 'role') }); SETTINGS_VIEWS.users(el); });
    el.querySelectorAll('[data-role]').forEach(s => s.onchange = async () => { await send('POST', `/api/users/${s.dataset.role}/role`, { role: s.value }); toast('Role changed'); });
    el.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { if (confirm('Delete this user?')) { try { await send('DELETE', `/api/users/${b.dataset.del}`); SETTINGS_VIEWS.users(el); } catch (e) { toast(e.message, true); } } });
  },
  async networks(el) {
    const [n, st] = await Promise.all([api('/api/settings/networks'), api('/api/stats?days=30')]);
    let ssids = [...n.ssids];
    const render = () => {
      el.innerHTML = `<section class="panel"><header><h2>My networks</h2></header><div class="body">
        <p class="muted">SSIDs you own. Enables the <a href="#/mynet">My networks</a> health view, evil-twin detection and configuration checks on the <a href="#/security">Security</a> page.</p>
        <div class="chips">${ssids.map((s, i) => `<span class="chip">${esc(s)}${isAdmin() ? `<a href="#" data-rm="${i}">✕</a>` : ''}</span>`).join('') || '<span class="faint">None yet</span>'}</div>
        ${isAdmin() ? `<form id="add-ssid" class="row" style="margin-top:12px"><input name="ssid" list="seen-ssids" placeholder="SSID" required><datalist id="seen-ssids">${st.ssids.map(x => `<option value="${esc(x.ssid)}">`).join('')}</datalist><button class="btn">Add</button></form>
        <div style="margin-top:16px"><button class="btn primary" id="save-net">Save</button></div>` : ''}
        ${n.bssids.length ? `<h3 class="subhead">Access points broadcasting them</h3>${tableHtml('<th>BSSID</th><th>SSID</th><th>Channel</th><th>Security</th><th>Trusted</th>',
          n.bssids.map(b => `<tr><td>${devLink(b.mac)}</td><td>${esc(b.ssid)}</td><td>${chText(b.channel, b.band)}</td><td class="muted">${esc(b.enc || '')}</td><td>${n.trusted_bssids.includes(b.mac) ? '<span class="tag on">yes</span>' : '<span class="tag">no</span>'}</td></tr>`).join(''))}
          <p class="faint small-text">Mark trusted access points on the <a href="#/security">Security</a> page.</p>` : ''}</div></section>`;
      el.querySelectorAll('[data-rm]').forEach(a => a.onclick = e => { e.preventDefault(); ssids.splice(+a.dataset.rm, 1); render(); });
      const f = el.querySelector('#add-ssid');
      if (f) f.onsubmit = e => { e.preventDefault(); const v = fv(f, 'ssid'); if (v && !ssids.includes(v)) ssids.push(v); render(); };
      const sv = el.querySelector('#save-net');
      if (sv) sv.onclick = async () => { await send('PUT', '/api/settings/networks', { ssids, trusted_bssids: n.trusted_bssids }); toast('Saved'); };
    };
    render();
  },
  async ignore(el) {
    const ig = await api('/api/settings/ignore');
    const ro = !isAdmin();
    el.innerHTML = `<section class="panel"><header><h2>Ignore list</h2></header><div class="body">
      <p class="muted">Matching devices and networks are dropped before anything is stored — they won't appear anywhere and won't trigger alerts.</p>
      <form id="ig" class="form-narrow">
        <label class="field">Devices (MAC addresses, one per line)<textarea name="macs" rows="4" ${ro ? 'readonly' : ''} placeholder="aa:bb:cc:dd:ee:ff">${esc(ig.macs.join('\n'))}</textarea></label>
        <label class="field">Vendor prefixes (first 3–5 bytes, one per line)<textarea name="prefixes" rows="3" ${ro ? 'readonly' : ''} placeholder="24:0a:c4">${esc(ig.prefixes.join('\n'))}</textarea></label>
        <div class="field">Networks (SSIDs)<div id="ig-ssids"></div>${ro ? '' : '<button type="button" class="btn small" id="add-ig">Add network</button>'}</div>
        ${ro ? '' : `<label class="check"><input type="checkbox" name="purge"> Also delete data already stored for matching devices</label>
        <div class="row" style="margin-top:12px"><button class="btn primary">Save</button><span class="faint small-text" id="ig-preview"></span></div>`}
      </form></div></section>`;
    const list = el.querySelector('#ig-ssids');
    const rows = ig.ssids.map(x => ({ ...x }));
    const draw = () => {
      list.innerHTML = rows.map((r, i) => `<div class="row ig-row"><input data-i="${i}" class="ig-ssid" value="${esc(r.ssid)}" placeholder="SSID" ${ro ? 'readonly' : ''}>
        <label class="check"><input type="checkbox" data-c="${i}" ${r.clients ? 'checked' : ''} ${ro ? 'disabled' : ''}> also ignore its clients</label>${ro ? '' : `<a href="#" data-x="${i}">✕</a>`}</div>`).join('') || '<div class="faint small-text">No networks ignored</div>';
      list.querySelectorAll('.ig-ssid').forEach(x => x.oninput = () => { rows[+x.dataset.i].ssid = x.value.trim(); });
      list.querySelectorAll('[data-c]').forEach(x => x.onchange = () => { rows[+x.dataset.c].clients = x.checked; });
      list.querySelectorAll('[data-x]').forEach(x => x.onclick = e => { e.preventDefault(); rows.splice(+x.dataset.x, 1); draw(); });
    };
    draw();
    if (ro) return;
    el.querySelector('#add-ig').onclick = () => { rows.push({ ssid: '', clients: false }); draw(); };
    const form = el.querySelector('#ig');
    const body = () => ({ macs: fv(form, 'macs').split(/\s+/).filter(Boolean), prefixes: fv(form, 'prefixes').split(/\s+/).filter(Boolean),
      ssids: rows.filter(r => r.ssid), purge: fv(form, 'purge') });
    const preview = async () => { const p = await send('POST', '/api/settings/ignore/preview', body()); el.querySelector('#ig-preview').textContent = `${p.devices} stored device${p.devices === 1 ? '' : 's'} match`; };
    form.addEventListener('change', preview);
    preview();
    form.onsubmit = async e => {
      e.preventDefault();
      const b = body();
      if (b.purge && !confirm('Permanently delete stored data for all matching devices?')) return;
      const r = await send('PUT', '/api/settings/ignore', b);
      toast(r.purged ? `Saved · purging ${r.purged} devices` : 'Saved');
    };
  },
  async sensors(el) {
    const ss = await api('/api/sensors');
    el.innerHTML = `<section class="panel"><header><h2>Sensors</h2><button class="btn primary" id="add-sensor">Add remote sensor</button></header><div class="body flush">${tableHtml(
      '<th>Sensor</th><th>Room</th><th>Status</th><th class="num">Last report</th><th>On map</th><th></th>',
      ss.map(s => { const st = (s.info && s.info.status) || []; return `<tr><td><b>${esc(s.name)}</b> <span class="mono faint">${esc(s.id)}</span></td><td>${esc(s.room || '—')}</td>
        <td>${s.online ? '<span class="tag on">online</span>' : '<span class="tag bad">offline</span>'} <span class="faint">${st.map(x => `${esc(x.name)} ${x.pps || 0} pkt/s`).join(', ')}</span></td>
        <td class="num muted">${s.id === 'local' ? '—' : ago(s.last_seen)}</td><td>${s.x != null ? 'placed' : '<span class="faint">not placed</span>'}</td>
        <td class="num"><button class="btn small" data-edit="${esc(s.id)}">Edit</button>${s.id !== 'local' ? ` <button class="btn small danger" data-del="${esc(s.id)}">Remove</button>` : ''}</td></tr>`; }).join(''))}</div></section>
      <p class="faint small-text">A remote sensor is this same container started with <code>YOLO_MODE=sensor</code> on another machine (e.g. a Raspberry Pi in another room). It forwards everything it captures here. Give each sensor a room name, then place it on the <a href="#/map">map</a>.</p>`;
    el.querySelector('#add-sensor').onclick = () => openModal('Add remote sensor', `<label class="field">Name<input name="name" required placeholder="e.g. Garage Pi"></label><label class="field">Room<input name="room" placeholder="e.g. Garage"></label>`,
      async f => {
        const r = await send('POST', '/api/sensors', { name: fv(f, 'name'), room: fv(f, 'room') || null });
        setTimeout(() => openModal(`Sensor “${r.id}” created`, `<p>Run this on the sensor machine (after connecting its adapters as in the README). <b>The token is shown only once.</b></p>
          <pre class="code" id="cmd">docker run -d --name yolo-sensor --restart unless-stopped --network host --privileged \\
  -e YOLO_MODE=sensor -e SERVER_URL=${esc(r.server_url)} \\
  -e SENSOR_TOKEN=${esc(r.token)} \\
  -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 \\
  yolo:latest</pre><button type="button" class="btn small" id="copy">Copy</button>`, null), 50);
        setTimeout(() => { const c = document.getElementById('copy'); if (c) c.onclick = () => navigator.clipboard.writeText(document.getElementById('cmd').textContent).then(() => toast('Copied')); }, 100);
        SETTINGS_VIEWS.sensors(el);
      });
    el.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => { const s = ss.find(x => x.id === b.dataset.edit);
      openModal(`Edit sensor ${s.id}`, `<label class="field">Name<input name="name" value="${esc(s.name)}"></label><label class="field">Room<input name="room" value="${esc(s.room || '')}"></label>
        <label class="check"><input type="checkbox" name="clear"> Remove from map</label>`,
      async f => { await send('PUT', `/api/sensors/${enc(s.id)}`, { name: fv(f, 'name'), room: fv(f, 'room'), clear_position: fv(f, 'clear') }); SETTINGS_VIEWS.sensors(el); }); });
    el.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { if (confirm('Remove this sensor and revoke its token?')) { await send('DELETE', `/api/sensors/${enc(b.dataset.del)}`); SETTINGS_VIEWS.sensors(el); } });
  },
  async notify(el) {
    const [ns, meta] = await Promise.all([api('/api/notifiers'), alertMeta()]);
    el.innerHTML = `<section class="panel"><header><h2>Notification channels</h2><button class="btn primary" id="add-n">Add channel</button></header><div class="body flush">${tableHtml(
      '<th>Name</th><th>Type</th><th></th>', ns.map(n => `<tr><td><span class="state-dot ${n.enabled ? 'on' : ''}"></span><b>${esc(n.name)}</b></td><td class="muted">${esc(n.type)}</td>
        <td class="num"><button class="btn small" data-test="${n.id}">Send test</button> <button class="btn small" data-edit="${n.id}">Edit</button> <button class="btn small danger" data-del="${n.id}">Delete</button></td></tr>`).join(''),
      'No channels yet')}</div></section><p class="faint small-text">Pick channels per rule under <a href="#/alerts?tab=rules">Alerts → Rules</a>.</p>`;
    const LABELS = { url: 'Server / URL', topic: 'Topic', token: 'Access token (optional)', priority: 'Priority 1–5 (optional)', bot_token: 'Bot token', chat_id: 'Chat ID',
      webhook_url: 'Webhook URL', secret_header: 'Extra header, e.g. "Authorization: Bearer xyz" (optional)', host: 'SMTP host', port: 'Port', security: 'Security',
      username: 'Username', password: 'Password', sender: 'From address', to: 'To address' };
    const modal = n => {
      n = n || { name: '', type: 'ntfy', config: {}, enabled: 1 };
      const form = openModal(n.id ? 'Edit channel' : 'Add notification channel', `<label class="field">Name<input name="name" value="${esc(n.name)}" required></label>
        <label class="field">Type<select name="type">${Object.keys(meta.notifier_types).map(t => `<option ${t === n.type ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
        <div id="nfields"></div><label class="check"><input type="checkbox" name="enabled" ${n.enabled ? 'checked' : ''}> Enabled</label>`,
      async f => {
        const config = {};
        meta.notifier_types[fv(f, 'type')].forEach(k => { const v = fv(f, 'c_' + k); if (v) config[k] = v; });
        const b = { name: fv(f, 'name'), type: fv(f, 'type'), config, enabled: fv(f, 'enabled') };
        if (n.id) await send('PUT', `/api/notifiers/${n.id}`, b); else await send('POST', '/api/notifiers', b);
        SETTINGS_VIEWS.notify(el);
      });
      const fields = () => {
        const t = form.elements.type.value;
        form.querySelector('#nfields').innerHTML = meta.notifier_types[t].map(k => k === 'security'
          ? `<label class="field">${LABELS[k]}<select name="c_security">${['starttls', 'ssl', 'none'].map(x => `<option ${(n.config.security || 'starttls') === x ? 'selected' : ''}>${x}</option>`).join('')}</select></label>`
          : `<label class="field">${LABELS[k] || k}<input name="c_${k}" value="${esc(t === n.type ? n.config[k] || '' : '')}" ${['password', 'bot_token', 'token'].includes(k) ? 'type="password" autocomplete="new-password"' : ''} placeholder="${k === 'url' && t === 'ntfy' ? 'https://ntfy.sh' : ''}"></label>`).join('');
      };
      form.elements.type.onchange = fields;
      fields();
    };
    el.querySelector('#add-n').onclick = () => modal(null);
    el.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => modal(ns.find(n => n.id === +b.dataset.edit)));
    el.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { if (confirm('Delete this channel?')) { await send('DELETE', `/api/notifiers/${b.dataset.del}`); SETTINGS_VIEWS.notify(el); } });
    el.querySelectorAll('[data-test]').forEach(b => b.onclick = async () => { b.disabled = true; try { await send('POST', `/api/notifiers/${b.dataset.test}/test`); toast('Test sent'); } catch (e) { toast(e.message, true); } b.disabled = false; });
  },
  async report(el) {
    const [cfg, ns] = await Promise.all([api('/api/settings/report'), api('/api/notifiers')]);
    el.innerHTML = `<section class="panel"><header><h2>Weekly report</h2></header><div class="body"><form id="rf" class="form-narrow">
      <label class="check"><input type="checkbox" name="email" ${cfg.email ? 'checked' : ''}> Send a weekly occupancy &amp; activity summary</label>
      <label class="field">Send via<select name="notifier_id"><option value="">Choose a channel…</option>${ns.map(n => `<option value="${n.id}" ${n.id === cfg.notifier_id ? 'selected' : ''}>${esc(n.name)} (${esc(n.type)})</option>`).join('')}</select></label>
      <div class="row"><label class="field">Day<select name="weekday">${WEEKDAYS.map((d, i) => `<option value="${i}" ${i === +cfg.weekday ? 'selected' : ''}>${d}</option>`).join('')}</select></label>
      <label class="field">Hour<input type="number" name="hour" min="0" max="23" value="${cfg.hour}"></label></div>
      <button class="btn primary">Save</button> <button type="button" class="btn" id="send">Send now</button>
      <p class="faint small-text">${cfg.last_sent ? 'Last sent ' + dt(cfg.last_sent) : 'Never sent'}. Email channels get an HTML report; other channels a text summary. See also <a href="#/reports">Reports</a>.</p></form></div></section>`;
    const f = el.querySelector('#rf');
    f.onsubmit = async e => { e.preventDefault(); await send('PUT', '/api/settings/report', { email: fv(f, 'email'), notifier_id: +fv(f, 'notifier_id') || null, weekday: +fv(f, 'weekday'), hour: +fv(f, 'hour') }); toast('Saved'); };
    el.querySelector('#send').onclick = async () => { try { await send('POST', '/api/reports/send'); toast('Report sent'); } catch (e) { toast(e.message, true); } };
  },
  async security(el) {
    const cfg = await api('/api/settings/security');
    el.innerHTML = `<section class="panel"><header><h2>Detection thresholds</h2></header><div class="body"><form id="sf" class="form-narrow">
      <div class="row"><label class="field">Deauth flood: frames<input type="number" name="deauth_threshold" min="3" value="${cfg.deauth_threshold}"></label>
      <label class="field">within seconds<input type="number" name="deauth_window" min="1" value="${cfg.deauth_window}"></label></div>
      <div class="row"><label class="field">KARMA AP: distinct SSIDs<input type="number" name="karma_ssids" min="2" value="${cfg.karma_ssids}"></label>
      <label class="field">within seconds<input type="number" name="karma_window" min="60" value="${cfg.karma_window}"></label></div>
      <button class="btn primary">Save</button></form></div></section>`;
    const f = el.querySelector('#sf');
    f.onsubmit = async e => { e.preventDefault(); const b = {}; ['deauth_threshold', 'deauth_window', 'karma_ssids', 'karma_window'].forEach(k => { b[k] = +fv(f, k); }); await send('PUT', '/api/settings/security', b); toast('Saved'); };
  },
  async tokens(el) {
    const ts = await api('/api/tokens');
    el.innerHTML = `<section class="panel"><header><h2>API tokens</h2><button class="btn primary" id="add-t">New token</button></header><div class="body flush">${tableHtml(
      '<th>Name</th><th>Scope</th><th class="num">Created</th><th class="num">Last used</th><th></th>', ts.map(t => `<tr><td><b>${esc(t.name)}</b></td><td><span class="tag">${esc(t.scope)}</span>${t.sensor_id ? ` <span class="faint">${esc(t.sensor_id)}</span>` : ''}</td>
        <td class="num muted">${ago(t.created)}</td><td class="num muted">${t.last_used ? ago(t.last_used) : 'never'}</td><td class="num"><button class="btn small danger" data-del="${t.id}">Revoke</button></td></tr>`).join(''), 'No tokens')}</div></section>
      <p class="faint small-text">Send as <code>Authorization: Bearer &lt;token&gt;</code>. <b>metrics</b>: only <code>/metrics</code> (Prometheus). <b>read</b>: read-only API. <b>admin</b>: full API. Sensor tokens are created under Sensors.</p>`;
    el.querySelector('#add-t').onclick = () => openModal('New API token', `<label class="field">Name<input name="name" required placeholder="e.g. prometheus"></label>
      <label class="field">Scope<select name="scope"><option value="metrics">metrics — Prometheus scraping</option><option value="read">read — read-only API</option><option value="admin">admin — full API</option></select></label>`,
    async f => {
      const r = await send('POST', '/api/tokens', { name: fv(f, 'name'), scope: fv(f, 'scope') });
      setTimeout(() => openModal('Token created', `<p>Copy it now — it won't be shown again.</p><pre class="code">${esc(r.token)}</pre>`, null), 50);
      SETTINGS_VIEWS.tokens(el);
    });
    el.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { if (confirm('Revoke this token?')) { await send('DELETE', `/api/tokens/${b.dataset.del}`); SETTINGS_VIEWS.tokens(el); } });
  },
};
