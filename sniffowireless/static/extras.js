'use strict';
/* DFS / radar and interference episodes (Channels page), Bluetooth tracker list (Security page) and Settings → Backup. */

// ===================================================================== interference
async function loadInterference(el, days) {
  if (!el) return;
  const r = await api(`/api/interference?days=${days}`);
  const eps = r.episodes;
  el.innerHTML = `<header><h2>Interference</h2><span class="faint">non-Wi-Fi energy: raised noise floor or unexplained retransmissions vs. each channel's 24 h baseline</span></header>
    <div class="body flush">${tableHtml('<th>When</th><th>Duration</th><th>Band</th><th>Channels</th><th>Likely cause</th><th class="num">Noise</th><th class="num">Retries</th>',
    eps.map(e => `<tr><td>${e.open ? '<span class="tag warn">ongoing</span> ' : ''}${dt(e.start_ts)}</td><td>${dur(e.end_ts - e.start_ts)}</td><td>${esc(e.band)} GHz</td>
      <td class="mono">${e.channels.join(', ')}</td><td style="white-space:normal;min-width:260px"><b>${esc(e.kind)}</b><div class="faint small-text">${esc(e.detail || '')}</div></td>
      <td class="num">${e.peak_noise_delta != null ? '+' + e.peak_noise_delta + ' dB' : '—'}</td>
      <td class="num">${Math.round((e.peak_retry || 0) * 100)}% <span class="faint">(normal ${Math.round((e.base_retry || 0) * 100)}%)</span></td></tr>`).join(''),
    `No interference detected in the last ${days} day${days === 1 ? '' : 's'}. Detection needs a day of channel measurements as baseline.`)}</div>`;
}

// ===================================================================== DFS / radar
async function loadDfs(el, days) {
  if (!el) return;
  const r = await api(`/api/dfs?days=${days}`);
  const now = r.now;
  const chip = c => {
    const closed = c.closed_until && c.closed_until > now;
    const cls = closed ? 'bad' : c.radar ? 'warn' : '';
    const tip = `Channel ${c.channel}: ${c.radar} radar hit${c.radar === 1 ? '' : 's'}${c.last ? ', last ' + dt(c.last) : ''}${closed ? `, closed until ${dt(c.closed_until)}` : ''}; ${c.aps_now} access point${c.aps_now === 1 ? '' : 's'} on it now`;
    return `<div class="dfs-chip ${cls}" title="${esc(tip)}"><b>${c.channel}</b><span>${c.radar ? c.radar + '×' : '—'}</span><i>${c.aps_now ? c.aps_now + ' AP' : ''}</i></div>`;
  };
  const evs = r.events;
  el.innerHTML = `<header><h2>DFS / radar</h2><span class="faint">5 GHz channels 52–144 are shared with radar; an access point that hears radar must leave the channel for 30 minutes</span></header>
    <div class="body">
      <div class="dfs-strip">${r.channels.map(chip).join('')}</div>
      <div class="faint small-text" style="margin-top:8px">Radar hits per channel in the last ${days} day${days === 1 ? '' : 's'}: <span class="tag warn">hit</span> radar seen · <span class="tag bad">closed</span> radar in the last 30 minutes. Counts include neighbours' access points: radar is a property of the location.
        ${r.mine_radar ? ` <b>${r.mine_radar} on my networks.</b>` : ''}</div>
    </div>
    <div class="body flush">${tableHtml('<th>When</th><th>Access point</th><th>From</th><th>To</th><th>What happened</th>',
      evs.slice(0, 100).map(e => `<tr><td>${dt(e.ts)}</td><td>${devLink(e.mac, e.ssid || e.mac)} ${e.mine ? '<span class="tag on">mine</span>' : ''}<div class="faint small-text">${esc(e.vendor || '')}</div></td>
        <td>ch ${e.from_ch}${e.dfs ? ' <span class="tag">DFS</span>' : ''}</td><td>ch ${e.to_ch}</td>
        <td>${e.dfs ? `<span class="tag warn">likely radar</span> ${e.csa ? 'announced a channel switch' : 'left without announcing'}` : e.csa ? 'announced a channel switch' : 'changed channel'}</td></tr>`).join(''),
      'No channel switches seen. They appear when an access point announces a switch (CSA) or moves to another channel.')}</div>
    ${r.aps.length ? `<div class="body"><h3 class="subhead">Access points on DFS channels now</h3></div><div class="body flush">${tableHtml('<th>Access point</th><th>Channel</th><th>Security</th><th class="num">Signal</th><th class="num">Last seen</th>',
      r.aps.map(a => `<tr><td>${devLink(a.mac, a.ssid || a.mac)} ${a.mine ? '<span class="tag on">mine</span>' : ''}</td><td>ch ${a.channel}</td><td class="muted">${esc(a.enc || '')}</td>
        <td class="num">${a.last_rssi != null ? a.last_rssi + ' dBm' : '—'}</td><td class="num muted">${ago(a.last_seen)}</td></tr>`).join(''))}</div>` : ''}`;
}

// ===================================================================== trackers
async function loadTrackers(el) {
  if (!el) return;
  const r = await api('/api/trackers');
  const ts = r.trackers;
  el.innerHTML = `<header><h2>Bluetooth trackers</h2><span class="faint">AirTag / Find My, Tile and SmartTag seen in the last ${r.lookback_days} days</span></header>
    <div class="body flush">${tableHtml('<th>Tracker</th><th>Status</th><th>Moves with</th><th class="num">Present</th><th class="num">Last seen</th><th></th>',
    ts.map(t => {
      const m = t.match;
      const status = t.known ? '<span class="tag on">yours (known)</span>'
        : t.following ? '<span class="tag bad">possibly following</span>' : '<span class="tag">unknown</span>';
      const moves = m && m.shared ? `${esc(m.person_name)} <span class="faint">${Math.round(m.ratio * 100)}% together · ${m.arrivals + m.departures}× arrived/left together</span>` : '<span class="faint">—</span>';
      return `<tr class="${t.following ? '' : t.known ? 'dim' : ''}"><td>${devLink(t.mac, t.label || t.mac)} <div class="faint small-text">${esc(t.tracker)}${t.room ? ' · ' + esc(t.room) : ''}</div></td>
        <td>${status}</td><td>${moves}</td><td class="num">${dur(t.present)} <span class="faint">${t.visits} visit${t.visits === 1 ? '' : 's'}</span></td>
        <td class="num muted">${ago(t.last_seen)}</td><td class="num">${isAdmin() && !t.known ? `<button class="btn small" data-mine="${esc(t.mac)}">It's mine</button>` : ''}</td></tr>`;
    }).join(''), 'No tracker tags seen')}
    <p class="faint small-text" style="padding:0 16px">A tag counts as <b>possibly following</b> someone when it's present almost only while that person (a "person" group or a known phone) is, and arrived or left together with them at least twice. A separated AirTag keeps its address up to ~24 h; on iPhone/Android the built-in "unknown tracker" alerts complement this.</p></div>`;
  el.querySelectorAll('[data-mine]').forEach(b => b.onclick = async () => {
    await send('PUT', `/api/devices/${enc(b.dataset.mine)}/meta`, { known: true });
    toast('Marked as yours');
    loadTrackers(el);
  });
}

// ===================================================================== settings → backup
/* Asks what to restore. `sections` are [{id, label, hint, count, unit}] from the server; `everything` (optional) adds the
   choice of replacing the whole database. Calls onSubmit('all') or onSubmit([ids]); a throw is shown in the dialog. */
function restoreChooser({ title, intro, sections, everything, submit, onSubmit }) {
  const form = openModal(title, `${intro ? `<p class="muted" style="margin-top:0">${intro}</p>` : ''}
    ${everything ? `<label class="check"><input type="radio" name="mode" value="all"> <b>Everything</b> <span class="faint">${esc(everything)}</span></label>
      <label class="check"><input type="radio" name="mode" value="pick" checked> <b>Only what I choose</b> <span class="faint">leaves everything else as it is</span></label>` : ''}
    <div id="rc-list" style="margin:10px 0">${sections.map(s => `<label class="check" style="align-items:flex-start"><input type="checkbox" name="sec" value="${esc(s.id)}" ${s.count ? '' : 'disabled'}>
      <span><b>${esc(s.label)}</b> <span class="faint">${s.count ? `${num(s.count)} ${s.count === 1 ? (s.unit === 'files' ? 'file' : 'entry') : esc(s.unit)}` : 'none in this backup'}</span>
        <span class="faint small-text" style="display:block">${esc(s.hint)}</span></span></label>`).join('')}</div>
    <div class="row"><button type="button" class="btn small ghost" id="rc-all">Select all</button><button type="button" class="btn small ghost" id="rc-none">Select none</button></div>`,
  async f => {
    const all = everything && f.querySelector('[name=mode]:checked').value === 'all';
    const picked = [...f.querySelectorAll('[name=sec]:checked')].map(x => x.value);
    if (!all && !picked.length) throw new Error('Choose at least one thing to restore');
    await onSubmit(all ? 'all' : picked);
  }, { submit, danger: true });
  const boxes = () => [...form.querySelectorAll('[name=sec]:not(:disabled)')];
  const mode = () => { const all = everything && form.querySelector('[name=mode]:checked').value === 'all'; form.querySelector('#rc-list').style.opacity = all ? .4 : 1; boxes().forEach(b => { b.disabled = all; }); };
  form.querySelector('#rc-all').onclick = () => boxes().forEach(b => { b.checked = true; });
  form.querySelector('#rc-none').onclick = () => boxes().forEach(b => { b.checked = false; });
  form.querySelectorAll('[name=mode]').forEach(r => r.onchange = mode);
  return form;
}

SETTINGS_VIEWS.backup = async function (el) {
  const b = await api('/api/backup/list');
  const s = b.settings;
  el.innerHTML = `<section class="panel"><header><h2>Configuration backup</h2></header><div class="body">
      <p class="muted">Settings, my networks, ignore list, labels, groups, alert rules, notification channels, sensors and users (password hashes) — no measurement history. Small; you choose what to restore, and it applies immediately.</p>
      <div class="row"><label class="check"><input type="checkbox" id="cfg-secrets"> Include notification secrets (tokens, passwords)</label></div>
      <div class="row" style="margin-top:8px"><button class="btn" id="cfg-dl">Download configuration</button>
        <label class="btn">Restore configuration…<input type="file" id="cfg-up" accept=".json,application/json" hidden></label></div></div></section>
    <section class="panel" style="margin-top:16px"><header><h2>Full backups</h2><button class="btn primary" id="full-now">Back up now</button></header><div class="body">
      <p class="muted">All data: the whole database (history, sessions, traffic, settings, users), the floor plan and icon, and handshake captures, as a <code>.tar.gz</code>. Taken safely while sniffowireless runs. Restoring replaces the current database (a copy is kept in <code>data/backups</code>) and restarts sniffowireless.</p>
      ${b.staged ? '<div class="callout">A restore is staged and will be applied when sniffowireless restarts.</div>' : ''}
      <form id="sched" class="row" style="margin-bottom:12px"><label class="check"><input type="checkbox" name="enabled" ${s.enabled ? 'checked' : ''}> Daily at</label>
        <input type="number" name="hour" min="0" max="23" value="${s.hour}" style="width:70px"><span class="muted">:00, keep</span>
        <input type="number" name="keep" min="1" max="365" value="${s.keep}" style="width:70px"><span class="muted">backups</span><button class="btn">Save</button>
        <span class="faint small-text">${s.last_run ? 'last scheduled backup ' + ago(s.last_run) : ''}</span></form>
      ${tableHtml('<th>Backup</th><th class="num">Size</th><th class="num">Created</th><th></th>', b.backups.map(f => `<tr><td class="mono">${esc(f.name)}</td>
        <td class="num">${fmtBytes(f.size)}</td><td class="num muted">${dt(f.created)}</td><td class="num"><a class="btn small" href="/api/backup/files/${enc(f.name)}" download>Download</a>
        <button class="btn small" data-restore="${esc(f.name)}">Restore</button> <button class="btn small danger" data-del="${esc(f.name)}">Delete</button></td></tr>`).join(''), 'No backups yet')}
      <div class="row" style="margin-top:12px"><label class="btn">Restore from file…<input type="file" id="full-up" accept=".gz,.tgz,application/gzip" hidden></label>
        <span class="faint small-text">Backups are stored in <code>./data/backups</code> — copy them off the machine too.</span></div></div></section>`;
  const reload = () => SETTINGS_VIEWS.backup(el);
  el.querySelector('#cfg-dl').onclick = () => { location.href = `/api/backup/config?secrets=${el.querySelector('#cfg-secrets').checked ? 1 : 0}`; };
  el.querySelector('#cfg-up').onchange = async e => {
    const f = e.target.files[0];
    e.target.value = '';
    if (!f) return;
    const hdr = { 'Content-Type': 'application/json', 'X-Sniffowireless': '1' };
    const ins = await fetch('/api/backup/config/inspect', { method: 'POST', headers: hdr, body: f });
    const info = await ins.json().catch(() => ({}));
    if (!ins.ok) { toast(info.detail || 'Not a configuration backup', true); return; }
    restoreChooser({ title: 'Restore configuration', intro: 'Each part you choose replaces what is set now; the rest stays as it is. It applies immediately.',
      sections: info.sections, submit: 'Restore', onSubmit: async sel => {
        const r = await fetch(`/api/backup/config?sections=${encodeURIComponent(sel.join(','))}`, { method: 'POST', headers: hdr, body: f });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || 'Restore failed');
        toast('Restored: ' + (Object.entries(d.restored).map(([k, v]) => `${v} ${k}`).join(', ') || 'settings'));
      } });
  };
  el.querySelector('#full-now').onclick = async e => {
    e.target.disabled = true;
    try { const r = await send('POST', '/api/backup/full'); toast(`Backup created (${fmtBytes(r.size)})`); reload(); } catch (err) { toast(err.message, true); e.target.disabled = false; }
  };
  el.querySelector('#sched').onsubmit = async e => {
    e.preventDefault();
    await send('PUT', '/api/backup/settings', { enabled: fv(e.target, 'enabled'), hour: +fv(e.target, 'hour'), keep: +fv(e.target, 'keep') });
    toast('Saved');
  };
  const restarting = () => {
    openModal('Restoring…', '<p>The backup was verified and sniffowireless is restarting to apply it. This page reloads in a few seconds.</p>', null);
    const wait = setInterval(async () => { try { if ((await fetch('/api/health')).ok) { clearInterval(wait); location.href = '/login'; } } catch { /* still down */ } }, 2000);
  };
  const chooseRestore = (name, source, info) => restoreChooser({ title: `Restore from ${name}`,
    intro: `Backup made ${dt(info.created)}. sniffowireless restarts to apply it, and keeps a copy of the current database first.`,
    sections: info.sections, everything: 'replaces ALL current data with the backup', submit: 'Restore and restart',
    onSubmit: async sel => { await send('POST', '/api/backup/restore-selected', { source, sections: sel }); restarting(); } });
  el.querySelectorAll('[data-restore]').forEach(x => x.onclick = async () => {
    try { chooseRestore(x.dataset.restore, x.dataset.restore, await api(`/api/backup/files/${enc(x.dataset.restore)}/sections`)); } catch (err) { toast(err.message, true); }
  });
  el.querySelectorAll('[data-del]').forEach(x => x.onclick = async () => { if (confirm('Delete this backup?')) { await send('DELETE', `/api/backup/files/${enc(x.dataset.del)}`); reload(); } });
  el.querySelector('#full-up').onchange = async e => {
    const f = e.target.files[0];
    e.target.value = '';
    if (!f) return;
    toast('Reading the backup…');
    const r = await fetch('/api/backup/inspect', { method: 'POST', headers: { 'Content-Type': 'application/gzip', 'X-Sniffowireless': '1' }, body: f });
    const info = await r.json().catch(() => ({}));
    if (!r.ok) { toast(info.detail || 'Not a valid backup', true); return; }
    chooseRestore(f.name, 'upload', info);
  };
};
