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

/* Beacon overhead per channel (Channels page): the share of the airtime that beacons alone take, from the access points heard in
   the last hour. A row opens the access points behind it. */
async function loadBeacons(el) {
  if (!el) return;
  const r = await api('/api/channels/beacons?hours=1');
  const pct = x => x < 0.1 ? (x * 100).toFixed(1) + '%' : Math.round(x * 100) + '%';
  const tag = l => l === 'bad' ? 'bad' : l === 'high' ? 'warn' : 'on';
  const bar = (x, l) => `<span class="meter"><i style="width:${Math.min(100, Math.round(x * 100 / 0.4))}%;background:var(--${l === 'bad' ? 'bad' : l === 'high' ? 'warn' : 'good'})"></i></span>`;
  const apRows = (band, ch) => r.aps.filter(a => a.band === band && a.channel === ch).map(a => `<tr class="${a.counts ? '' : 'faint'}">
      <td>${a.ssid ? esc(a.ssid) : '<span class="faint">hidden</span>'}${a.mine ? ' <span class="tag on">mine</span>' : ''}</td><td>${devLink(a.mac)}</td>
      <td class="num">${a.rssi != null ? a.rssi + ' dBm' : '—'}</td><td class="num">${a.rate} Mb/s${a.known ? '' : ' <span class="faint" title="Not reported by the sensor (an older version): assumed">?</span>'}</td>
      <td class="num">${a.interval} TU</td><td class="num">${a.length} B</td><td class="num">${a.counts ? pct(a.airtime) : '<span title="Weaker than ' + r.cca + ' dBm: not deferred to">—</span>'}</td></tr>`).join('');
  el.innerHTML = `<header><h2>Beacon overhead</h2><span class="faint">the airtime beacons alone take, from the access points heard in the last hour (at ${r.cca} dBm or stronger) · under ${Math.round(r.thresholds.high * 100)}% is fine, over ${Math.round(r.thresholds.bad * 100)}% is a problem</span></header>
    ${r.advice.length ? `<div class="body">${r.advice.map(a => `<div class="small-text" style="margin:4px 0"><span class="tag ${a.level === 'bad' ? 'bad' : a.level === 'high' ? 'warn' : ''}">${a.level === 'info' ? 'tip' : a.level === 'bad' ? 'problem' : 'high'}</span> ${esc(a.text)}</div>`).join('')}</div>` : ''}
    <div class="body flush">${tableHtml('<th>Channel</th><th class="num">BSSIDs</th><th class="num">SSIDs</th><th class="num">Radios</th><th class="num">Beacons/s</th><th class="num">Beacon airtime</th><th class="num">Yours</th>',
      r.channels.map(c => `<tr class="link" data-bo="${c.band}|${c.channel}"><td>${chText(c.channel, c.band)}${c.weak ? ` <span class="faint" title="Access points weaker than ${r.cca} dBm, not counted">+${c.weak} weak</span>` : ''}</td>
        <td class="num">${c.aps}</td><td class="num">${c.ssids}</td><td class="num">${c.radios}</td><td class="num">${c.beacons_per_s}</td>
        <td class="num">${bar(c.airtime, c.level)} <span class="tag ${tag(c.level)}">${pct(c.airtime)}</span></td><td class="num muted">${c.mine ? pct(c.mine) : '—'}</td></tr>
        <tr hidden data-bo-aps="${c.band}|${c.channel}"><td colspan="7" style="padding:0 0 8px 24px">${tableHtml('<th>SSID</th><th>BSSID</th><th class="num">Signal</th><th class="num">Beacon rate</th><th class="num">Interval</th><th class="num">Size</th><th class="num">Airtime</th>', apRows(c.band, c.channel))}</td></tr>`).join(''),
      'No access points heard in the last hour')}</div>`;
  el.querySelectorAll('tr[data-bo]').forEach(tr => tr.onclick = () => { const d = el.querySelector(`tr[data-bo-aps="${tr.dataset.bo}"]`); d.hidden = !d.hidden; });

/* Co-channel interference between my own access points (cci.py): per band, a matrix of how loud two of my radios are heard together
   (the weaker of the two, at the sensor that hears both best), where they share a channel, and a channel plan for all of them. */
async function loadCci(el) {
  if (!el) return;
  const r = await api('/api/channels/cci?hours=24');
  if (!r.radios.length) return;
  el.hidden = false;
  const byId = Object.fromEntries(r.radios.map(x => [x.id, x]));
  const short = x => `${esc(x.ssids[0] || 'hidden')}${x.ssids.length > 1 ? ` +${x.ssids.length - 1}` : ''} <span class="mono faint">${esc(x.bssids[0].slice(-5))}</span>`;
  const shade = (p) => !p ? '' : `background:color-mix(in srgb, var(--${p.conflict >= 1 ? 'bad' : p.conflict > 0 ? 'warn' : 'ap'}) ${Math.round(15 + 60 * Math.min(1, (p.overlap + 95) / 45))}%, transparent)`;
  const bands = ['2.4', '5', '6'].filter(b => r.radios.some(x => x.band === b));
  const matrix = b => {
    const rs = r.radios.filter(x => x.band === b);
    if (rs.length < 2) return `<div class="faint small-text">Only one of your radios on ${b} GHz.</div>`;
    const pair = (a, c) => r.pairs.find(p => (p.a === a.id && p.b === c.id) || (p.a === c.id && p.b === a.id));
    return `<div class="table-wrap"><table class="cci"><thead><tr><th></th>${rs.map(x => `<th title="${esc(x.label)}">${short(x)}<div class="faint">ch ${x.channel}</div></th>`).join('')}</tr></thead><tbody>
      ${rs.map(a => `<tr><th title="${esc(a.label)}">${short(a)} <span class="faint">ch ${a.channel}</span></th>${rs.map(c => {
        if (a.id === c.id) return '<td class="faint">—</td>';
        const p = pair(a, c);
        return p ? `<td style="${shade(p)}" title="Heard together at ${esc(p.sensor_name)}: the weaker at ${p.overlap} dBm.${p.same_channel ? ' Same channel: they share its airtime there.' : p.conflict > 0 ? ' Overlapping channels.' : ' Different channels: no conflict.'}">${p.overlap}${p.same_channel ? ' <b>!</b>' : ''}</td>` : '<td></td>';
      }).join('')}</tr>`).join('')}</tbody></table></div>`;
  };
  const plans = bands.map(b => r.plan[b]).filter(Boolean);
  const changes = bands.flatMap(b => (r.plan[b] && r.plan[b].change ? r.plan[b].radios.filter(x => x.suggested !== x.current).map(x => ({ ...x, band: b })) : []));
  const shared = r.spots.filter(s => s.mine.length >= 2);
  el.innerHTML = `<header><h2>Your access points: co-channel interference</h2><span class="faint">two of your radios on one channel share its airtime wherever both are heard at ${r.cca} dBm or stronger</span></header>
    <div class="body">
      ${shared.length ? shared.map(s => `<div class="small-text" style="margin:3px 0"><span class="tag warn">shared</span> At <b>${esc(s.sensor_name)}</b>, channel ${s.channel} (${s.band} GHz) is used by ${s.mine.length} of your radios (${s.mine.map(i => short(byId[i])).join(', ')})${s.others ? ` and ${s.others} neighbouring access point${s.others === 1 ? '' : 's'}` : ''}.</div>`).join('')
        : '<div class="small-text"><span class="tag on">ok</span> None of your radios that are heard together share a channel.</div>'}
      <div class="grid cols-${Math.min(3, bands.length)}" style="margin-top:10px">${bands.map(b => `<div><h3 class="subhead">${b} GHz</h3>${matrix(b)}</div>`).join('')}</div>
      <p class="faint small-text">Each cell: the weaker of the two signals where one sensor hears both best. Red: the same channel; amber: overlapping channels. With sensors in several rooms this shows where your access points meet.</p>
      <h3 class="subhead">Channel plan</h3>
      ${changes.length ? tableHtml('<th>Radio</th><th>Band</th><th>Now</th><th>Suggested</th>', changes.map(x => `<tr><td>${short(byId[x.id])}</td><td class="muted">${x.band} GHz</td><td>ch ${x.current}</td><td><b>ch ${x.suggested}</b></td></tr>`).join(''))
        + `<p class="faint small-text">Overlap score of all your radios together: ${plans.map((p, i) => `${bands[i]} GHz ${p.before} → ${p.after}`).join(' · ')} (lower is better). It counts your own radios that are heard together, the neighbours' access points they hear and the measured airtime per channel. Channel widths are not known, so on 5 and 6 GHz radios in the same 80 MHz block count as half a conflict.</p>`
        : '<div class="small-text"><span class="tag on">ok</span> Your radios are on a good set of channels; no change would help enough to be worth it.</div>'}
    </div>`;
}
