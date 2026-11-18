'use strict';
/* The audit report (#/audit, audit.py): everything sniffowireless found about my networks on one page, findings first, in order of
   how much they matter and what to do about them. Print / PDF gives a clean printout to hand over. */
(() => {
  const SEV = { high: ['bad', 'High'], medium: ['warn', 'Medium'], low: ['', 'Low'], info: ['', 'Info'] };
  const pct = x => x == null ? '—' : (x * 100).toFixed(x < 0.1 ? 1 : 0) + '%';
  const ms = x => x == null ? '—' : x < 1000 ? `${Math.round(x)} ms` : `${(x / 1000).toFixed(1)} s`;
  const yes = v => v ? 'yes' : '—';

  addRoute('/audit', async (_, params) => {
    const days = +(params.get('days') || 7);
    app.innerHTML = '<div class="empty">Putting the report together…</div>';
    const r = await api(`/api/audit?days=${days}`);
    const c = r.counts;
    const section = (title, body, sub = '') => `<section class="panel span-3 audit-sec"><header><h2>${title}</h2>${sub ? `<span class="faint">${sub}</span>` : ''}</header><div class="body">${body}</div></section>`;
    const findings = r.findings.length ? r.findings.map(f => `<div class="audit-f sev-${f.severity}">
        <div><span class="tag ${SEV[f.severity][0]}">${SEV[f.severity][1]}</span> <span class="faint small-text">${esc(f.area)}</span></div>
        <div><b>${esc(f.title)}</b>${f.detail ? `<div class="small-text">${esc(f.detail)}</div>` : ''}${f.advice ? `<div class="small-text muted">→ ${esc(f.advice)}</div>` : ''}</div></div>`).join('')
      : '<div class="empty">Nothing to report.</div>';
    const ch = r.changes;
    const fline = f => `<li><span class="tag ${SEV[f.severity][0]}">${SEV[f.severity][1]}</span> ${esc(f.title)}</li>`;
    const changes = ch ? `<p class="small-text">Since the snapshot of ${dt(ch.since)}${ch.reason === 'report' ? ' (sent with the scheduled report)' : ''}: <b>${ch.new.length}</b> new, <b>${ch.fixed.length}</b> fixed, <b>${ch.still}</b> still open${ch.worse.length ? `, ${ch.worse.length} got worse` : ''}.</p>
        ${ch.new.length ? `<h3 class="subhead">New</h3><ul class="tight">${ch.new.map(fline).join('')}</ul>` : ''}
        ${ch.worse.length ? `<h3 class="subhead">Worse</h3><ul class="tight">${ch.worse.map(fline).join('')}</ul>` : ''}
        ${ch.fixed.length ? `<h3 class="subhead">Fixed</h3><ul class="tight">${ch.fixed.map(f => `<li class="muted"><s>${esc(f.title)}</s></li>`).join('')}</ul>` : ''}`
      : '<p class="small-text faint">No snapshot yet. Keep one (or let the scheduled report keep one each time), and the next report says what is new, fixed and still open.</p>';
    const aps = r.aps.length ? tableHtml('<th>Network</th><th>BSSID</th><th>Channel</th><th class="num">Width</th><th>Security</th><th>PMF</th><th>Roaming</th><th>WPS</th><th class="num">Beacon rate</th><th class="num">Colour</th>',
      r.aps.map(a => `<tr><td>${esc(a.ssid)}${a.model ? `<div class="faint small-text">${esc(a.model)}</div>` : ''}</td><td class="mono">${esc(a.mac)}</td><td>${chText(a.channel, a.band)}</td>
        <td class="num">${a.width || 20} MHz</td><td>${esc(a.akm.join(', ') || a.enc || '—')}${a.transition ? ' <span class="tag">transition</span>' : ''}</td>
        <td>${esc(a.pmf || '—')}</td><td>${esc(a.roaming.join(', ') || '—')}</td><td>${a.wps ? '<span class="warn-text">on</span>' : '—'}</td>
        <td class="num">${a.basic_rate ? a.basic_rate + ' Mb/s' : '—'}</td><td class="num">${a.colour ?? '—'}</td></tr>`).join('')) : '<div class="empty">No access points of your networks heard in this period.</div>';
    const chans = r.channels.length ? tableHtml('<th>Channel</th><th class="num">Busy</th><th class="num">Retries</th><th class="num">Noise</th><th class="num">Frames/s</th>',
      r.channels.map(x => `<tr><td>${chText(x.channel, x.band)}</td><td class="num">${pct(x.utilization)}</td><td class="num">${pct(x.retry_rate)}</td>
        <td class="num">${x.noise != null ? x.noise + ' dBm' : '—'}</td><td class="num">${x.fps ?? '—'}</td></tr>`).join('')) : '<div class="faint">No channel measurements of your channels.</div>';
    const plan = r.plan.length ? `<p class="small-text">Suggested so that your radios that are heard together stop sharing a channel:</p>${tableHtml('<th>Radio</th><th>Band</th><th>Now</th><th>Suggested</th>',
      r.plan.map(x => `<tr><td>${esc(x.label)}</td><td>${x.band} GHz</td><td>ch ${x.current}</td><td><b>ch ${x.suggested}</b></td></tr>`).join(''))}` : '<p class="small-text">No channel change would help enough to be worth it.</p>';
    const L = r.link, J = r.joins, R = J.roams || {};
    const clients = `<div class="grid cols-4">${[['Clients with data', L.total, `${L.by.ok} healthy · ${L.by.warn} so-so · ${L.by.bad} poor`],
      ['Connection attempts', (J.counts || {}).attempts || 0, `${(J.counts || {}).failed || 0} failed`], ['Roams', R.count || 0, Object.entries(R.methods || {}).map(([k, v]) => `${v} ${k}`).join(' · ')],
      ['Median roam', ms(R.median_ms), R.slow ? `${R.slow} slower than 150 ms` : '']].map(([l, v, m]) => `<div class="card"><div class="label">${l}</div><div class="value">${typeof v === 'number' ? num(v) : v}</div><div class="meta">${esc(m)}</div></div>`).join('')}</div>
      ${L.worst.filter(x => x.verdict.level !== 'ok').length ? `<h3 class="subhead">Weakest links</h3>${tableHtml('<th>Client</th><th>Link</th><th>Why</th>',
        L.worst.filter(x => x.verdict.level !== 'ok').map(x => `<tr><td>${esc(x.name || x.mac)}</td><td>${esc(x.verdict.short)}</td><td class="small-text" style="white-space:normal">${esc(x.verdict.text)}</td></tr>`).join(''))}` : ''}
      ${J.causes.length ? `<h3 class="subhead">Why connections failed</h3>${tableHtml('<th>Cause</th><th class="num">Times</th><th class="num">Clients</th>',
        J.causes.map(x => `<tr><td>${esc(x.cause)}</td><td class="num">${x.count}</td><td class="num">${x.clients}</td></tr>`).join(''))}` : ''}`;
    const ready = r.readiness.clients ? tableHtml('<th>Change</th><th class="num">Ready</th><th class="num">Would drop off</th><th class="num">Not known</th>',
      r.readiness.questions.map(q => `<tr><td>${esc(q.title)}</td><td class="num">${q.ready}</td><td class="num">${q.key === 'six' ? '—' : q.drop}</td><td class="num">${q.unknown}</td></tr>`).join(''))
      + `<p class="small-text">Generations: ${Object.entries(r.readiness.summary.generations || {}).map(([k, n]) => `${esc(k)} ${n}`).join(' · ')}</p>` : '<div class="faint">No clients of your networks.</div>';
    const intf = (r.interference.length ? tableHtml('<th>Kind</th><th>Band</th><th class="num">Episodes</th>', r.interference.map(e => `<tr><td>${esc(e.kind)}</td><td>${esc(e.band)} GHz</td><td class="num">${e.n}</td></tr>`).join(''))
      : '<p class="small-text">No interference episodes.</p>') + `<p class="small-text">Radar made your access points leave a DFS channel ${r.radar} time${r.radar === 1 ? '' : 's'}.</p>`;
    app.innerHTML = `<div class="page-head"><div><h1>Wi-Fi audit · ${esc(r.site)}</h1><div class="sub">${r.networks.length ? esc(r.networks.join(', ')) : 'No networks of yours set'} · the last ${days} days · made ${dt(r.generated)}</div></div>
      <div class="row no-print">${seg('days', [[7, '7 days'], [14, '14 days'], [30, '30 days']], days)} ${isAdmin() ? '<button class="btn ghost" id="snap" title="Keep these findings to compare later reports with">Keep snapshot</button>' : ''} <button class="btn" id="print">Print / PDF</button></div></div>
      <div class="grid cols-4">${['high', 'medium', 'low', 'info'].map(s => `<div class="card"><div class="label">${SEV[s][1]}</div><div class="value ${s === 'high' && c.high ? 'err' : ''}">${c[s]}</div><div class="meta">finding${c[s] === 1 ? '' : 's'}</div></div>`).join('')}</div>
      <div class="grid cols-3" style="margin-top:16px">
        ${section('Findings', findings, 'in order of how much they matter')}
        ${section('Changes', changes, 'compared with the last snapshot')}
        ${section('Access points', aps, `${r.aps.length} BSSIDs of your networks`)}
        ${section('Channels', chans + '<h3 class="subhead">Channel plan</h3>' + plan, 'how busy your channels were while the sensors listened')}
        ${section('Clients', clients, 'their links, connections and roams')}
        ${section('Client readiness', ready, `${r.readiness.clients} clients`)}
        ${section('Interference and radar', intf)}
        ${section('How this was measured', `<p class="small-text">Passively, by ${r.sensors.length} sensor${r.sensors.length === 1 ? '' : 's'} (${r.sensors.map(s => esc(s.name) + (s.room ? ` in ${esc(s.room)}` : '')).join(', ')}), from what the radios hear: beacons, probe and association requests, data frame headers and the steps of connections. Nothing was sent to the network. A sensor that hops channels hears each channel part of the time, so counts are samples. Details are on the Channels, My networks and Security pages.</p>`)}
      </div>`;
    onSeg(app, 'days', v => { location.hash = hrefWith('/audit', { days: v }); });
    document.getElementById('print').onclick = () => window.print();
    const snap = document.getElementById('snap');
    if (snap) snap.onclick = async () => { const x = await send('POST', `/api/audit/snapshot?days=${days}`); toast(`Snapshot kept: ${x.findings} findings`); route(); };
  });
})();
