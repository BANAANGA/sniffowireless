'use strict';
/* How clients join and roam (joins.py): a client's connection attempts step by step, with the step that failed and why, its roams
   with their duration, and its disconnects; on My networks the failures by cause and the roam times of every client. */

const JOIN_OUTCOME_TAG = { connected: 'on', failed: 'bad', incomplete: '', 'in progress': 'warn' };
const ROAM_TIME_TAG = { fast: 'on', ok: 'on', slow: 'warn', 'very slow': 'bad' };
const ROAM_TIME_HELP = 'Under 50 ms is fast; up to 150 ms is fine for calls; slower roams can be heard as a gap in a call.';
const joinMs = ms => ms == null ? '—' : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;

function joinSteps(a) {
  return `<div class="join-steps">${a.steps.map(s => `<span class="join-step ${s.ok ? '' : 'bad'} ${s.from_ap ? 'ap' : 'cl'}" title="${esc(s.label)}${s.code ? ' · code ' + s.code : ''} · ${s.from_ap ? 'sent by the access point' : 'sent by the client'}">
    <i>${s.from_ap ? '←' : '→'}</i>${esc(s.label.replace('4-way handshake ', '4-way ').replace(' request', '').replace(' response', ' resp.'))}<b>+${joinMs(s.ms)}</b></span>`).join('')}</div>`;
}

async function loadJoins(el, mac) {
  if (!el) return;
  const r = await api(`/api/joins/${enc(mac)}?hours=168`);
  if (!r.attempts.length && !r.disconnects.length) return;
  el.hidden = false;
  const fails = r.attempts.filter(a => a.outcome === 'failed').length;
  el.innerHTML = `<header><h2>Connections</h2><span class="faint">every step heard of its connections in the last 7 days${fails ? ` · <span class="err">${fails} failed</span>` : ''}</span></header>
    <div class="body">
      ${r.roams.length ? `<h3 class="subhead" style="margin-top:0">Roams</h3>${tableHtml('<th>When</th><th>From</th><th>To</th><th>Method</th><th class="num">Took</th>',
        r.roams.map(x => `<tr><td class="muted">${dt(x.ts)}</td><td>${devLink(x.from)}</td><td>${devLink(x.to)}${x.ssid ? ` <span class="faint">${esc(x.ssid)}</span>` : ''}</td>
          <td>${esc(x.method || '?')}${x.steered ? ' <span class="tag" title="The access point asked it to move (802.11v BSS transition)">steered</span>' : ''}</td>
          <td class="num"><span class="tag ${ROAM_TIME_TAG[x.grade] || ''}" title="${esc(ROAM_TIME_HELP)}">${joinMs(x.ms)}</span></td></tr>`).join(''))}` : ''}
      <h3 class="subhead">Attempts</h3>
      <div class="join-list">${r.attempts.slice(0, 40).map(a => `<div class="join ${a.outcome === 'failed' ? 'failed' : ''}">
        <div class="row" style="justify-content:space-between;gap:8px"><div><span class="tag ${JOIN_OUTCOME_TAG[a.outcome] || ''}">${esc(a.outcome)}</span>
          ${a.ssid ? `<b>${esc(a.ssid)}</b> ` : ''}${devLink(a.bssid)} <span class="faint">${esc(a.method || '')}${a.came_from ? ` · from ${esc(a.came_from)}` : ''}${a.steered ? ' · steered (802.11v)' : ''}</span></div>
          <span class="faint small-text">${dt(a.start)}${a.duration_ms != null ? ` · ${joinMs(a.duration_ms)}` : ''}</span></div>
        ${a.why ? `<div class="small-text ${a.outcome === 'failed' ? 'err' : 'faint'}" style="margin:4px 0">${a.failed_at ? `<b>${esc(a.failed_at)}:</b> ` : ''}${esc(a.why)}</div>` : ''}
        ${joinSteps(a)}</div>`).join('') || '<div class="empty">No attempts heard</div>'}</div>
      ${r.disconnects.length ? `<h3 class="subhead">Disconnects</h3>${tableHtml('<th>When</th><th>Access point</th><th>By</th><th>Reason</th>',
        r.disconnects.slice(0, 30).map(x => `<tr><td class="muted">${dt(x.ts)}</td><td>${devLink(x.bssid)}${x.ssid ? ` <span class="faint">${esc(x.ssid)}</span>` : ''}</td><td>${esc(x.by)}</td>
          <td>${esc(x.reason)} <span class="faint">(${x.code})</span>${x.hint ? `<div class="faint small-text">${esc(x.hint)}</div>` : ''}</td></tr>`).join(''))}` : ''}
      <p class="faint small-text">A sensor that hops channels hears only part of a connection; one that stays on the access point's channel hears all of it.</p>
    </div>`;
}

async function loadSiteJoins(el, days) {
  if (!el) return;
  const r = await api(`/api/joins?hours=${days * 24}`);
  if (!r.counts.attempts) return;
  el.hidden = false;
  const c = r.counts, rs = r.roam_stats;
  el.innerHTML = `<header><h2>Connections &amp; roaming</h2><span class="faint">connection attempts and roams heard on your access points</span></header>
    <div class="body">
      <div class="grid cols-4">${[['Attempts', c.attempts, `${c.connected} connected`], ['Failed', c.failed, c.incomplete ? `${c.incomplete} only partly heard` : ''],
        ['Roams', rs.count, Object.entries(rs.methods).map(([k, v]) => `${v} ${k}`).join(' · ')], ['Median roam', joinMs(rs.median_ms), rs.slow ? `${rs.slow} of ${rs.timed} slower than 150 ms` : rs.timed ? 'all under 150 ms' : '']]
        .map(([l, v, m]) => `<div class="card"><div class="label">${l}</div><div class="value">${typeof v === 'number' ? num(v) : v}</div><div class="meta">${esc(m)}</div></div>`).join('')}</div>
      ${r.causes.length ? `<h3 class="subhead">Why connections failed</h3>${tableHtml('<th>Cause</th><th class="num">Times</th><th class="num">Clients</th><th class="num">Last</th>',
        r.causes.map(x => `<tr><td style="white-space:normal"><b>${esc(x.cause)}</b><div class="faint small-text">${esc(x.example)}</div></td><td class="num">${x.count}</td><td class="num">${x.clients}</td><td class="num muted">${ago(x.last)}</td></tr>`).join(''))}
        <h3 class="subhead">Failed attempts</h3>${tableHtml('<th>When</th><th>Client</th><th>Access point</th><th>Failed at</th>',
        r.failures.slice(0, 30).map(f => `<tr class="link" data-href="#/device/${enc(f.mac)}"><td class="muted">${dt(f.start)}</td><td>${f.name ? esc(f.name) + ' ' : ''}<span class="mono faint">${esc(f.mac)}</span></td>
          <td>${esc(f.ssid || '')} <span class="mono faint">${esc(f.bssid)}</span></td><td>${esc(f.failed_at || '')}</td></tr>`).join(''))}` : ''}
      ${r.roams.length ? `<h3 class="subhead">Roams</h3>${tableHtml('<th>When</th><th>Client</th><th>From → to</th><th>Method</th><th class="num">Took</th>',
        r.roams.slice(0, 30).map(x => `<tr class="link" data-href="#/device/${enc(x.mac)}"><td class="muted">${dt(x.ts)}</td><td>${x.name ? esc(x.name) + ' ' : ''}<span class="mono faint">${esc(x.mac)}</span></td>
          <td class="mono small-text">${esc(x.from)} → ${esc(x.to)}</td><td>${esc(x.method || '?')}${x.steered ? ' <span class="tag">steered</span>' : ''}</td>
          <td class="num"><span class="tag ${ROAM_TIME_TAG[x.grade] || ''}" title="${esc(ROAM_TIME_HELP)}">${joinMs(x.ms)}</span></td></tr>`).join(''))}` : ''}
    </div>`;
  linkRows(el);
}
