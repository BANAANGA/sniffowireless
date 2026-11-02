'use strict';
/* Ethernet / LAN views: the LAN page and the "Network" panel on device pages. Uses helpers from app.js/views.js. */

function fmtBytes(b) {
  if (b == null) return '—';
  const u = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return `${b >= 100 || i === 0 ? Math.round(b) : b.toFixed(1)} ${u[i]}`;
}
const LAN_IN = KINDS.ap.color, LAN_OUT = KINDS.wifi_client.color;

function trafficChart(canvas, series, bucket, hours) {
  const now = Date.now() / 1000;
  chart(canvas, { type: 'line', data: { datasets: [
    { label: 'Received', data: series.map(p => ({ x: p.t, y: (p.in_b || 0) * 8 / bucket })), borderColor: LAN_IN, backgroundColor: LAN_IN + '18', fill: true, pointRadius: 0, borderWidth: 1.5, tension: .25 },
    { label: 'Sent', data: series.map(p => ({ x: p.t, y: (p.out_b || 0) * 8 / bucket })), borderColor: LAN_OUT, backgroundColor: LAN_OUT + '18', fill: true, pointRadius: 0, borderWidth: 1.5, tension: .25 }] },
    options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { ...timeScale(hours * 3600), min: now - hours * 3600, max: now }, y: yScale({ ticks: { color: FAINT, callback: v => fmtBytes(v / 8) + '/s' } }) },
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 8, boxHeight: 8, color: MUTED } },
        tooltip: { callbacks: { title: i => dt(i[0].parsed.x), label: i => `${i.dataset.label}: ${fmtBytes(i.parsed.y / 8)}/s` } } } } });
}

// ===================================================================== LAN page
addRoute('/lan', async (_, params) => {
  const hours = +(params.get('hours') || 24);
  const l = await api(`/api/lan?hours=${hours}`);
  const name = d => d.label || d.name || d.ident || d.vendor || d.mac;
  app.innerHTML = `<div class="page-head"><div><h1>LAN</h1><div class="sub">Wired / LAN devices discovered via ARP, DHCP, mDNS, SSDP and LLDP, and the traffic the Ethernet sensor can see.</div></div>
    ${seg('hours', [[1, '1h'], [24, '24h'], [168, '7d']], hours)}</div>
    ${!l.online.length && !l.has_traffic ? '<div class="callout">No LAN data yet. Set <code>ETH_INTERFACES</code> (see README → Ethernet monitoring). On a normal switch port yolo only sees discovery broadcasts; connect it to a mirror/SPAN port to see all traffic.</div>' : ''}
    <div class="grid cols-4">${[['Online', l.online.length, 'devices with an IP'], ['Received', fmtBytes(l.total_in), `in ${hours}h`], ['Sent', fmtBytes(l.total_out), `in ${hours}h`],
      ['DHCP servers', l.dhcp_servers.length, l.dhcp_servers.some(s => !s.trusted) && l.dhcp_servers.length > 1 ? 'more than one — check' : '']].map(([a, b, c]) => `<div class="card"><div class="label">${a}</div><div class="value">${b}</div><div class="meta">${esc(c)}</div></div>`).join('')}</div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel span-2"><header><h2>Traffic</h2><span class="faint">throughput, all devices</span></header><div class="body"><div class="chart-box"><canvas id="lan-tl"></canvas></div></div></section>
      <section class="panel"><header><h2>Top talkers</h2></header><div class="body"><ul class="bars-list">${(() => { const max = Math.max(1, ...l.talkers.map(t => (t.bytes_out || 0) + (t.bytes_in || 0)));
        return l.talkers.slice(0, 10).map(t => `<li data-href="#/device/${enc(t.mac)}"><div><div class="name">${esc(name(t))} <span class="faint mono">${esc(t.ip || '')}</span></div>
          <div class="track"><i style="width:${(t.bytes_in || 0) / max * 100}%;background:${LAN_IN}"></i><i style="width:${(t.bytes_out || 0) / max * 100}%;background:${LAN_OUT}"></i></div></div><div class="n">${fmtBytes((t.bytes_out || 0) + (t.bytes_in || 0))}</div></li>`).join('') || '<div class="empty">No traffic seen</div>'; })()}</ul></div></section>
      <section class="panel span-3"><header><h2>Devices online</h2><span class="faint">${l.online.length}</span></header><div class="body flush">${tableHtml(
        '<th>IP</th><th>Device</th><th>Identified as</th><th>MAC</th><th class="num">Traffic</th><th class="num">First seen</th><th class="num">Last seen</th>',
        l.online.map(d => `<tr class="link" data-href="#/device/${enc(d.mac)}"><td class="mono">${esc(d.ip)}</td><td>${d.watch ? '<span class="star">★</span>' : ''}${d.label ? `<b>${esc(d.label)}</b>` : esc(d.name || '')} ${d.kind !== 'lan' ? kindBadge(d.kind) : ''}</td>
          <td class="muted trunc">${esc(d.ident || d.vendor || '—')}</td><td class="mono faint">${esc(d.mac)}</td><td class="num">${d.bytes ? fmtBytes(d.bytes) : '<span class="faint">—</span>'}</td>
          <td class="num muted">${ago(d.first_seen)}</td><td class="num">${ago(d.last_seen)}</td></tr>`).join(''), 'No devices discovered yet')}</div></section>
      <section class="panel span-2"><header><h2>Internet destinations</h2><span class="faint">by traffic</span></header><div class="body flush">${tableHtml(
        '<th>Destination</th><th>Service</th><th class="num">Devices</th><th class="num">Traffic</th>',
        l.external.map(p => `<tr><td>${p.peer_name ? `<b>${esc(p.peer_name)}</b> ` : ''}<span class="mono faint">${esc(p.peer)}</span></td><td class="muted">${esc(p.service)}</td><td class="num">${p.devices}</td><td class="num">${fmtBytes(p.bytes)}</td></tr>`).join(''),
        'No internet traffic seen (needs a mirror/SPAN port or running on the router)')}</div></section>
      <section class="panel"><header><h2>Services</h2><span class="faint">traffic by protocol</span></header><div class="body"><ul class="bars-list">${(() => { const max = Math.max(1, ...l.services.map(s => s[1]));
        return l.services.map(([s, b]) => `<li><div><div class="name">${esc(s)}</div><div class="track"><i style="width:${b / max * 100}%;background:${KINDS.lan.color}"></i></div></div><div class="n">${fmtBytes(b)}</div></li>`).join('') || '<div class="empty">No data</div>'; })()}</ul></div></section>
      <section class="panel span-2"><header><h2>DNS lookups</h2><span class="faint">most widely looked-up names</span></header><div class="body flush">${tableHtml(
        '<th>Name</th><th class="num">Devices</th><th class="num">Lookups</th><th class="num">Last</th>',
        l.dns.map(d => `<tr><td class="trunc" style="max-width:420px">${esc(d.name)}</td><td class="num">${d.devices}</td><td class="num muted">${num(d.queries)}</td><td class="num muted">${ago(d.last_seen)}</td></tr>`).join(''),
        'No plain DNS seen (devices using DNS-over-HTTPS/TLS are invisible here)')}</div></section>
      <section class="panel"><header><h2>DHCP servers</h2></header><div class="body flush">${tableHtml(
        '<th>Server</th><th>Gateway</th><th class="num">Replies</th><th>Trusted</th>',
        l.dhcp_servers.map(s => `<tr><td>${devLink(s.mac, s.ip || s.mac)}<div class="faint small-text">${esc(s.vendor || s.name || s.mac)}</div></td><td class="mono muted">${esc(s.router || '—')}</td><td class="num muted">${num(s.replies)}</td>
          <td>${isAdmin() ? `<label class="switch"><input type="checkbox" data-dhcp="${esc(s.mac)}" ${s.trusted ? 'checked' : ''}><span></span></label>` : (s.trusted ? 'yes' : 'no')}</td></tr>`).join(''),
        'None seen yet')}
        <p class="faint small-text" style="padding:0 16px">Trust your real DHCP server: any other server answering then raises a <b>rogue DHCP</b> alert.</p></div></section>
    </div>`;
  onSeg(app, 'hours', v => { location.hash = hrefWith('/lan', { hours: v }); });
  linkRows(app);
  bindLi(app);
  trafficChart(document.getElementById('lan-tl'), l.series, l.bucket, hours);
  app.querySelectorAll('[data-dhcp]').forEach(c => c.onchange = async () => {
    await send('POST', '/api/lan/dhcp-trust', { mac: c.dataset.dhcp, trust: c.checked });
    toast(c.checked ? 'Trusted' : 'No longer trusted');
  });
  every(30000, async () => { if (location.hash.startsWith('#/lan')) route(); });
});

// ===================================================================== device panel
function lanPanel(d) {
  const lfp = ((d.extra || {}).fp || {}).lan;
  if (!d.ip && !lfp && d.kind !== 'lan') return '';
  return `<section class="panel span-3" id="lan-panel"><header><h2>Network (LAN)</h2><span class="faint" id="lan-sub"></span></header>
    <div class="body"><div class="kv" id="lan-kv"></div>
    <div class="grid cols-3" style="margin-top:16px"><div class="span-2"><h3 class="subhead" style="margin-top:0">Traffic</h3><div class="chart-box short"><canvas id="dev-lan-tl"></canvas></div></div>
    <div><h3 class="subhead" style="margin-top:0">DNS lookups</h3><div id="dev-dns" class="scroll-box"></div></div></div>
    <h3 class="subhead">Talks to</h3><div id="dev-peers"></div></div></section>`;
}

async function bindLanPanel(d) {
  if (!document.getElementById('lan-panel')) return;
  const hours = 24;
  const r = await api(`/api/devices/${enc(d.mac)}/lan?hours=${hours}`);
  const lfp = ((d.extra || {}).fp || {}).lan || {};
  const dhcp = lfp.dhcp || {}, mdns = lfp.mdns || {}, ssdp = lfp.ssdp || {}, lldp = lfp.lldp || {};
  const facts = [
    ['IP address', d.ip ? `<span class="mono">${esc(d.ip)}</span>` : '—'],
    ['Hostname', esc(d.name || '—')],
    dhcp.vendor ? ['DHCP vendor class', `<span class="mono">${esc(dhcp.vendor)}</span>`] : null,
    dhcp.prl ? ['DHCP fingerprint', `<span class="mono small-text">${esc(dhcp.prl)}</span>`] : null,
    (mdns.services || []).length ? ['mDNS services', mdns.services.map(s => `<span class="tag">${esc(s)}</span>`).join(' ')] : null,
    ssdp.server ? ['UPnP server', esc(ssdp.server)] : null,
    lldp.sysdesc ? ['LLDP', esc(`${lldp.sysname || ''} · ${lldp.sysdesc}${lldp.port ? ' · port ' + lldp.port : ''}`)] : null,
    r.dhcp_server ? ['DHCP server', `yes · ${num(r.dhcp_server.replies)} replies`] : null,
  ].filter(Boolean);
  document.getElementById('lan-kv').innerHTML = facts.map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join('');
  const tot = r.series.reduce((a, p) => [a[0] + (p.in_b || 0), a[1] + (p.out_b || 0)], [0, 0]);
  document.getElementById('lan-sub').textContent = `${fmtBytes(tot[0])} received · ${fmtBytes(tot[1])} sent in 24h`;
  if (r.series.length) trafficChart(document.getElementById('dev-lan-tl'), r.series, r.bucket, hours);
  else document.getElementById('dev-lan-tl').parentElement.innerHTML = '<div class="empty">No traffic seen for this device</div>';
  document.getElementById('dev-dns').innerHTML = r.dns.length ? `<ul class="plain">${r.dns.slice(0, 40).map(x => `<li class="trunc"><span>${esc(x.name)}</span> <span class="faint small-text">${num(x.count)}× · ${ago(x.last_seen)}</span></li>`).join('')}</ul>` : '<div class="faint">No plain DNS lookups seen</div>';
  const pe = document.getElementById('dev-peers');
  pe.innerHTML = tableHtml('<th>Peer</th><th>Service</th><th class="num">Sent</th><th class="num">Received</th>',
    r.peers.slice(0, 20).map(p => `<tr><td>${p.peer_mac ? devLink(p.peer_mac, p.peer_name || p.peer) : `${p.peer_name ? `<b>${esc(p.peer_name)}</b> ` : ''}<span class="mono faint">${esc(p.peer)}</span>`}${p.local ? ' <span class="tag">local</span>' : ''}</td>
      <td class="muted">${esc(p.service)}</td><td class="num">${fmtBytes(p.bytes_out)}</td><td class="num">${fmtBytes(p.bytes_in)}</td></tr>`).join(''), 'No conversations seen');
}
