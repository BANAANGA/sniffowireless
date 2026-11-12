'use strict';
/* LoRa page: what was heard on 868/915 MHz and which protocol it looks like. Uses helpers from app.js/views.js.
   Addresses, frame types and signal are shown. Message text, positions and node names are shown only for what the public Meshtastic
   default key (or no key) opens, and only while that is switched on in Settings → LoRa bands; private channels are never read. */

const LORA_COLORS = { meshtastic: '#3ecf8e', meshcore: '#4cc2ff', lorawan: '#f5b84a', 'lora-aprs': '#c792ea', unknown: '#8b95a5' };

addRoute('/lora', async (_, params) => {
  const hours = +(params.get('hours') || 24);
  const d = await api(`/api/lora?hours=${hours}`);
  const span = hours * 3600;
  const rf = radioFilter('/lora', params, [['protocol', 'Protocol'], ['type', 'Node type'], ['settings', 'Radio settings'], ['position', 'Position']], d.nodes, { hours });
  const nodes = rf.shown;
  const color = p => LORA_COLORS[p] || LORA_COLORS.unknown;
  const total = d.protocols.reduce((a, p) => a + p.packets, 0);
  const max = Math.max(1, ...d.protocols.map(p => p.packets));
  const level = x => { const w = x.protocol === 'unknown' ? '' : x.confidence >= 80 ? 'sure' : x.confidence >= 65 ? 'likely' : 'a guess';
    return w ? ` <span class="faint small-text">${w}</span>` : ''; };
  const sig = x => x.rssi != null ? `${Math.round(x.rssi)} dBm` : '—';
  // Everything below that came off the air is untrusted text: always escaped.
  const pos = (lat, lon) => (typeof lat === 'number' && typeof lon === 'number') ? `<a href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=15/${lat}/${lon}" target="_blank" rel="noopener noreferrer">${lat.toFixed(4)}, ${lon.toFixed(4)}</a>` : '';
  const detail = p => { const i = p.info || [];
    if (i.text) return `“${esc(i.text)}”`;
    if (i.position) return pos(i.position.lat, i.position.lon) || '—';
    if (i.user) return esc([i.user.long_name, i.user.short_name && `(${i.user.short_name})`, i.user.hardware].filter(Boolean).join(' '));
    if (i.telemetry) return esc(Object.entries(i.telemetry).map(([k, v]) => `${k.replace('_', ' ')} ${v}`).join(', '));
    if (i.waypoint) return esc([i.waypoint.name, i.waypoint.description].filter(Boolean).join(' · ')) + (pos(i.waypoint.lat, i.waypoint.lon) ? ' ' + pos(i.waypoint.lat, i.waypoint.lon) : '');
    return ''; };

  app.innerHTML = `<div class="page-head"><div><h1>LoRa</h1><div class="sub">What was heard on the LoRa bands and which protocol it looks like. The radio hops between the profiles below, so a quiet profile can still be busy while the radio listens to another. Private traffic stays hidden: you see addresses, frame types and signal, and, from the public Meshtastic channel, its messages and positions.</div></div>
    <div class="row"><a class="btn small ghost" href="/api/export/lora-nodes.csv" download>Nodes (CSV)</a><a class="btn small ghost" href="/api/export/lora-packets.csv?hours=${hours}" download>Packets (CSV)</a>
      ${seg('hours', [[1, '1h'], [24, '24h'], [168, '7d']], hours)}</div></div>
    ${!d.configured ? '<div class="callout">No LoRa receiver configured. Flash a Heltec WiFi LoRa 32 V3 with <code>firmware/lora-sniffer</code> and set <code>LORA_DEVICES</code> (see README → LoRa).</div>' : ''}
    ${d.configured && !total && !d.sensors.some(s => s.error) ? '<div class="empty">Nothing heard yet. LoRa networks are often sparse; check that the listening profiles match your region.</div>' : ''}
    ${d.sensors.map(s => `<div class="callout">${esc(s.iface || s.name)}: ${s.error ? `<span class="err">${esc(s.error)}</span>` : esc([s.state, s.firmware, s.profile ? 'on ' + s.profile : '', s.crc_errors ? s.crc_errors + ' bad frames' : ''].filter(Boolean).join(' · '))}${s.warning ? `<div class="warn-text small-text">${esc(s.warning)}</div>` : ''}${d.firmware_latest && s.fw_version != null && s.fw_version < d.firmware_latest ? `<div class="warn-text small-text">Its firmware (version ${s.fw_version}) is older than the version this server offers (${d.firmware_latest}). Update it in <a href="#/settings?tab=loraflasher">Settings → LoRa flasher</a>.</div>` : ''}</div>`).join('')}
    <div class="grid cols-4">${[['Packets', num(total), `in ${hours}h`], ['Protocols', d.protocols.filter(p => p.protocol !== 'unknown').length, 'recognised'], ['Nodes', d.nodes.length, 'addresses heard'],
      ['Unidentified', num((d.protocols.find(p => p.protocol === 'unknown') || {}).packets || 0), 'could be anything']].map(([a, b, c]) => `<div class="card"><div class="label">${a}</div><div class="value">${b}</div><div class="meta">${esc(c)}</div></div>`).join('')}</div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel"><header><h2>Protocols</h2></header><div class="body"><ul class="bars-list">${d.protocols.map(p => `<li><div><div class="name">${esc(p.label)}</div><div class="track"><i style="width:${p.packets / max * 100}%;background:${color(p.protocol)}"></i></div></div><div class="n">${num(p.packets)}</div></li>`).join('') || '<li class="faint">Nothing yet</li>'}</ul></div></section>
      <section class="panel span-2"><header><h2>Packets over time</h2><span class="faint">${d.protocols.map(p => `<span class="swatch" style="background:${color(p.protocol)}"></span>${esc(p.label)}`).join(' &nbsp; ')}</span></header><div class="body"><div class="chart-box"><canvas id="lora-tl"></canvas></div></div></section>
      <section class="panel span-3"><header><h2>Listening on</h2><span class="faint">the radio visits each profile in turn</span></header><div class="body flush">${tableHtml(
        '<th>Profile</th><th>Settings</th><th class="num">Packets heard</th><th class="num" title="Time the frames heard on this profile occupied the channel">Airtime heard</th><th class="num" title="Airtime heard divided by the time the radio listened on this profile (estimated: a hopping radio listens to each profile 1/N of the time)">Channel use (est.)</th>',
        d.listening.map(p => { const got = d.profiles.filter(x => x.profile === p.name).reduce((a, x) => a + x.packets, 0);
          return `<tr><td>${esc(p.label)} <span class="faint mono">${esc(p.name)}</span></td><td class="mono muted">${esc(p.describe)}</td><td class="num">${num(got)}</td><td class="num">${p.air_s >= 60 ? (p.air_s / 60).toFixed(1) + ' min' : p.air_s.toFixed(1) + ' s'}</td><td class="num">${(p.use * 100).toFixed(p.use < 0.1 ? 1 : 0)}%</td></tr>`; }).join(''), 'No profiles')}</div></section>
      ${d.decode_public || d.messages.length ? `<section class="panel span-3"><header><h2>Public messages</h2><span class="faint">${d.decode_public ? 'Meshtastic public channel, newest first' : 'reading is switched off'}</span></header><div class="body flush">${tableHtml(
        '<th>Time</th><th>From</th><th>Message</th><th class="num">Signal</th>',
        d.messages.map(m => `<tr><td class="num">${dt(m.ts)}</td><td>${m.from ? `<b>${esc(m.from)}</b> ` : ''}<span class="mono faint">${esc(m.src || '')}</span></td><td>${esc(m.text || '')}</td><td class="num">${esc(sig(m))}</td></tr>`).join(''),
        d.decode_public ? 'No messages on the public channel yet' : 'Switch it on in Settings → LoRa bands')}</div></section>` : ''}
      <section class="panel span-3"><header><h2>Nodes</h2><span class="faint">${rf.count ? `${nodes.length} of ${d.nodes.length}` : d.nodes.length}</span>${d.nodes.length ? rf.html : ''}</header><div class="body flush">${tableHtml(
        '<th>Protocol</th><th>Address</th><th>Name</th><th>Type</th><th>Position</th><th class="num">Packets</th><th class="num">Signal</th><th class="num">Last seen</th><th></th>',
        nodes.map(n => `<tr><td><span class="swatch" style="background:${color(n.protocol)}"></span>${esc(n.label)}</td><td class="mono">${esc(n.addr)}</td><td>${n.given_name ? `<b>${esc(n.given_name)}</b> ${n.name ? `<span class="faint">${esc(n.name)}</span>` : ''}` : esc(n.name || '—')}${watchTag(n)}</td><td class="muted">${esc(n.kind || '—')}</td><td>${pos(n.lat, n.lon) || '<span class="faint">—</span>'}</td><td class="num">${num(n.packets)}</td><td class="num">${esc(sig(n))}</td><td class="num">${ago(n.last_seen)}</td><td class="num">${isAdmin() ? `<button class="btn small ghost" data-watch="${esc(n.protocol)}|${esc(n.addr)}" title="Name or watch this node">${n.watch ? '★' : '☆'}</button>` : ''}</td></tr>`).join(''), rf.count ? 'No node matches these filters' : 'No nodes heard yet')}</div></section>
      <section class="panel span-3"><header><h2>Latest packets</h2><span class="faint">newest first</span></header><div class="body flush">${tableHtml(
        '<th>Time</th><th>Protocol</th><th>Type</th><th>Detail</th><th>From</th><th>To</th><th class="num">Hops</th><th class="num">Bytes</th><th class="num">Signal</th>',
        d.recent.map(p => `<tr><td class="num">${dt(p.ts)}</td><td><span class="swatch" style="background:${color(p.protocol)}"></span>${esc(p.label)}${level(p)}</td><td class="muted">${esc(p.kind || '—')}</td><td>${detail(p)}</td><td class="mono">${esc(p.src || '—')}</td><td class="mono">${esc(p.dst || '—')}</td><td class="num">${p.hops == null ? '—' : p.hops}</td><td class="num">${num(p.bytes)}</td><td class="num">${esc(sig(p))}</td></tr>`).join(''), 'No packets yet')}</div></section>
    </div>`;
  onSeg(app, 'hours', v => { location.hash = hrefWith('/lora', { ...rf.active, hours: v }); });
  rf.bind(app);
  app.querySelectorAll('button[data-watch]').forEach(b => b.onclick = () => { const [proto, addr] = b.dataset.watch.split('|'); const n = d.nodes.find(x => x.protocol === proto && x.addr === addr);
    editRadio('lora', proto, addr, { label: n.given_name, watch: n.watch, silent: n.silent_min }, () => route()); });
  if (d.t.length > 1) {
    const xy = arr => d.t.map((x, i) => ({ x, y: (arr || [])[i] || 0 }));
    chart(document.getElementById('lora-tl'), { type: 'line', data: { datasets: d.protocols.map(p => ({ label: p.label, data: xy(d.series[p.protocol]),
      borderColor: color(p.protocol), fill: false, borderWidth: 1.5, pointRadius: 0, tension: .3 })) },
      options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        scales: { x: { ...timeScale(span), min: d.t[0], max: d.t[d.t.length - 1] }, y: yScale({}) },
        plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } } } });
  }
});
