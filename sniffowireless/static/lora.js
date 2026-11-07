'use strict';
/* LoRa page: what was heard on 868/915 MHz and which protocol it looks like. Uses helpers from app.js/views.js.
   Only addresses, frame types and signal are shown: the radio contents (and any message text) are never kept. */

const LORA_COLORS = { meshtastic: '#3ecf8e', meshcore: '#4cc2ff', lorawan: '#f5b84a', 'lora-aprs': '#c792ea', unknown: '#8b95a5' };

addRoute('/lora', async (_, params) => {
  const hours = +(params.get('hours') || 24);
  const d = await api(`/api/lora?hours=${hours}`);
  const span = hours * 3600;
  const color = p => LORA_COLORS[p] || LORA_COLORS.unknown;
  const total = d.protocols.reduce((a, p) => a + p.packets, 0);
  const max = Math.max(1, ...d.protocols.map(p => p.packets));
  const level = x => { const w = x.protocol === 'unknown' ? '' : x.confidence >= 80 ? 'sure' : x.confidence >= 65 ? 'likely' : 'a guess';
    return w ? ` <span class="faint small-text">${w}</span>` : ''; };
  const sig = x => x.rssi != null ? `${Math.round(x.rssi)} dBm` : '—';

  app.innerHTML = `<div class="page-head"><div><h1>LoRa</h1><div class="sub">What was heard on the LoRa bands and which protocol it looks like. The radio hops between the profiles below, so a quiet profile can still be busy while the radio listens to another. Message contents stay hidden: you see addresses, frame types and signal.</div></div>
    ${seg('hours', [[1, '1h'], [24, '24h'], [168, '7d']], hours)}</div>
    ${!d.configured ? '<div class="callout">No LoRa receiver configured. Flash a Heltec WiFi LoRa 32 V3 with <code>firmware/lora-sniffer</code> and set <code>LORA_DEVICES</code> (see README → LoRa).</div>' : ''}
    ${d.configured && !total && !d.sensors.some(s => s.error) ? '<div class="empty">Nothing heard yet. LoRa networks are often sparse; check that the listening profiles match your region.</div>' : ''}
    ${d.sensors.map(s => `<div class="callout">${esc(s.iface || s.name)}: ${s.error ? `<span class="err">${esc(s.error)}</span>` : esc([s.state, s.firmware, s.profile ? 'on ' + s.profile : '', s.crc_errors ? s.crc_errors + ' bad frames' : ''].filter(Boolean).join(' · '))}${s.warning ? `<div class="warn-text small-text">${esc(s.warning)}</div>` : ''}</div>`).join('')}
    <div class="grid cols-4">${[['Packets', num(total), `in ${hours}h`], ['Protocols', d.protocols.filter(p => p.protocol !== 'unknown').length, 'recognised'], ['Nodes', d.nodes.length, 'addresses heard'],
      ['Unidentified', num((d.protocols.find(p => p.protocol === 'unknown') || {}).packets || 0), 'could be anything']].map(([a, b, c]) => `<div class="card"><div class="label">${a}</div><div class="value">${b}</div><div class="meta">${esc(c)}</div></div>`).join('')}</div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel"><header><h2>Protocols</h2></header><div class="body"><ul class="bars-list">${d.protocols.map(p => `<li><div><div class="name">${esc(p.label)}</div><div class="track"><i style="width:${p.packets / max * 100}%;background:${color(p.protocol)}"></i></div></div><div class="n">${num(p.packets)}</div></li>`).join('') || '<li class="faint">Nothing yet</li>'}</ul></div></section>
      <section class="panel span-2"><header><h2>Packets over time</h2><span class="faint">${d.protocols.map(p => `<span class="swatch" style="background:${color(p.protocol)}"></span>${esc(p.label)}`).join(' &nbsp; ')}</span></header><div class="body"><div class="chart-box"><canvas id="lora-tl"></canvas></div></div></section>
      <section class="panel span-3"><header><h2>Listening on</h2><span class="faint">the radio visits each profile in turn</span></header><div class="body flush">${tableHtml(
        '<th>Profile</th><th>Settings</th><th class="num">Packets heard</th><th class="num" title="Time the frames heard on this profile occupied the channel">Airtime heard</th><th class="num" title="Airtime heard divided by the time the radio listened on this profile (estimated: a hopping radio listens to each profile 1/N of the time)">Channel use (est.)</th>',
        d.listening.map(p => { const got = d.profiles.filter(x => x.profile === p.name).reduce((a, x) => a + x.packets, 0);
          return `<tr><td>${esc(p.label)} <span class="faint mono">${esc(p.name)}</span></td><td class="mono muted">${esc(p.describe)}</td><td class="num">${num(got)}</td><td class="num">${p.air_s >= 60 ? (p.air_s / 60).toFixed(1) + ' min' : p.air_s.toFixed(1) + ' s'}</td><td class="num">${(p.use * 100).toFixed(p.use < 0.1 ? 1 : 0)}%</td></tr>`; }).join(''), 'No profiles')}</div></section>
      <section class="panel span-3"><header><h2>Nodes</h2><span class="faint">${d.nodes.length}</span></header><div class="body flush">${tableHtml(
        '<th>Protocol</th><th>Address</th><th>Name</th><th>Type</th><th class="num">Packets</th><th class="num">Signal</th><th class="num">Last seen</th>',
        d.nodes.map(n => `<tr><td><span class="swatch" style="background:${color(n.protocol)}"></span>${esc(n.label)}</td><td class="mono">${esc(n.addr)}</td><td>${esc(n.name || '—')}</td><td class="muted">${esc(n.kind || '—')}</td><td class="num">${num(n.packets)}</td><td class="num">${esc(sig(n))}</td><td class="num">${ago(n.last_seen)}</td></tr>`).join(''), 'No nodes heard yet')}</div></section>
      <section class="panel span-3"><header><h2>Latest packets</h2><span class="faint">newest first</span></header><div class="body flush">${tableHtml(
        '<th>Time</th><th>Protocol</th><th>Type</th><th>From</th><th>To</th><th class="num">Hops</th><th class="num">Bytes</th><th class="num">Signal</th>',
        d.recent.map(p => `<tr><td class="num">${dt(p.ts)}</td><td><span class="swatch" style="background:${color(p.protocol)}"></span>${esc(p.label)}${level(p)}</td><td class="muted">${esc(p.kind || '—')}</td><td class="mono">${esc(p.src || '—')}</td><td class="mono">${esc(p.dst || '—')}</td><td class="num">${p.hops == null ? '—' : p.hops}</td><td class="num">${num(p.bytes)}</td><td class="num">${esc(sig(p))}</td></tr>`).join(''), 'No packets yet')}</div></section>
    </div>`;
  onSeg(app, 'hours', v => { location.hash = hrefWith('/lora', { hours: v }); });
  if (d.t.length > 1) {
    const xy = arr => d.t.map((x, i) => ({ x, y: (arr || [])[i] || 0 }));
    chart(document.getElementById('lora-tl'), { type: 'line', data: { datasets: d.protocols.map(p => ({ label: p.label, data: xy(d.series[p.protocol]),
      borderColor: color(p.protocol), fill: false, borderWidth: 1.5, pointRadius: 0, tension: .3 })) },
      options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        scales: { x: { ...timeScale(span), min: d.t[0], max: d.t[d.t.length - 1] }, y: yScale({}) },
        plugins: { tooltip: { callbacks: { title: i => dt(i[0].parsed.x) } } } } });
  }
});
