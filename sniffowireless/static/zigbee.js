'use strict';
/* Zigbee / IEEE 802.15.4 page. Uses helpers from app.js/views.js. */

addRoute('/zigbee', async (_, params) => {
  const hours = +(params.get('hours') || 24);
  const z = await api(`/api/zigbee?hours=${hours}`);
  const pan = p => p == null ? '—' : '0x' + p.toString(16).padStart(4, '0');
  const hasData = z.networks.length || z.radios.length || z.total_frames;
  const maxFrames = Math.max(1, ...z.channels.map(c => c.frames));
  const energy = z.channels.filter(c => c.rssi != null);
  const stack = n => ({ 1: 'Zigbee (2006/2007)', 2: 'Zigbee PRO' })[n.stack_profile] || `Profile ${n.stack_profile ?? '?'}`;
  const signal = x => x.rssi != null ? `${x.rssi} dBm` : x.lqi != null ? `LQI ${x.lqi}` : '—';

  app.innerHTML = `<div class="page-head"><div><h1>Zigbee &amp; 802.15.4</h1><div class="sub">Networks found by scanning, and every radio heard by listening passively. Encrypted contents stay hidden: you see addresses, frame types and timing.</div></div>
    ${seg('hours', [[1, '1h'], [24, '24h'], [168, '7d']], hours)}</div>
    ${!z.configured ? '<div class="callout">No Zigbee stick configured. Plug in a coordinator stick and set <code>ZIGBEE_DEVICES</code> (see README → Zigbee &amp; 802.15.4).</div>' : ''}
    ${z.configured && !hasData && !z.sensors.some(s => s.error) ? '<div class="empty">Nothing heard yet. Scans run every few minutes; battery devices transmit only briefly.</div>' : ''}
    ${z.sensors.map(s => `<div class="callout">${esc(s.iface || s.name)}: ${s.error ? `<span class="err">${esc(s.error)}</span>` : esc([s.state, s.firmware, s.channel ? 'ch ' + s.channel : ''].filter(Boolean).join(' · '))}${s.warning ? `<div class="warn-text small-text">${esc(s.warning)}</div>` : ''}</div>`).join('')}
    <div class="grid cols-4">${[['Networks', z.networks.length, 'answered a scan'], ['Radios', z.radios.length, 'heard or addressed'], ['Frames', num(z.total_frames), `in ${hours}h`],
      ['Encrypted radios', z.radios.filter(r => r.encrypted > 0).length, 'at the radio layer']].map(([a, b, c]) => `<div class="card"><div class="label">${a}</div><div class="value">${b}</div><div class="meta">${esc(c)}</div></div>`).join('')}</div>
    <div class="grid cols-3" style="margin-top:16px">
      <section class="panel"><header><h2>Frames per channel</h2></header><div class="body"><ul class="bars-list">${z.channels.map(c => `<li><div><div class="name">Channel ${c.channel}</div><div class="track"><i style="width:${c.frames / maxFrames * 100}%;background:${KINDS.ble.color}"></i></div></div><div class="n">${num(c.frames)}</div></li>`).join('')}</ul></div></section>
      <section class="panel span-2"><header><h2>Networks</h2><span class="faint">${z.networks.length}</span></header><div class="body flush">${tableHtml(
        '<th>PAN</th><th>Extended ID</th><th class="num">Channel</th><th>Stack</th><th>Joining</th><th class="num">Routers</th><th class="num">Signal</th><th class="num">Last seen</th>',
        z.networks.map(n => `<tr><td class="mono">${pan(n.pan)}</td><td class="mono faint" title="${esc(n.vendor ? 'Maybe made by ' + n.vendor + ' (only a hint: many coordinators pick a random ID)' : '')}">${esc(n.ext_pan)}${n.vendor ? ` <span class="muted">${esc(n.vendor)}?</span>` : ''}</td><td class="num">${n.channel}</td><td class="muted">${esc(stack(n))}</td><td>${n.permit_join ? '<b>Open</b>' : '<span class="faint">Closed</span>'}</td><td class="num">${n.routers.length || '—'}</td><td class="num">${esc(signal(n))}</td><td class="num">${ago(n.last_seen)}</td></tr>`).join(''),
        'No networks found yet')}</div></section>
      ${energy.length ? `<section class="panel"><header><h2>Channel interference</h2><span class="faint">strongest signal, lower is better</span></header><div class="body"><ul class="bars-list">${energy.map(c => `<li><div><div class="name">Channel ${c.channel}</div><div class="track"><i style="width:${Math.max(0, Math.min(100, (c.rssi + 100) / 70 * 100))}%;background:${KINDS.ap.color}"></i></div></div><div class="n">${c.rssi} dBm</div></li>`).join('')}</ul></div></section>` : ''}
      <section class="panel ${energy.length ? 'span-2' : 'span-3'}"><header><h2>Radios heard</h2><span class="faint">protocol labels are guesses from unencrypted fields, not proof</span></header><div class="body flush">${tableHtml(
        '<th>Address</th><th>PAN</th><th>Protocol</th><th class="num">Channels</th><th class="num">Sent</th><th class="num">Received</th><th class="num">Encrypted</th><th class="num">Signal</th><th class="num">Last seen</th>',
        z.radios.map(r => `<tr><td class="mono">${esc(r.addr)}${r.vendor ? ` <span class="muted">${esc(r.vendor)}?</span>` : ''}</td><td class="mono faint">${pan(r.pan)}</td><td class="muted trunc" title="${esc(r.types.join(', '))}">${esc(r.hint_label)}</td><td class="num">${r.channels.join(', ')}</td><td class="num">${num(r.sent)}</td><td class="num">${num(r.received)}</td><td class="num">${num(r.encrypted)}</td><td class="num">${r.sent ? esc(signal(r)) : '<span class="faint" title="Only ever seen as a destination">—</span>'}</td><td class="num">${ago(r.last_seen)}</td></tr>`).join(''),
        'No radios heard yet')}</div></section>
    </div>`;
  onSeg(app, 'hours', v => { location.hash = hrefWith('/zigbee', { hours: v }); });
});
