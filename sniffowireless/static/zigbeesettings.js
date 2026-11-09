'use strict';
/* Settings → Zigbee: which channels each Zigbee stick listens on, how long on each, how often it scans for networks and whether it
   listens passively at all, for this server and for remote sensors. Saving applies at once on this server; a remote sensor picks the
   settings up with its next upload (the same way as Settings → Wi-Fi channels and LoRa bands). */

SETTINGS_VIEWS.zigbee = async function (el) {
  let data = await api('/api/zigbee-settings');
  const ids = () => data.targets.map(t => t.id).join(',');
  const own = c => !c || (!c.channels && !c.hop_interval && !c.scan_interval && c.sniff == null);
  const ALL = Array.from({ length: 16 }, (_, i) => i + 11);

  function statusTag(t) {
    const c = t.config, has = c && !own(c);
    if (!t.sticks.length) return '<span class="tag">no Zigbee stick reported</span>';
    if (t.id !== 'local' && !t.online) return `<span class="tag warn">offline</span>${has ? ' <span class="faint small-text">applies when it reconnects</span>' : ''}`;
    if (t.too_old) return '<span class="tag bad">sensor software too old</span> <span class="faint small-text">update the sensor image to change its Zigbee settings from here</span>';
    if (!c || !c.rev) return '<span class="tag">using its own settings</span>';
    return t.applied ? `<span class="tag on">applied</span>${own(c) ? ' <span class="faint small-text">back on its own settings</span>' : ''}` : '<span class="tag warn">waiting for the sensor…</span>';
  }
  const canEdit = t => t.sticks.length > 0 || (t.id !== 'local' && !t.online);
  const chans = list => !list || !list.length ? '' : list.length === 16 ? 'all channels (11-26)' : 'channel' + (list.length > 1 ? 's ' : ' ') + list.join(', ');
  const stickRows = t => t.sticks.map(b => `<tr><td class="mono"><span class="state-dot ${b.state === 'error' ? '' : 'on'}"></span>${esc(b.iface || b.name)}</td>
      <td class="muted">${esc(chans(b.zb_channels))}${b.channel ? ` <span class="faint">· now ${esc(b.channel)}</span>` : ''}</td>
      <td class="num muted">${num(b.packets || 0)}</td>
      <td>${b.error ? `<span class="err small-text">${esc(b.error)}</span>` : `<span class="muted">${esc([b.state, b.firmware].filter(Boolean).join(' · '))}</span>`}${b.warning ? `<div class="warn-text small-text">${esc(b.warning)}</div>` : ''}</td></tr>`).join('');
  const stickTable = t => t.sticks.length ? tableHtml('<th>Stick</th><th>Listening on</th><th class="num">Frames</th><th>State</th>', stickRows(t), '') : '';
  const sniffValue = c => c && c.sniff != null ? (c.sniff ? '1' : '0') : '';

  function panel(t) {
    const c = t.config || {};
    const d = data.defaults;
    return `<section class="panel" data-t="${esc(t.id)}" style="margin-bottom:16px"><header><h2>${esc(t.name)}</h2><span class="zs-status">${statusTag(t)}</span></header><div class="body">
      ${!canEdit(t) ? `<p class="muted" style="margin:0">${t.id === 'local' ? 'This server has no Zigbee stick configured. Set <code>ZIGBEE_DEVICES</code> to use one here.' : 'This sensor reports no Zigbee stick.'}</p>` : ''}
      <div class="zs-sticks">${stickTable(t)}</div>
      ${canEdit(t) ? `<form class="zs-form form-narrow" style="margin-top:14px">
        <label class="field">Channels <span class="faint">(empty: the sensor's own setting${t.id === 'local' ? `, ${esc(d.channels.split(',').length === 16 ? 'all' : d.channels)}` : ''})</span>
          <input name="channels" value="${esc(c.channels || '')}" placeholder="e.g. 15,20-25" maxlength="200" autocomplete="off"></label>
        <div class="zs-chips" style="margin:6px 0">${ALL.map(n => `<button type="button" class="btn small ghost zs-chip" data-ch="${n}">${n}</button>`).join(' ')}
          <button type="button" class="btn small ghost zs-all">All</button><button type="button" class="btn small ghost zs-none">Clear</button></div>
        <p class="faint small-text">Zigbee uses channels 11 to 26. A stick hears one channel at a time and hops over the ones you choose, so the fewer channels, the less brief traffic it misses.
          Zigbee networks usually sit on 11, 15, 20, 25 or 26; Wi-Fi and Thread use some of the others.</p>
        <div class="row" style="gap:16px;flex-wrap:wrap">
          <label class="field">Time on each channel (s) <input name="hop" type="number" step="0.5" min="0.2" max="600" value="${c.hop_interval || ''}" placeholder="${esc(String(d.hop_interval))}" style="width:110px"></label>
          <label class="field">Network scan every (s) <input name="scan" type="number" step="30" min="30" max="86400" value="${c.scan_interval || ''}" placeholder="${esc(String(d.scan_interval))}" style="width:110px"></label>
          <label class="field">Passive listening
            <select name="sniff"><option value="" ${sniffValue(c) === '' ? 'selected' : ''}>The sensor's own (${d.sniff ? 'on' : 'off'})</option><option value="1" ${sniffValue(c) === '1' ? 'selected' : ''}>On</option><option value="0" ${sniffValue(c) === '0' ? 'selected' : ''}>Off: network scans only</option></select></label></div>
        <div class="row"><button class="btn primary">Save</button><button type="button" class="btn zs-reset" ${own(c) ? 'hidden' : ''}>Back to the sensor's own settings</button></div></form>` : ''}
    </div></section>`;
  }

  function render() {
    el.innerHTML = `<p class="muted" style="margin-top:0">Choose which Zigbee channels each stick listens on and how it scans. Saving applies at once on this server; a remote sensor picks it up within a few seconds.
      Anything left empty stays as the sensor's own configuration (<code>ZIGBEE_CHANNELS</code>, <code>ZIGBEE_HOP_INTERVAL</code>, <code>ZIGBEE_SCAN_INTERVAL</code>, <code>ZIGBEE_SNIFF</code>) says.
      The stick itself is only listened to, never changed: the device path stays an environment setting (<code>ZIGBEE_DEVICES</code>).</p>
      ${data.targets.map(panel).join('')}`;
    el.querySelectorAll('.panel[data-t]').forEach(p => bind(p, data.targets.find(t => t.id === p.dataset.t)));
  }

  function bind(p, t) {
    const form = p.querySelector('.zs-form');
    if (!form) return;
    const input = form.elements.channels;
    const chosen = () => {
      const out = new Set();
      input.value.split(',').map(x => x.trim()).filter(Boolean).forEach(tok => {
        const [lo, hi] = tok.split('-').map(Number);
        for (let c = lo; c <= (hi || lo); c++) if (c >= 11 && c <= 26) out.add(c);
      });
      return out;
    };
    const set = s => { input.value = [...s].sort((a, b) => a - b).join(','); paint(); };
    const paint = () => { const s = chosen(); p.querySelectorAll('.zs-chip').forEach(b => b.classList.toggle('on', s.has(+b.dataset.ch))); };
    p.querySelectorAll('.zs-chip').forEach(b => b.onclick = () => { const s = chosen(); s.has(+b.dataset.ch) ? s.delete(+b.dataset.ch) : s.add(+b.dataset.ch); set(s); });
    p.querySelector('.zs-all').onclick = () => set(new Set(ALL));
    p.querySelector('.zs-none').onclick = () => set(new Set());
    input.addEventListener('input', paint);
    paint();
    form.onsubmit = async e => {
      e.preventDefault();
      const body = { channels: input.value.trim() || null, hop_interval: form.elements.hop.value ? +form.elements.hop.value : null,
        scan_interval: form.elements.scan.value ? +form.elements.scan.value : null, sniff: form.elements.sniff.value === '' ? null : form.elements.sniff.value === '1' };
      try {
        await send('PUT', `/api/zigbee-settings/${enc(t.id)}`, body);
        toast(t.id === 'local' ? 'Saved and applied' : 'Saved; the sensor applies it with its next upload');
        await refresh(false);
        p.querySelector('.zs-reset').hidden = false;
      } catch (err) { toast(err.message, true); }
    };
    p.querySelector('.zs-reset').onclick = async () => {
      if (!confirm(`Go back to the own settings of ${t.name}?`)) return;
      try { await send('DELETE', `/api/zigbee-settings/${enc(t.id)}`); toast('Back on its own settings'); await refresh(true); } catch (err) { toast(err.message, true); }
    };
  }

  // Refresh what changes by itself (sticks, applied / waiting) without redrawing the forms being edited.
  async function refresh(full) {
    const next = await api('/api/zigbee-settings');
    const changed = ids() !== next.targets.map(t => t.id).join(',');
    data = next;
    if (full || changed) { render(); return; }
    data.targets.forEach(t => {
      const p = el.querySelector(`.panel[data-t="${CSS.escape(t.id)}"]`);
      if (!p) return;
      p.querySelector('.zs-status').innerHTML = statusTag(t);
      p.querySelector('.zs-sticks').innerHTML = stickTable(t);
    });
  }

  render();
  every(4000, () => refresh(false).catch(() => { /* offline: keep what is shown */ }));
};
