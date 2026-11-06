'use strict';
/* Settings → Wi-Fi channels: which channels each Wi-Fi adapter listens on, for this server and for remote sensors.
   Saving applies at once on this server; a remote sensor picks the settings up with its next upload. */

const CH_PRESETS = [['default', 'Default (2.4 + 5 GHz common)'], ['2.4ghz', '2.4 GHz'], ['5common', '5 GHz common'], ['5ghz', 'All 5 GHz'],
  ['6ghz', '6 GHz (preferred channels)'], ['6all', 'All 6 GHz'], ['all', 'Everything']];
const CH_PRESET_BAND = { '2.4ghz': '2.4', '5common': '5', '5ghz': '5', '6ghz': '6', '6all': '6' };

SETTINGS_VIEWS.wifichannels = async function (el) {
  let data = await api('/api/channel-settings');
  const ids = () => data.targets.map(t => t.id).join(',');
  const own = c => !c || (!c.channels && !Object.keys(c.per_iface || {}).length && !c.regdomain && !c.hop_interval);
  const bandsOf = t => { const known = t.adapters.filter(a => a.supported_bands && a.supported_bands.length); return known.length === t.adapters.length && known.length ? new Set(known.flatMap(a => a.supported_bands)) : null; };

  function statusTag(t) {
    const c = t.config, has = c && !own(c);
    if (!t.adapters.length) return '<span class="tag">no Wi-Fi adapters reported</span>';
    if (t.id !== 'local' && !t.online) return `<span class="tag warn">offline</span>${has ? ' <span class="faint small-text">applies when it reconnects</span>' : ''}`;
    if (t.too_old) return '<span class="tag bad">sensor software too old</span> <span class="faint small-text">update the sensor image to change its channels from here</span>';
    if (!c || !c.rev) return '<span class="tag">using its own settings</span>';
    return t.applied ? `<span class="tag on">applied</span>${own(c) ? ' <span class="faint small-text">back on its own settings</span>' : ''}` : '<span class="tag warn">waiting for the sensor…</span>';
  }
  // Not for a sensor that is online and reports no Wi-Fi adapter (Bluetooth only), nor for this server without any.
  const canEdit = t => t.adapters.length > 0 || (t.id !== 'local' && !t.online);
  const adapterRows = t => t.adapters.map(a => `<tr><td class="mono"><span class="state-dot ${a.state === 'error' ? '' : 'on'}"></span>${esc(a.iface)}</td>
      <td class="muted">${a.supported_bands && a.supported_bands.length ? a.supported_bands.map(b => esc(b) + ' GHz').join(' · ') : '<span class="faint">unknown</span>'}</td>
      <td class="muted trunc" style="max-width:360px" title="${esc((a.channels || []).join(', '))}">${(a.channels || []).length ? esc((a.channels || []).join(', ')) : '—'}${a.channel ? ` <span class="faint">· now ${esc(a.channel)}</span>` : ''}</td>
      <td class="num muted">${(Number(a.pps) || 0).toFixed(1)}/s</td>
      <td>${a.error ? `<span class="err small-text">${esc(a.error)}</span>` : `<span class="muted">${esc(a.state || '')}</span>`}${a.warning ? `<div class="warn-text small-text">${esc(a.warning)}</div>` : ''}</td></tr>`).join('');
  const adapterTable = t => t.adapters.length ? tableHtml('<th>Adapter</th><th>Can tune</th><th>Listening on</th><th class="num">Frames</th><th>State</th>', adapterRows(t), '') : '';

  function panel(t) {
    const c = t.config || {}, per = c.per_iface || {};
    const supported = bandsOf(t);
    const chips = CH_PRESETS.map(([tok, label]) => {
      const band = CH_PRESET_BAND[tok], off = supported && band && !supported.has(band);
      return `<button type="button" class="btn small ghost ch-chip" data-tok="${tok}" ${off ? `title="No adapter here can tune ${band} GHz" style="opacity:.55"` : ''}>${esc(label)}</button>`;
    }).join(' ');
    return `<section class="panel" data-t="${esc(t.id)}" style="margin-bottom:16px"><header><h2>${esc(t.name)}</h2><span class="ch-status">${statusTag(t)}</span></header><div class="body">
      ${!canEdit(t) ? `<p class="muted" style="margin:0">${t.id === 'local' ? 'This server has no Wi-Fi adapter configured. Set <code>WIFI_INTERFACES</code> to capture here.' : 'This sensor reports no Wi-Fi adapter (it may be Bluetooth only).'}</p>` : ''}
      <div class="ch-adapters">${adapterTable(t)}</div>
      ${canEdit(t) ? `<form class="ch-form form-narrow" style="margin-top:14px">
        <label class="field">Channels <span class="faint">(empty: ${t.id === 'local' && t.env_channels ? `this machine's own setting, ${esc(t.env_channels.length > 14 ? t.env_channels.slice(0, 14).join(', ') + '…' : t.env_channels.join(', '))}` : "the sensor's own setting"})</span>
          <input name="channels" value="${esc(c.channels || '')}" placeholder="e.g. default,6ghz   or   1,6,11,36-48" maxlength="200" autocomplete="off"></label>
        <div class="row" style="flex-wrap:wrap;gap:6px;margin-bottom:6px">${chips}</div>
        <p class="faint small-text" style="margin-top:0">Channel numbers like <code>1,6,11</code> or <code>36-48</code> (1–14 are 2.4 GHz, higher numbers 5 GHz). 6 GHz channels need a prefix: <code>6g:37</code>.
          A bare <code>5</code> or <code>6</code> on its own means that whole band, so write <code>2g:6</code> for 2.4 GHz channel 6. With several adapters the list is split between them.</p>
        ${t.adapters.length > 1 ? `<div class="field">Per adapter <span class="faint">(empty: share the list above; a single channel locks the adapter to it)</span>
          ${t.adapters.map(a => `<div class="row" style="margin:4px 0"><span class="mono" style="min-width:70px">${esc(a.iface)}</span>
            <input data-per="${esc(a.iface)}" value="${esc(per[a.iface] || '')}" placeholder="share the list" maxlength="200" style="flex:1" autocomplete="off"></div>`).join('')}</div>`
          : t.adapters.length === 1 ? `<input type="hidden" data-per="${esc(t.adapters[0].iface)}" value="">` : ''}
        <div class="row"><label class="field">Regulatory domain<input name="regdomain" value="${esc(c.regdomain || '')}" maxlength="2" placeholder="NL" style="width:80px;text-transform:uppercase"></label>
          <label class="field">Time on each channel (s)<input name="hop" type="number" step="0.1" min="0.2" max="60" value="${c.hop_interval || ''}" placeholder="0.5" style="width:110px"></label></div>
        <p class="faint small-text" style="margin-top:0">The country decides which channels an adapter may use; 6 GHz stays off until one is set.</p>
        <div class="row"><button class="btn primary">Save</button><button type="button" class="btn ch-reset" ${own(c) ? 'hidden' : ''}>Back to the sensor's own settings</button></div></form>` : ''}
    </div></section>`;
  }

  function render() {
    el.innerHTML = `<p class="muted" style="margin-top:0">Choose which channels each Wi-Fi adapter listens on. Saving applies at once on this server; a remote sensor picks it up within a few seconds.
      Anything left empty stays as the sensor's own configuration (its environment variables) says.</p>${data.targets.map(panel).join('')}`;
    el.querySelectorAll('.panel[data-t]').forEach(p => bind(p, data.targets.find(t => t.id === p.dataset.t)));
  }

  function bind(p, t) {
    const form = p.querySelector('.ch-form');
    if (!form) return;
    const input = form.elements.channels;
    const tokens = () => input.value.split(',').map(x => x.trim()).filter(Boolean);
    const paint = () => p.querySelectorAll('.ch-chip').forEach(b => b.classList.toggle('on', tokens().includes(b.dataset.tok)));
    p.querySelectorAll('.ch-chip').forEach(b => b.onclick = () => {
      const cur = tokens(), i = cur.indexOf(b.dataset.tok);
      i >= 0 ? cur.splice(i, 1) : cur.push(b.dataset.tok);
      input.value = cur.join(',');
      paint();
    });
    input.addEventListener('input', paint);
    paint();
    form.onsubmit = async e => {
      e.preventDefault();
      // A per-adapter list is sent when filled in. Emptied after having been set, it is sent as "" (share the list);
      // one never touched is left out, so what the sensor's own environment says for that adapter stands.
      const prev = (t.config && t.config.per_iface) || {}, per_iface = {};
      p.querySelectorAll('[data-per]').forEach(x => {
        const v = x.value.trim();
        if (v !== '') per_iface[x.dataset.per] = v;
        else if (prev[x.dataset.per] !== undefined && prev[x.dataset.per] !== null) per_iface[x.dataset.per] = '';
      });
      const body = { channels: input.value.trim() || null, per_iface,
        regdomain: form.elements.regdomain.value.trim().toUpperCase() || null, hop_interval: form.elements.hop.value ? +form.elements.hop.value : null };
      try {
        const r = await send('PUT', `/api/channel-settings/${enc(t.id)}`, body);
        toast(t.id === 'local' ? 'Saved and applied' : 'Saved; the sensor applies it with its next upload');
        (r.warnings || []).forEach(w => toast(w, true));
        await refresh(true);
      } catch (err) { toast(err.message, true); }
    };
    p.querySelector('.ch-reset').onclick = async () => {
      if (!confirm(`Go back to the own settings of ${t.name}?`)) return;
      try { await send('DELETE', `/api/channel-settings/${enc(t.id)}`); toast('Back on its own settings'); await refresh(true); } catch (err) { toast(err.message, true); }
    };
  }

  // Refresh what changes by itself (adapters, applied / waiting) without redrawing the forms being edited.
  async function refresh(full) {
    const next = await api('/api/channel-settings');
    const changed = ids() !== next.targets.map(t => t.id).join(',');
    data = next;
    if (full || changed) { render(); return; }
    data.targets.forEach(t => {
      const p = el.querySelector(`.panel[data-t="${CSS.escape(t.id)}"]`);
      if (!p) return;
      p.querySelector('.ch-status').innerHTML = statusTag(t);
      p.querySelector('.ch-adapters').innerHTML = adapterTable(t);
    });
  }

  render();
  every(4000, () => refresh(false).catch(() => { /* offline: keep what is shown */ }));
};
