'use strict';
/* Settings → LoRa bands: which LoRa profiles (frequency, bandwidth, spreading factor, sync word) each LoRa board hops over, for this
   server and for remote sensors, plus whether the public Meshtastic channel is read. Saving applies at once on this server;
   a remote sensor picks the settings up with its next upload (the same way as Settings → Wi-Fi channels). */

SETTINGS_VIEWS.lorabands = async function (el) {
  let data = await api('/api/lora-settings');
  const ids = () => data.targets.map(t => t.id).join(',');
  const own = c => !c || (!c.profiles && !c.hop_interval);
  const GROUPS = [['meshtastic', 'Meshtastic'], ['meshcore', 'MeshCore'], ['lorawan', 'LoRaWAN'], ['lora-aprs', 'LoRa APRS'], ['custom', 'Other']];

  function statusTag(t) {
    const c = t.config, has = c && !own(c);
    if (!t.boards.length) return '<span class="tag">no LoRa board reported</span>';
    if (t.id !== 'local' && !t.online) return `<span class="tag warn">offline</span>${has ? ' <span class="faint small-text">applies when it reconnects</span>' : ''}`;
    if (t.too_old) return '<span class="tag bad">sensor software too old</span> <span class="faint small-text">update the sensor image to change its LoRa bands from here</span>';
    if (!c || !c.rev) return '<span class="tag">using its own settings</span>';
    return t.applied ? `<span class="tag on">applied</span>${own(c) ? ' <span class="faint small-text">back on its own settings</span>' : ''}` : '<span class="tag warn">waiting for the sensor…</span>';
  }
  const canEdit = t => t.boards.length > 0 || (t.id !== 'local' && !t.online);
  const boardRows = t => t.boards.map(b => `<tr><td class="mono"><span class="state-dot ${b.state === 'error' ? '' : 'on'}"></span>${esc(b.iface || b.name)}</td>
      <td class="muted trunc" style="max-width:420px" title="${esc((b.profiles || []).join(', '))}">${(b.profiles || []).length} profile${(b.profiles || []).length === 1 ? '' : 's'}${b.channel ? ` <span class="faint">· now ${esc(b.channel)}</span>` : ''}</td>
      <td class="num muted">${num(b.packets || 0)}</td>
      <td>${b.error ? `<span class="err small-text">${esc(b.error)}</span>` : `<span class="muted">${esc(b.state || '')}</span>`}${b.warning ? `<div class="warn-text small-text">${esc(b.warning)}</div>` : ''}</td></tr>`).join('');
  const boardTable = t => t.boards.length ? tableHtml('<th>Board</th><th>Listening on</th><th class="num">Frames</th><th>State</th>', boardRows(t), '') : '';

  function panel(t) {
    const c = t.config || {};
    const chips = GROUPS.map(([proto, label]) => {
      const items = data.known.filter(k => k.protocol === proto);
      return items.length ? `<div style="margin:6px 0"><span class="faint small-text" style="display:inline-block;min-width:92px">${esc(label)}</span>${items.map(k =>
        `<button type="button" class="btn small ghost lb-chip" data-tok="${esc(k.token)}" title="${esc(k.describe)}">${esc(k.label)}</button>`).join(' ')}</div>` : '';
    }).join('');
    return `<section class="panel" data-t="${esc(t.id)}" style="margin-bottom:16px"><header><h2>${esc(t.name)}</h2><span class="lb-status">${statusTag(t)}</span></header><div class="body">
      ${!canEdit(t) ? `<p class="muted" style="margin:0">${t.id === 'local' ? 'This server has no LoRa board configured. Set <code>LORA_DEVICES</code> to listen here.' : 'This sensor reports no LoRa board.'}</p>` : ''}
      <div class="lb-boards">${boardTable(t)}</div>
      ${canEdit(t) ? `<form class="lb-form form-narrow" style="margin-top:14px">
        <label class="field">Profiles <span class="faint">(empty: ${t.id === 'local' && t.own ? `this machine's own setting, ${t.own.length} profile${t.own.length === 1 ? '' : 's'}` : "the sensor's own setting"})</span>
          <input name="profiles" value="${esc(c.profiles || '')}" placeholder="e.g. meshtastic-eu868,lorawan:eu868:7-9" maxlength="1000" autocomplete="off"></label>
        <div class="lb-chips">${chips}</div>
        <p class="faint small-text">Comma-separated: profile names, <code>meshtastic:&lt;region&gt;[:&lt;preset&gt;]</code>, <code>lorawan:&lt;region&gt;[:&lt;sf or range&gt;]</code> or your own
          <code>name=freq/bw/sf/cr/sync</code> (MHz, kHz, spreading factor, coding rate 5–8, sync word like 0x34). A LoRa radio hears one frequency and one spreading factor at a time and hops
          between the profiles, so the more you pick the less time is spent on each: LoRaWAN devices spread over three channels and up to six spreading factors, the Meshtastic and MeshCore defaults over one each.</p>
        <label class="field">Time on each profile (s) <input name="hop" type="number" step="0.5" min="0.5" max="600" value="${c.hop_interval || ''}" placeholder="${esc(String(data.hop_default))}" style="width:110px"></label>
        <p class="faint small-text lb-cycle" style="margin-top:0"></p>
        <div class="row"><button class="btn primary">Save</button><button type="button" class="btn lb-reset" ${own(c) ? 'hidden' : ''}>Back to the sensor's own settings</button></div></form>` : ''}
    </div></section>`;
  }

  function render() {
    el.innerHTML = `<p class="muted" style="margin-top:0">Choose which LoRa bands and protocols each LoRa board listens on. Saving applies at once on this server; a remote sensor picks it up within a few seconds.
      Anything left empty stays as the sensor's own configuration (<code>LORA_REGION</code>, <code>LORA_PROFILES</code>) says.</p>
      <section class="panel" style="margin-bottom:16px"><header><h2>Public Meshtastic channel</h2></header><div class="body">
        <label class="check"><input type="checkbox" id="lb-decode" ${data.decode_public ? 'checked' : ''}> Read messages, positions, node names and telemetry sent on the public default channel (or unencrypted)</label>
        <p class="faint small-text" style="margin-bottom:0">Only what the published default Meshtastic key (or no key) opens is read: it is broadcast to everyone in range by design. Private channels and direct messages stay unreadable.
          Readable text and positions are stored with the packets and shown on the LoRa page, so they are kept for as long as LoRa data is kept. Switch off to keep addresses and signal only.
          ${data.decode_env === false ? 'The environment variable <code>LORA_DECODE_PUBLIC=0</code> sets the default to off.' : ''}</p></div></section>
      ${data.targets.map(panel).join('')}`;
    document.getElementById('lb-decode').onchange = async e => {
      try { await send('PUT', '/api/lora-settings', { decode_public: e.target.checked }); toast(e.target.checked ? 'The public channel is read' : 'The public channel is no longer read'); }
      catch (err) { toast(err.message, true); e.target.checked = !e.target.checked; }
    };
    el.querySelectorAll('.panel[data-t]').forEach(p => bind(p, data.targets.find(t => t.id === p.dataset.t)));
  }

  function bind(p, t) {
    const form = p.querySelector('.lb-form');
    if (!form) return;
    const input = form.elements.profiles;
    const tokens = () => input.value.split(',').map(x => x.trim()).filter(Boolean);
    const paint = () => p.querySelectorAll('.lb-chip').forEach(b => b.classList.toggle('on', tokens().includes(b.dataset.tok)));
    p.querySelectorAll('.lb-chip').forEach(b => b.onclick = () => {
      const cur = tokens(), i = cur.indexOf(b.dataset.tok);
      i >= 0 ? cur.splice(i, 1) : cur.push(b.dataset.tok);
      input.value = cur.join(',');
      paint();
    });
    input.addEventListener('input', paint);
    paint();
    form.onsubmit = async e => {
      e.preventDefault();
      const body = { profiles: input.value.trim() || null, hop_interval: form.elements.hop.value ? +form.elements.hop.value : null };
      try {
        const r = await send('PUT', `/api/lora-settings/${enc(t.id)}`, body);
        toast(t.id === 'local' ? 'Saved and applied' : 'Saved; the sensor applies it with its next upload');
        p.querySelector('.lb-cycle').textContent = r.profiles ? `${r.profiles} profile${r.profiles === 1 ? '' : 's'}${r.cycle_seconds ? `: one round takes about ${r.cycle_seconds >= 120 ? Math.round(r.cycle_seconds / 60) + ' minutes' : r.cycle_seconds + ' seconds'}` : ''}.` : '';
        await refresh(false);
        p.querySelector('.lb-reset').hidden = false;
      } catch (err) { toast(err.message, true); }
    };
    p.querySelector('.lb-reset').onclick = async () => {
      if (!confirm(`Go back to the own settings of ${t.name}?`)) return;
      try { await send('DELETE', `/api/lora-settings/${enc(t.id)}`); toast('Back on its own settings'); await refresh(true); } catch (err) { toast(err.message, true); }
    };
  }

  // Refresh what changes by itself (boards, applied / waiting) without redrawing the forms being edited.
  async function refresh(full) {
    const next = await api('/api/lora-settings');
    const changed = ids() !== next.targets.map(t => t.id).join(',');
    data = next;
    if (full || changed) { render(); return; }
    data.targets.forEach(t => {
      const p = el.querySelector(`.panel[data-t="${CSS.escape(t.id)}"]`);
      if (!p) return;
      p.querySelector('.lb-status').innerHTML = statusTag(t);
      p.querySelector('.lb-boards').innerHTML = boardTable(t);
    });
  }

  render();
  every(4000, () => refresh(false).catch(() => { /* offline: keep what is shown */ }));
};
