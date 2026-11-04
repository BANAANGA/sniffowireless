'use strict';
// Settings → Appearance (admin): app name, icon and colours. Changes preview live and apply for everyone on Save.

const APPEARANCE_GROUPS = [
  ['Surfaces', [['bg', 'Background'], ['panel', 'Panels'], ['border', 'Borders'], ['text', 'Text'], ['muted', 'Secondary text'], ['icon', 'Icon']]],
  ['Device types', [['ap', 'Access points'], ['wifi_client', 'Wi-Fi clients'], ['ble', 'BLE devices'], ['bt_classic', 'Bluetooth classic'], ['lan', 'LAN devices']]],
  ['Status', [['good', 'Good / online'], ['warn', 'Warning'], ['bad', 'Problem / alert']]],
];
const APPEARANCE_PRESETS = {
  default: ['Default', {}],
  slate: ['Slate', { bg: '#0f141a', panel: '#151c24', border: '#233040', text: '#e3e9f0', muted: '#8b98a8', icon: '#e3e9f0' }],
  forest: ['Forest', { bg: '#0b0f0c', panel: '#111712', border: '#1e2820', text: '#e4ebe5', muted: '#8a978c', icon: '#e4ebe5', ap: '#4fc3d9', wifi_client: '#7bd88f' }],
  vicecity: ['Vice City', { bg: '#120822', panel: '#1b0f33', border: '#3a2266', text: '#fdeaff', muted: '#a58fc9', icon: '#ff4fa3',
    ap: '#19e3ff', wifi_client: '#ff4fa3', ble: '#ffb347', bt_classic: '#b565ff', lan: '#7fd8e8', good: '#2ef2b0', warn: '#ffb347', bad: '#ff3b6b' }, 'vicecity'],
  contrast: ['High contrast', { bg: '#000000', panel: '#0a0a0a', border: '#3a3a3a', text: '#ffffff', muted: '#b5b8bd', icon: '#ffffff', ap: '#5ccfff',
    wifi_client: '#4ee39b', ble: '#ffc65c', bt_classic: '#ff7a77', lan: '#c4ccd8', good: '#4ee39b', warn: '#ffc65c', bad: '#ff7a77' }],
};
const CLOCK_CHOICES = [['auto', 'Automatic (browser language)'], ['24', '24-hour (13:05)'], ['12', '12-hour (1:05 PM)']];
const ICON_NAMES = { dot: 'Dot (default)', wifi: 'Wi-Fi', radar: 'Radar', bluetooth: 'Bluetooth', eye: 'Eye', shield: 'Shield', custom: 'Uploaded image' };

SETTINGS_VIEWS.appearance = async function (el) {
  const saved = await api('/api/appearance');
  const defaults = saved.defaults;
  let draft = { name: saved.name, icon: saved.icon, clock: saved.clock || 'auto', style: saved.style || '', colors: { ...saved.colors } };
  let iconUrl = saved.icon_url;

  const asAppearance = () => {
    const custom = Object.keys(draft.colors).filter(k => draft.colors[k] !== defaults[k]);
    return { ...saved, name: draft.name || 'sniffowireless', icon: draft.icon, clock: draft.clock, style: draft.style, icon_url: iconUrl, colors: { ...draft.colors }, custom_colors: custom };
  };
  const preview = () => { applyAppearance(asAppearance(), { cache: false }); themeToJs(); paintPreview(); };

  el.innerHTML = `<section class="panel"><header><h2>Appearance</h2><div class="row">
      <select id="ap-preset" aria-label="Preset"><option value="">Presets…</option>${Object.entries(APPEARANCE_PRESETS).map(([k, [l]]) => `<option value="${k}">${l}</option>`).join('')}</select>
      <button class="btn" id="ap-reset" type="button">Reset to default</button><button class="btn primary" id="ap-save" type="button">Save</button></div></header>
    <div class="body">
      <p class="muted" style="margin-top:0">Applies to everyone, including the sign-in page. Changes preview right away; <b>Save</b> keeps them, leaving the page without saving undoes them.</p>
      <div class="row form-narrow"><label class="field">Name<input id="ap-name" maxlength="32" value="${esc(draft.name)}" autocomplete="off"></label>
        <label class="field">Time format (default)<select id="ap-clock">${CLOCK_CHOICES.map(([v, l]) => `<option value="${v}" ${draft.clock === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label></div>
      <div class="field"><span>Icon</span><div class="ap-icons" id="ap-icons"></div>
        <div class="row" style="margin-top:8px"><label class="btn small">Upload image…<input type="file" id="ap-upload" accept="image/png,image/jpeg,image/webp" hidden></label>
        <button class="btn small" id="ap-remove" type="button" ${iconUrl ? '' : 'hidden'}>Remove uploaded image</button>
        <span class="faint small-text">PNG, JPEG or WebP, square, up to 256 kB. Also used as the browser tab icon.</span></div></div>
      ${APPEARANCE_GROUPS.map(([title, keys]) => `<h3 class="small-head">${title}</h3><div class="ap-grid">${keys.map(([k, l]) => `
        <label class="ap-color" data-k="${k}"><input type="color" data-color="${k}" aria-label="${l}"><span class="lbl">${l}</span>
          <input type="text" data-hex="${k}" maxlength="7" spellcheck="false" aria-label="${l} hex"></label>`).join('')}</div>`).join('')}
      <h3 class="small-head">Preview</h3><div class="ap-preview" id="ap-preview"></div>
    </div></section>`;

  const $ = s => el.querySelector(s);
  function paintIcons() {
    $('#ap-icons').innerHTML = Object.keys(ICON_NAMES).filter(k => k !== 'custom' || iconUrl).map(k => `<button type="button" class="ap-icon ${draft.icon === k ? 'on' : ''}"
      data-icon="${k}" title="${ICON_NAMES[k]}" aria-label="${ICON_NAMES[k]}" aria-pressed="${draft.icon === k}">${brandIconHtml({ icon: k, icon_url: iconUrl }, 24)}</button>`).join('');
    el.querySelectorAll('[data-icon]').forEach(b => b.onclick = () => { draft.icon = b.dataset.icon; paintIcons(); preview(); });
    $('#ap-remove').hidden = !iconUrl;
  }
  function paintColors() {
    el.querySelectorAll('[data-color]').forEach(i => { i.value = draft.colors[i.dataset.color]; });
    el.querySelectorAll('[data-hex]').forEach(i => { i.value = draft.colors[i.dataset.hex]; });
    el.querySelectorAll('.ap-color').forEach(l => l.classList.toggle('changed', draft.colors[l.dataset.k] !== defaults[l.dataset.k]));
  }
  function paintPreview() {
    $('#ap-preview').innerHTML = `<span class="mono">${esc(dt(Date.now() / 1000))}</span>` + Object.keys(KINDS).map(k => kindBadge(k)).join('')
      + '<span class="tag on">online</span><span class="tag warn">warning</span><span class="tag bad">alert</span><span class="muted">secondary text</span><span class="faint">faint text</span>';
  }
  const setColor = (k, v) => {
    v = v.trim().toLowerCase();
    if (!/^#[0-9a-f]{6}$/.test(v)) return false;
    draft.colors[k] = v;
    paintColors();
    preview();
    return true;
  };
  el.querySelectorAll('[data-color]').forEach(i => { i.oninput = () => setColor(i.dataset.color, i.value); });
  el.querySelectorAll('[data-hex]').forEach(i => {
    i.onchange = () => { if (!setColor(i.dataset.hex, i.value)) { i.value = draft.colors[i.dataset.hex]; toast('Use a #rrggbb colour', true); } };
  });
  $('#ap-name').oninput = e => { draft.name = e.target.value; preview(); };
  $('#ap-clock').onchange = e => { draft.clock = e.target.value; preview(); };
  $('#ap-preset').onchange = e => {
    const p = APPEARANCE_PRESETS[e.target.value];
    if (!p) return;
    draft.colors = { ...defaults, ...p[1] };
    draft.style = p[2] || '';
    e.target.value = '';
    paintColors();
    preview();
  };
  $('#ap-reset').onclick = () => { draft = { name: 'sniffowireless', icon: 'dot', clock: 'auto', style: '', colors: { ...defaults } }; $('#ap-name').value = 'sniffowireless'; $('#ap-clock').value = 'auto'; paintIcons(); paintColors(); preview(); };
  $('#ap-upload').onchange = async e => {
    const f = e.target.files[0];
    e.target.value = '';
    if (!f) return;
    if (f.size > 256 * 1024) return toast('Icon larger than 256 kB', true);
    const r = await fetch('/api/appearance/icon', { method: 'POST', headers: { 'Content-Type': f.type || 'application/octet-stream', 'X-Sniffowireless': '1' }, body: f });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) return toast(d.detail || 'Upload failed', true);
    iconUrl = d.icon_url;
    draft.icon = 'custom';
    Object.assign(saved, { icon_url: d.icon_url });
    paintIcons();
    preview();
    toast('Icon uploaded — Save to keep the other changes');
  };
  $('#ap-remove').onclick = async () => {
    const d = await send('DELETE', '/api/appearance/icon');
    iconUrl = null;
    if (draft.icon === 'custom') draft.icon = d.icon;
    paintIcons();
    preview();
  };
  $('#ap-save').onclick = async () => {
    try {
      const d = await send('PUT', '/api/appearance', { name: draft.name.trim() || 'sniffowireless', icon: draft.icon, clock: draft.clock, style: draft.style, colors: draft.colors });
      Object.assign(saved, d);
      applyAppearance(d);
      themeToJs();
      toast('Appearance saved');
    } catch (err) { toast(err.message, true); }
  };
  // Leaving the tab without saving restores the saved look.
  const restore = () => { window.removeEventListener('hashchange', restore); loadAppearance().then(themeToJs); };
  window.addEventListener('hashchange', restore);

  paintIcons();
  paintColors();
  paintPreview();
};
