'use strict';
// Appearance (name, icon, colours) set by an admin. Loaded before everything else on every page; the last-used
// appearance is cached in localStorage so pages don't flash the stock look while /api/appearance loads.

const ICON_SVGS = {
  wifi: '<path d="M2 6.5a9 9 0 0 1 12 0M4.2 8.8a6 6 0 0 1 7.6 0M6.4 11a3 3 0 0 1 3.2 0" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="13" r="1.2" fill="currentColor"/>',
  radar: '<circle cx="8" cy="8" r="6.3" fill="none" stroke="currentColor" stroke-width="1.3" stroke-opacity=".55"/><circle cx="8" cy="8" r="3.4" fill="none" stroke="currentColor" stroke-width="1.3" stroke-opacity=".8"/><path d="M8 8 13 3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="8" r="1.3" fill="currentColor"/>',
  bluetooth: '<path d="M4.5 5 11 10.5 8 13V3l3 2.5L4.5 11" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
  eye: '<path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8Z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><circle cx="8" cy="8" r="2.2" fill="currentColor"/>',
  shield: '<path d="M8 1.8 13.2 3.8v4c0 3.2-2.2 5.4-5.2 6.4-3-1-5.2-3.2-5.2-6.4v-4Z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M5.6 8.1 7.3 9.8l3.2-3.4" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>',
};
const DOT_FAVICON = (c) => `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><circle cx='8' cy='8' r='3' fill='${c}'/><circle cx='8' cy='8' r='6.5' fill='none' stroke='${c}' stroke-opacity='.4'/></svg>`;
const HEX_RE = /^#[0-9a-f]{6}$/;
let APPEARANCE = null;

// Markup for the brand icon. Built-in glyphs are our own SVG; an uploaded icon is an <img> of the stored file.
function brandIconHtml(a, size = 18) {
  if (a.icon === 'custom' && a.icon_url) return `<img class="brand-img" src="${a.icon_url}" alt="" width="${size}" height="${size}">`;
  if (ICON_SVGS[a.icon]) return `<svg class="brand-svg" viewBox="0 0 16 16" width="${size}" height="${size}" aria-hidden="true">${ICON_SVGS[a.icon]}</svg>`;
  return '<span class="dot"></span>';
}

function applyAppearance(a, { cache = true } = {}) {
  if (!a || !a.colors) return;
  APPEARANCE = a;
  const c = a.colors, root = document.documentElement.style;
  const custom = new Set(a.custom_colors || []);
  const set = (v, val) => { if (HEX_RE.test(val)) root.setProperty(v, val); };
  ['bg', 'panel', 'border', 'text', 'muted', 'ap', 'wifi_client', 'ble', 'bt_classic', 'lan', 'good', 'warn', 'bad', 'icon']
    .forEach(k => custom.has(k) ? set(`--${k}`, c[k]) : root.removeProperty(`--${k}`));
  // Shades derived from the chosen surface colours; the stock values in style.css stay exact by default.
  const derive = (v, on, expr) => on ? root.setProperty(v, expr) : root.removeProperty(v);
  derive('--panel-2', custom.has('panel') || custom.has('text'), 'color-mix(in srgb, var(--panel), var(--text) 3%)');
  derive('--border-2', custom.has('border') || custom.has('text'), 'color-mix(in srgb, var(--border), var(--text) 6%)');
  derive('--faint', custom.has('muted') || custom.has('bg'), 'color-mix(in srgb, var(--muted), var(--bg) 40%)');
  if (a.style) document.documentElement.dataset.style = a.style; else delete document.documentElement.dataset.style;
  const name = a.name || 'sniffowireless';
  document.querySelectorAll('.brand').forEach(b => { b.innerHTML = `${brandIconHtml(a)}<span class="brand-name"></span>`; b.querySelector('.brand-name').textContent = name; });
  document.title = document.body && document.body.classList.contains('login-page') ? `${name} · sign in` : name;
  const fav = document.querySelector('link[rel="icon"]');
  if (fav) {
    const ic = HEX_RE.test(c.icon) ? c.icon : '#e6e7e9';
    fav.href = a.icon === 'custom' && a.icon_url ? a.icon_url
      : 'data:image/svg+xml,' + encodeURIComponent(ICON_SVGS[a.icon]
        ? `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' color='${ic}'>${ICON_SVGS[a.icon]}</svg>` : DOT_FAVICON(ic));
  }
  if (cache) { try { localStorage.setItem('sniffowireless.appearance', JSON.stringify(a)); } catch { /* private mode */ } }
}

async function loadAppearance() {
  try {
    const r = await fetch('/api/appearance');
    if (r.ok) applyAppearance(await r.json());
  } catch { /* keep the cached / stock look */ }
  return APPEARANCE;
}

(() => {
  let cached = null;
  try { cached = JSON.parse(localStorage.getItem('sniffowireless.appearance') || 'null'); } catch { /* ignore */ }
  const go = () => { if (cached) applyAppearance(cached, { cache: false }); };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go, { once: true }); else go();
})();

// ------------------------------------------------------------------ clock (12 / 24 hour)
// This browser's choice (Settings → Account) wins over the admin default (Settings → Appearance); 'auto' follows
// the browser's locale.
function clockMode() {
  let mine = null;
  try { mine = localStorage.getItem('sniffowireless.clock'); } catch { /* private mode */ }
  const m = mine || (APPEARANCE && APPEARANCE.clock) || 'auto';
  return ['12', '24'].includes(m) ? m : 'auto';
}
function uses12h() {
  const m = clockMode();
  if (m !== 'auto') return m === '12';
  try { return /h1[12]/.test(new Intl.DateTimeFormat([], { hour: 'numeric' }).resolvedOptions().hourCycle || ''); } catch { return false; }
}
// Options for toLocale*String with the chosen hour cycle.
function clockOpts(opts = {}) {
  const m = clockMode();
  return m === 'auto' ? opts : { ...opts, hourCycle: m === '12' ? 'h12' : 'h23' };
}
// An hour of the day: "13:00" or "1 PM"; short: "13" or "1p" (axis labels).
function hourLabel(h, short = false) {
  h = ((+h % 24) + 24) % 24;
  if (!uses12h()) return short ? String(h) : `${String(h).padStart(2, '0')}:00`;
  const n = h % 12 || 12, ap = h < 12 ? 'AM' : 'PM';
  return short ? `${n}${ap[0].toLowerCase()}` : `${n} ${ap}`;
}
