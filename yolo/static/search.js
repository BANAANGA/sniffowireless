'use strict';
/* Global search: sidebar box with live results (press "/" to focus) and a full results page (#/search?q=). */

const SEARCH_SECTIONS = [
  ['devices', 'Devices'], ['groups', 'Groups'], ['networks', 'Networks (SSIDs)'], ['probes', 'Probed networks'],
  ['dns', 'DNS lookups'], ['events', 'Events'], ['alerts', 'Alerts'], ['findings', 'Security findings'], ['sensors', 'Sensors'],
];

function hl(text, q) {
  const s = String(text ?? '');
  if (!q) return esc(s);
  const i = s.toLowerCase().indexOf(q.toLowerCase());
  return i < 0 ? esc(s) : `${esc(s.slice(0, i))}<mark>${esc(s.slice(i, i + q.length))}</mark>${esc(s.slice(i + q.length))}`;
}

// One result -> [href, title html, meta html]
function searchItem(sec, x, q) {
  switch (sec) {
    case 'devices': {
      const title = x.label || x.name || x.ssid || x.ident || x.vendor || x.mac;
      const meta = [kindBadge(x.kind), `<span class="mono">${hl(x.mac, q)}</span>`, x.ip ? `<span class="mono">${hl(x.ip, q)}</span>` : '',
        x.label && x.name ? hl(x.name, q) : '', x.ident && x.ident !== title ? hl(x.ident, q) : '',
        x.vendor && x.vendor !== title && !(x.ident || '').includes(x.vendor) ? hl(x.vendor, q) : '', x.notes ? hl(x.notes, q) : '', ago(x.last_seen)].filter(Boolean);
      return [`#/device/${enc(x.mac)}`, hl(title, q), meta.join(' · ')];
    }
    case 'groups': return [`#/group/${x.id}`, hl(x.name, q), [x.kind, x.notes ? hl(x.notes, q) : ''].filter(Boolean).join(' · ')];
    case 'networks': return [hrefWith('/devices', { ssid: x.ssid }), hl(x.ssid, q), `${x.aps} access point${x.aps === 1 ? '' : 's'} · ${esc(x.enc || '')} · ${ago(x.last_seen)}`];
    case 'probes': return [hrefWith('/devices', { probe: x.ssid }), hl(x.ssid, q), `probed by ${x.devices} device${x.devices === 1 ? '' : 's'} · ${ago(x.last_seen)}`];
    case 'dns': return ['#/lan', hl(x.name, q), `looked up by ${x.devices} device${x.devices === 1 ? '' : 's'} · ${ago(x.last_seen)}`];
    case 'events': return [(x.mac || '').startsWith('rf:') ? '#/channels' : `#/device/${enc(x.mac)}`,
      `<span class="ev ev-${esc(x.type)}">${esc(x.type.replace(/_/g, ' '))}</span> ${hl(x.label || x.name || x.ssid || x.mac, q)}`,
      [dt(x.ts), x.detail ? hl(x.detail, q) : ''].filter(Boolean).join(' · ')];
    case 'alerts': return ['#/alerts', hl(x.title, q), `${sevTag(x.severity)} ${dt(x.ts)}`];
    case 'findings': return ['#/security', hl(x.title, q), `${sevTag(x.severity)} ${esc(x.status)} · ${ago(x.last_seen)}`];
    case 'sensors': return ['#/settings?tab=sensors', hl(x.name, q), [x.room ? hl(x.room, q) : '', `<span class="mono">${hl(x.id, q)}</span>`].filter(Boolean).join(' · ')];
  }
  return ['#/', '', ''];
}

// ---------------------------------------------------------------- sidebar box
(function () {
  const input = document.getElementById('gsearch');
  const pop = document.getElementById('gsearch-pop');
  if (!input) return;
  let timer = null, seq = 0, active = -1;
  const links = () => [...pop.querySelectorAll('a.sr')];
  const close = () => { pop.hidden = true; active = -1; };
  const mark = i => {
    const l = links();
    l.forEach((a, j) => a.classList.toggle('on', j === i));
    if (l[i]) l[i].scrollIntoView({ block: 'nearest' });
    active = i;
  };
  async function run() {
    const q = input.value.trim();
    if (q.length < 2) { close(); return; }
    const id = ++seq;
    const r = await api(`/api/search?q=${enc(q)}&limit=5`);
    if (id !== seq) return;  // a newer query is on its way
    const secs = SEARCH_SECTIONS.filter(([k]) => r.results[k].length);
    pop.innerHTML = (secs.length ? secs.map(([k, label]) => `<div class="sr-sec">${label}</div>` + r.results[k].map(x => {
      const [href, title, meta] = searchItem(k, x, q);
      return `<a class="sr" href="${href}"><span class="sr-t">${title}</span><span class="sr-m">${meta}</span></a>`;
    }).join('')).join('') : '<div class="sr-empty">No matches</div>')
      + `<a class="sr sr-all" href="${hrefWith('/search', { q })}">All results for “${esc(q)}” <span class="faint">Enter</span></a>`;
    const rect = input.getBoundingClientRect();  // fixed position: the sidebar would clip an absolute popup
    pop.style.top = `${rect.bottom + 6}px`;
    pop.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - pop.offsetWidth - 8))}px`;
    pop.hidden = false;
    active = -1;
  }
  input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(run, 180); });
  input.addEventListener('focus', () => { if (input.value.trim().length >= 2) run(); });
  input.addEventListener('keydown', e => {
    const l = links();
    if (e.key === 'ArrowDown') { e.preventDefault(); mark(Math.min(l.length - 1, active + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); mark(Math.max(0, active - 1)); }
    else if (e.key === 'Escape') { close(); input.blur(); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const q = input.value.trim();
      if (active >= 0 && l[active]) location.hash = l[active].getAttribute('href');
      else if (q) location.hash = hrefWith('/search', { q });
      close();
      input.blur();
    }
  });
  pop.addEventListener('mousedown', e => e.preventDefault());  // keep focus while clicking a result
  pop.addEventListener('click', e => { if (e.target.closest('a')) { close(); input.blur(); } });
  input.addEventListener('blur', () => setTimeout(close, 100));
  document.addEventListener('keydown', e => {
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
      e.preventDefault();
      input.focus();
      input.select();
    }
  });
})();

// ---------------------------------------------------------------- results page
addRoute('/search', async (_, params) => {
  const q = params.get('q') || '';
  const only = params.get('in') || '';
  const box = document.getElementById('gsearch');
  if (box && document.activeElement !== box) box.value = q;
  app.innerHTML = `<div class="page-head"><div><h1>Search</h1><div class="sub" id="s-sub">&nbsp;</div></div></div>
    <form class="filters" id="s-form"><input type="search" name="q" value="${esc(q)}" placeholder="MAC, IP, name, label, SSID, vendor, domain, event text…" style="width:420px" autofocus>
      <select name="in"><option value="">Everything</option>${SEARCH_SECTIONS.map(([k, l]) => `<option value="${k}" ${only === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <button class="btn primary">Search</button></form><div id="s-res"></div>`;
  const form = document.getElementById('s-form');
  form.onsubmit = e => { e.preventDefault(); location.hash = hrefWith('/search', { q: fv(form, 'q'), in: fv(form, 'in') }); };
  form.elements.in.onchange = () => form.requestSubmit();
  const res = document.getElementById('s-res');
  if (q.trim().length < 2) { res.innerHTML = '<div class="empty">Type at least 2 characters.</div>'; return; }
  const r = await api(`/api/search?q=${enc(q)}&limit=${only ? 200 : 25}${only ? '&section=' + only : ''}`);
  document.getElementById('s-sub').textContent = `${r.total} result${r.total === 1 ? '' : 's'} for “${q}” · ${r.ms} ms`;
  const secs = SEARCH_SECTIONS.filter(([k]) => r.results[k] && r.results[k].length);
  res.innerHTML = secs.length ? `<div class="grid">${secs.map(([k, label]) => `<section class="panel"><header><h2>${label}</h2>
      <span class="faint">${r.results[k].length}${r.more[k] ? '+' : ''}${r.more[k] && !only ? ` · <a href="${hrefWith('/search', { q, in: k })}">show all</a>` : ''}</span></header>
      <div class="body flush"><ul class="sr-list">${r.results[k].map(x => { const [href, t, m] = searchItem(k, x, q);
        return `<li><a href="${href}"><span class="sr-t">${t}</span><span class="sr-m">${m}</span></a></li>`; }).join('')}</ul></div></section>`).join('')}</div>`
    : `<div class="empty">Nothing matches “${esc(q)}”.</div>`;
});
