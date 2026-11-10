'use strict';
/* Live application logs (admins). Lines arrive over Server-Sent Events and are rendered with textContent:
   log messages can contain names / SSIDs chosen by strangers. */

const LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];
const LOG_MAX = 5000;

addRoute('/logs', async (_, params) => {
  if (!isAdmin()) { app.innerHTML = '<div class="empty">Only admins can view the logs.</div>'; return; }
  const sensor = params.get('sensor') || '';  // '' = this server, else a remote sensor's id
  let snap;
  try { snap = await api(`/api/logs?limit=1000${sensor ? '&sensor=' + enc(sensor) : ''}`); }
  catch (e) { if (sensor) { location.hash = '#/logs'; return; } throw e; }  // a sensor that was deleted
  const remote = !!snap.sensor, cur = (snap.sensors.find(x => x.id === sensor) || {});
  const tabs = [{ id: '', name: 'This server' }, ...snap.sensors].map(x => `<a href="${hrefWith('/logs', { sensor: x.id })}" class="${x.id === sensor ? 'on' : ''}">${x.id && !x.online ? '<span class="state-dot"></span>' : x.id ? '<span class="state-dot on"></span>' : ''}${esc(x.name)}${x.id && !x.lines ? ' <span class="faint">(no logs yet)</span>' : ''}</a>`).join('');
  app.innerHTML = `<div class="page-head"><div><h1>Logs</h1><div class="sub">${remote ? `Log of the remote sensor ${esc(cur.name || sensor)}${cur.online ? '' : ' <span class="tag warn">offline</span>'}` : 'Live application log'} · <span id="lg-state" class="live ok">connecting…</span></div></div>
    ${remote ? '' : `<div class="row"><label class="muted small-text">Log level</label>
      <select id="lg-level">${['DEBUG', 'INFO', 'WARNING', 'ERROR'].map(l => `<option ${l === snap.level ? 'selected' : ''}>${l}</option>`).join('')}</select></div>`}</div>
    ${snap.sensors.length ? `<nav class="tabbar" aria-label="Log source">${tabs}</nav>` : ''}
    <div class="filters">
      <select id="lg-min"><option value="0">All levels</option><option value="1" selected>Info and up</option><option value="2">Warnings and errors</option><option value="3">Errors only</option></select>
      <select id="lg-src"><option value="">All sources</option></select>
      <input type="search" id="lg-q" placeholder="Filter text…">
      <button class="btn" id="lg-pause">Pause</button>
      <label class="check"><input type="checkbox" id="lg-follow" checked> Follow</label>
      <label class="check"><input type="checkbox" id="lg-wrap"> Wrap lines</label>
      <button class="btn" id="lg-clear">Clear view</button>
      <button class="btn" id="lg-dl">Download</button>
      <span class="faint small-text" id="lg-count"></span>
    </div>
    <section class="panel"><div class="logview" id="lg"></div></section>
    <p class="faint small-text">${remote
      ? `The sensor sends its new log lines with every upload and this server keeps the last ${snap.capacity.toLocaleString()} in memory (also in <code>docker logs sniffowireless-sensor</code> on the sensor). Its log level is the sensor's own <code>LOG_LEVEL</code>; a sensor that has not been updated yet sends none.`
      : `Keeps the last ${snap.capacity.toLocaleString()} lines in memory (also in <code>docker compose logs sniffowireless</code>). Debug level shows details such as Bluetooth command failures; switch back to Info afterwards.`}</p>`;

  const view = document.getElementById('lg');
  view.style.setProperty('--lg-time', uses12h() ? '16ch' : '13ch');  // "11:48:29.958 PM" vs "23:48:29.958"
  const st = document.getElementById('lg-state');
  const minSel = document.getElementById('lg-min'), srcSel = document.getElementById('lg-src'), qIn = document.getElementById('lg-q');
  const follow = document.getElementById('lg-follow');
  let lines = [], paused = false, pending = [], lastId = 0;
  const sources = new Set();

  const visible = r => LOG_LEVELS.indexOf(r.level) >= +minSel.value &&
    (!srcSel.value || r.logger === srcSel.value) &&
    (!qIn.value || `${r.logger} ${r.msg}`.toLowerCase().includes(qIn.value.toLowerCase()));

  function row(r) {
    const div = document.createElement('div');
    div.className = `lg lg-${r.level.toLowerCase()}`;
    const t = document.createElement('span');
    t.className = 'lg-t';
    const d = new Date(r.ts * 1000);
    t.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: uses12h() ? 'h12' : 'h23' })
      .replace(/(\d\d:\d\d:\d\d)/, `$1.${String(d.getMilliseconds()).padStart(3, '0')}`);
    t.title = d.toLocaleString([], clockOpts());
    const lv = document.createElement('span');
    lv.className = 'lg-l';
    lv.textContent = r.level;
    const src = document.createElement('span');
    src.className = 'lg-s';
    src.textContent = r.logger;
    const msg = document.createElement('span');
    msg.className = 'lg-m';
    msg.textContent = r.msg;
    div.append(t, lv, src, msg);
    return div;
  }
  function addSources(items) {
    let added = false;
    items.forEach(r => { if (!sources.has(r.logger)) { sources.add(r.logger); added = true; } });
    if (added) {
      const cur = srcSel.value;
      srcSel.innerHTML = '<option value="">All sources</option>' + [...sources].sort().map(s => `<option ${s === cur ? 'selected' : ''}>${esc(s)}</option>`).join('');
    }
  }
  function updateCount() {
    document.getElementById('lg-count').textContent = `${view.childElementCount.toLocaleString()} shown · ${lines.length.toLocaleString()} received${paused && pending.length ? ` · ${pending.length} waiting` : ''}`;
  }
  function render() {
    view.replaceChildren(...lines.filter(visible).slice(-LOG_MAX).map(row));
    if (!view.childElementCount) view.append(Object.assign(document.createElement('div'), { className: 'empty', textContent: 'No log lines match' }));
    if (follow.checked) view.scrollTop = view.scrollHeight;
    updateCount();
  }
  function append(items) {
    if (!items.length) return;
    lastId = Math.max(lastId, items[items.length - 1].id);
    lines = lines.concat(items).slice(-LOG_MAX);
    addSources(items);
    if (paused) { pending = pending.concat(items); updateCount(); return; }
    const empty = view.querySelector('.empty');
    if (empty) empty.remove();
    const nearBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const frag = document.createDocumentFragment();
    items.filter(visible).forEach(r => frag.append(row(r)));
    view.append(frag);
    while (view.childElementCount > LOG_MAX) view.firstChild.remove();
    if (follow.checked && nearBottom) view.scrollTop = view.scrollHeight;
    updateCount();
  }

  append(snap.items);
  render();

  // Live stream; EventSource reconnects by itself and resumes after the last received id.
  let es = null;
  function connect() {
    es = new EventSource(`/api/logs/stream?after=${lastId}${sensor ? '&sensor=' + encodeURIComponent(sensor) : ''}`);
    es.addEventListener('logs', e => { try { append(JSON.parse(e.data)); } catch { /* ignore malformed */ } });
    es.onopen = () => { st.textContent = 'live'; st.className = 'live ok'; };
    es.onerror = () => {
      st.textContent = 'reconnecting…'; st.className = 'live err';
      if (es.readyState === EventSource.CLOSED) setTimeout(() => { if (location.hash.startsWith('#/logs')) connect(); }, 3000);
    };
  }
  connect();
  onLeave(() => es && es.close());

  [minSel, srcSel].forEach(el => el.onchange = render);
  let qt;
  qIn.oninput = () => { clearTimeout(qt); qt = setTimeout(render, 150); };
  document.getElementById('lg-wrap').onchange = e => view.classList.toggle('wrap', e.target.checked);
  follow.onchange = () => { if (follow.checked) view.scrollTop = view.scrollHeight; };
  view.addEventListener('scroll', () => {
    const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    if (!atBottom && follow.checked && view.dataset.userScroll) follow.checked = false;
    if (atBottom && !follow.checked && view.dataset.userScroll) follow.checked = true;
  });
  view.addEventListener('wheel', () => { view.dataset.userScroll = '1'; }, { passive: true });
  const pauseBtn = document.getElementById('lg-pause');
  pauseBtn.onclick = () => {
    paused = !paused;
    pauseBtn.textContent = paused ? 'Resume' : 'Pause';
    pauseBtn.classList.toggle('primary', paused);
    if (!paused) { pending = []; render(); }
    updateCount();
  };
  document.getElementById('lg-clear').onclick = () => { lines = []; pending = []; render(); };
  document.getElementById('lg-dl').onclick = () => {
    const text = lines.filter(visible).map(r => `${new Date(r.ts * 1000).toISOString()} ${r.level.padEnd(8)} ${r.logger}: ${r.msg}`).join('\n');
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' })),
      download: `sniffowireless-log${sensor ? '-' + sensor : ''}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.txt` });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  const levelSel = document.getElementById('lg-level');
  if (levelSel) levelSel.onchange = async e => {
    try { await send('PUT', '/api/logs/level', { level: e.target.value }); toast(`Log level: ${e.target.value}`); if (e.target.value === 'DEBUG') { minSel.value = '0'; render(); } }
    catch (err) { toast(err.message, true); }
  };
});
