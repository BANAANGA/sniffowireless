/* Frame inspector (#/frames, admins only), laid out like Wireshark: the frame list on top (display filter, colours per kind of
   frame), the decoded fields of the chosen frame in the middle and its bytes at the bottom. Choosing a field highlights its
   bytes; clicking a byte chooses the field it belongs to.
   Two modes: a recording from Settings -> Frame recording (scrolls in pages), or Live: what this server's radios or a remote
   sensor's hear right now, for a minute unless chosen otherwise (an hour at most), arriving as it is heard. */
(() => {
  const PAGE = 500;
  const LIVE_ROWS = 5000;     // rows kept on the page in live mode; the server keeps 20,000 (see capture.LIVE_KEEP)
  const QUICK = [['Beacons', 'beacon'], ['Probes', 'probe'], ['Deauth', 'deauthentication || disassociation'], ['Wi-Fi data', 'wifi && data'],
    ['BLE', 'ble'], ['Classic BT', 'proto == "BR/EDR"'], ['Zigbee', 'zigbee'], ['Thread', 'thread'], ['LoRa', 'lora'], ['Strong (> -60 dBm)', 'rssi > -60']];
  const RADIO = { wifi: 'Wi-Fi', bt: 'Bluetooth', zigbee: 'Zigbee / Thread', lora: 'LoRa' };
  const DURATIONS = [[60, '1 minute'], [300, '5 minutes'], [900, '15 minutes'], [1800, '30 minutes'], [3600, '1 hour']];
  const FILTER_HELP = 'Fields: no, time, radio, proto, type, src, dst, addr, bssid, info, len, rssi, channel, ssid, name, company, sensor, pan, epid, network. Operators: == != > < >= <= contains, combined with && || ! ( ). A bare word matches a radio (wifi, ble, zigbee, lora) or a word in the protocol, type or info.';
  const expanded = new Map();   // path of a field ("IEEE 802.11 Beacon frame/Frame Control Field") -> open; kept while moving between frames

  addRoute('/frames', async (_, params) => {
    if (!isAdmin()) { app.innerHTML = '<div class="empty">Only admins can inspect recordings.</div>'; return; }
    const list = await api('/api/captures');
    const live = params.get('mode') === 'live';
    const filter = params.get('f') || '';
    const files = list.files;
    const file = params.get('file') || (files[0] && files[0].name) || '';
    app.innerHTML = `<div class="page-head"><div><h1>Frames</h1><div class="sub">What each radio delivered and how it is taken apart: a recording, frame by frame, or live.
      Record under <a href="#/settings?tab=capture">Settings → Frame recording</a>.</div></div>
      <div class="row">${seg('mode', [['', 'Recordings'], ['live', 'Live']], live ? 'live' : '')}
      ${!live && files.length ? `<select id="fx-file" title="Recording">${files.map(f => `<option value="${esc(f.name)}" ${f.name === file ? 'selected' : ''}>${esc(f.name)}${f.sensor_name ? ' · ' + esc(f.sensor_name) : ''} · ${bytes(f.size)}</option>`).join('')}</select>
        <a class="btn ghost" href="/api/captures/${enc(file)}" download>Download</a><button class="btn ghost" id="fx-delall" type="button">Delete all…</button>` : ''}</div></div>
      <div id="fx-root"></div>`;
    onSeg(app, 'mode', v => { location.hash = hrefWith('/frames', { mode: v || undefined, f: filter }); });
    const root = app.querySelector('#fx-root');
    if (live) { await liveView(root, list, params); return; }
    if (!files.length) {
      root.innerHTML = `<div class="callout">There are no recordings yet. ${list.blocked ? esc(list.blocked) + '.' : 'Make one under <a href="#/settings?tab=capture">Settings → Frame recording</a>, or watch the radios <a href="#/frames?mode=live">live</a>.'}</div>`;
      return;
    }
    app.querySelector('#fx-file').onchange = e => { location.hash = hrefWith('/frames', { file: e.target.value, f: filter }); };
    app.querySelector('#fx-delall').onclick = () => deleteAll(files.length, () => { if (location.hash === '#/frames') route(); else location.hash = '#/frames'; });
    root.innerHTML = '<div class="empty">Reading the recording…</div>';
    await recordingView(root, file, filter);
  });

  async function deleteAll(n, done) {
    if (!confirm(`Delete all ${n} recording${n === 1 ? '' : 's'}? This can't be undone.`)) return;
    try { const r = await send('DELETE', '/api/captures'); toast(`Deleted ${r.deleted} recording${r.deleted === 1 ? '' : 's'}`); done(); } catch (e) { toast(e.message, true); }
  }
  window.deleteAllRecordings = deleteAll;   // Settings -> Frame recording has the same button

  async function getJson(path) {
    const r = await fetch(path, { headers: { 'X-Sniffowireless': '1' } });
    let d = null;
    try { d = await r.json(); } catch { /* empty */ }
    if (!r.ok) { const e = new Error((d && d.detail) || `${r.status} ${r.statusText}`); e.status = r.status; throw e; }
    return d;
  }

  const cell = v => v == null || v === '' ? '' : esc(v);
  const rowHtml = x => `<tr data-no="${x.no}" class="fx-${x.color || 'other'}"><td class="num">${x.no}</td><td class="num">${(x.time || 0).toFixed(6)}</td>
    <td class="mono">${cell(x.src)}</td><td class="mono">${cell(x.dst)}</td><td>${cell(x.proto)}</td><td class="num">${x.len ?? ''}</td>
    <td class="num">${x.rssi != null ? esc(x.rssi) : ''}</td><td>${cell(x.channel)}</td><td class="fx-info" title="${cell(x.info)}">${cell(x.info)}</td></tr>`;

  /* The filter bar, the three panes and the status line; `go(filter)` applies a filter, `detail(no)` fetches a frame. */
  function layout(root, { filter, bad, status, go, detail, top = '' }) {
    root.innerHTML = `${top}<form id="fx-f" class="fx-bar" autocomplete="off">
        <input id="fx-q" class="mono" spellcheck="false" placeholder="Display filter, e.g.  beacon && rssi > -60   ·   addr == aa:bb:cc:dd:ee:ff   ·   ssid contains home" value="${esc(filter)}">
        <button class="btn">Apply</button><button class="btn ghost" type="button" id="fx-clear">Clear</button></form>
      ${bad ? `<div class="err small-text fx-err">${esc(bad)}</div>` : ''}
      <div class="fx-quick">${QUICK.map(([l, f]) => `<button class="btn small ghost" type="button" data-q="${esc(f)}">${l}</button>`).join('')}
        <span class="faint small-text fx-help" title="${esc(FILTER_HELP)}">Filter help</span></div>
      <div class="fx">
        <div class="fx-list" id="fx-list" tabindex="0"><table class="fx-t"><thead><tr><th class="num">No.</th><th class="num">Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th class="num">Length</th><th class="num">Signal</th><th>Ch.</th><th>Info</th></tr></thead><tbody id="fx-rows"></tbody></table></div>
        <div class="fx-detail"><div class="fx-tree" id="fx-tree"><div class="empty">Choose a frame.</div></div><div class="fx-hex mono" id="fx-hex"></div></div>
        <div class="fx-status small-text"><span id="fx-count"></span><span class="faint" id="fx-note">${status || ''}</span><span id="fx-field" class="faint"></span></div>
      </div>`;
    const q = root.querySelector('#fx-q');
    root.querySelector('#fx-f').onsubmit = e => { e.preventDefault(); go(q.value.trim()); };
    root.querySelector('#fx-clear').onclick = () => go('');
    root.querySelectorAll('[data-q]').forEach(b => b.onclick = () => go(b.dataset.q));
    q.classList.toggle('fx-ok', !!filter && !bad);
    q.classList.toggle('fx-bad', !!bad);
    const p = { rows: root.querySelector('#fx-rows'), listEl: root.querySelector('#fx-list'), sel: null };
    const pane = detailPane(root, go);
    p.choose = async (no, scroll) => {
      p.sel = no;
      p.rows.querySelectorAll('tr.sel').forEach(r => r.classList.remove('sel'));
      const tr = p.rows.querySelector(`tr[data-no="${no}"]`);
      if (tr) { tr.classList.add('sel'); if (scroll) tr.scrollIntoView({ block: 'nearest' }); }
      let d;
      try { d = await detail(no); } catch (e) { pane.error(e.message); return; }
      if (p.sel === no) pane.show(d);
    };
    p.rows.onclick = e => { const tr = e.target.closest('tr[data-no]'); if (tr) p.choose(+tr.dataset.no); };
    return p;
  }

  /* Arrow keys, Page Up/Down, Home and End move through `items()`; `more()` loads the next page when near the end. */
  function keys(p, items, more) {
    p.listEl.onkeydown = async e => {
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End', 'PageDown', 'PageUp'].includes(e.key)) return;
      e.preventDefault();
      let list = items();
      const i = list.findIndex(x => x.no === p.sel);
      const step = { ArrowDown: 1, ArrowUp: -1, PageDown: 20, PageUp: -20 }[e.key];
      let j = e.key === 'Home' ? 0 : e.key === 'End' ? list.length - 1 : Math.max(0, Math.min(list.length - 1, (i < 0 ? -1 : i) + step));
      if (more && j >= list.length - 5) { await more(); list = items(); }
      j = Math.min(j, list.length - 1);
      if (list[j]) p.choose(list[j].no, true);
    };
  }

  // ------------------------------------------------------------------ a recording
  async function recordingView(root, file, filter) {
    const base = `/api/captures/${enc(file)}/frames`;
    let first, bad = '';
    const id = location.hash;
    const fetchFirst = async url => {   // a big recording is read in the background: show how far, and ask again
      for (;;) {
        const d = await getJson(url);
        if (!d.loading) return d;
        if (location.hash !== id) throw new Error('left');
        root.innerHTML = `<div class="empty">Reading the recording… ${num(d.read)} frames so far.</div>`;
        await new Promise(r => setTimeout(r, 800));
      }
    };
    try { first = await fetchFirst(`${base}?limit=${PAGE}&filter=${enc(filter)}`); } catch (e) {
      if (e.message === 'left') return;
      if (e.status !== 400 || !filter) { root.innerHTML = `<div class="callout"><span class="err">${esc(e.message)}</span></div>`; return; }
      bad = e.message;   // a filter that doesn't parse: show it in red with the reason, and all frames
      try { first = await fetchFirst(`${base}?limit=${PAGE}`); } catch (e2) { root.innerHTML = `<div class="callout"><span class="err">${esc(e2.message)}</span></div>`; return; }
    }
    const st = { items: first.items, matched: first.matched, total: first.total, loading: false, filter: bad ? '' : filter };
    const counts = Object.entries(first.counts).map(([k, n]) => `${RADIO[k] || k} ${num(n)}`).join(' · ');
    const p = layout(root, {
      filter, bad, go: f => { location.hash = hrefWith('/frames', { file, f: f || undefined }); }, detail: no => getJson(`${base}/${no}`),
      status: esc(counts) + (first.truncated ? ' · only the first 200,000 frames are shown' : '') + (first.incomplete ? ' · the file ends early (still being written, or cut short)' : ''),
    });
    p.rows.innerHTML = st.items.map(rowHtml).join('') || `<tr><td colspan="9" class="empty">No frame matches this filter.</td></tr>`;
    root.querySelector('#fx-count').textContent = `Displayed ${num(st.matched)} of ${num(st.total)} frames`;
    async function more() {
      if (st.loading || st.items.length >= st.matched) return;
      st.loading = true;
      try {
        const d = await getJson(`${base}?offset=${st.items.length}&limit=${PAGE}&filter=${enc(st.filter)}`);
        st.items.push(...d.items);
        p.rows.insertAdjacentHTML('beforeend', d.items.map(rowHtml).join(''));
      } catch (e) { toast(e.message, true); }
      st.loading = false;
    }
    p.listEl.onscroll = () => { if (p.listEl.scrollTop + p.listEl.clientHeight > p.listEl.scrollHeight - 400) more(); };
    keys(p, () => st.items, more);
    if (st.items.length) p.choose(st.items[0].no);
  }

  // ------------------------------------------------------------------ live
  async function liveView(root, list, params) {
    if (list.blocked) { root.innerHTML = `<div class="callout"><span class="err">${esc(list.blocked)}.</span> Live capture shows the real addresses, so switch it off first.</div>`; return; }
    const source = params.get('source') || 'local';
    const filter = params.get('f') || '';
    const sources = [{ id: 'local', name: 'This server', online: true }, ...list.sensors];
    const go = f => { location.hash = hrefWith('/frames', { mode: 'live', source, f: f || undefined }); };
    let state = null;
    try { state = await getJson(`/api/frames/live?source=${enc(source)}&limit=1`); } catch { /* none yet */ }
    const top = `<div class="fx-live panel"><div class="body">
      <form id="fx-lf" class="row" autocomplete="off">
        <label class="field">Radios of<select name="source">${sources.map(x => `<option value="${esc(x.id)}" ${x.id === source ? 'selected' : ''} ${x.online ? '' : 'disabled'}>${esc(x.name)}${x.online ? '' : ' (offline)'}</option>`).join('')}</select></label>
        <div class="row">${Object.entries(RADIO).map(([k, l]) => `<label class="check"><input type="checkbox" name="r-${k}" ${!state || state.radios.includes(k) ? 'checked' : ''}> ${l}</label>`).join('')}</div>
        <label class="field">For<select name="seconds">${DURATIONS.map(([v, l]) => `<option value="${v}" ${v === 60 ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <button class="btn primary" id="fx-start">Start</button><button class="btn" type="button" id="fx-stop" hidden>Stop</button>
        <button class="btn ghost" type="button" id="fx-save" ${state && state.total ? '' : 'disabled'} title="Keep what was heard as a recording">Save as recording</button>
        <label class="check"><input type="checkbox" id="fx-follow" checked> Follow the newest</label>
      </form>
      <div class="small-text" id="fx-live-state"></div></div></div>`;
    const st = { items: [], last: 0, open: false, filter, polling: false, frames: state ? state.total : 0 };
    let bad = '';
    if (filter) { try { await getJson(`/api/frames/live?source=${enc(source)}&limit=1&filter=${enc(filter)}`); } catch (e) { if (e.status === 400) { bad = e.message; st.filter = ''; } } }
    const p = layout(root, { filter, bad, go, top, detail: no => getJson(`/api/frames/live/${no}?source=${enc(source)}`) });
    const f = root.querySelector('#fx-lf'), stateEl = root.querySelector('#fx-live-state');
    const follow = root.querySelector('#fx-follow');
    f.source.onchange = () => { location.hash = hrefWith('/frames', { mode: 'live', source: f.source.value, f: filter || undefined }); };
    p.rows.innerHTML = `<tr><td colspan="9" class="empty">${state ? '' : 'Choose the radios and press Start.'}</td></tr>`;
    keys(p, () => st.items);
    p.listEl.addEventListener('scroll', () => {   // scrolling up to look at something stops following, scrolling to the end starts it again
      const atEnd = p.listEl.scrollTop + p.listEl.clientHeight >= p.listEl.scrollHeight - 30;
      if (!atEnd && follow.checked && st.open) follow.checked = false;
      else if (atEnd && !follow.checked) follow.checked = true;
    });

    const show = d => {
      st.open = d.open;
      st.frames = d.total;
      root.querySelector('#fx-stop').hidden = !d.open;
      root.querySelector('#fx-start').textContent = d.open ? 'Start again' : 'Start';
      root.querySelector('#fx-save').disabled = !d.total;
      const quiet = d.open && d.now - (d.last_frame || d.started) > 10;
      stateEl.innerHTML = d.open
        ? `<span class="tag on">Live</span> ${num(d.total)} frames · stops in ${dur(Math.max(0, Math.round(d.until - d.now)))}${d.dropped ? ` · <span class="warn-text">${num(d.dropped)} frames were too many to send live</span>` : ''}
           ${quiet ? `<div class="faint">Nothing heard for a while.${source !== 'local' ? ' A remote sensor needs version 33.3 or newer to send its frames live (the Android app: 1.4.0).' : ''}</div>` : ''}`
        : `<span class="tag">Stopped</span> ${num(d.total)} frames heard${d.total > d.kept ? `, the newest ${num(d.kept)} kept` : ''}. Start again for more, or save them as a recording.`;
      root.querySelector('#fx-count').textContent = `Displayed ${num(st.items.length)}${st.items.length >= LIVE_ROWS ? ' (the newest)' : ''} of ${num(d.total)} frames`;
    };

    async function poll() {
      if (st.polling) return;
      st.polling = true;
      try {
        for (let round = 0; round < 5; round++) {   // catch up in a few rounds when a lot arrived
          const d = await getJson(`/api/frames/live?source=${enc(source)}&after=${st.last}&limit=1000&filter=${enc(st.filter)}`);
          if (!root.isConnected) return;
          if (st.items.length === 0 && d.items.length) p.rows.innerHTML = '';
          st.last = d.last;
          if (d.items.length) {
            st.items.push(...d.items);
            p.rows.insertAdjacentHTML('beforeend', d.items.map(rowHtml).join(''));
            const extra = st.items.length - LIVE_ROWS;
            if (extra > 0) {
              st.items.splice(0, extra);
              for (let i = 0; i < extra && p.rows.firstElementChild; i++) p.rows.firstElementChild.remove();
            }
            if (follow.checked) p.listEl.scrollTop = p.listEl.scrollHeight;
            if (p.sel == null) p.choose(st.items[0].no);
          }
          show(d);
          if (d.items.length < 1000) break;
        }
      } catch (e) {
        if (e.status === 404) stateEl.innerHTML = '<span class="faint">Choose the radios and press Start.</span>';
        else stateEl.innerHTML = `<span class="err">${esc(e.message)}</span>`;
      } finally { st.polling = false; }
    }

    f.onsubmit = async e => {
      e.preventDefault();
      const radios = Object.keys(RADIO).filter(k => f[`r-${k}`].checked);
      try { await send('POST', '/api/frames/live', { source, radios, seconds: +f.seconds.value }); } catch (err) { toast(err.message, true); return; }
      st.items = []; st.last = 0; p.sel = null;
      p.rows.innerHTML = '<tr><td colspan="9" class="empty">Listening…</td></tr>';
      follow.checked = true;
      poll();
    };
    root.querySelector('#fx-stop').onclick = async () => { await send('DELETE', `/api/frames/live?source=${enc(source)}`); poll(); };
    root.querySelector('#fx-save').onclick = async () => {
      try { const r = await send('POST', `/api/frames/live/save?source=${enc(source)}`); toast(`Saved ${num(r.frames)} frames as ${r.name}`); } catch (e) { toast(e.message, true); }
    };
    if (state) poll();
    every(1000, () => { if (st.open) poll(); });
  }

  // ------------------------------------------------------------------ the decoded fields and the bytes
  function detailPane(root, go) {
    const treeEl = root.querySelector('#fx-tree'), hexEl = root.querySelector('#fx-hex'), fieldEl = root.querySelector('#fx-field');
    let flat = [], bytesEls = [];

    function renderTree(d) {
      flat = [];
      const s = d.summary;
      const link = a => isMac(a) ? `<a class="mono" href="#/device/${enc(a)}">${esc(a)}</a>` : `<span class="mono">${esc(a)}</span>`;
      const strip = `<div class="fx-strip">${s.src ? `<span>From ${link(s.src)} <button class="btn small ghost" type="button" data-addr="${esc(s.src)}" title="Show only frames to or from this address">Filter</button></span>` : ''}
        ${s.dst && s.dst !== 'Broadcast' ? `<span>to ${link(s.dst)}</span>` : ''}${s.ssid ? `<span>network <a href="#/ssid/${enc(s.ssid)}">${esc(s.ssid)}</a></span>` : ''}</div>`;
      const walk = (nodes, depth, parent, path) => nodes.map(n => {
        const i = flat.length, p = path + '/' + n.n;
        flat.push({ n, parent, depth, p });
        const kids = n.c && n.c.length;
        const open = kids && (expanded.has(p) ? expanded.get(p) : depth === 0 && !/^Frame \d+$/.test(n.n));
        const label = esc(n.n) + (n.v != null ? `: <span class="fx-v">${esc(n.v)}</span>` : '');
        return `<div class="fx-n${kids ? ' fx-k' : ''}${open ? ' open' : ''}" data-i="${i}"><div class="fx-row" style="padding-left:${depth * 16 + 4}px">
          <span class="fx-car"></span>${label}</div>${kids ? `<div class="fx-c">${walk(n.c, depth + 1, i, p)}</div>` : ''}</div>`;
      }).join('');
      treeEl.innerHTML = strip + `<div class="fx-nodes mono">${walk(d.tree, 0, -1, '')}</div>`;
      treeEl.querySelectorAll('[data-addr]').forEach(b => b.onclick = () => go(`addr == ${b.dataset.addr}`));
    }

    treeEl.onclick = e => {
      const row = e.target.closest('.fx-row');
      if (!row || e.target.closest('a,button')) return;
      const el = row.parentElement, i = +el.dataset.i;
      if (el.classList.contains('fx-k') && (e.target.classList.contains('fx-car') || el.classList.contains('fx-picked'))) {
        el.classList.toggle('open');
        expanded.set(flat[i].p, el.classList.contains('open'));
      }
      pick(i);
    };
    treeEl.ondblclick = e => {
      const el = e.target.closest('.fx-n.fx-k');
      if (!el) return;
      el.classList.toggle('open');
      expanded.set(flat[+el.dataset.i].p, el.classList.contains('open'));
    };

    function pick(i, fromHex) {
      treeEl.querySelectorAll('.fx-picked').forEach(x => x.classList.remove('fx-picked'));
      const el = treeEl.querySelector(`.fx-n[data-i="${i}"]`);
      if (!el) return;
      el.classList.add('fx-picked');
      for (let p = flat[i].parent; p >= 0; p = flat[p].parent) {
        const pe = treeEl.querySelector(`.fx-n[data-i="${p}"]`);
        if (pe && !pe.classList.contains('open')) { pe.classList.add('open'); expanded.set(flat[p].p, true); }
      }
      if (fromHex) el.querySelector('.fx-row').scrollIntoView({ block: 'nearest' });
      const n = flat[i].n;
      highlight(n.o, n.l);
      fieldEl.textContent = n.o != null ? `${n.n} · ${n.l} byte${n.l === 1 ? '' : 's'} at offset ${n.o}` : n.n;
    }

    function renderHex(hex) {
      const b = [];
      for (let i = 0; i < hex.length; i += 2) b.push(parseInt(hex.slice(i, i + 2), 16));
      let html = '';
      for (let r = 0; r < b.length; r += 16) {
        const row = b.slice(r, r + 16);
        html += `<div class="fx-hr"><span class="fx-off">${r.toString(16).padStart(4, '0')}</span><span class="fx-hb">${row.map((x, j) =>
          `<span data-b="${r + j}">${x.toString(16).padStart(2, '0')}</span>${j === 7 ? ' ' : ''}`).join('')}</span><span class="fx-ha">${row.map((x, j) =>
          `<span data-b="${r + j}">${x >= 32 && x < 127 ? esc(String.fromCharCode(x)) : '.'}</span>`).join('')}</span></div>`;
      }
      hexEl.innerHTML = html || '<div class="faint">No bytes.</div>';
      bytesEls = [];
      hexEl.querySelectorAll('[data-b]').forEach(s => { (bytesEls[+s.dataset.b] = bytesEls[+s.dataset.b] || []).push(s); });
    }

    function highlight(o, l) {
      hexEl.querySelectorAll('.hl').forEach(x => x.classList.remove('hl'));
      if (o == null) return;
      for (let i = o; i < o + l; i++) (bytesEls[i] || []).forEach(s => s.classList.add('hl'));
      const firstEl = (bytesEls[o] || [])[0];
      if (firstEl) firstEl.scrollIntoView({ block: 'nearest' });
    }

    hexEl.onclick = e => {
      const s = e.target.closest('[data-b]');
      if (!s) return;
      const b = +s.dataset.b;
      let best = -1;   // the smallest field holding this byte, the way Wireshark picks one
      flat.forEach((f, i) => { const n = f.n; if (n.o != null && n.l > 0 && b >= n.o && b < n.o + n.l && (best < 0 || n.l <= flat[best].n.l)) best = i; });
      if (best >= 0) pick(best, true);
    };

    return {
      show(d) { renderTree(d); renderHex(d.hex); fieldEl.textContent = ''; },
      error(msg) { treeEl.innerHTML = `<div class="callout"><span class="err">${esc(msg)}</span></div>`; hexEl.innerHTML = ''; },
    };
  }
})();
