'use strict';
/* Walk survey (#/walk, walk.py): walk around with a sensor and tap where you stand on the floor plan; the page draws heatmaps of
   the signal from the points (inverse-distance weighting between them). */
(() => {
  const STEPS = [[-60, '#1fa463', 'strong (−60 dBm or better)'], [-67, '#7bc043', 'good for calls and video (−67)'], [-75, '#f4c20d', 'fair (−75)'],
    [-82, '#f08a24', 'weak (−82)'], [-200, '#d93025', 'too weak']];
  const colour = v => (STEPS.find(([t]) => v >= t) || STEPS[STEPS.length - 1])[1];
  const OVER = [[3, '#d93025', '3 or more'], [2, '#7bc043', '2 (roaming works)'], [1, '#f4c20d', '1'], [0, '#888', 'none']];

  /* The value of a layer at one point: the best of the access points it covers, or (overlap) how many of mine are good there. */
  function value(p, layer, aps) {
    const vals = Object.entries(p.readings).filter(([m]) => {
      const a = aps[m];
      if (layer.startsWith('ap:')) return m === layer.slice(3);
      if (!a || !a.mine) return false;
      return layer === 'mine' || layer === 'overlap' || a.band === layer.slice(5);
    }).map(([, v]) => v);
    if (layer === 'overlap') return vals.filter(v => v >= -67).length;
    return vals.length ? Math.max(...vals) : null;
  }

  function paint(canvas, pts, layer, aps) {
    const w = canvas.width = canvas.clientWidth, h = canvas.height = canvas.clientHeight;
    const g = canvas.getContext('2d');
    g.clearRect(0, 0, w, h);
    const known = pts.map(p => ({ x: p.x * w, y: p.y * h, v: value(p, layer, aps) })).filter(p => p.v != null);
    if (!known.length) return;
    const cell = 8, reach = Math.max(w, h) * 0.18;
    for (let y = 0; y < h; y += cell) {
      for (let x = 0; x < w; x += cell) {
        let num = 0, den = 0, near = Infinity;
        for (const p of known) {
          const d2 = (p.x - x - cell / 2) ** 2 + (p.y - y - cell / 2) ** 2;
          near = Math.min(near, d2);
          const wgt = 1 / Math.max(d2, 1) ** 1.5;
          num += wgt * p.v; den += wgt;
        }
        if (Math.sqrt(near) > reach) continue;   // too far from any point to say
        const v = num / den;
        g.fillStyle = layer === 'overlap' ? (OVER.find(([t]) => Math.round(v) >= t) || OVER[3])[1] : colour(v);
        g.globalAlpha = 0.45;
        g.fillRect(x, y, cell, cell);
      }
    }
    g.globalAlpha = 1;
  }

  addRoute('/walk', async (_, params) => {
    const list = await api('/api/walk');
    const sid = +(params.get('s') || (list.surveys[0] && list.surveys[0].id) || 0);
    const layer = params.get('l') || 'mine';
    const fp = list.floorplan || {};
    const ratio = fp.width && fp.height ? fp.height / fp.width : 0.64;
    const s = sid ? await api(`/api/walk/${sid}`) : null;
    const mineAps = s ? Object.values(s.aps).filter(a => a.mine) : [];
    const layers = [['mine', 'My networks'], ['band:2.4', '2.4 GHz'], ['band:5', '5 GHz'], ['band:6', '6 GHz'], ['overlap', 'Overlap']];
    app.innerHTML = `<div class="page-head"><div><h1>Walk survey</h1><div class="sub">Walk around with a sensor and tap where you stand: the readings of the last ${list.window} seconds become a point, and the points a heatmap.</div></div>
      <div class="row no-print">${list.surveys.length ? `<select id="w-pick">${list.surveys.map(x => `<option value="${x.id}" ${x.id === sid ? 'selected' : ''}>${esc(x.name)} · ${x.points} points · ${dt(x.created)}</option>`).join('')}</select>` : ''}
        ${isAdmin() ? '<button class="btn" id="w-new">New survey…</button>' : ''}</div></div>
      ${!fp.image ? '<div class="callout">Upload a floor plan first (Map → Edit layout): the survey is drawn on it.</div>' : ''}
      ${s ? `<div class="grid cols-3">
        <section class="panel span-2"><header><h2>${esc(s.name)}</h2><span class="row">${seg('layer', [...layers, ...mineAps.map(a => [`ap:${a.mac}`, `${a.ssid} ${a.band}G …${a.mac.slice(-5)}`])].filter(([k]) => k.startsWith('ap:') || k === 'mine' || k === 'overlap' || mineAps.some(a => `band:${a.band}` === k)), layer)}</span></header>
          <div class="body"><div class="map walk" id="w-map" style="padding-top:${ratio * 100}%;${fp.image ? `background-image:url(/api/floorplan/image?v=${fp.updated || fp.width || 1})` : ''}">
            <canvas id="w-heat"></canvas>${s.points.map(p => `<div class="walk-pt" style="left:${p.x * 100}%;top:${p.y * 100}%" title="${esc(Object.keys(p.readings).length + ' access points')}">${(v => v == null ? '' : layer === 'overlap' ? v : v)(value(p, layer, s.aps)) ?? ''}</div>`).join('')}</div>
            ${s.open && isAdmin() ? `<div class="row" style="margin-top:8px"><span id="w-now" class="small-text">…</span><button class="btn small ghost" id="w-undo" ${s.points.length ? '' : 'disabled'}>Undo last point</button><button class="btn small" id="w-stop">Finish</button></div>`
              : isAdmin() ? '<div class="row" style="margin-top:8px"><button class="btn small ghost" id="w-resume">Go on with this survey</button><button class="btn small ghost" id="w-del">Delete it</button></div>' : ''}
          </div></section>
        <section class="panel"><header><h2>Legend</h2></header><div class="body small-text">
          ${(layer === 'overlap' ? OVER.map(([, c, l]) => [c, l]) : STEPS.map(([, c, l]) => [c, l])).map(([c, l]) => `<div><span class="swatch" style="background:${c}"></span> ${l}</div>`).join('')}
          <p class="faint">${layer === 'overlap' ? 'How many of your access points are heard at −67 dBm or better: two or more lets clients roam; on one channel they share the air.' : 'The strongest of the chosen access points at each spot. −67 dBm is the usual target for calls and video.'}</p>
          ${(() => { const vals = s.points.map(p => value(p, 'mine', s.aps)).filter(v => v != null); return vals.length ? `<p><b>${Math.round(vals.filter(v => v >= -67).length * 100 / vals.length)}%</b> of the points are covered at −67 dBm or better by your networks.</p>` : ''; })()}
          <p class="faint">Sensor: ${esc((list.sensors.find(x => x.id === s.sensor) || {}).name || s.sensor)} · ${s.points.length} points</p></div></section></div>`
        : '<div class="empty">No surveys yet. Start one with “New survey…”, then walk around with the sensor and tap where you stand.</div>'}`;
    onSeg(app, 'layer', v => { location.hash = hrefWith('/walk', { s: sid, l: v }); });
    const pick = app.querySelector('#w-pick');
    if (pick) pick.onchange = () => { location.hash = hrefWith('/walk', { s: pick.value }); };
    const nw = app.querySelector('#w-new');
    if (nw) nw.onclick = () => openModal('New walk survey', `<label class="field">Name<input name="name" value="Survey ${new Date().toLocaleDateString()}"></label>
        <label class="field">The sensor you carry<select name="sensor">${list.sensors.map(x => `<option value="${esc(x.id)}">${esc(x.name)}${x.online === false ? ' (offline)' : ''}</option>`).join('')}</select></label>`,
      async f => { const r = await send('POST', '/api/walk', { name: f.name.value, sensor: f.sensor.value }); location.hash = hrefWith('/walk', { s: r.id }); }, { submit: 'Start' });
    if (!s) return;
    const canvas = app.querySelector('#w-heat');
    const draw = () => paint(canvas, s.points, layer, s.aps);
    draw();
    window.addEventListener('resize', draw, { once: true });
    const map = app.querySelector('#w-map');
    if (s.open && isAdmin()) {
      map.classList.add('tap');
      map.onclick = async e => {
        const b = map.getBoundingClientRect();
        try {
          const r = await send('POST', `/api/walk/${sid}/point`, { x: (e.clientX - b.left) / b.width, y: (e.clientY - b.top) / b.height });
          toast(`Point added: ${r.aps} access points`);
          route();
        } catch (err) { toast(err.message, true); }
      };
      const nowEl = app.querySelector('#w-now');
      const tick = async () => {
        try {
          const n = await api(`/api/walk/${sid}/now`);
          nowEl.innerHTML = `Heard now: <b>${n.aps}</b> access points${n.best_mine != null ? ` · yours at best <b>${n.best_mine} dBm</b>` : ''}. Stand still for ${list.window} s, then tap where you are.`;
        } catch { /* try again */ }
      };
      tick();
      every(2000, tick);
      app.querySelector('#w-undo').onclick = async () => { const last = s.points[s.points.length - 1]; if (last) { await send('DELETE', `/api/walk/${sid}/point/${last.id}`); route(); } };
      app.querySelector('#w-stop').onclick = async () => { await send('POST', `/api/walk/${sid}/stop`); route(); };
    } else if (isAdmin()) {
      app.querySelector('#w-resume').onclick = async () => { await send('POST', `/api/walk/${sid}/resume`); route(); };
      app.querySelector('#w-del').onclick = async () => { if (!confirm(`Delete “${s.name}” and its ${s.points.length} points?`)) return; await send('DELETE', `/api/walk/${sid}`); location.hash = '#/walk'; };
    }
  });
})();
