'use strict';
/* Walk survey (#/walk, walk.py): walk around with a sensor and tap where you stand on the floor plan; the page draws heatmaps of
   the signal from the points (inverse-distance weighting between them). */
(() => {
  const STEPS = [[-60, '#1fa463', 'strong (−60 dBm or better)'], [-67, '#7bc043', 'good for calls and video (−67)'], [-75, '#f4c20d', 'fair (−75)'],
    [-82, '#f08a24', 'weak (−82)'], [-200, '#d93025', 'too weak']];
  const colour = v => (STEPS.find(([t]) => v >= t) || STEPS[STEPS.length - 1])[1];
  const OVER = [[3, '#d93025', '3 or more'], [2, '#7bc043', '2 (roaming works)'], [1, '#f4c20d', '1'], [0, '#888', 'none']];
  const CCI = [[3, '#d93025', '3 or more share its channel'], [2, '#f08a24', '2'], [1, '#f4c20d', '1'], [0, '#1fa463', 'none: the channel is its own']];
  const DIFF = [[6, '#1fa463', '6 dB or more better'], [3, '#7bc043', '3–6 dB better'], [-3, '#999', 'about the same'], [-6, '#f08a24', '3–6 dB worse'],
    [-200, '#d93025', '6 dB or more worse']];
  const COUNTS = { overlap: OVER, cci: CCI };

  /* The value of a layer at one point: the best of the access points it covers, or (overlap) how many of mine are good there. */
  /* second: the second-strongest of mine (what roaming designs aim for); cci: how many other access points (anyone's) are heard
     above −82 dBm on the channel of the strongest of mine there. */
  function value(p, layer, aps) {
    const vals = Object.entries(p.readings).filter(([m]) => {
      const a = aps[m];
      if (layer.startsWith('ap:')) return m === layer.slice(3);
      if (!a || !a.mine) return false;
      return ['mine', 'overlap', 'second', 'cci'].includes(layer) || a.band === layer.slice(5);
    }).map(([, v]) => v);
    if (layer === 'overlap') return vals.filter(v => v >= -67).length;
    if (layer === 'second') return vals.length > 1 ? vals.sort((a, b) => b - a)[1] : vals.length ? -100 : null;
    if (layer === 'cci') {
      const top = Object.entries(p.readings).filter(([m]) => aps[m] && aps[m].mine).sort((a, b) => b[1] - a[1])[0];
      if (!top) return null;
      const ch = aps[top[0]].channel;
      return Object.entries(p.readings).filter(([m, v]) => m !== top[0] && v >= -82 && aps[m] && aps[m].channel === ch).length;
    }
    return vals.length ? Math.max(...vals) : null;
  }
  const fill = (layer, v) => COUNTS[layer] ? (COUNTS[layer].find(([t]) => Math.round(v) >= t) || COUNTS[layer][COUNTS[layer].length - 1])[1] : colour(v);

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
        g.fillStyle = fill(layer, v);
        g.globalAlpha = 0.45;
        g.fillRect(x, y, cell, cell);
      }
    }
    g.globalAlpha = 1;
  }

  /* The comparison of two surveys: the cells the server worked out, coloured by how much better or worse. */
  function paintDiff(canvas, c) {
    const w = canvas.width = canvas.clientWidth, h = canvas.height = canvas.clientHeight;
    const g = canvas.getContext('2d');
    g.clearRect(0, 0, w, h);
    const cw = w / c.n, ch = h / c.rows;
    g.globalAlpha = 0.5;
    for (const x of c.cells) {
      g.fillStyle = (DIFF.find(([t]) => x.d >= t) || DIFF[DIFF.length - 1])[1];
      g.fillRect(x.x * w - cw / 2, x.y * h - ch / 2, cw + 0.5, ch + 0.5);
    }
    g.globalAlpha = 1;
  }

  const legendRows = rows => rows.map(([, c, l]) => `<div><span class="swatch" style="background:${c}"></span> ${l}</div>`).join('');
  const LAYER_HELP = {
    overlap: 'How many of your access points are heard at −67 dBm or better: two or more lets clients roam; on one channel they share the air.',
    second: 'The second-strongest of your access points. Designs for roaming (and for calls while walking) aim for −67 dBm or better from two at once.',
    cci: 'How many other access points, yours or the neighbours’, are heard above −82 dBm on the channel of the strongest of yours. They all take turns on the air: fewer is faster.',
  };

  /* Coverage, the dead spots, and the extra access point (walk.py analyse()). */
  function analysis(s) {
    const a = s.analysis;
    if (!a.points) return '';
    const byRoom = {};
    for (const d of a.dead) (byRoom[d.room || 'elsewhere'] = byRoom[d.room || 'elsewhere'] || []).push(d);
    const sg = a.suggest;
    return `<h3>Coverage</h3><p><b>${Math.round(a.points_good * 100 / a.points)}%</b> of the points${a.area_good != null ? ` and <b>${a.area_good}%</b> of the surveyed area` : ''} are covered at −67 dBm or better by your networks.</p>
      <h3>Dead spots</h3>${a.dead.length ? `<p>${a.dead.length} point${a.dead.length > 1 ? 's' : ''} where none of yours reaches −75 dBm:</p><ul class="tight">${Object.entries(byRoom).map(([r, l]) =>
        `<li>${esc(r)}: ${l.length} (${l.some(d => d.best == null) ? 'some hear none of yours' : `worst ${Math.min(...l.map(d => d.best))} dBm`})</li>`).join('')}</ul>` : '<p class="faint">None: everywhere you stood, one of yours was at −75 dBm or better.</p>'}
      <h3>An extra access point</h3>${sg ? `<p>One at the <span class="walk-new inline">+</span> on the map${sg.room ? ` (near the ${esc(sg.room)})` : ''} would bring <b>${sg.fixes}%</b> of the weak area to −67 dBm or better: coverage ${a.area_good}% → <b>${sg.area_after}%</b>.</p>
        <p class="faint small-text">An estimate: a signal falling off as ${sg.model.a} dBm at 1 m, exponent ${sg.model.n}${sg.model.fitted ? ', fitted to this survey' : ' (the usual indoor values: too few points to fit this floor)'}, over a floor ${s.width_m} m wide. Walls in the way make it weaker.</p>`
        : `<p class="faint">${a.area_good === 100 ? 'Not needed: the whole surveyed area is covered.' : 'Nothing to suggest yet: survey a few more points, and mark your networks (Settings → Networks).'}</p>`}`;
  }

  addRoute('/walk', async (_, params) => {
    const list = await api('/api/walk');
    const sid = +(params.get('s') || (list.surveys[0] && list.surveys[0].id) || 0);
    const layer = params.get('l') || 'mine';
    const fp = list.floorplan || {};
    const ratio = fp.width && fp.height ? fp.height / fp.width : 0.64;
    const s = sid ? await api(`/api/walk/${sid}`) : null;
    const mineAps = s ? Object.values(s.aps).filter(a => a.mine) : [];
    const layers = [['mine', 'My networks'], ['band:2.4', '2.4 GHz'], ['band:5', '5 GHz'], ['band:6', '6 GHz'], ['second', 'Second AP'], ['overlap', 'Overlap'],
      ['cci', 'Shared channel']];
    const cmp = +(params.get('c') || 0);
    const diff = s && cmp && cmp !== sid ? await api(`/api/walk/${sid}/compare/${cmp}`) : null;
    app.innerHTML = `<div class="page-head"><div><h1>Walk survey</h1><div class="sub">Walk around with a sensor and tap where you stand: the readings of the last ${list.window} seconds become a point, and the points a heatmap.</div></div>
      <div class="row no-print">${list.surveys.length ? `<select id="w-pick">${list.surveys.map(x => `<option value="${x.id}" ${x.id === sid ? 'selected' : ''}>${esc(x.name)} · ${x.points} points · ${dt(x.created)}</option>`).join('')}</select>` : ''}
        ${isAdmin() ? '<button class="btn" id="w-new">New survey…</button>' : ''}</div></div>
      ${!fp.image ? '<div class="callout">Upload a floor plan first (Map → Edit layout): the survey is drawn on it.</div>' : ''}
      ${s ? `<div class="grid cols-3">
        <section class="panel span-2"><header><h2>${esc(s.name)}</h2><span class="row">${seg('layer', [...layers, ...mineAps.map(a => [`ap:${a.mac}`, `${a.ssid} ${a.band}G …${a.mac.slice(-5)}`])].filter(([k]) => !k.startsWith('band:') || mineAps.some(a => `band:${a.band}` === k)), diff ? '' : layer)}</span></header>
          <div class="body"><div class="map walk" id="w-map" style="padding-top:${ratio * 100}%;${fp.image ? `background-image:url(/api/floorplan/image?v=${fp.updated || fp.width || 1})` : ''}">
            <canvas id="w-heat"></canvas>${diff ? '' : s.analysis.suggest ? `<div class="walk-new" style="left:${s.analysis.suggest.x * 100}%;top:${s.analysis.suggest.y * 100}%" title="An extra access point here">+</div>` : ''}${s.points.map(p => `<div class="walk-pt" style="left:${p.x * 100}%;top:${p.y * 100}%" title="${esc(Object.keys(p.readings).length + ' access points')}">${diff ? '' : value(p, layer, s.aps) ?? ''}</div>`).join('')}</div>
            <div class="row" style="margin-top:8px"><label class="small-text">Compare with <select id="w-cmp"><option value="">—</option>${list.surveys.filter(x => x.id !== sid).map(x => `<option value="${x.id}" ${x.id === cmp ? 'selected' : ''}>${esc(x.name)} · ${dt(x.created)}</option>`).join('')}</select></label>
              <span class="faint small-text">Floor ${s.width_m} m wide${isAdmin() ? ' <a href="#" id="w-width">change</a>' : ''}</span></div>
            ${s.open && isAdmin() ? `<div class="row" style="margin-top:8px"><span id="w-now" class="small-text">…</span><button class="btn small ghost" id="w-undo" ${s.points.length ? '' : 'disabled'}>Undo last point</button><button class="btn small" id="w-stop">Finish</button></div>`
              : isAdmin() ? '<div class="row" style="margin-top:8px"><button class="btn small ghost" id="w-resume">Go on with this survey</button><button class="btn small ghost" id="w-del">Delete it</button></div>' : ''}
          </div></section>
        <section class="panel"><header><h2>Legend</h2></header><div class="body small-text">
          ${diff ? `${legendRows(DIFF)}<p class="faint">The strongest of your access points now, against “${esc((list.surveys.find(x => x.id === cmp) || {}).name || '')}”, where both surveys have points nearby.</p>
            <p>Better in <b>${diff.better}%</b> of the area, worse in <b>${diff.worse}%</b>${diff.median != null ? ` (median ${diff.median > 0 ? '+' : ''}${diff.median} dB)` : ''}. Covered at −67 dBm or better: <b>${diff.good_before}%</b> → <b>${diff.good_after}%</b>.</p>`
            : `${legendRows(COUNTS[layer] || STEPS)}<p class="faint">${LAYER_HELP[layer] || 'The strongest of the chosen access points at each spot. −67 dBm is the usual target for calls and video.'}</p>`}
          ${analysis(s)}
          <p class="faint">Sensor: ${esc((list.sensors.find(x => x.id === s.sensor) || {}).name || s.sensor)} · ${s.points.length} points</p></div></section></div>`
        : '<div class="empty">No surveys yet. Start one with “New survey…”, then walk around with the sensor and tap where you stand.</div>'}`;
    onSeg(app, 'layer', v => { location.hash = hrefWith('/walk', { s: sid, l: v }); });
    const cmpSel = app.querySelector('#w-cmp');
    if (cmpSel) cmpSel.onchange = () => { location.hash = hrefWith('/walk', { s: sid, l: layer, c: cmpSel.value }); };
    const wid = app.querySelector('#w-width');
    if (wid) wid.onclick = e => { e.preventDefault(); openModal('Floor width', `<label class="field">How wide the floor plan is, in metres<input name="w" type="number" min="3" max="500" step="0.5" value="${s.width_m}"></label><p class="faint small-text">Used for the distances when suggesting where an extra access point would help.</p>`,
      async f => { await send('PUT', `/api/walk/${sid}`, { width_m: +f.w.value }); route(); }); };
    const pick = app.querySelector('#w-pick');
    if (pick) pick.onchange = () => { location.hash = hrefWith('/walk', { s: pick.value }); };
    const nw = app.querySelector('#w-new');
    if (nw) nw.onclick = () => openModal('New walk survey', `<label class="field">Name<input name="name" value="Survey ${new Date().toLocaleDateString()}"></label>
        <label class="field">Floor width (metres)<input name="width" type="number" min="3" max="500" step="0.5" value="20"></label>
        <label class="field">The sensor you carry<select name="sensor">${list.sensors.map(x => `<option value="${esc(x.id)}">${esc(x.name)}${x.online === false ? ' (offline)' : ''}</option>`).join('')}</select></label>`,
      async f => { const r = await send('POST', '/api/walk', { name: f.name.value, sensor: f.sensor.value, width_m: +f.width.value || 20 }); location.hash = hrefWith('/walk', { s: r.id }); }, { submit: 'Start' });
    if (!s) return;
    const canvas = app.querySelector('#w-heat');
    const draw = () => diff ? paintDiff(canvas, diff) : paint(canvas, s.points, layer, s.aps);
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
