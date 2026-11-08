'use strict';
/* Name and watch a LoRa node or Zigbee radio (Settings has no page for it: it is done where they are listed). */

// kind 'lora' (ref: protocol) or 'zigbee' (ref: PAN number). cur: what the list row knows.
function editRadio(kind, ref, addr, cur, done) {
  if (!isAdmin()) return;
  openModal(`${kind === 'lora' ? 'LoRa node' : 'Zigbee radio'} ${addr}`,
    `<label class="field">Name<input name="label" value="${esc(cur.label || '')}" maxlength="60" placeholder="e.g. Garden Meshtastic" autocomplete="off"></label>
     <label class="check"><input type="checkbox" name="watch" ${cur.watch ? 'checked' : ''}> Watch it: raise an event when it goes silent, and again when it is back</label>
     <label class="field">Silent after (minutes)<input name="silent" type="number" min="5" max="20160" value="${cur.silent || 60}" style="width:110px"></label>
     <p class="faint small-text" style="margin-top:0">The radio hops between profiles and hears a node only part of the time, so choose well above how often the node transmits. Notify yourself with an alert rule on <i>Watched … went silent</i>. Empty name and not watched: forget it.</p>`,
    async f => {
      await send('PUT', '/api/radios/watch', { kind, ref: String(ref), addr, label: fv(f, 'label') || null, watch: fv(f, 'watch'), silent_min: +fv(f, 'silent') || 60 });
      toast('Saved');
      if (done) done();
    });
}

const watchTag = n => n.watch ? (n.watch_state === 'silent' ? ' <span class="tag bad" title="Not heard for longer than its limit">silent</span>' : ' <span class="tag on" title="Watched">watched</span>') : '';
