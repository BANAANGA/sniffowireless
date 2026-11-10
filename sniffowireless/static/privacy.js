'use strict';
/* Settings → Privacy: what is stored (hashed MAC addresses), how long it is kept (retention), and the anonymised view
   (display only). The server does the work; see macprivacy.py, dataprivacy.py and anonymize.py. */

SETTINGS_VIEWS.privacy = async function (el) {
  let st = await api('/api/privacy/storage');
  let ret = await api('/api/retention');
  let p = await api('/api/privacy');

  const when = ts => ts ? new Date(ts * 1000).toLocaleString() : '';

  function render() {
    const notes = [];
    if (st.hash_macs) {
      notes.push(`Capture of WPA handshakes is switched off while this is on: a capture file contains the real addresses of the network and the client.`);
      if (st.handshakes) notes.push(`<b>${st.handshakes}</b> handshake capture file${st.handshakes === 1 ? '' : 's'} already stored contain real addresses (delete them under Settings → Clear data).`);
    }
    if (st.backups) notes.push(`<b>${st.backups}</b> backup${st.backups === 1 ? '' : 's'} made earlier still contain the real addresses; delete them if that matters.`);
    el.innerHTML = `
      <section class="panel" style="max-width:820px"><header><h2>Storage: never keep full MAC addresses</h2>${st.hash_macs ? '<span class="tag on">on</span>' : '<span class="tag">off</span>'}</header>
        <div class="body">
          <p class="muted" style="margin-top:0">A MAC address identifies a device, and so often a person. With this on, every <b>static</b> (globally unique) address is replaced by a pseudonym <b>before it is stored</b>: the vendor part stays, the rest becomes a keyed hash, <span class="mono">a4:83:e7:5c:21:0b</span> → <span class="mono">a4:83:e7:3c:9e:61</span>. The same device always gets the same pseudonym, so you still see it come and go, and vendors, device types and statistics keep working. Randomised addresses are not static and are left alone (unless you choose <i>all</i>).</p>
          <label class="check" style="display:flex;gap:8px;align-items:center;margin:10px 0"><input type="checkbox" id="st-on" ${st.hash_macs ? 'checked' : ''} ${st.forced ? 'disabled' : ''}>
            <b>Hash static MAC addresses before storing them</b>${st.forced ? ' <span class="faint">(forced on by HASH_MACS=1)</span>' : ''}</label>
          <label class="field form-narrow" style="margin-left:26px">Which addresses<select id="st-scope">
            <option value="static" ${st.scope === 'static' ? 'selected' : ''}>Static addresses only (recommended)</option>
            <option value="all" ${st.scope === 'all' ? 'selected' : ''}>All addresses, randomised ones too</option></select></label>
          ${st.hash_macs ? `<div class="kv" style="margin:12px 0 4px 26px"><div><span>Pseudonyms in use</span><b>${st.aliases.toLocaleString()}</b></div>
            <div><span>Key</span><b class="mono">${esc(st.key || '')}</b></div>
            ${st.hashed_at ? `<div><span>Existing data hashed</span><b>${esc(when(st.hashed_at))}</b></div>` : ''}</div>` : ''}
          ${st.hash_macs && st.unhashed_devices ? `<div class="notice-red" style="margin:12px 0 4px 26px;padding:10px 12px;border-radius:6px">
            <b>${st.unhashed_devices.toLocaleString()}</b> device${st.unhashed_devices === 1 ? '' : 's'} already in the database still ${st.unhashed_devices === 1 ? 'has' : 'have'} a full address.
            ${st.pending_existing ? '<b>Restart the application</b> to replace them: it is done at the next start and can take a while on a big database.'
              : `<div style="margin-top:8px"><button class="btn" id="st-existing" type="button">Hash the existing data…</button></div>`}</div>` : ''}
          ${notes.length ? `<ul class="small-text" style="margin:12px 0 0 26px">${notes.map(n => `<li>${n}</li>`).join('')}</ul>` : ''}
          <details style="margin:14px 0 0 26px"><summary class="muted" style="cursor:pointer">What this protects, and what it does not</summary>
            <div class="faint small-text" style="margin-top:8px"><p><b>Protects</b> against a leaked or stolen database, backup, export or log: without the key the addresses cannot be recovered. The key is kept in a file next to the database (or in <span class="mono">PRIVACY_KEY</span>), not inside it; keep it out of backups.</p>
              <p><b>Does not protect</b> against someone who has the database <i>and</i> the key: only 24 bits of an address are unknown once the vendor is known, so they can recompute the pseudonym of any address they can guess. The radios still hear real addresses, and remote sensors still send them to the server (use HTTPS); the server keeps the real address of a device heard in the last few minutes in memory only, so that <i>play sound</i> and <i>read exact version</i> still work. Randomised addresses and addresses written by hand in a label or note are not touched. A pseudonym typed or clicked in the interface works as before, and a real address you type is turned into its pseudonym, so searches, the ignore list and My networks keep working; a partial address is only found by its vendor part.</p></div></details>
        </div></section>

      <section class="panel" style="max-width:820px;margin-top:16px"><header><h2>Data retention</h2><span class="faint">database ${esc(bytes(ret.db_bytes))}</span></header>
        <div class="body flush"><table><thead><tr><th>Kind of data</th><th class="num" style="width:150px">Keep for (days)</th></tr></thead><tbody>
          ${ret.kinds.map(k => `<tr><td><b>${esc(k.label)}</b><div class="faint small-text">${esc(k.hint)}</div></td>
            <td class="num"><input type="number" min="0" max="3650" data-ret="${esc(k.kind)}" value="${k.days || ''}" placeholder="${ret.default} (default)" style="width:110px" aria-label="${esc(k.label)} days"></td></tr>`).join('')}
        </tbody></table></div>
        <div class="body"><div class="row"><button class="btn primary" id="ret-save" type="button">Save</button><button class="btn" id="ret-run" type="button">Delete what is older now</button></div>
          <p class="faint small-text" style="margin-bottom:0">Empty means the general limit, <b>${ret.default} days</b> (the <span class="mono">RETENTION_DAYS</span> setting). Anything older is deleted about once an hour, or with the button. LAN, Zigbee and LoRa data have their own limits under Settings → Modules. A shorter time is the simplest way to hold less personal data; a limit only applies to data stored from now on and to what is already stored, and deleting cannot be undone.</p></div></section>

      <h3 class="small-head" style="margin-top:24px;max-width:820px">Anonymised view (display only)</h3>
      <p class="muted" style="margin-top:0;max-width:820px">Show pseudonyms instead of real MAC addresses and / or SSIDs to <b>everyone</b>, admins included: in every page, export and API response. Useful for screenshots, demos and giving others access. The database keeps what it keeps; this only changes what is shown.</p>
      <section class="panel" style="max-width:820px"><div class="body flush"><table><tbody>
        <tr><td style="width:34px"><input type="checkbox" id="pv-macs" ${p.macs ? 'checked' : ''} aria-label="Anonymise MAC addresses"></td>
          <td><b>MAC addresses</b><div class="faint small-text">The vendor part stays, the rest becomes a pseudonym. Multicast and broadcast addresses are left alone.</div></td></tr>
        <tr><td><input type="checkbox" id="pv-ssids" ${p.ssids ? 'checked' : ''} aria-label="Anonymise SSIDs"></td>
          <td><b>SSIDs</b><div class="faint small-text">Network names become <span class="mono">Network-1a2b3c</span>, also where they appear in events and logs.</div></td></tr>
      </tbody></table></div></section>
      <div class="faint small-text" style="max-width:820px;margin-top:12px">
        <p>The same name always gets the same pseudonym, also after a restart, and links, searches and forms keep working. Notifications that are sent out (ntfy, e-mail, …), backups and the sensors' own uploads keep the real values: for that, use <b>Storage</b> above. A MAC address or SSID written in free text (a label, a note) is not recognised. Downloaded handshake captures contain the real addresses.</p></div>`;

    el.querySelector('#st-on').onchange = saveStorage;
    el.querySelector('#st-scope').onchange = () => { if (el.querySelector('#st-on').checked) saveStorage(); };
    const ex = el.querySelector('#st-existing');
    if (ex) ex.onclick = hashExisting;
    el.querySelector('#ret-save').onclick = saveRetention;
    el.querySelector('#ret-run').onclick = runCleanup;
    ['macs', 'ssids'].forEach(k => el.querySelector('#pv-' + k).onchange = saveView);
  }

  async function saveStorage() {
    const on = el.querySelector('#st-on').checked, scope = el.querySelector('#st-scope').value;
    if (on && !st.hash_macs && !confirm('Switch on hashed storage?\n\nFrom now on full static MAC addresses are replaced by pseudonyms before they are stored. This cannot recover addresses that were stored before; use "Hash the existing data" for those.\n\nHandshake capture is switched off while this is on.')) { render(); return; }
    if (!on && st.hash_macs && !confirm('Switch hashed storage off?\n\nNew data will be stored with full MAC addresses again. Pseudonyms already stored stay as they are.')) { render(); return; }
    try { st = await send('PUT', '/api/privacy/storage', { hash_macs: on, scope }); toast(on ? 'Hashed storage is on' : 'Hashed storage is off'); }
    catch (e) { toast(e.message, true); st = await api('/api/privacy/storage'); }
    render();
  }

  async function hashExisting() {
    if (!confirm(`Replace the full MAC addresses already in the database?\n\nThis is done at the next start of the application, can take a long time on a big database (the file is compacted afterwards, which needs free disk space about the size of the database), cannot be undone, and old backups keep the real addresses.\n\nMake a backup first if you may need the real addresses. Continue?`)) return;
    try { st = await send('POST', '/api/privacy/storage/hash-existing', {}); toast('Restart the application to replace the stored addresses'); }
    catch (e) { toast(e.message, true); }
    render();
  }

  async function saveRetention() {
    const days = {};
    el.querySelectorAll('[data-ret]').forEach(i => { days[i.dataset.ret] = i.value === '' ? 0 : parseInt(i.value, 10); });
    try { ret = await send('PUT', '/api/retention', { days }); toast('Retention saved'); }
    catch (e) { toast(e.message, true); }
    render();
  }

  async function runCleanup() {
    if (!confirm('Delete everything older than the limits above now? This cannot be undone.')) return;
    try { await send('POST', '/api/retention/run', {}); toast('Cleaning up; the database size updates when it is done'); setTimeout(async () => { ret = await api('/api/retention'); render(); }, 4000); }
    catch (e) { toast(e.message, true); }
  }

  async function saveView() {
    try {
      p = await send('PUT', '/api/privacy', { macs: el.querySelector('#pv-macs').checked, ssids: el.querySelector('#pv-ssids').checked });
      await loadModules();  // the pill in the menu
      toast('Saved');
      route();  // redraw everything with (or without) the pseudonyms
      return;
    } catch (e) { toast(e.message, true); p = await api('/api/privacy'); }
    render();
  }
  render();
};
