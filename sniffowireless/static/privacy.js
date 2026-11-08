'use strict';
/* Settings → Privacy: the anonymised view. The data stays real; everyone sees pseudonyms for MAC addresses and / or SSIDs. */

SETTINGS_VIEWS.privacy = async function (el) {
  let p = await api('/api/privacy');

  function render() {
    el.innerHTML = `<p class="muted" style="margin-top:0">Show pseudonyms instead of real MAC addresses and / or SSIDs, to <b>everyone</b>, admins included: in every page, export and API response. Useful for screenshots, demos and giving others access.</p>
      <section class="panel" style="max-width:760px"><div class="body flush"><table><tbody>
        <tr><td style="width:34px"><input type="checkbox" id="pv-macs" ${p.macs ? 'checked' : ''} aria-label="Anonymise MAC addresses"></td>
          <td><b>MAC addresses</b><div class="faint small-text">The vendor part stays, the rest becomes a pseudonym: <span class="mono">a4:83:e7:5c:21:0b</span> → <span class="mono">a4:83:e7:9f:3e:61</span>. Multicast and broadcast addresses are left alone.</div></td></tr>
        <tr><td><input type="checkbox" id="pv-ssids" ${p.ssids ? 'checked' : ''} aria-label="Anonymise SSIDs"></td>
          <td><b>SSIDs</b><div class="faint small-text">Network names become <span class="mono">Network-1a2b3c</span>, also where they appear in events and logs.</div></td></tr>
      </tbody></table></div></section>
      <div class="faint small-text" style="max-width:760px;margin-top:12px">
        <p>The same name always gets the same pseudonym, also after a restart, and links, searches and forms keep working: a pseudonym typed or clicked in the interface is turned back into the real value before anything is looked up.</p>
        <p><b>Display only.</b> The database, backups, notifications that are sent out (ntfy, e-mail, …) and the sensors' own uploads keep the real values, so this is not a way to store less personal data. A MAC address or SSID written in free text (a label, a note) is not recognised. Downloaded handshake captures contain the real addresses.</p></div>`;
    ['macs', 'ssids'].forEach(k => el.querySelector('#pv-' + k).onchange = save);
  }

  async function save() {
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
