'use strict';
/* Settings → Modules: switch off the kinds of radios this installation doesn't use, so their menu entries, overview
   cards and statistics disappear. Display only: capture keeps following the environment variables. */

SETTINGS_VIEWS.modules = async function (el) {
  let data = await api('/api/modules');
  const desc = { wifi: 'Access points, Wi-Fi clients, networks, channels, security and investigations', bluetooth: 'BLE devices and Bluetooth classic',
    lan: 'Wired devices, traffic, DNS and DHCP', zigbee: 'Zigbee and other 802.15.4 networks and radios', lora: 'Meshtastic, MeshCore, LoRaWAN and other LoRa traffic' };

  function render() {
    const unused = data.modules.filter(m => m.enabled && !m.in_use);
    el.innerHTML = `<p class="muted" style="margin-top:0">Hide what you don't use. A hidden kind disappears from the menu, the overview and the statistics. Nothing is deleted and capture is not changed (that follows the environment variables), so you can switch it back on at any time.</p>
      <section class="panel" style="max-width:760px"><div class="body flush"><table><tbody>${data.modules.map(m => `<tr>
        <td style="width:34px"><input type="checkbox" data-module="${esc(m.id)}" ${m.enabled ? 'checked' : ''} aria-label="Show ${esc(m.label)}"></td>
        <td><b>${esc(m.label)}</b><div class="faint small-text">${esc(desc[m.id] || '')}</div>
          ${m.has_retention ? `<div class="small-text" style="margin-top:6px">Keep its data <input type="number" min="1" max="3650" data-keep="${esc(m.id)}" value="${m.retention || ''}" placeholder="${data.default_retention}" style="width:80px"> days <span class="faint">(empty: ${data.default_retention}, the general setting)</span></div>` : ''}</td>
        <td class="num">${m.in_use ? '<span class="tag on">in use</span>' : '<span class="tag">nothing seen or configured</span>'}</td></tr>`).join('')}</tbody></table></div></section>
      <div class="row" style="margin-top:12px"><button class="btn" id="mod-unused" ${unused.length ? '' : 'disabled'}>Hide the ${unused.length || ''} unused</button>
        <span class="faint small-text">${unused.length ? unused.map(m => esc(m.label)).join(', ') : 'Everything shown is in use'}</span></div>`;
    el.querySelectorAll('input[data-module]').forEach(b => b.onchange = () => save(data.modules.filter(m => m.id === b.dataset.module ? !b.checked : !m.enabled).map(m => m.id)));
    el.querySelectorAll('input[data-keep]').forEach(i => i.onchange = () => save(data.modules.filter(m => !m.enabled).map(m => m.id), { [i.dataset.keep]: +i.value || 0 }));
    el.querySelector('#mod-unused').onclick = () => save(data.modules.filter(m => !m.enabled || !m.in_use).map(m => m.id));
  }

  async function save(disabled, retention) {
    try {
      data = await send('PUT', '/api/modules', retention ? { disabled, retention } : { disabled });
      await loadModules();  // the menu follows at once
      toast('Saved');
      route();  // redraws the settings tabs too (Wi-Fi channels goes with Wi-Fi)
      return;
    } catch (e) { toast(e.message, true); data = await api('/api/modules'); }
    render();
  }
  render();
};
