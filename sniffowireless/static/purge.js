'use strict';
/* Settings → Clear data: delete everything stored for one kind of radio, or its events and alert history, or the application log. */

SETTINGS_VIEWS.purge = async function (el) {
  let data = await api('/api/purge');
  const NAMES = { devices: 'devices (with their sessions, signal history and events)', channel_stats: 'channel survey rows', interference: 'interference episodes',
    dfs_events: 'radar / channel switch events', ap_enc: 'security history of access points', findings: 'security findings', lan_dns: 'DNS names', lan_flows: 'flow rows',
    lan_traffic: 'traffic rows', dhcp_servers: 'DHCP servers', zigbee_networks: 'networks', zigbee_radios: 'radios', zigbee_channels: 'channel rows', zigbee_energy: 'energy readings',
    lora_packets: 'packets', lora_nodes: 'nodes', lora_stats: 'statistics rows', events: 'events', alert_log: 'alert history entries' };
  const list = o => Object.entries(o).filter(([, n]) => n).map(([k, n]) => `${num(n)} ${NAMES[k] || k}`).join(', ') || 'nothing';

  function render() {
    el.innerHTML = `<p class="muted" style="margin-top:0">Delete what is stored for one kind of radio, for starting over or after trying something out. <b>This cannot be undone</b>: make a <a href="#/settings?tab=backup">backup</a> first if you may want it back.
        Labels, notes, groups and watch flags, alert rules, notification channels, settings, users, sensors and downloaded handshake captures are kept. Capture continues: new data appears as it is heard.</p>
      <section class="panel" style="max-width:900px"><div class="body">
        ${data.modules.map(m => `<div style="padding:10px 0;border-bottom:1px solid var(--border)">
          <div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:8px"><b>${esc(m.label)}</b>
            <span><button class="btn small danger" data-m="${esc(m.id)}" data-what="entries" ${m.entries_total ? '' : 'disabled'}>Clear entries</button>
              <button class="btn small danger" data-m="${esc(m.id)}" data-what="logs" ${m.logs_total ? '' : 'disabled'}>Clear events</button></span></div>
          <div class="small-text muted" style="margin-top:4px">Stored: ${esc(list(m.entries))}</div>
          <div class="small-text muted">Events and alert history: ${esc(list(m.logs))}</div></div>`).join('')}
        <div style="padding:10px 0"><div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:8px"><b>Application log</b><button class="btn small danger" id="pg-applog">Clear log</button></div>
          <div class="small-text muted" style="margin-top:4px">The log lines shown under Logs (kept in memory only)</div></div>
      </div></section>`;
    el.querySelectorAll('button[data-m]').forEach(b => b.onclick = () => ask(data.modules.find(m => m.id === b.dataset.m), b.dataset.what));
    el.querySelector('#pg-applog').onclick = async () => {
      if (!confirm('Clear the application log?')) return;
      try { const r = await send('DELETE', '/api/purge/app-log'); toast(`Cleared ${num(r.deleted)} log lines`); } catch (e) { toast(e.message, true); }
    };
  }

  function ask(m, what) {
    const entries = what === 'entries';
    const body = entries ? m.entries : m.logs;
    openModal(`${entries ? 'Clear the stored data of' : 'Clear the events and alert history of'} ${m.label}`,
      `<p style="margin-top:0">This deletes <b>${esc(list(body))}</b>${entries && m.entries.devices ? ` and, for the devices, their sessions, signal history, probes and events` : ''}.</p>
       <p class="muted">It cannot be undone.${entries ? ' Labels, groups and settings stay.' : ''}</p>`,
      async () => {
        const r = await send('POST', '/api/purge', { module: m.id, entries, logs: !entries, confirm: m.id });
        toast('Deleted: ' + list(r.deleted));
        data = await api('/api/purge');
        render();
      }, { submit: entries ? 'Delete the data' : 'Delete the events', danger: true });
  }
  render();
};
