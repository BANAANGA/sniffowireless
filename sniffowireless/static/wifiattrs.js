'use strict';
/* Device-page rows for the extra Wi-Fi attributes (see wifiattrs.py): what an access point says about itself in its
   beacons, what a client says it can do, its link rate and, when switched on, other addresses it may have used. */

const AKM_HELP = {
  'PSK': 'WPA2-Personal: one shared password.', 'SAE': 'WPA3-Personal: password with SAE, which resists offline guessing.',
  'OWE': 'Opportunistic Wireless Encryption: encrypted without a password (open networks with encryption).',
  '802.1X': 'Enterprise login (each user signs in, usually through a RADIUS server).', 'DPP': 'Device Provisioning Protocol.',
  'CCKM': 'Cisco fast roaming.',
};
const ROAM_HELP = { '11k': 'Neighbour reports: tells clients which other access points to try.', '11v': 'BSS transition: can steer clients to another access point.', '11r': 'Fast BSS transition: quick, secure roaming between access points.' };

function wifiAkmTag(a) {
  const base = a.replace(/^FT-/, '').replace(/-SHA\d+$/, '').replace(/-EXT$/, '');
  const help = (AKM_HELP[a] || AKM_HELP[base] || '') + (a.startsWith('FT-') ? ' Fast-roaming variant.' : '');
  return `<span class="tag" title="${esc(help)}">${esc(a)}</span>`;
}

function wifiApRows(ex, d) {
  const a = ex && ex.ap;
  const rows = [], tags = xs => xs.join(' ');
  if (ex && ex.skew) rows.push(['Clock drift', `${ex.skew.ppm > 0 ? '+' : ''}${ex.skew.ppm} ppm <span class="faint">(how fast or slow its beacon timer runs; each timer has its own value, and two timers under one address raise an alert)</span>`]);
  if (!a) return rows;
  if (a.bsig) rows.push(['Beacon fingerprint', `<span class="mono">${esc(a.bsig)}</span> <span class="faint">(how its beacons are built; the same model and firmware give the same value)</span>`]);
  if (a.boot) {
    const secs = Math.max(0, Date.now() / 1000 - a.boot);
    rows.push(['Up for', `${dur(secs)} <span class="faint">(since ${dt(a.boot)}, estimated from the beacon timestamp; some access points reset it on their own)</span>`]);
  }
  if (a.rsn) {
    const r = a.rsn, bits = [...(r.akm || []).map(wifiAkmTag)];
    bits.push(`<span class="tag ${r.pmf === 'off' ? 'warn' : 'on'}" title="${esc(r.pmf === 'required' ? 'Management frame protection is required: clients ignore forged deauthentication and disassociation frames.' : r.pmf === 'optional' ? 'Management frame protection is supported but not required: older clients can still be kicked off with forged frames.' : 'No management frame protection: anyone nearby can disconnect clients with forged deauthentication frames.')}">PMF ${esc(r.pmf)}</span>`);
    if (r.transition) bits.push('<span class="tag warn" title="WPA3 and WPA2 on the same network: clients that connect with WPA2 get no WPA3 protection.">WPA3 + WPA2 transition</span>');
    if ((r.pairwise || []).includes('TKIP')) bits.push('<span class="tag warn" title="TKIP is an old cipher with known weaknesses.">TKIP</span>');
    rows.push(['Security details', `${tags(bits)} <span class="faint">${esc((r.pairwise || []).join(', '))}</span>`]);
  }
  if (a.wpa1) rows.push(['Old WPA', '<span class="tag warn" title="Also announces WPA version 1 (TKIP), the pre-WPA2 standard.">WPA 1 offered</span>']);
  if (a.load) rows.push(['Load', `${a.load.sta} connected · ${a.load.util}% of the time busy <span class="faint">(reported by the access point)</span>`]);
  if (a.ap_name) rows.push(['AP name', `${esc(a.ap_name)} <span class="faint">(announced in its beacons by ${esc(a.ap_name_src || 'the access point')}; an administrator can set it to anything)</span>`]);
  if (a.beacon_tu) rows.push(['Beacon interval', `${a.beacon_tu} TU <span class="faint">≈ ${Math.round(a.beacon_tu * 1.024)} ms</span>`]);
  if (a.country) rows.push(['Country', `${esc(a.country)}${a.country_env ? ` <span class="faint">(${esc(a.country_env)})</span>` : ''}`]);
  if (a.roaming && a.roaming.length) rows.push(['Roaming', tags(a.roaming.map(x => `<span class="tag" title="${esc(ROAM_HELP[x] || '')}">802.${esc(x)}</span>`))]);
  const gen = [];
  if (a.bss_color != null) gen.push(`<span class="tag" title="BSS colour: Wi-Fi 6 uses it to tell neighbouring networks on the same channel apart.">BSS colour ${a.bss_color}</span>`);
  if (a.mlo) gen.push('<span class="tag" title="Multi-link operation: this access point can use several bands at once (Wi-Fi 7).">multi-link (Wi-Fi 7)</span>');
  if (gen.length) rows.push(['Wi-Fi 6 / 7', tags(gen)]);
  const more = [];
  if (a.mbssid) more.push(['multiple BSSID (several networks from one radio)', 'One radio serves several networks, each with its own address, from a single set of beacons.']);
  if (a.interworking) more.push(['interworking / Hotspot', 'Announces Hotspot / interworking information, as carrier and public Wi-Fi does.']);
  if (a.ftm) more.push(['FTM location ranging', 'Answers fine timing measurement requests, so devices can work out their distance to it.']);
  if (a.beacon_protection) more.push(['beacon protection', 'Protects its beacons against forgery.']);
  if (a.mesh_id) more.push([`mesh “${a.mesh_id}”`, 'Part of an 802.11s mesh network with this mesh ID.']);
  (a.aruba || []).forEach(x => more.push([`Aruba ${x}`, 'An element Aruba access points add to their beacons.']));
  if (more.length) rows.push(['Also announces', more.map(([l, h]) => tagWithHelp(l, h)).join(' ')]);
  if (a.wps_configured != null || a.wps_locked) rows.push(['WPS', `${a.wps_configured ? 'configured' : 'not configured'}${a.wps_locked ? ' · <span class="warn-text">setup locked</span>' : ''}`]);
  if (a.rnr && a.rnr.length) rows.push(['Neighbouring APs', `<span class="faint">announced in its beacons (often the same device on another band):</span> ${a.rnr.map(n => `${devLink(n.bssid)} <span class="faint">ch ${n.ch}</span>`).join(', ')}`]);
  return rows;
}

function wifiClientRows(ex, d) {
  const rows = [];
  if (ex.scan) rows.push(['Scan behaviour', `${ex.scan.size} probe request${ex.scan.size === 1 ? '' : 's'} per burst${ex.scan.size > 1 ? `, ${ex.scan.gap_ms} ms apart` : ''}, a burst about every ${ex.scan.period} s <span class="faint">(median of ${ex.scan.bursts} bursts)</span>`]);
  if (ex.rate_up != null || ex.rate_down != null) {
    rows.push(['Link rate', [ex.rate_up != null ? `↑ ${ex.rate_up} Mbit/s` : '', ex.rate_down != null ? `↓ ${ex.rate_down} Mbit/s` : ''].filter(Boolean).join(' &nbsp; ') + ' <span class="faint">(last data frame heard)</span>']);
  }
  if (ex.noise != null) rows.push(['Noise floor', `${ex.noise} dBm${d.last_rssi != null ? ` <span class="faint">· signal-to-noise ${d.last_rssi - ex.noise} dB</span>` : ''}`]);
  if (ex.same_as && ex.same_as.length) {
    rows.push(['Possibly the same device', `${ex.same_as.map(x => `${devLink(x.mac)} <span class="faint" title="The second address carried on the frame counter of the first, within seconds. Only a guess: other devices can match by chance.">counter +${x.step}</span>`).join(', ')}`]);
  }
  return rows;
}

function wifiFeaturesHtml(ci) {
  if (!ci) return '';
  const t = [...(ci.caps || [])];
  if (ci.dsss === false) t.push('no 802.11b rates');
  if (ci.chan_count) t.push(`${ci.chan_count} channels supported`);
  if (ci.txp) t.push(`TX power ${ci.txp[0]}–${ci.txp[1]} dBm`);
  if (!t.length) return '';
  return `<div style="margin-top:10px"><span class="faint small-text">What it says it can do: </span>${t.map(x => tagWithHelp(x, capHelp(x), 'margin:0 6px 6px 0')).join('')}</div>`;
}

/* Link quality (linkstats.py): the rates, MCS and retries of a client's data frames, each way, and what they point to. On a
   client's page its own link; on an access point's page its clients'; on My networks every client with a problem. */
const LINK_TAG = { ok: 'on', warn: 'warn', bad: 'bad', none: '' };
const linkVerdict = v => `<span class="tag ${LINK_TAG[v.level]}" title="${esc(v.text)}">${esc(v.short)}</span>`;
const linkPct = x => x == null ? '—' : (x * 100).toFixed(x < 0.1 ? 1 : 0) + '%';
const linkPhy = s => s.phy ? `${esc(s.phy === 'legacy' ? 'legacy (a/b/g)' : s.phy === 'HE' ? 'HE (Wi-Fi 6)' : s.phy === 'VHT' ? 'VHT (Wi-Fi 5)' : 'HT (Wi-Fi 4)')}${s.nss ? ` · ${s.nss} stream${s.nss > 1 ? 's' : ''}` : ''}${s.width ? ` · ${s.width} MHz` : ''}` : '—';

async function loadLinkQuality(el, mac, isAp) {
  if (!el) return;
  const hours = 24;
  if (isAp) {
    const r = await api(`/api/link?hours=${hours}&bssid=${enc(mac)}`);
    if (!r.clients.length) return;
    el.hidden = false;
    el.innerHTML = `<header><h2>Clients' link quality</h2><span class="faint">their data frames in the last 24 hours, the worst first</span></header>
      <div class="body flush">${linkTable(r.clients)}</div>`;
    linkRows(el);
    return;
  }
  const r = await api(`/api/link/${enc(mac)}?hours=${hours}`);
  if (!r.up && !r.down) return;
  el.hidden = false;
  const side = (s, label) => !s ? `<div><h3 class="subhead">${label}</h3><div class="faint">No data frames heard this way.</div></div>` : `<div>
      <h3 class="subhead">${label} ${linkVerdict(s.verdict)}</h3>
      <p class="small-text" style="margin:4px 0 8px">${esc(s.verdict.text)}</p>
      <div class="kv">${[['Data frames', num(s.frames)], ['Sent again (retries)', linkPct(s.retry_rate)], ['Median rate', s.median_rate != null ? s.median_rate + ' Mb/s' : '—'],
        ['Median MCS', s.mcs_median ?? '—'], ['PHY', linkPhy(s)], ...(s.rssi != null ? [['Signal', s.rssi + ' dBm']] : [])].map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join('')}</div></div>`;
  const useMcs = (r.up && r.up.mcs.length) || (r.down && r.down.mcs.length);
  el.innerHTML = `<header><h2>Link quality</h2><span class="faint">its data frames in the last 24 hours: at which rate they went, and how many had to be sent again</span></header>
    <div class="body"><div class="grid cols-2">${side(r.up, 'Sent by this device ↑')}${side(r.down, 'Sent to this device ↓')}</div>
    <h3 class="subhead">${useMcs ? 'Frames per MCS' : 'Frames per rate'}</h3><div class="chart-box short"><canvas id="linkq-chart"></canvas></div>
    <p class="faint small-text">Low MCS with few retries: a weak signal, the link slowed down to what the distance allows. High MCS with many retries: the signal is fine but frames get lost (interference, a busy channel). Legacy rates only: an old radio.</p></div>`;
  const keys = useMcs ? [...new Set([...(r.up?.mcs || []), ...(r.down?.mcs || [])].map(x => x.mcs))].sort((a, b) => a - b)
    : [...new Set([...(r.up?.rates || []), ...(r.down?.rates || [])].map(x => x.rate))].sort((a, b) => a - b);
  const series = (s, color, label) => s ? { label, backgroundColor: color, borderRadius: 2, maxBarThickness: 22,
    data: keys.map(k => { const t = s.frames || 1; const hit = (useMcs ? s.mcs : s.rates).find(x => (useMcs ? x.mcs : x.rate) === k); return hit ? +(hit.frames * 100 / t).toFixed(1) : 0; }) } : null;
  chart(document.getElementById('linkq-chart'), { type: 'bar', data: { labels: keys.map(k => useMcs ? 'MCS ' + k : k + ' Mb/s'),
    datasets: [series(r.up, KINDS.wifi_client.color + 'cc', '↑ sent'), series(r.down, KINDS.ap.color + 'cc', '↓ received')].filter(Boolean) },
    options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { color: FAINT } }, y: yScale({ ticks: { color: FAINT, callback: v => v + '%' } }) },
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 8, boxHeight: 8, color: MUTED } } } } });
}

function linkTable(clients) {
  const dir = (s, signal) => !s ? '<td class="num faint">—</td><td class="num faint">—</td>' + (signal ? '<td class="num faint">—</td>' : '')
    : `<td class="num">${linkPct(s.retry_rate)}</td><td class="num muted">${s.mcs_median != null ? 'MCS ' + s.mcs_median : s.median_rate != null ? s.median_rate + ' Mb/s' : '—'}</td>${signal ? `<td class="num muted">${s.rssi != null ? s.rssi + ' dBm' : '—'}</td>` : ''}`;
  return tableHtml('<th>Client</th><th>Link</th><th class="num">Frames</th><th class="num">↑ retries</th><th class="num">↑ median</th><th class="num">↑ signal</th><th class="num">↓ retries</th><th class="num">↓ median</th><th>PHY</th>',
    clients.map(c => `<tr class="link" data-href="#/device/${enc(c.mac)}"><td>${c.name ? esc(c.name) + ' ' : ''}<span class="mono faint">${esc(c.mac)}</span></td>
      <td>${linkVerdict(c.verdict)}</td><td class="num muted">${num(c.frames)}</td>${dir(c.up, true)}${dir(c.down, false)}
      <td class="muted small-text">${linkPhy(c)}</td></tr>`).join(''));
}
